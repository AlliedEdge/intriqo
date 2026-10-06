"""Worker boundary, ledger, queue, and parser behavior."""

from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import time
from pathlib import Path

import pytest
from intriqo_ml.inference_v2 import DetectorState, MLDetectionResult
from intriqo_ml.ml_worker import (
    DecisionLedger,
    InputLine,
    MLWorker,
    _assert_regular_input,
    _assert_write_locations,
    iter_bounded_jsonl,
    main,
)


def _record(flow_id: str = "1") -> dict[str, object]:
    return {
        "schema_version": "flow_features.v2",
        "metadata": {
            "engine_instance_id": "123e4567-e89b-42d3-a456-426614174000",
            "flow_id": flow_id,
            "first_seen": "2023-11-14T22:13:20.000000001Z",
            "timestamp": "2023-11-14T22:13:23.000000001Z",
            "export_reason": "shutdown_flush",
            "network": {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.20",
                "src_port": 40000,
                "dst_port": 443,
                "protocol": "TCP",
            },
        },
        "measurements": {
            "packet_count": 3,
            "byte_count": 120,
            "duration_seconds": 3.0,
            "bytes_per_packet": 40.0,
            "packets_per_second": 1.0,
            "bytes_per_second": 40.0,
            "fwd_packet_count": 2,
            "rev_packet_count": 1,
            "fwd_byte_count": 80,
            "rev_byte_count": 40,
            "syn_count": 2,
            "fin_count": 0,
            "rst_count": 0,
            "initial_syn_count": 1,
            "syn_ack_count": 1,
            "ack_count": 1,
            "tcp_handshake_started": True,
            "tcp_syn_ack_seen": True,
            "tcp_handshake_completed": True,
        },
        "timing": {"policy": "capture_order_nondecreasing_population.v1", "gap_count": 2},
        "features": {
            "duration_seconds": 3.0,
            "packet_count": 3,
            "packets_per_second": 1.0,
            "minor_direction_packet_fraction": 1 / 3,
            "mean_ipv4_packet_bytes": 40.0,
            "ipv4_direction_byte_imbalance": 1 / 3,
            "syn_packet_fraction": 2 / 3,
            "fin_packet_fraction": 0.0,
            "flow_iat_std_seconds": 0.5,
        },
    }


class FakeDetector:
    state = DetectorState.READY

    def __init__(self, *, anomaly: bool = True, delay: float = 0.0, fail: bool = False) -> None:
        self.anomaly = anomaly
        self.delay = delay
        self.fail = fail

    def detect(self, record):  # type: ignore[no-untyped-def]
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            self.state = DetectorState.DEGRADED
            raise RuntimeError("inference failure")
        return MLDetectionResult(
            "isolation_forest_v2",
            "controlled-v2/isolation-forest-v2",
            record.metadata.engine_instance_id,
            record.metadata.flow_id,
            0.6,
            0.5,
            self.anomaly,
            "flow_features.v2",
            "2026-01-01T00:00:00Z",
            "a" * 64,
            "b" * 64,
        )


def _raw(*records: dict[str, object], malformed: bool = False) -> bytes:
    lines = [json.dumps(record) for record in records]
    if malformed:
        lines.insert(0, "not-json")
    return ("\n".join(lines) + "\n").encode()


def test_disabled_cli_does_not_open_paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("INTRIQO_ML_ENABLED", raising=False)
    missing = tmp_path / "missing-input.jsonl"
    status = tmp_path / "status.json"
    assert main(
        [
            str(missing),
            "--output",
            str(tmp_path / "out"),
            "--ledger",
            str(tmp_path / "ledger"),
            "--status-file",
            str(status),
        ]
    ) == 0
    assert not missing.exists()
    assert not (tmp_path / "out").exists()
    assert not (tmp_path / "ledger").exists()
    assert json.loads(status.read_text()) == {
        "detector_state": DetectorState.DEGRADED.value,
        "reason": "disabled_by_configuration",
        "state": "DISABLED",
    }


def test_malformed_inference_and_minimal_event(tmp_path: Path) -> None:
    with DecisionLedger(tmp_path / "decisions.sqlite", 10) as ledger:
        output = io.StringIO()
        stats = MLWorker(FakeDetector(fail=False), ledger, output).run(
            io.BytesIO(_raw(_record(), malformed=True))
        )
    assert stats["rejected"] == 1
    assert stats["anomalies"] == 1
    event = json.loads(output.getvalue())
    assert set(event) == {
        "event_id",
        "event_type",
        "severity",
        "timestamp",
        "source_address",
        "destination_address",
        "details",
    }
    assert "src_port" not in json.dumps(event)

    with DecisionLedger(tmp_path / "failed.sqlite", 10) as ledger:
        stats = MLWorker(FakeDetector(fail=True), ledger, io.StringIO()).run(
            io.BytesIO(_raw(_record()))
        )
    assert stats["inference_errors"] == 1
    assert stats["detector_state"] == DetectorState.DEGRADED.value
    assert stats["inference_count"] == 1
    assert float(stats["inference_seconds"]) > 0
    assert stats["inference_seconds_mean"] == stats["inference_seconds"]
    assert stats["decisions_reserved"] == 0


def test_ledger_deduplicates_across_restart_and_fails_closed_at_capacity(tmp_path: Path) -> None:
    raw = _raw(_record())
    first_output = io.StringIO()
    with DecisionLedger(tmp_path / "decisions.sqlite", 1) as ledger:
        first = MLWorker(FakeDetector(), ledger, first_output).run(io.BytesIO(raw))
    second_output = io.StringIO()
    with DecisionLedger(tmp_path / "decisions.sqlite", 1) as ledger:
        second = MLWorker(FakeDetector(), ledger, second_output).run(io.BytesIO(raw))
    assert first["decisions_reserved"] == 1
    assert second["decisions_duplicate"] == 1
    assert second_output.getvalue() == ""

    with DecisionLedger(tmp_path / "full.sqlite", 1) as ledger:
        full = MLWorker(FakeDetector(), ledger, io.StringIO()).run(
            io.BytesIO(_raw(_record("1"), _record("2")))
        )
    assert full["ledger_capacity_drops"] == 1


def test_oversize_and_follow_partial_are_bounded() -> None:
    oversized = b"{" + b"x" * 9000 + b"}\n"
    lines = list(iter_bounded_jsonl(io.BytesIO(oversized + b"{}\n")))
    assert lines[0].error is not None and lines[0].error.code == "record_too_large"
    assert lines[1].raw == b"{}\n"

    stop = threading.Event()
    observed: list[InputLine] = []

    def consume() -> None:
        observed.extend(iter_bounded_jsonl(io.BytesIO(b"partial"), follow=True, stop_event=stop, poll_seconds=0.01))

    thread = threading.Thread(target=consume)
    thread.start()
    time.sleep(0.03)
    stop.set()
    thread.join(1.0)
    assert not thread.is_alive()
    assert len(observed) == 1
    assert observed[0].drop_reason == "shutdown_partial"


def test_exact_record_size_excludes_lf_and_crlf() -> None:
    for terminator in (b"\n", b"\r\n"):
        rows = list(iter_bounded_jsonl(io.BytesIO(b"x" * 8192 + terminator + b"{}\n")))
        assert rows[0].error is None
        assert rows[0].raw == b"x" * 8192 + terminator
        assert rows[1].raw == b"{}\n"

        oversized_rows = list(iter_bounded_jsonl(io.BytesIO(b"x" * 8193 + terminator + b"{}\n")))
        assert oversized_rows[0].error is not None
        assert oversized_rows[0].error.code == "record_too_large"
        assert oversized_rows[1].raw == b"{}\n"


def test_queue_overflow_is_drop_newest() -> None:
    records = _raw(*[_record(str(index)) for index in range(30)])
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "ledger.sqlite"
        with DecisionLedger(path, 100) as ledger:
            stats = MLWorker(
                FakeDetector(delay=0.01), ledger, io.StringIO(), queue_capacity=1
            ).run(io.BytesIO(records))
    assert int(stats["queue_overflows"]) > 0
    assert stats["queue_peak"] == 1
    assert stats["queue_depth"] == 0
    assert stats["dropped_queue_overflow"] == stats["queue_overflows"]


def test_slow_transport_has_finite_shutdown_drain(tmp_path: Path) -> None:
    class SlowTransport:
        def send(self, _payload: object) -> None:
            time.sleep(0.3)

    started = time.monotonic()
    with DecisionLedger(tmp_path / "slow.sqlite", 10) as ledger:
        stats = MLWorker(
            FakeDetector(),
            ledger,
            io.StringIO(),
            transport=SlowTransport(),
            shutdown_timeout_seconds=0.03,
        ).run(io.BytesIO(_raw(_record())))
    assert time.monotonic() - started < 0.2
    assert stats["status"] == "shutdown_timeout"
    assert stats["abandoned_drops"] == 0


def test_output_only_mode_is_not_delivery_failure(tmp_path: Path) -> None:
    with DecisionLedger(tmp_path / "output-only.sqlite", 10) as ledger:
        stats = MLWorker(FakeDetector(), ledger, io.StringIO()).run(io.BytesIO(_raw(_record())))
    assert stats["delivery_mode"] == "output_only"
    assert stats["delivery_failures"] == 0


def test_output_and_ledger_errors_are_counted_without_crashing(tmp_path: Path) -> None:
    output = io.StringIO()
    output.close()
    ledger = DecisionLedger(tmp_path / "output-error.sqlite", 10)
    try:
        output_stats = MLWorker(FakeDetector(), ledger, output).run(io.BytesIO(_raw(_record())))
    finally:
        ledger.close()
    assert output_stats["output_failures"] == 1
    assert output_stats["decisions_reserved"] == 1

    closed_ledger = DecisionLedger(tmp_path / "ledger-error.sqlite", 10)
    closed_ledger.close()
    ledger_stats = MLWorker(FakeDetector(), closed_ledger, io.StringIO()).run(
        io.BytesIO(_raw(_record()))
    )
    assert ledger_stats["ledger_failures"] == 1


def test_input_device_and_write_aliases_are_rejected(tmp_path: Path) -> None:
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    try:
        try:
            _assert_regular_input(fifo)
        except ValueError:
            pass
        else:
            raise AssertionError("FIFO input was accepted")
    finally:
        fifo.unlink()

    input_path = tmp_path / "corpus" / "input.jsonl"
    input_path.parent.mkdir()
    input_path.write_bytes(b"{}")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    model = artifacts / "model.joblib"
    model.write_bytes(b"model")
    with_ledger = tmp_path / "ledger.sqlite"
    with_ledger.write_bytes(b"")
    try:
        _assert_write_locations(
            input_path,
            input_path.parent / "out.jsonl",
            with_ledger,
            None,
            None,
            [model, artifacts / "model_metadata.json"],
        )
    except ValueError:
        pass
    else:
        raise AssertionError("corpus/artifact write location was accepted")
