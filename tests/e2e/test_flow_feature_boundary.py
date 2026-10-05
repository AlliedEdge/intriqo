"""Real C++ engine JSONL -> unchanged Python ML boundary, without services.

Run with PYTHONPATH=ml/src:engine/tests/fixtures and INTRIQO_ENGINE_BINARY set.
The successful path never builds, rewrites or normalizes feature JSON in Python.
"""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from flow_feature_fixture import write_flow_feature_pcap
from intriqo_ml import FlowFeatureRecord, parse_flow_feature_record
from intriqo_ml.consumer import consume_flow_feature_records, iter_flow_feature_records

ROOT = Path(__file__).resolve().parents[2]
ENGINE = Path(os.environ.get(
    "INTRIQO_ENGINE_BINARY", str(ROOT / "build/flow-release/engine/intriqo-engine")
))
# 1e-12 relative/absolute tolerates binary64 rounding while remaining far below
# the fixture's one-nanosecond differences. No tolerance is used for counters.
FLOAT_REL_TOL = FLOAT_ABS_TOL = 1e-12


def _engine(tmp_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    assert ENGINE.is_file(), "build the engine or set INTRIQO_ENGINE_BINARY"
    # Pin configuration so developer environment overrides cannot change fixtures.
    return subprocess.run(
        [str(ENGINE), "--output", str(tmp_path / "events.jsonl"),
         "--event-queue-capacity", "0", "--flow-idle-timeout", "1",
         "--max-active-flows", "32", "--max-tracked-sources", "4096",
         "--max-tracked-observations", "100000", *args],
        cwd=ROOT, capture_output=True, text=True, timeout=15, check=False,
    )


def _summary(run: subprocess.CompletedProcess[str]) -> dict[str, str]:
    assert run.returncode == 0, run.stderr
    shutdown = next(line for line in run.stdout.splitlines() if line.startswith("shutdown "))
    return dict(re.findall(r"([a-z_]+)=([^ ]+)", shutdown))


@dataclass(frozen=True)
class EngineOutput:
    path: Path
    raw: bytes
    summary: dict[str, str]


@pytest.fixture
def generated(tmp_path: Path) -> EngineOutput:
    source = tmp_path / "controlled.pcap"
    target = tmp_path / "features.jsonl"
    write_flow_feature_pcap(source)
    run = _engine(tmp_path, "--pcap", str(source), "--feature-output", str(target),
                  "--feature-queue-capacity", "32")
    return EngineOutput(target, target.read_bytes(), _summary(run))


def _validated(raw: bytes) -> dict[str, FlowFeatureRecord]:
    results = list(iter_flow_feature_records(io.BytesIO(raw)))
    assert results
    assert all(result.error is None for result in results)
    records = [result.record for result in results]
    assert all(record is not None for record in records)
    by_id = {record.metadata.flow_id: record for record in records if record is not None}
    assert len(by_id) == len(records), "one retirement record per distinct flow ID"
    assert len({record.metadata.engine_instance_id for record in by_id.values()}) == 1
    return by_id


def test_cpp_pcap_values_lifecycle_and_independent_flows(generated: EngineOutput) -> None:
    summary = generated.summary
    for field, expected in {
        "status": "complete", "packets_received": "13", "packets_parsed": "13",
        "packets_rejected": "0", "flows_created": "5", "flows_expired": "3",
        "flows_flushed": "2", "flows_evicted": "0", "flows_active": "0",
        "feature_records_generated": "5", "feature_records_submitted": "5",
        "feature_records_written": "5", "feature_records_dropped": "0",
        "feature_queue_depth": "0", "feature_write_failures": "0",
        "feature_generation_failures": "0", "feature_validation_failures": "0",
    }.items():
        assert summary[field] == expected, field
    by_id = _validated(generated.raw)
    assert set(by_id) == {"1", "2", "3", "4", "5"}
    # Expected values come from the explicit packet bytes/timestamps, not from
    # copying the serialized record. Match IDs, not assumed JSONL line ordering.
    expected = {
        "1": ("TCP", 41000, 443, 6, 240, 4, 2, 160, 80, .600000013,
              "20.123456789", "20.723456802", "idle_expired", (2, 2, 0, 1, 1, 2),
              (True, True, True)),
        "2": ("UDP", 42000, 5353, 2, 67, 1, 1, 32, 35, .250000007,
              "20.173456789", "20.423456796", "idle_expired", (0, 0, 0, 0, 0, 0),
              (False, False, False)),
        "3": ("TCP", 43000, 8080, 2, 80, 1, 1, 40, 40, .575000017,
              "20.248456789", "20.823456806", "idle_expired", (0, 0, 1, 0, 0, 1),
              (False, False, False)),
        "4": ("UDP", 44000, 53, 2, 68, 1, 1, 32, 36, .250000008,
              "23.123456812", "23.373456820", "shutdown_flush", (0, 0, 0, 0, 0, 0),
              (False, False, False)),
        "5": ("TCP", 45000, 8443, 1, 40, 1, 0, 40, 0, 0.,
              "23.623456789", "23.623456789", "shutdown_flush", (1, 0, 0, 1, 0, 0),
              (True, False, False)),
    }
    for identity, values in expected.items():
        (protocol, src_port, dst_port, packets, byte_count, fwd_packets, rev_packets,
         fwd_bytes, rev_bytes, duration, first, last, reason, flags, handshake) = values
        record = by_id[identity]
        metadata, network, features = record.metadata, record.metadata.network, record.features
        assert record.schema_version == "flow_features.v1"
        assert metadata.engine_uuid.version == 4
        assert metadata.flow_id_number == int(identity)
        assert network.protocol == protocol
        assert network.src_ip == f"192.0.2.{9 + int(identity)}"
        assert network.dst_ip == f"198.51.100.{19 + int(identity)}"
        assert (network.src_port, network.dst_port) == (src_port, dst_port)
        assert metadata.first_seen == f"2023-11-14T22:13:{first}Z"
        assert metadata.timestamp == f"2023-11-14T22:13:{last}Z"
        assert metadata.timestamp_time.nanosecond == int(last.split(".")[1])
        assert metadata.export_reason == reason
        assert (features.packet_count, features.byte_count) == (packets, byte_count)
        assert (features.fwd_packet_count, features.rev_packet_count) == (fwd_packets, rev_packets)
        assert (features.fwd_byte_count, features.rev_byte_count) == (fwd_bytes, rev_bytes)
        assert (features.syn_count, features.fin_count, features.rst_count,
                features.initial_syn_count, features.syn_ack_count, features.ack_count) == flags
        assert (features.tcp_handshake_started, features.tcp_syn_ack_seen,
                features.tcp_handshake_completed) == handshake
        for field, value in {
            "duration_seconds": duration,
            "bytes_per_packet": byte_count / packets,
            "packets_per_second": packets / duration if duration else 0.,
            "bytes_per_second": byte_count / duration if duration else 0.,
        }.items():
            actual = getattr(features, field)
            assert type(actual) is float
            assert actual == pytest.approx(value, rel=FLOAT_REL_TOL, abs=FLOAT_ABS_TOL), field
        assert type(features.packet_count) is int
        assert type(features.tcp_handshake_completed) is bool
    # FIN does not retire the flow: the final ACK remains in the same ID and the
    # single record is emitted on idle expiry, never a fabricated "completion".
    assert by_id["1"].features.fin_count == 2 and by_id["1"].features.packet_count == 6
    assert generated.path.read_bytes() == generated.raw


def _consumer_cli(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "intriqo_ml.consumer", str(path)], cwd=ROOT,
        env=os.environ | {"PYTHONPATH": str(ROOT / "ml/src")},
        text=True, capture_output=True, timeout=15, check=False,
    )


def test_real_consumer_cli_accepts_untouched_cpp_output(generated: EngineOutput) -> None:
    run = _consumer_cli(generated.path)
    assert run.returncode == 0, run.stderr
    assert run.stdout == "validated=5 rejected=0\n"
    assert run.stderr == ""
    assert generated.path.read_bytes() == generated.raw


def test_invalid_variants_of_real_cpp_record_are_sanitized_and_continue(
    generated: EngineOutput, tmp_path: Path
) -> None:
    original = generated.raw.splitlines()[0]
    variants: list[tuple[bytes, str]] = []
    for change, code in [("missing", "invalid_record"), ("type", "invalid_record"),
                         ("version", "unsupported_schema_version")]:
        value: dict[str, Any] = json.loads(original)
        if change == "missing":
            del value["features"]["packet_count"]
        elif change == "type":
            value["features"]["packet_count"] = "PRIVATE_PAYLOAD"
        else:
            value["schema_version"] = "PRIVATE_PAYLOAD"
        variants.append((json.dumps(value).encode(), code))
    for token in [b"NaN", b"Infinity", b"-Infinity", b"1e999"]:
        # Change only the existing genuine numeric field; no successful test
        # record is manufactured from an expected Python dictionary.
        raw, count = re.subn(rb'"bytes_per_second":[^,}]+',
                             b'"bytes_per_second":' + token, original)
        assert count == 1
        variants.append((raw, "nonfinite_number"))
    variants.append((original[:-1], "invalid_json"))
    mixed = original + b"\n" + b"\n".join(raw for raw, _ in variants) + b"\n" + generated.raw
    results = list(iter_flow_feature_records(io.BytesIO(mixed)))
    assert results[0].record is not None
    assert [result.error.code for result in results[1:9] if result.error] == [
        code for _, code in variants
    ]
    assert all(result.record is not None for result in results[9:])
    diagnostics = io.StringIO()
    counts = consume_flow_feature_records(io.BytesIO(mixed), error_stream=diagnostics)
    assert (counts.validated, counts.rejected) == (6, 8)
    assert "PRIVATE_PAYLOAD" not in diagnostics.getvalue()
    assert "192.0.2." not in diagnostics.getvalue()
    assert "unsupported flow feature schema version" in diagnostics.getvalue()
    target = tmp_path / "invalid.jsonl"
    target.write_bytes(mixed)
    run = _consumer_cli(target)
    assert run.returncode == 1
    assert run.stdout == "validated=6 rejected=8\n"
    assert "line 2: rejected:" in run.stderr and "line 9: rejected:" in run.stderr
    assert "PRIVATE_PAYLOAD" not in run.stdout + run.stderr
    assert "Traceback" not in run.stderr
    # Consumption is downstream-only. Rejections never alter the engine's file.
    assert generated.path.read_bytes() == generated.raw


def test_capacity_eviction_and_shutdown_stream_remain_correlated(tmp_path: Path) -> None:
    target = tmp_path / "features.jsonl"
    run = _engine(tmp_path, "--synthetic", "--synthetic-packets", "10",
                  "--synthetic-unique-ports", "10", "--max-active-flows", "2",
                  "--feature-output", str(target), "--feature-queue-capacity", "16")
    summary = _summary(run)
    assert summary["flows_evicted"] == "8" and summary["flows_flushed"] == "2"
    assert summary["feature_records_written"] == "10"
    assert summary["feature_records_dropped"] == "0"
    by_id = _validated(target.read_bytes())
    assert set(by_id) == {str(index) for index in range(1, 11)}
    for identity, record in by_id.items():
        assert record.metadata.export_reason == (
            "capacity_evicted" if int(identity) <= 8 else "shutdown_flush"
        )
        assert record.metadata.network.src_ip == "192.0.2.10"
        assert record.metadata.network.dst_ip == "198.51.100.20"
        assert record.metadata.network.src_port == 49152
        assert record.metadata.network.dst_port == int(identity)
        assert record.features.packet_count == 1 and record.features.byte_count == 40
        assert record.features.fwd_packet_count == 1 and record.features.rev_packet_count == 0
        assert record.features.syn_count == 1


def test_python_absence_and_feature_file_failure_do_not_block_detection(tmp_path: Path) -> None:
    # The engine finishes without launching Python in both configurations.
    for feature_args in [[], ["--feature-output", str(tmp_path / "missing/features.jsonl")]]:
        events = tmp_path / "events.jsonl"
        if events.exists():
            events.unlink()  # each FileEventSink run intentionally appends
        run = _engine(tmp_path, "--synthetic", "--synthetic-packets", "10",
                      "--synthetic-unique-ports", "10", *feature_args)
        summary = _summary(run)
        assert summary["packets_parsed"] == "10" and summary["flows_active"] == "0"
        assert summary["events_emitted"] == "1" and summary["sink_failures"] == "0"
        assert json.loads(events.read_text())["event_type"] == "PORT_SCAN"
        if feature_args:
            assert summary["feature_records_generated"] == "10"
            assert summary["feature_records_dropped"] == "10"
            assert summary["feature_write_failures"] == "1"
            assert "deterministic IDS unaffected" in run.stderr
        else:
            assert summary["feature_records_generated"] == "0"


def test_public_parser_agrees_with_stream_on_real_record(generated: EngineOutput) -> None:
    by_id = _validated(generated.raw)
    for raw in generated.raw.splitlines():
        parsed = parse_flow_feature_record(raw)
        assert parsed == by_id[parsed.metadata.flow_id]
