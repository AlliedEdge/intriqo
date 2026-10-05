"""Real-process C++ capture/parser/flows -> file JSONL -> strict Python models."""
from __future__ import annotations

import importlib.util
import json
import os
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest
from intriqo_ml.consumer import iter_flow_feature_records

ROOT = Path(__file__).resolve().parents[3]
ENGINE = Path(os.environ.get("INTRIQO_ENGINE_BINARY", ROOT / "build/flow-release/engine/intriqo-engine"))


@pytest.fixture(scope="module")
def engine() -> Path:
    assert ENGINE.is_file(), "build intriqo-engine and set INTRIQO_ENGINE_BINARY"
    return ENGINE.resolve()


def tcp_fixture():
    spec = importlib.util.spec_from_file_location(
        "syn_fixture", ROOT / "engine/tests/fixtures/syn_flood_fixture.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_records(path: Path):
    with path.open("rb") as stream:
        lines = list(iter_flow_feature_records(stream))
    assert lines and all(line.error is None and line.record is not None for line in lines)
    raw = [json.loads(line) for line in path.read_text().splitlines()]
    records = [line.record for line in lines]
    # Compare every field, not just a chosen feature or a precomputed event count.
    assert [record.model_dump(mode="json") for record in records] == raw
    identities = [(r.metadata.engine_instance_id, r.metadata.flow_id) for r in records]
    assert len(set(identities)) == len(records)
    return records


def run_engine(engine: Path, tmp_path: Path, *args: str):
    output = tmp_path / "features.jsonl"
    events = tmp_path / "events.jsonl"
    run = subprocess.run(
        [str(engine), *args, "--output", str(events), "--feature-output", str(output)],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert run.returncode == 0, run.stderr
    assert "feature_generation_failures=0" in run.stdout
    assert "feature_records_dropped=0" in run.stdout
    assert "feature_queue_depth=0" in run.stdout
    return run, load_records(output), events


def test_synthetic_real_flow_stream_and_consumer_cli(engine, tmp_path):
    run, records, events = run_engine(engine, tmp_path, "--synthetic", "--synthetic-packets", "30")
    assert len(records) == 10
    assert "packets_processed=30" in run.stdout and "feature_records_written=10" in run.stdout
    for record in records:
        assert record.schema_version == "flow_features.v1"
        assert record.metadata.export_reason == "shutdown_flush"
        assert record.features.packet_count == record.features.fwd_packet_count == 3
        assert record.features.byte_count == record.features.fwd_byte_count == 120
        assert record.features.syn_count == record.features.initial_syn_count == 3
        assert record.features.rev_packet_count == 0
        assert not record.features.tcp_handshake_completed
    assert json.loads(events.read_text().strip())["event_type"] == "PORT_SCAN"
    consumer = subprocess.run(
        [sys.executable, "-m", "intriqo_ml.consumer", str(tmp_path / "features.jsonl")],
        env=os.environ | {"PYTHONPATH": str(ROOT / "ml/src")},
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert consumer.returncode == 0, consumer.stderr
    assert consumer.stdout.strip() == "validated=10 rejected=0"


def test_completed_tcp_pcap_flow_rates_and_direction(engine, tmp_path):
    fixture = tcp_fixture()
    path = tmp_path / "handshake.pcap"
    fixture.write_completed_handshake_pcap(path, count=4, duration_seconds=0.3)
    _, records, _ = run_engine(engine, tmp_path, "--pcap", str(path))
    assert len(records) == 4
    for record in records:
        f = record.features
        assert record.metadata.network.src_ip == "192.0.2.10"
        assert record.metadata.network.dst_ip == "198.51.100.20"
        assert record.metadata.network.protocol == "TCP"
        assert f.packet_count == 3 and f.byte_count == 120
        assert f.fwd_packet_count == 2 and f.rev_packet_count == 1
        assert f.fwd_byte_count == 80 and f.rev_byte_count == 40
        assert f.syn_count == 2 and f.initial_syn_count == 1
        assert f.syn_ack_count == 1 and f.ack_count == 1
        assert f.tcp_handshake_started and f.tcp_syn_ack_seen and f.tcp_handshake_completed
        assert f.duration_seconds == pytest.approx(0.002)
        assert f.packets_per_second == pytest.approx(1500.0)
        assert f.bytes_per_second == pytest.approx(60000.0)
        assert f.bytes_per_packet == 40.0


@pytest.mark.parametrize("extra,reason", [
    (["--flow-idle-timeout", "0.05"], "idle_expired"),
    (["--max-active-flows", "1"], "capacity_evicted"),
])
def test_incomplete_pcap_retirement_is_not_discarded(engine, tmp_path, extra, reason):
    path = tmp_path / "incomplete.pcap"
    tcp_fixture().write_half_open_pcap(path, count=4, duration_seconds=0.3)
    run, records, _ = run_engine(engine, tmp_path, "--pcap", str(path), *extra)
    assert len(records) == 4
    assert [r.metadata.export_reason for r in records] == [reason] * 3 + ["shutdown_flush"]
    assert "feature_records_written=4" in run.stdout
    assert all(r.features.packet_count == 1 for r in records)
    assert all(r.features.duration_seconds == r.features.packets_per_second == 0 for r in records)
    assert all(r.features.tcp_handshake_started and not r.features.tcp_handshake_completed for r in records)


def test_udp_ipv4_lengths_and_nanosecond_timestamps(engine, tmp_path):
    path = tmp_path / "udp.pcap"
    fixture = tcp_fixture()
    source, destination = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 20])
    def frame(reverse: bool) -> bytes:
        src, dst = (destination, source) if reverse else (source, destination)
        ports = (53, 40000) if reverse else (40000, 53)
        udp = struct.pack("!HHHH", *ports, 11, 0) + b"abc"
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 31, 0, 0, 64, 17, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", fixture.checksum(ip)) + ip[12:]
        return bytes.fromhex("0200000000010200000000020800") + ip + udp
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        for fraction, reverse in [(123456789, False), (623456789, True)]:
            data = frame(reverse)
            output.write(struct.pack("<IIII", 1700000000, fraction, len(data), len(data)))
            output.write(data)
    _, records, _ = run_engine(engine, tmp_path, "--pcap", str(path))
    assert len(records) == 1
    record = records[0]
    assert record.metadata.first_seen == "2023-11-14T22:13:20.123456789Z"
    assert record.metadata.timestamp == "2023-11-14T22:13:20.623456789Z"
    f = record.features
    assert record.metadata.network.protocol == "UDP"
    assert f.packet_count == 2 and f.byte_count == 62
    assert f.fwd_packet_count == f.rev_packet_count == 1
    assert f.fwd_byte_count == f.rev_byte_count == 31
    assert f.duration_seconds == 0.5 and f.packets_per_second == 4.0
    assert f.bytes_per_second == 124.0 and f.bytes_per_packet == 31.0
    assert f.syn_count == f.fin_count == f.rst_count == 0
    assert not f.tcp_handshake_started


@pytest.mark.parametrize("shutdown_signal", [signal.SIGINT, signal.SIGTERM])
def test_real_signal_shutdown_drains_feature_stream(engine, tmp_path, shutdown_signal):
    features = tmp_path / "signal-features.jsonl"
    process = subprocess.Popen(
        [str(engine), "--synthetic", "--synthetic-packets", "1000000000",
         "--output", str(tmp_path / "events.jsonl"), "--feature-output", str(features)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        assert process.stdout is not None
        assert "startup status=starting" in process.stdout.readline()
        assert "capture_ready=true" in process.stdout.readline()
        time.sleep(0.03)
        process.send_signal(shutdown_signal)
        out, err = process.communicate(timeout=10)
        assert process.returncode == 0, err
        assert "flows_active=0" in out and "feature_records_dropped=0" in out
        records = load_records(features)
        assert len(records) == 10
        assert all(r.metadata.export_reason == "shutdown_flush" for r in records)
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def test_unavailable_stream_does_not_require_python_or_stop_cpp(engine, tmp_path):
    run = subprocess.run(
        [str(engine), "--synthetic", "--synthetic-packets", "30", "--output", str(tmp_path / "events.jsonl"),
         "--feature-output", str(tmp_path / "missing-directory/features.jsonl")],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert run.returncode == 0
    assert "packets_processed=30" in run.stdout and "events_emitted=1" in run.stdout
    assert "feature_records_dropped=10" in run.stdout and "feature_write_failures=1" in run.stdout
    assert "warning:" in run.stderr


@pytest.mark.parametrize("flags", [
    ["--feature-queue-capacity", "0"], ["--feature-queue-capacity", "65537"],
    ["--feature-queue-capacity", "1"],
])
def test_invalid_feature_configuration_is_rejected(engine, flags):
    run = subprocess.run([str(engine), "--synthetic", *flags], capture_output=True, timeout=10, check=False)
    assert run.returncode == 2


def test_feature_and_event_files_must_not_be_mixed(engine, tmp_path):
    output = str(tmp_path / "same.jsonl")
    run = subprocess.run([str(engine), "--synthetic", "--output", output, "--feature-output", output],
                         capture_output=True, timeout=10, check=False)
    assert run.returncode == 2 and not Path(output).exists()
