"""Actual PCAP -> native C++ v2 sink -> strict Python -> gated CSV artifact."""
from __future__ import annotations

import csv
import json
import os
import statistics
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from intriqo_ml.datasets.config import DatasetError
from intriqo_ml.datasets.native_pcap_v2 import prepare_native_pcap_v2
from intriqo_ml.flow_features_v2 import FEATURES_V2, parse_flow_feature_record_v2

ROOT = Path(__file__).resolve().parents[3]
ENGINE = Path(os.environ.get("INTRIQO_ENGINE_BINARY", ROOT / "build/flow-release/engine/intriqo-engine"))


def write_fixture(path):
    subprocess.run([sys.executable, str(ROOT / "engine/tests/fixtures/flow_feature_fixture.py"), str(path)], check=True)


def run_engine(pcap, output, schema="flow_features.v2"):
    return subprocess.run([str(ENGINE), "--pcap", str(pcap), "--flow-idle-timeout", "1",
                           "--feature-output", str(output), "--feature-schema", schema,
                           "--output", str(output.with_suffix(".events"))],
                          capture_output=True, text=True, timeout=20, check=False)


def test_every_v2_feature_from_actual_packet_capture(tmp_path):
    pcap = tmp_path / "controlled.pcap"
    write_fixture(pcap)
    output = tmp_path / "features.jsonl"
    run = run_engine(pcap, output)
    assert run.returncode == 0, run.stderr
    assert "feature_generation_failures=0" in run.stdout
    assert "feature_records_written=5" in run.stdout
    records = [parse_flow_feature_record_v2(line) for line in output.read_bytes().splitlines()]
    expected = {
        1: (0.600000013, 6, 6/0.600000013, 1/3, 40, 1/3, 1/3, 1/3,
            statistics.pstdev([100000001,100000002,200000006,100000002,100000002])/1e9),
        2: (0.250000007, 2, 2/0.250000007, 0.5, 33.5, 3/67, 0, 0, 0),
        3: (0.575000017, 2, 2/0.575000017, 0.5, 40, 0, 0, 0, 0),
        4: (0.250000008, 2, 2/0.250000008, 0.5, 34, 4/68, 0, 0, 0),
        5: (0, 1, 0, 0, 40, 1, 1, 0, 0),
    }
    assert {r.metadata.flow_id_number for r in records} == set(expected)
    for record in records:
        actual = tuple(getattr(record.features, name) for name in FEATURES_V2)
        assert actual == pytest.approx(expected[record.metadata.flow_id_number], rel=1e-12, abs=1e-20)
        assert record.timing.gap_count == record.features.packet_count - 1
        assert record.model_dump(mode="json") == json.loads(record.model_dump_json())
        assert record.metadata.first_seen_time.nanosecond > 0
    assert [r.metadata.export_reason for r in records].count("idle_expired") == 3


def test_decreasing_capture_time_is_rejected_not_sorted_or_approximated(tmp_path):
    pcap = tmp_path / "anomaly.pcap"
    write_fixture(pcap)
    data = bytearray(pcap.read_bytes())
    offset = 24
    # Third file packet belongs to flow 1. Give it a capture timestamp 1 ns
    # before that flow's creation packet; packet accounting must still proceed.
    for index in range(3):
        seconds, _nanos, captured, _ = struct.unpack_from("<IIII", data, offset)
        if index == 2:
            struct.pack_into("<II", data, offset, seconds, 123456788)
        offset += 16 + captured
    pcap.write_bytes(data)
    output = tmp_path / "v2.jsonl"
    run = run_engine(pcap, output)
    assert run.returncode == 0
    assert "feature_generation_failures=1" in run.stdout
    assert len(output.read_text().splitlines()) == 4
    legacy = run_engine(pcap, tmp_path / "v1.jsonl", "flow_features.v1")
    assert legacy.returncode == 0 and "feature_records_written=5" in legacy.stdout
    with pytest.raises(DatasetError, match="native_feature_replay_failed"):
        prepare_native_pcap_v2(pcap, ENGINE, tmp_path / "blocked")


def test_controlled_native_dataset_artifact_has_only_genuine_nine_inputs(tmp_path):
    pcap = tmp_path / "controlled.pcap"
    write_fixture(pcap)
    output = tmp_path / "prototype"
    result = prepare_native_pcap_v2(pcap, ENGINE, output)
    assert result.flow_count == 5
    with (output / "features.csv").open(newline="") as stream:
        rows = list(csv.reader(stream))
    assert rows[0] == list(FEATURES_V2) and len(rows) == 6
    manifest = json.loads((output / "dataset_manifest.json").read_text())
    assert manifest["training_ready"] is False
    assert manifest["label_status"] == "UNLABELLED"
    assert manifest["official_cic_flow_alignment_established"] is False
    assert set(manifest["artifact_sha256"]) == {"features.csv", "metadata.csv", "native_features_v2.jsonl"}
    with pytest.raises(DatasetError, match="output_exists"):
        prepare_native_pcap_v2(pcap, ENGINE, output)


def test_prototype_refuses_held_out_inputs_before_open(tmp_path):
    pcap = tmp_path / "Wednesday-workingHours.pcap"
    with pytest.raises(DatasetError, match="held_out_input_prohibited"):
        prepare_native_pcap_v2(pcap, ENGINE, tmp_path / "refused")
    assert not (tmp_path / "refused").exists()


@pytest.mark.parametrize("args", [
    ["--feature-schema", "flow_features.v3", "--feature-output", "unused.jsonl"],
    ["--feature-schema", "flow_features.v2"],
])
def test_v2_cli_requires_explicit_supported_schema_and_destination(args):
    run = subprocess.run([str(ENGINE), "--synthetic", *args], capture_output=True, timeout=10, check=False)
    assert run.returncode == 2
