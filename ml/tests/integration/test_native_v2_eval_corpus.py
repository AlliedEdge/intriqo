"""The pre-capture corpus build produces a blocked, model-free receipt."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from intriqo_ml.native_v2_eval.build import build_corpus
from intriqo_ml.native_v2_eval.replay import replay_native_v2

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "ml/artifacts/feature-analysis/controlled-v2"
ENGINE = Path(os.environ.get("INTRIQO_ENGINE_BINARY", ROOT / "build/flow-release/engine/intriqo-engine"))


def test_empty_controlled_design_is_explicitly_blocked(tmp_path: Path) -> None:
    output = tmp_path / "controlled-run"
    result = build_corpus(
        experiment_manifest_path=CORPUS / "experiment_manifest.json",
        capture_manifest_path=CORPUS / "capture_manifest.json",
        split_definition_path=CORPUS / "split_definition.json",
        output_dir=output,
    )
    assert result["status"] == "BLOCKED_ON_CONTROLLED_CAPTURE"
    quality = json.loads((output / "quality_report.json").read_text())
    assert quality["counts"]["total_flows"] == 0
    assert quality["ready_for_model_training"] is False
    assert not list(output.glob("**/model.joblib"))
    assert not list(output.glob("**/*score*"))


def test_replay_wrapper_records_verified_native_counters(tmp_path: Path) -> None:
    if not ENGINE.is_file():
        pytest.skip("native engine binary is not built")
    pcap = tmp_path / "fixture.pcap"
    subprocess.run(
        [sys.executable, str(ROOT / "engine/tests/fixtures/flow_feature_fixture.py"), str(pcap)],
        check=True,
    )
    result = replay_native_v2(
        capture_id="fixture-capture",
        pcap=pcap,
        engine=ENGINE,
        output_dir=tmp_path / "replay",
    )
    assert result.report["status"] == "complete"
    assert len(result.records) == 5
    assert result.report["counters"]["packets_received"] == 13
    assert result.report["counters"]["feature_records_written"] == 5
