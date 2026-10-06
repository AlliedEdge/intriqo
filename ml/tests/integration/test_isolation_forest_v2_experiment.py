"""One end-to-end controlled-v2 experiment ordering/integrity check."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from intriqo_ml.models.isolation_forest_v2 import run_experiment


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_controlled_v2_fit_validation_lock_test_pipeline(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[3]
    enrolled = root / "ml" / "artifacts" / "feature-analysis" / "controlled-v2"
    run_dir = enrolled / "run-complete-20261006"
    source_hashes = {
        name: _sha256(enrolled / name)
        for name in (
            "completed_experiment_manifest.json",
            "completed_capture_manifest.json",
            "completed_split_definition.json",
            "corpus_status.json",
        )
    }
    result = run_experiment(run_dir, tmp_path / "controlled-v2", fit=True, evaluate=True, enrolled_dir=enrolled)
    assert result["status"] == "V2_MODEL_EVALUATED"
    output = tmp_path / "controlled-v2"
    lock = json.loads((output / "experiment_lock.json").read_text(encoding="utf-8"))
    evaluation = json.loads((output / "evaluation_manifest.json").read_text(encoding="utf-8"))
    test_metrics = json.loads((output / "test_metrics.json").read_text(encoding="utf-8"))
    assert lock["test_data_accessed"] is False
    assert evaluation["test_data_accessed_only_after_lock"] is True
    assert evaluation["test_evaluated_once"] is True
    assert test_metrics["flow_count"] == 10
    assert test_metrics["TP"] == 9 and test_metrics["TN"] == 1
    assert test_metrics["FP"] == 0 and test_metrics["FN"] == 0
    assert {
        name: _sha256(enrolled / name)
        for name in source_hashes
    } == source_hashes
