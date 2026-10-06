"""Focused controls for the isolated controlled-v2 Isolation Forest experiment."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

import joblib  # type: ignore[import-untyped]
import numpy as np
import pytest
from intriqo_ml.flow_features_v2 import FEATURES_V2
from intriqo_ml.models import isolation_forest_v2 as v2
from intriqo_ml.models.isolation_forest import scores_from_sklearn


def _row(index: int, split: str, label: str, family: str | None = None) -> v2.CorpusRow:
    base = float(index + 1)
    return v2.CorpusRow(
        features=(base, base + 1, base + 2, 0.2, 40.0 + base, 0.1, 0.1, 0.0, 0.01),
        capture_id=f"capture-{split}-{index}",
        native_line_number=1,
        engine_instance_id=f"engine-{index}",
        flow_id=str(index),
        split=split,
        label=label,
        attack_family=family,
        source_label_id=f"label-{index}",
        scenario_id=f"scenario-{index}",
    )


class SpyCorpus:
    corpus_status = "READY_FOR_V2_MODEL_TRAINING"
    split_definition_hash = "a" * 64
    dataset_manifest_hash = "b" * 64
    source_hashes: ClassVar[dict[str, str]] = {"run/features.csv": "c" * 64}
    source_sizes: ClassVar[dict[str, int]] = {"run/features.csv": 1}
    source_manifest_hashes: ClassVar[dict[str, str]] = {"completed_split_definition.json": "d" * 64}

    def __init__(self) -> None:
        self.rows = tuple(
            [_row(index, "train_normal", "BENIGN") for index in range(6)]
            + [_row(index + 6, "validation", "BENIGN" if index == 0 else "ATTACK", None if index == 0 else "SYN_FLOOD") for index in range(10)]
            + [_row(index + 16, "test", "BENIGN" if index == 0 else "ATTACK", None if index == 0 else "PORT_SCAN") for index in range(10)]
        )
        self.requested: list[str] = []

    def split(self, name: str) -> tuple[v2.CorpusRow, ...]:
        self.requested.append(name)
        return tuple(row for row in self.rows if row.split == name)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_v2_feature_contract_is_exactly_nine_and_ordered() -> None:
    assert FEATURES_V2 == (
        "duration_seconds",
        "packet_count",
        "packets_per_second",
        "minor_direction_packet_fraction",
        "mean_ipv4_packet_bytes",
        "ipv4_direction_byte_imbalance",
        "syn_packet_fraction",
        "fin_packet_fraction",
        "flow_iat_std_seconds",
    )
    schema, _ = v2._authoritative_feature_schema()
    assert schema["features"] == list(FEATURES_V2)
    assert schema["feature_count"] == 9


def test_threshold_candidates_include_every_unique_score_and_no_alert() -> None:
    candidates = v2.validation_threshold_candidates([0.1, 0.2, 0.2, 0.9], [False, False, True, True])
    assert [row["threshold"] for row in candidates] == [0.1, 0.2, 0.9, np.nextafter(0.9, np.inf)]
    threshold, details = v2.select_validation_threshold(candidates)
    assert threshold == 0.9
    assert details["test_used_for_selection"] is False
    assert candidates[1]["TP"] == 2 and candidates[1]["FP"] == 1


@pytest.mark.parametrize("value", [np.nan, np.inf, -np.inf])
def test_nonfinite_features_and_scores_are_rejected(value: float) -> None:
    row = _row(1, "train_normal", "BENIGN")
    with pytest.raises(ValueError, match="finite"):
        v2._array([replace(row, features=(value, *row.features[1:]))])
    with pytest.raises(ValueError, match="finite"):
        v2.validation_threshold_candidates([value], [False])


def test_malformed_or_missing_feature_header_is_rejected(tmp_path: Path) -> None:
    run_dir = tmp_path / "corpus"
    run_dir.mkdir()
    (run_dir / "features.csv").write_text("duration_seconds,packet_count\n1,2\n", encoding="utf-8")
    (run_dir / "metadata.csv").write_text("capture_id\ncap\n", encoding="utf-8")
    with pytest.raises(ValueError, match="feature order mismatch"):
        v2._parse_csv_rows(run_dir, {})


def test_training_rejects_any_non_benign_row(tmp_path: Path) -> None:
    corpus = SpyCorpus()
    corpus.rows = tuple(
        _row(index, "train_normal", "ATTACK", "SYN_FLOOD") if index == 0 else row
        for index, row in enumerate(corpus.rows)
    )
    output = tmp_path / "run"
    output.mkdir()
    with pytest.raises(ValueError, match="BENIGN"):
        v2._fit_phase(corpus, output)  # type: ignore[arg-type]
    assert not (output / "model.joblib").exists()


def test_per_scenario_and_attack_family_aggregation_is_controller_labelled() -> None:
    predictions: list[dict[str, Any]] = [
        {"scenario_id": "benign", "capture_id": "c1", "split": "test", "ground_truth": "BENIGN", "attack_family": None, "predicted_label": "BENIGN"},
        {"scenario_id": "attack-1", "capture_id": "c2", "split": "test", "ground_truth": "ATTACK", "attack_family": "SYN_FLOOD", "predicted_label": "ATTACK"},
        {"scenario_id": "attack-2", "capture_id": "c3", "split": "test", "ground_truth": "ATTACK", "attack_family": "PORT_SCAN", "predicted_label": "BENIGN"},
    ]
    scenarios = v2.aggregate_per_scenario(predictions)
    families = v2.aggregate_per_attack_family(predictions)
    assert scenarios["benign"] == {"total": 1, "detected_as_anomaly": 0, "false_positive_rate": 0.0, "small_sample_note": "one benign test flow; FPR is not statistically precise"}
    assert scenarios["attack"] == {"total": 2, "detected": 1, "missed": 1, "recall": 0.5, "small_sample_note": "nine test attack flows across two attack families; descriptive only"}
    assert families["families"]["SYN_FLOOD"]["detected"] == 1
    assert families["families"]["PORT_SCAN"]["missed"] == 1


def test_fit_validation_lock_test_order_and_immutable_fit_artifacts(tmp_path: Path) -> None:
    corpus = SpyCorpus()
    output = tmp_path / "run"
    output.mkdir()
    fit_result = v2._fit_phase(corpus, output)  # type: ignore[arg-type]
    assert corpus.requested == ["train_normal", "validation"]
    assert fit_result["status"] == "READY_FOR_V2_MODEL_EVALUATION"
    lock = json.loads((output / "experiment_lock.json").read_text(encoding="utf-8"))
    assert lock["test_data_accessed"] is False
    fit_hashes = {name: _sha256(output / name) for name in v2.FIT_ARTIFACT_NAMES}

    evaluation = v2._evaluate_phase(corpus, output)  # type: ignore[arg-type]
    assert corpus.requested == ["train_normal", "validation", "test"]
    assert evaluation["status"] == "V2_MODEL_EVALUATED"
    assert {name: _sha256(output / name) for name in v2.FIT_ARTIFACT_NAMES} == fit_hashes
    prediction = json.loads((output / "test_predictions.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert {
        "scenario_id", "capture_id", "split", "ground_truth", "attack_family", "model_score",
        "threshold", "prediction", "predicted_label", "correct",
    } <= prediction.keys()
    artifact_manifest = json.loads((output / "artifact_manifest.json").read_text(encoding="utf-8"))
    for name, details in artifact_manifest["artifact_sha256"].items():
        assert _sha256(output / name) == details["sha256"]


def test_lock_rejects_mutation_before_test_access(tmp_path: Path) -> None:
    corpus = SpyCorpus()
    output = tmp_path / "run"
    output.mkdir()
    v2._fit_phase(corpus, output)  # type: ignore[arg-type]
    with (output / "threshold.json").open("a", encoding="utf-8") as stream:
        stream.write("\n")
    with pytest.raises(ValueError, match="lock hash mismatch|fit artifact hash mismatch"):
        v2._evaluate_phase(corpus, output)  # type: ignore[arg-type]
    assert corpus.requested == ["train_normal", "validation"]


def test_deterministic_seed_reproduces_scores(tmp_path: Path) -> None:
    first_corpus, second_corpus = SpyCorpus(), SpyCorpus()
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    v2._fit_phase(first_corpus, first)  # type: ignore[arg-type]
    v2._fit_phase(second_corpus, second)  # type: ignore[arg-type]
    first_model = joblib.load(first / "model.joblib")
    second_model = joblib.load(second / "model.joblib")
    rows = first_corpus.split("validation")
    features, _ = v2._array(rows)
    np.testing.assert_array_equal(
        scores_from_sklearn(first_model, v2._model_input(features)),
        scores_from_sklearn(second_model, v2._model_input(features)),
    )
