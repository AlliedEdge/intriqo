"""Tiny synthetic checks for the standalone, validation-locked baseline."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import joblib
import matplotlib
import numpy as np
import pytest
from intriqo_ml.models import isolation_forest as baseline
from intriqo_ml.models import validation_operating_points as operating_analysis

matplotlib.use("Agg")

FEATURES = ("duration_seconds", "packet_count", "packets_per_second")
PARAMETERS = {
    "n_estimators": 300,
    "max_samples": "auto",
    "contamination": "auto",
    "random_state": 42,
    "n_jobs": -1,
}
SCORE_DEFINITION = "-model.score_samples(features)"
SPLITS = ("train_normal", "validation", "test")
PLOTS = {
    "validation_score_distribution.png",
    "test_score_distribution.png",
    "precision_recall_curve.png",
    "roc_curve.png",
    "confusion_matrix.png",
    "per_attack_family_recall.png",
}
FIT_ARTIFACTS = {
    "model.joblib",
    "model_metadata.json",
    "threshold.json",
    "validation_metrics.json",
    "score_statistics.json",
    "feature_schema.json",
    "validation_score_distribution.png",
    "fit_manifest.json",
    "validation_threshold_candidates.csv",
}
ARTIFACTS = PLOTS | FIT_ARTIFACTS | {"test_metrics.json", "evaluation_manifest.json"}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def write_split(
    root: Path,
    split: str,
    features: Sequence[Sequence[object]],
    labels: Sequence[str],
    *,
    header: Sequence[str] = FEATURES,
    attack_flags: Sequence[object] | None = None,
) -> None:
    with (root / f"{split}_features.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(header)
        writer.writerows(features)
    if attack_flags is None:
        attack_flags = [str(label != "BENIGN").lower() for label in labels]
    with (root / f"{split}_metadata.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["label", "is_attack", "source_file", "source_line", "capture_group"])
        for line, (label, attack) in enumerate(zip(labels, attack_flags), start=2):
            writer.writerow([label, attack, f"{split}-synthetic.csv", line, split])


def write_manifest(root: Path) -> None:
    """Keep prepared-artifact hashes/counts real, including after fixture edits."""
    paths = [root / f"{split}_{kind}.csv" for split in SPLITS for kind in ("features", "metadata")]
    paths.append(root / "preprocessing.json")
    counts: dict[str, int] = {}
    composition: dict[str, dict[str, int]] = {}
    for split in SPLITS:
        with (root / f"{split}_metadata.csv").open(encoding="utf-8", newline="") as stream:
            labels = [row["label"] for row in csv.DictReader(stream)]
        counts[split] = len(labels)
        composition[split] = dict(Counter(labels))
    write_json(
        root / "dataset_manifest.json",
        {
            "manifest_version": "dataset_manifest.v1",
            "dataset_id": "synthetic-isolation-forest-unit-fixture",
            "dataset_source": "synthetic; no real dataset",
            "dataset_version": "synthetic.v1",
            "subset_description": "32 training rows and tiny mixed evaluation splits",
            "selected_files": [],
            "features": list(FEATURES),
            "labels_separate_from_features": True,
            "label_column": "label",
            "evaluation_metadata_column": "is_attack",
            "split_seed": 42,
            "split_strategy": "fixed_synthetic_groups",
            "preprocessing": {"kind": "none"},
            "counts": {
                "total_rows": sum(counts.values()),
                "valid_rows": sum(counts.values()),
                "invalid_rows": 0,
                "duplicate_rows": 0,
                "split_input_rows": counts,
                "split_valid_rows": counts,
            },
            "label_composition": composition,
            "artifact_sha256": {path.name: sha256(path) for path in paths},
            "artifact_sizes_bytes": {path.name: path.stat().st_size for path in paths},
            "model_implementation": None,
        },
    )


def write_dataset(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    train = [
        [1.0 + index * 0.025, 20 + index % 5, (20 + index % 5) / (1.0 + index * 0.025)]
        for index in range(32)
    ]
    write_split(root, "train_normal", train, ["BENIGN"] * len(train))
    write_split(
        root,
        "validation",
        [train[2], train[10], train[25], [15, 900, 60], [0.02, 200, 10000], [8, 400, 50]],
        ["BENIGN", "BENIGN", "BENIGN", "DDoS", "DDoS", "FTP-Patator"],
    )
    write_split(
        root,
        "test",
        [train[5], train[15], train[5], [30, 1500, 50], [0.01, 400, 40000]],
        ["BENIGN", "BENIGN", "DDoS", "DDoS", "FTP-Patator"],
    )
    write_json(root / "preprocessing.json", {"kind": "none", "fit_split": None, "parameters": {}})
    write_manifest(root)


@pytest.fixture
def prepared_dataset(tmp_path: Path) -> Path:
    root = tmp_path / "prepared"
    write_dataset(root)
    return root


@pytest.fixture(scope="module")
def completed_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, dict[str, Any]]:
    root = tmp_path_factory.mktemp("isolation-forest")
    dataset = root / "prepared"
    output = root / "run"
    write_dataset(dataset)
    summary = baseline.run_experiment(dataset, output, fit=True, evaluate=True)
    return dataset, output, summary


def test_score_conversion_is_exactly_negative_score_samples() -> None:
    class NormalityModel:
        def score_samples(self, features: object) -> np.ndarray:
            assert features is rows
            return raw_scores

    rows = np.array([[1.0, 20.0, 20.0]] * 4 + [[0.01, 400.0, 40000.0]])
    raw_scores = np.array([-0.125, -0.75, -0.5, 0.25, 0.0])
    scores = baseline.scores_from_sklearn(NormalityModel(), rows)
    np.testing.assert_array_equal(scores, -raw_scores)
    # The conversion has no offset, clipping, normalization, or decision_function.
    assert scores[3] == -0.25


def test_default_configuration_is_explicit_and_deterministic() -> None:
    assert baseline.FEATURES == FEATURES
    assert baseline.DEFAULT_MODEL_PARAMETERS == PARAMETERS


def test_validation_threshold_maximizes_recall_under_one_percent_benign_fpr() -> None:
    scores = np.array([0.1] * 98 + [0.6, 0.7, 0.8, 0.65, 0.5])
    is_attack = np.array([False] * 100 + [True] * 3)
    threshold = baseline.select_validation_threshold(scores, is_attack)
    assert threshold == 0.65
    metrics = baseline.confusion_metrics(scores, is_attack, threshold)
    assert metrics["FPR"] == 0.01
    assert metrics["recall"] == pytest.approx(2 / 3)
    # Detecting the remaining lower-scored attack would exceed the FPR cap.
    assert baseline.confusion_metrics(scores, is_attack, 0.5)["FPR"] > 0.01


def test_validation_threshold_breaks_equal_recall_by_f1() -> None:
    scores = [0.1] * 99 + [0.7, 0.9, 0.8]
    is_attack = [False] * 100 + [True, True]
    threshold = baseline.select_validation_threshold(scores, is_attack)
    assert threshold == 0.8
    assert baseline.confusion_metrics(scores, is_attack, 0.7)["recall"] == 1.0
    assert baseline.confusion_metrics(scores, is_attack, threshold)["F1"] == 1.0


def test_tied_scores_are_alerted_as_one_group() -> None:
    scores = [0.1] * 99 + [0.8, 0.8, 0.8]
    is_attack = [False] * 100 + [True, True]
    threshold = baseline.select_validation_threshold(scores, is_attack)
    assert threshold == 0.8
    metrics = baseline.confusion_metrics(scores, is_attack, threshold)
    assert (metrics["TP"], metrics["FP"], metrics["FN"]) == (2, 1, 0)
    assert metrics["FPR"] == 0.01


@pytest.mark.parametrize(
    "scores,is_attack",
    [([0.7, 0.7], [False, True]), ([0.1, 0.5, 0.9], [False, False, False])],
    ids=["top-score-tie-exceeds-cap", "no-attacks-all-metrics-tied"],
)
def test_no_alert_threshold_is_above_every_score_and_deterministic(
    scores: list[float], is_attack: list[bool]
) -> None:
    threshold = baseline.select_validation_threshold(scores, is_attack)
    assert threshold == np.nextafter(max(scores), np.inf)
    assert baseline.select_validation_threshold(scores[::-1], is_attack[::-1]) == threshold
    metrics = baseline.confusion_metrics(scores, is_attack, threshold)
    assert metrics["TP"] == metrics["FP"] == metrics["FPR"] == 0


def test_no_alert_threshold_handles_the_largest_finite_float() -> None:
    maximum = np.finfo(np.float64).max
    threshold = baseline.select_validation_threshold([maximum, maximum], [False, True])
    assert threshold == np.inf
    assert baseline.confusion_metrics([maximum, maximum], [False, True], threshold)["FP"] == 0


@pytest.mark.parametrize("cap", [-0.01, 1.01, np.nan, np.inf])
def test_validation_threshold_rejects_invalid_fpr_caps(cap: float) -> None:
    with pytest.raises(ValueError, match="false_positive_rate"):
        baseline.select_validation_threshold([0.1, 0.9], [False, True], cap)


def test_validation_threshold_rejects_empty_validation() -> None:
    with pytest.raises(ValueError, match="empty validation"):
        baseline.select_validation_threshold([], [])


def test_confusion_metrics_use_inclusive_threshold_and_documented_auc_summaries() -> None:
    metrics = baseline.confusion_metrics([0.9, 0.7, 0.7, 0.1, 0.2], [1, 1, 0, 1, 0], 0.7)
    assert {key: metrics[key] for key in ("TP", "TN", "FP", "FN")} == {
        "TP": 2, "TN": 1, "FP": 1, "FN": 1,
    }
    for upper, lower in (("TP", "tp"), ("TN", "tn"), ("FP", "fp"), ("FN", "fn")):
        assert metrics[upper] == metrics[lower]
    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == metrics["TPR"] == metrics["tpr"] == pytest.approx(2 / 3)
    assert metrics["F1"] == metrics["f1"] == pytest.approx(2 / 3)
    assert metrics["FPR"] == metrics["fpr"] == metrics["specificity"] == 0.5
    assert metrics["balanced_accuracy"] == pytest.approx(7 / 12)
    assert metrics["roc_auc"] == pytest.approx(7 / 12)
    assert metrics["average_precision"] == metrics["pr_auc"] == pytest.approx(34 / 45)
    assert metrics["sample_count"] == 5
    assert metrics["threshold"] == 0.7


@pytest.mark.parametrize(
    "scores,is_attack,threshold,precision,recall,specificity,balanced,ap",
    [
        ([], [], 1.0, 0.0, 0.0, 0.0, 0.0, 0.0),
        ([0.1, 0.2], [False, False], 1.0, 0.0, 0.0, 1.0, 0.5, 0.0),
        ([0.1, 0.2], [True, True], 1.0, 0.0, 0.0, 0.0, 0.0, 1.0),
        ([0.1, 0.2], [True, True], 0.0, 1.0, 1.0, 0.0, 0.5, 1.0),
    ],
    ids=["empty", "all-benign-no-alerts", "all-attacks-no-alerts", "all-attacks-alerted"],
)
def test_confusion_metrics_have_finite_zero_denominator_conventions(
    scores: list[float],
    is_attack: list[bool],
    threshold: float,
    precision: float,
    recall: float,
    specificity: float,
    balanced: float,
    ap: float,
) -> None:
    metrics = baseline.confusion_metrics(scores, is_attack, threshold)
    assert metrics["precision"] == precision
    assert metrics["recall"] == recall
    assert metrics["F1"] == recall
    assert metrics["FPR"] == 0.0
    assert metrics["specificity"] == specificity
    assert metrics["balanced_accuracy"] == balanced
    assert metrics["roc_auc"] == 0.0
    assert metrics["average_precision"] == metrics["pr_auc"] == ap
    assert all(np.isfinite(value) for value in metrics.values())


@pytest.mark.parametrize("score", [np.nan, np.inf, -np.inf])
@pytest.mark.parametrize("operation", ["metrics", "threshold"])
def test_score_apis_reject_nonfinite_values(score: float, operation: str) -> None:
    with pytest.raises(ValueError, match="non-finite"):
        if operation == "metrics":
            baseline.confusion_metrics([score], [False], 0.5)
        else:
            baseline.select_validation_threshold([score], [False])


@pytest.mark.parametrize(
    "scores,is_attack,message",
    [([0.5], [False, True], "same row count"), ([0.5], [2], "boolean or zero/one")],
)
def test_score_apis_reject_misaligned_or_nonbinary_labels(
    scores: list[float], is_attack: list[object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        baseline.confusion_metrics(scores, is_attack, 0.5)
    with pytest.raises(ValueError, match=message):
        baseline.select_validation_threshold(scores, is_attack)


def test_load_split_preserves_exact_features_and_separates_labels(prepared_dataset: Path) -> None:
    features, labels, is_attack = baseline.load_split(prepared_dataset, "validation")
    assert features.shape == (6, 3)
    assert features.dtype == np.float64
    assert labels.tolist() == ["BENIGN", "BENIGN", "BENIGN", "DDoS", "DDoS", "FTP-Patator"]
    assert is_attack.dtype == np.bool_
    assert is_attack.tolist() == [False, False, False, True, True, True]
    np.testing.assert_array_equal(features[3], [15.0, 900.0, 60.0])


@pytest.mark.parametrize(
    "header",
    [FEATURES[::-1], FEATURES[:-1], (*FEATURES, "label")],
    ids=["wrong-order", "missing-feature", "unexpected-label-feature"],
)
def test_load_split_rejects_nonexact_feature_headers(
    prepared_dataset: Path, header: tuple[str, ...]
) -> None:
    write_split(prepared_dataset, "validation", [[1, 20, 20]], ["BENIGN"], header=header)
    with pytest.raises(ValueError, match="feature header/order mismatch"):
        baseline.load_split(prepared_dataset, "validation")


@pytest.mark.parametrize("value", ["", "NaN", "inf", "-inf", "1e309", "-1e309", "not-a-number"])
def test_load_split_rejects_missing_nonfinite_and_overflowing_numeric_values(
    prepared_dataset: Path, value: str
) -> None:
    write_split(prepared_dataset, "validation", [[1, 20, value]], ["BENIGN"])
    with pytest.raises(ValueError, match="numeric value"):
        baseline.load_split(prepared_dataset, "validation")


def test_load_split_rejects_misaligned_feature_and_metadata_counts(prepared_dataset: Path) -> None:
    write_split(prepared_dataset, "validation", [[1, 20, 20], [2, 20, 10]], ["BENIGN"])
    with pytest.raises(ValueError, match="row count mismatch"):
        baseline.load_split(prepared_dataset, "validation")


@pytest.mark.parametrize("label,flag", [("BENIGN", "true"), ("DDoS", "false"), ("BENIGN", "maybe")])
def test_load_split_rejects_inconsistent_or_invalid_attack_metadata(
    prepared_dataset: Path, label: str, flag: str
) -> None:
    write_split(prepared_dataset, "validation", [[1, 20, 20]], [label], attack_flags=[flag])
    with pytest.raises(ValueError, match="is_attack"):
        baseline.load_split(prepared_dataset, "validation")


@pytest.mark.parametrize("split", ["train_normal", "validation", "test"])
def test_finite_float64_overflow_is_rejected_at_the_model_boundary(
    prepared_dataset: Path, tmp_path: Path, split: str
) -> None:
    write_split(prepared_dataset, split, [[1, 20, "1e39"]], ["BENIGN"])
    write_manifest(prepared_dataset)
    features, _, _ = baseline.load_split(prepared_dataset, split)
    assert np.isfinite(features).all()
    with pytest.raises(ValueError, match="float32"):
        baseline.run_experiment(prepared_dataset, tmp_path / "overflow", fit=True, evaluate=True)


@pytest.mark.parametrize("labels", [["BENIGN", "DDoS"], ["DDoS", "FTP-Patator"], []])
def test_training_requires_nonempty_benign_only_rows(
    prepared_dataset: Path, tmp_path: Path, labels: list[str]
) -> None:
    write_split(prepared_dataset, "train_normal", [[1, 20, 20]] * len(labels), labels)
    write_manifest(prepared_dataset)
    output = tmp_path / "not-benign-only"
    with pytest.raises(ValueError, match="BENIGN"):
        baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    assert not (output / "model.joblib").exists()


def test_prepared_manifest_hashes_and_sizes_match_the_synthetic_fixture(prepared_dataset: Path) -> None:
    manifest = read_json(prepared_dataset / "dataset_manifest.json")
    assert manifest["features"] == list(FEATURES)
    assert manifest["preprocessing"] == {"kind": "none"}
    for name, digest in manifest["artifact_sha256"].items():
        assert sha256(prepared_dataset / name) == digest
        assert (prepared_dataset / name).stat().st_size == manifest["artifact_sizes_bytes"][name]


def test_fit_only_locks_validation_threshold_without_opening_test_data(
    prepared_dataset: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_open = Path.open
    opened: list[str] = []

    def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path.parent == prepared_dataset and path.name.endswith(".csv"):
            opened.append(path.name)
            assert not path.name.startswith("test_"), "fit-only touched held-out test data"
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    output = tmp_path / "fit-only"
    result = baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    assert "validation_features.csv" in opened
    assert "validation_metadata.csv" in opened
    threshold = read_json(output / "threshold.json")
    assert threshold["selection_data_split"] == "validation"
    assert threshold["test_used_for_selection"] is False
    validation = read_json(output / "validation_metrics.json")
    assert validation["threshold"] == threshold["threshold"]
    assert validation["FPR"] <= 0.01
    assert result["fit"] is True and result["evaluate"] is False
    assert not (output / "test_metrics.json").exists()
    assert not (output / "evaluation_manifest.json").exists()


@pytest.mark.parametrize("missing", ["model.joblib", "threshold.json"])
def test_evaluate_requires_a_fitted_run_with_a_locked_threshold(
    prepared_dataset: Path, tmp_path: Path, missing: str
) -> None:
    output = tmp_path / "missing-artifact"
    baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    required = output / missing
    # A fit-only run must have a lock; this assertion also diagnoses an incomplete fit.
    assert required.is_file(), f"fit-only did not create required artifact {missing}"
    required.unlink()
    with pytest.raises((FileNotFoundError, ValueError), match="model|threshold|lock"):
        baseline.run_experiment(prepared_dataset, output, fit=False, evaluate=True)
    assert not (output / "test_metrics.json").exists()


def test_evaluate_without_any_fitted_run_fails(prepared_dataset: Path, tmp_path: Path) -> None:
    output = tmp_path / "never-fitted"
    with pytest.raises(FileNotFoundError, match="model"):
        baseline.run_experiment(prepared_dataset, output, fit=False, evaluate=True)
    assert not (output / "test_metrics.json").exists()


def test_separate_evaluation_preserves_the_fitted_model_and_threshold_lock(
    prepared_dataset: Path, tmp_path: Path
) -> None:
    output = tmp_path / "separate-fit-evaluate"
    fit_result = baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    assert set(fit_result["artifacts"]) == FIT_ARTIFACTS
    assert {path.name for path in output.iterdir() if path.is_file()} == FIT_ARTIFACTS
    receipt = read_json(output / "fit_manifest.json")
    receipt_before = (output / "fit_manifest.json").read_bytes()
    statistics_before = read_json(output / "score_statistics.json")
    assert set(receipt["artifact_sha256"]) == FIT_ARTIFACTS - {"fit_manifest.json"}
    assert set(receipt["artifact_sizes_bytes"]) == set(receipt["artifact_sha256"])
    assert set(receipt["artifact_hash_scopes"]) == {"score_statistics.json"}
    for name, digest in receipt["artifact_sha256"].items():
        assert sha256(output / name) == digest, name
        assert (output / name).stat().st_size == receipt["artifact_sizes_bytes"][name], name
    threshold_before = (output / "threshold.json").read_bytes()
    model_before = sha256(output / "model.joblib")
    threshold = read_json(output / "threshold.json")["threshold"]
    result = baseline.run_experiment(prepared_dataset, output, fit=False, evaluate=True)
    assert result["fit"] is False and result["evaluate"] is True
    assert result["threshold"] == threshold
    assert (output / "threshold.json").read_bytes() == threshold_before
    assert sha256(output / "model.joblib") == model_before
    assert read_json(output / "test_metrics.json")["threshold"] == threshold
    assert (output / "fit_manifest.json").read_bytes() == receipt_before
    for name, digest in receipt["artifact_sha256"].items():
        if name != "score_statistics.json":
            assert sha256(output / name) == digest, name
            assert (output / name).stat().st_size == receipt["artifact_sizes_bytes"][name], name
    # Evaluation extends statistics with test results; the receipt's locked
    # validation-only projection must remain exactly the original fit content.
    statistics_after = read_json(output / "score_statistics.json")
    assert "test" in statistics_after
    assert {key: value for key, value in statistics_after.items() if key != "test"} == statistics_before
    manifest = read_json(output / "evaluation_manifest.json")
    assert manifest["artifact_sha256"]["fit_manifest.json"] == sha256(output / "fit_manifest.json")
    assert manifest["artifact_sha256"]["validation_threshold_candidates.csv"] == receipt["artifact_sha256"]["validation_threshold_candidates.csv"]


def test_evaluate_rejects_an_unfitted_model_artifact(prepared_dataset: Path, tmp_path: Path) -> None:
    from sklearn.ensemble import IsolationForest

    output = tmp_path / "unfitted-model"
    baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    joblib.dump(IsolationForest(**PARAMETERS), output / "model.joblib")
    with pytest.raises(ValueError):
        baseline.run_experiment(prepared_dataset, output, fit=False, evaluate=True)
    assert not (output / "test_metrics.json").exists()
    assert not (output / "evaluation_manifest.json").exists()


def test_evaluate_refuses_a_different_prepared_manifest(prepared_dataset: Path, tmp_path: Path) -> None:
    output = tmp_path / "wrong-provenance"
    baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    manifest = read_json(prepared_dataset / "dataset_manifest.json")
    manifest["dataset_version"] = "synthetic.changed.v2"
    write_json(prepared_dataset / "dataset_manifest.json", manifest)
    with pytest.raises(ValueError, match="manifest.*SHA256|manifest.*hash"):
        baseline.run_experiment(prepared_dataset, output, fit=False, evaluate=True)
    assert not (output / "test_metrics.json").exists()


def test_run_artifact_hashes_manifest_provenance_and_png_outputs(
    completed_run: tuple[Path, Path, dict[str, Any]]
) -> None:
    dataset, output, summary = completed_run
    manifest = read_json(output / "evaluation_manifest.json")
    digest = sha256(dataset / "dataset_manifest.json")
    assert set(summary["artifacts"]) == ARTIFACTS
    assert {path.name for path in output.iterdir() if path.is_file()} == ARTIFACTS
    assert manifest["dataset_manifest_sha256"] == summary["dataset_manifest_sha256"] == digest
    dataset_manifest = read_json(dataset / "dataset_manifest.json")
    assert manifest["dataset_manifest"] == dataset_manifest
    assert set(dataset_manifest["artifact_sizes_bytes"]) == set(dataset_manifest["artifact_sha256"])
    for name, expected_hash in dataset_manifest["artifact_sha256"].items():
        assert sha256(dataset / name) == expected_hash, name
        assert (dataset / name).stat().st_size == dataset_manifest["artifact_sizes_bytes"][name], name
    assert set(manifest["artifact_sha256"]) == ARTIFACTS - {"evaluation_manifest.json"}
    assert set(manifest["artifact_sizes_bytes"]) == set(manifest["artifact_sha256"])
    for name, expected_hash in manifest["artifact_sha256"].items():
        path = output / name
        assert sha256(path) == expected_hash, name
        assert path.stat().st_size == manifest["artifact_sizes_bytes"][name], name
    for name in ("model_metadata.json", "feature_schema.json", "threshold.json", "fit_manifest.json"):
        assert read_json(output / name)["dataset_manifest_sha256"] == digest
    model_digest = sha256(output / "model.joblib")
    assert manifest["model_sha256"] == model_digest
    for name in ("model_metadata.json", "threshold.json", "fit_manifest.json"):
        assert read_json(output / name)["model_sha256"] == model_digest
    lock = read_json(output / "threshold.json")
    assert manifest["threshold_method"] == lock["threshold_method"]
    for name in ("validation_metrics.json", "test_metrics.json", "score_statistics.json"):
        assert read_json(output / name)["threshold"] == lock["threshold"]
    for name in PLOTS:
        assert (output / name).read_bytes().startswith(b"\x89PNG\r\n\x1a\n"), name
    assert manifest["split_counts"] == {
        "train_normal": 32, "validation": 6, "test": 5, "validation_attack": 3, "test_attack": 3,
    }
    assert manifest["label_counts"] == {
        "train_normal": {"BENIGN": 32},
        "validation": {"BENIGN": 3, "DDoS": 2, "FTP-Patator": 1},
        "test": {"BENIGN": 2, "DDoS": 2, "FTP-Patator": 1},
    }


def test_saved_model_parameters_feature_schema_and_score_semantics(
    completed_run: tuple[Path, Path, dict[str, Any]]
) -> None:
    dataset, output, _ = completed_run
    model = joblib.load(output / "model.joblib")
    metadata = read_json(output / "model_metadata.json")
    schema = read_json(output / "feature_schema.json")
    manifest = read_json(output / "evaluation_manifest.json")
    threshold = read_json(output / "threshold.json")
    statistics = read_json(output / "score_statistics.json")
    assert metadata["parameters"] == manifest["parameters"] == PARAMETERS
    assert {key: model.get_params()[key] for key in PARAMETERS} == PARAMETERS
    assert len(model.estimators_) == 300
    assert model.n_features_in_ == 3
    assert model.max_samples_ == 32
    assert metadata["fit_rows"] == metadata["train_rows"] == 32
    assert metadata["seed"] == manifest["seed"] == 42
    for artifact in (metadata, schema, manifest, threshold):
        assert artifact["features"] == list(FEATURES)
    for artifact in (metadata, schema):
        assert artifact["preprocessing"] == "none"
        assert artifact["loaded_dtype"] == "float64"
        assert artifact["model_input_dtype"] == "float32"
    assert manifest["score_definition"] == statistics["score_definition"] == SCORE_DEFINITION
    assert threshold["threshold_method"]["score_definition"] == SCORE_DEFINITION
    assert threshold["threshold_method"]["decision_rule"] == "anomaly_score >= threshold"
    assert threshold["threshold_method"]["tie_break"] == ["recall", "f1", "lower_fpr", "higher_threshold"]
    assert threshold["threshold_method"]["max_false_positive_rate"] == 0.01
    assert threshold["threshold_method"]["selection_split"] == "validation"
    assert threshold["threshold_method"]["test_used_for_selection"] is False
    assert manifest["metric_conventions"] == {
        "zero_denominator": 0.0, "roc_auc_without_both_classes": 0.0, "pr_auc": "average_precision",
    }
    assert metadata["versions"]["numpy"] == np.__version__
    assert metadata["python_version"] == metadata["versions"]["python"]
    assert metadata["sklearn_version"] == metadata["versions"]["scikit_learn"]
    rows, _, _ = baseline.load_split(dataset, "test")
    np.testing.assert_array_equal(
        baseline.scores_from_sklearn(model, rows.astype(np.float32)),
        -model.score_samples(rows.astype(np.float32)),
    )


def test_test_metrics_use_the_validation_threshold_and_report_collisions_per_family(
    completed_run: tuple[Path, Path, dict[str, Any]]
) -> None:
    dataset, output, summary = completed_run
    model = joblib.load(output / "model.joblib")
    threshold = read_json(output / "threshold.json")["threshold"]
    validation_rows, _, validation_attack = baseline.load_split(dataset, "validation")
    validation_scores = baseline.scores_from_sklearn(model, validation_rows.astype(np.float32))
    assert threshold == baseline.select_validation_threshold(validation_scores, validation_attack)
    rows, labels, is_attack = baseline.load_split(dataset, "test")
    scores = baseline.scores_from_sklearn(model, rows.astype(np.float32))
    metrics = read_json(output / "test_metrics.json")
    expected = baseline.confusion_metrics(scores, is_attack, threshold)
    assert summary["threshold"] == threshold
    assert summary["test_metrics"] == expected
    for key, value in expected.items():
        assert metrics[key] == value
    assert read_json(output / "validation_metrics.json")["FPR"] <= 0.01
    assert metrics["feature_collision_summary"] == {
        "total_rows": 5,
        "unique_feature_groups": 4,
        "duplicate_rows": 1,
        "mixed_label_groups": 1,
        "mixed_label_rows": 2,
        "mixed_attack_benign_groups": 1,
        "mixed_attack_benign_rows": 2,
    }
    per_family = metrics["per_attack_family_recall"]
    assert per_family == metrics["per_label_attack_detection"]
    assert set(per_family) == {"DDoS", "FTP-Patator"}
    for family, family_metrics in per_family.items():
        mask = labels == family
        support = int(mask.sum())
        detected = int((mask & (scores >= threshold)).sum())
        assert family_metrics == {
            "support": support, "attack_rows": support, "detected": detected,
            "missed": support - detected, "recall": detected / support,
        }


def test_evaluate_refuses_re_evaluation_by_default_without_changing_artifacts(
    completed_run: tuple[Path, Path, dict[str, Any]]
) -> None:
    dataset, output, _ = completed_run
    before = {path.name: sha256(path) for path in output.iterdir() if path.is_file()}
    with pytest.raises(FileExistsError, match="already exist"):
        baseline.run_experiment(dataset, output, fit=False, evaluate=True)
    assert {path.name: sha256(path) for path in output.iterdir() if path.is_file()} == before


def test_two_tiny_end_to_end_runs_have_identical_models_scores_and_metrics(
    completed_run: tuple[Path, Path, dict[str, Any]], tmp_path: Path
) -> None:
    dataset, first, first_summary = completed_run
    second = tmp_path / "repeat"
    second_summary = baseline.run_experiment(dataset, second, fit=True, evaluate=True)
    assert first_summary["threshold"] == second_summary["threshold"]
    assert first_summary["test_metrics"] == second_summary["test_metrics"]
    assert first_summary["split_counts"] == second_summary["split_counts"]
    models = [joblib.load(root / "model.joblib") for root in (first, second)]
    for split in SPLITS:
        rows, _, _ = baseline.load_split(dataset, split)
        np.testing.assert_array_equal(
            baseline.scores_from_sklearn(models[0], rows.astype(np.float32)),
            baseline.scores_from_sklearn(models[1], rows.astype(np.float32)),
        )
    for name in ("validation_metrics.json", "test_metrics.json", "feature_schema.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes(), name
    for name in ("model_metadata.json", "threshold.json", "score_statistics.json"):
        values = [read_json(root / name) for root in (first, second)]
        for value in values:
            value.pop("created_at_utc", None)
        assert values[0] == values[1], name


def test_evaluate_does_not_open_validation_or_select_a_threshold_again(
    prepared_dataset: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "locked-evaluation"
    baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    original_open = Path.open
    original_score = baseline.scores_from_sklearn
    scoring_calls: list[int] = []

    def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        assert not (path.parent == prepared_dataset and path.name.startswith("validation_"))
        return original_open(path, *args, **kwargs)

    def forbidden_selection(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("evaluation attempted to reselect the threshold")

    def counted_score(model: Any, features: Any) -> Any:
        scoring_calls.append(len(features))
        return original_score(model, features)

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(baseline, "_select_threshold_details", forbidden_selection)
    monkeypatch.setattr(baseline, "scores_from_sklearn", counted_score)
    baseline.run_experiment(prepared_dataset, output, fit=False, evaluate=True)
    assert scoring_calls == [5]
    manifest = read_json(output / "evaluation_manifest.json")
    assert manifest["runtime"]["training_seconds"] > 0
    assert manifest["runtime"]["validation_scoring_seconds"] > 0
    assert manifest["runtime"]["test_scoring_seconds"] > 0


@pytest.mark.parametrize("name", ["threshold.json", "model.joblib", "validation_metrics.json"])
def test_evaluate_rejects_tampered_fit_artifacts_before_reading_test(
    prepared_dataset: Path, tmp_path: Path, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "tampered"
    baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    with (output / name).open("ab") as stream:
        stream.write(b"\n ")
    original_open = Path.open

    def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        assert not (path.parent == prepared_dataset and path.name.startswith("test_"))
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    with pytest.raises(ValueError, match="hash/size mismatch"):
        baseline.run_experiment(prepared_dataset, output, fit=False, evaluate=True)


def test_every_validation_candidate_matches_direct_confusion_metrics(
    completed_run: tuple[Path, Path, dict[str, Any]]
) -> None:
    dataset, output, _ = completed_run
    model = joblib.load(output / "model.joblib")
    rows, _, attacks = baseline.load_split(dataset, "validation")
    scores = baseline.scores_from_sklearn(model, rows.astype(np.float32))
    with (output / "validation_threshold_candidates.csv").open(encoding="utf-8") as stream:
        candidates = list(csv.DictReader(stream))
    assert len(candidates) == len(np.unique(scores)) + 1
    for candidate in candidates:
        expected = baseline.confusion_metrics(scores, attacks, float(candidate["threshold"]))
        for key in ("precision", "recall", "F1", "FPR", "TPR", "TP", "TN", "FP", "FN"):
            assert float(candidate[key]) == pytest.approx(expected[key])


def test_output_must_not_overwrite_or_pollute_the_prepared_dataset(prepared_dataset: Path) -> None:
    for output in (prepared_dataset, prepared_dataset / "model-output"):
        with pytest.raises(ValueError, match="outside the dataset"):
            baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=True)


def test_dataset_checksum_is_verified_not_just_recorded(prepared_dataset: Path, tmp_path: Path) -> None:
    with (prepared_dataset / "train_normal_features.csv").open("a", encoding="utf-8") as stream:
        stream.write("1,2,2\n")
    with pytest.raises(ValueError, match="hash/size mismatch"):
        baseline.run_experiment(prepared_dataset, tmp_path / "run", fit=True, evaluate=False)


@pytest.mark.parametrize(
    "cap,threshold,tp,fp,ftp_recall,ssh_recall",
    [(0.0, 0.8, 1, 0, 1.0, 0.0), (0.01, 0.65, 2, 1, 1.0, 0.5), (0.02, 0.5, 3, 2, 1.0, 1.0)],
)
def test_diagnostic_points_maximize_recall_with_one_shared_threshold(
    cap: float, threshold: float, tp: int, fp: int, ftp_recall: float, ssh_recall: float,
) -> None:
    scores = np.array([0.1] * 98 + [0.6, 0.7, 0.8, 0.65, 0.5])
    labels = np.array(["BENIGN"] * 100 + ["FTP-Patator", "SSH-Patator", "SSH-Patator"])
    point = operating_analysis.calculate_operating_points(scores, labels, [cap])[0]
    expected = baseline.confusion_metrics(scores, labels != "BENIGN", threshold)
    assert point["threshold"] == point["maximum_recall_threshold"] == threshold
    assert point["tp"] == tp and point["fp"] == fp
    assert point["actual_fpr"] <= cap
    assert point["maximum_recall_at_fpr_cap"] == point["recall"] == tp / 3
    for key in ("precision", "f1", "tp", "tn", "fp", "fn", "balanced_accuracy"):
        assert point[key] == pytest.approx(expected[key])
    assert point["FTP-Patator_recall"] == ftp_recall
    assert point["SSH-Patator_recall"] == ssh_recall
    assert point["per_family"]["FTP-Patator"]["detected"] == int(ftp_recall)
    assert point["per_family"]["SSH-Patator"]["detected"] == int(2 * ssh_recall)


def test_diagnostic_fpr_caps_use_available_ties_without_interpolation() -> None:
    scores = np.array([0.1] * 99 + [0.8, 0.8, 0.8])
    labels = np.array(["BENIGN"] * 100 + ["FTP-Patator", "SSH-Patator"])
    points = operating_analysis.calculate_operating_points(scores, labels, [0.005, 0.01])
    assert points[0]["threshold"] == np.nextafter(0.8, np.inf)
    assert points[0]["actual_fpr"] == points[0]["recall"] == 0
    assert points[1]["threshold"] == 0.8
    assert points[1]["actual_fpr"] == 0.01 and points[1]["recall"] == 1
    assert points[1]["FTP-Patator_recall"] == points[1]["SSH-Patator_recall"] == 1


def test_diagnostic_default_targets_match_a_direct_candidate_reference() -> None:
    assert operating_analysis.DEFAULT_FPR_CAPS == (0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.02, 0.05, 0.1)
    scores = np.array([0.1] * 90 + [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.8, 0.9, 0.9, 0.95, 0.8, 0.6, 0.4])
    labels = np.array(["BENIGN"] * 100 + ["FTP-Patator", "SSH-Patator", "SSH-Patator", "FTP-Patator"])
    candidates = [*np.unique(scores), np.nextafter(scores.max(), np.inf)]
    for point in operating_analysis.calculate_operating_points(scores, labels):
        reference = [(float(threshold), baseline.confusion_metrics(scores, labels != "BENIGN", float(threshold))) for threshold in candidates]
        feasible = [(threshold, metrics) for threshold, metrics in reference if metrics["fpr"] <= point["target_fpr"]]
        best = max(feasible, key=lambda item: (item[1]["recall"], item[1]["f1"], -item[1]["fpr"], item[0]))
        assert point["threshold"] == best[0]
        assert point["maximum_recall_at_fpr_cap"] == max(metrics["recall"] for _, metrics in feasible)


@pytest.mark.parametrize("cap", [-0.01, 1.01, np.nan, np.inf])
def test_diagnostic_points_reject_invalid_caps(cap: float) -> None:
    with pytest.raises(ValueError, match="FPR caps"):
        operating_analysis.calculate_operating_points([0.1, 0.8], ["BENIGN", "FTP-Patator"], [cap])


def test_diagnostic_locked_fractions_and_validation_collisions_are_explicit() -> None:
    report = operating_analysis.validation_diagnostics(
        [0.8, 0.8, 0.8, 0.1], ["BENIGN", "FTP-Patator", "SSH-Patator", "BENIGN"],
        [[1, 2, 3], [1, 2, 3], [4, 5, 6], [7, 8, 9]], 0.8, [0.5],
    )
    locked = report["locked_operating_point"]
    assert locked["attack_fraction_at_or_above"] == 1
    assert locked["benign_fraction_at_or_above"] == 0.5
    assert locked["attack_fraction_strictly_above"] == locked["benign_fraction_strictly_above"] == 0
    collisions = report["representation_collisions"]
    assert collisions["prepared_validation_float64"]["mixed_label_groups"] == 1
    assert collisions["prepared_validation_float64"]["mixed_label_rows"] == 2
    assert collisions["representation_limits"]["attack_rows_sharing_exact_vector_with_benign"] == 1
    assert report["ranking"]["roc_auc"] == locked["roc_auc"]
    assert report["score_distributions"]["attack"]["p99_9"] == 0.8
    assert report["test_data_used"] is False


def test_validation_diagnostic_preserves_fit_artifacts_and_never_reads_test(
    prepared_dataset: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "validation-diagnostic"
    baseline.run_experiment(prepared_dataset, output, fit=True, evaluate=False)
    before = {name: sha256(output / name) for name in FIT_ARTIFACTS}
    original_open, original_load = Path.open, baseline.load_split

    def guarded_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        assert not (path.parent == prepared_dataset and path.name.startswith("test_"))
        return original_open(path, *args, **kwargs)

    def validation_only_load(path: Path, split: str) -> Any:
        assert split == "validation"
        return original_load(path, split)

    def forbidden_fit(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("validation diagnostics must never refit")

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(baseline, "load_split", validation_only_load)
    monkeypatch.setattr(baseline.IsolationForest, "fit", forbidden_fit)
    report = operating_analysis.run_validation_analysis(prepared_dataset, output)
    assert {name: sha256(output / name) for name in FIT_ARTIFACTS} == before
    assert report["locked_operating_point"]["threshold"] == read_json(output / "threshold.json")["threshold"]
    assert report["provenance"]["original_artifact_sha256"] == before
    assert {path.name for path in output.iterdir()} == FIT_ARTIFACTS | set(operating_analysis.DIAGNOSTIC_FILES)
    csv_info = report["diagnostic_artifacts"]["validation_operating_points.csv"]
    assert csv_info["sha256"] == sha256(output / "validation_operating_points.csv")
    with (output / "validation_operating_points.csv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == len(operating_analysis.DEFAULT_FPR_CAPS)
    for row, point in zip(rows, report["operating_points"]):
        for field in operating_analysis.CSV_FIELDS:
            assert float(row[field]) == point[field]
    with pytest.raises(FileExistsError, match="already exist"):
        operating_analysis.run_validation_analysis(prepared_dataset, output)
