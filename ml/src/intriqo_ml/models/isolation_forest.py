"""A reproducible, leakage-safe Isolation Forest baseline.

The prepared dataset is deliberately consumed as two aligned CSV files per
split.  The model sees the three values in :data:`FEATURES` without scaling or
other preprocessing.  Values are read as float64 for validation and are
converted to float32 only at the sklearn boundary.

The validation threshold is selected from the validation scores alone.  It is
the best threshold with a validation false-positive rate no greater than one
percent (recall, F1, lower FPR, and higher threshold are the tie breakers).
Fitting persists the model and validation-only lock before touching test data.
Evaluation verifies the saved fit receipt and scores test once with that lock;
it never reads or rescores the validation split.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, cast

import joblib  # type: ignore[import-untyped]
import numpy as np
from numpy.typing import NDArray
from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
from sklearn.metrics import (  # type: ignore[import-untyped]
    average_precision_score,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)
from sklearn.utils.validation import check_is_fitted  # type: ignore[import-untyped]

FEATURES: Final[tuple[str, ...]] = (
    "duration_seconds",
    "packet_count",
    "packets_per_second",
)
DEFAULT_MODEL_PARAMETERS: Final[dict[str, Any]] = {
    "n_estimators": 300,
    "max_samples": "auto",
    "contamination": "auto",
    "random_state": 42,
    "n_jobs": -1,
}

FloatArray = NDArray[np.float64]
BoolArray = NDArray[np.bool_]
StringArray = NDArray[np.str_]
MetricMap = dict[str, float | int]
_SPLITS: Final[tuple[str, ...]] = ("train_normal", "validation", "test")
_SCORE_DEFINITION: Final[str] = "-model.score_samples(features)"
_FIT_ARTIFACT_NAMES: Final[tuple[str, ...]] = (
    "model.joblib",
    "model_metadata.json",
    "threshold.json",
    "validation_metrics.json",
    "score_statistics.json",
    "feature_schema.json",
    "validation_score_distribution.png",
    "validation_threshold_candidates.csv",
)
_TEST_ARTIFACT_NAMES: Final[tuple[str, ...]] = (
    "test_metrics.json",
    "evaluation_manifest.json",
    "test_score_distribution.png",
    "precision_recall_curve.png",
    "roc_curve.png",
    "confusion_matrix.png",
    "per_attack_family_recall.png",
)
_ARTIFACT_NAMES: Final[tuple[str, ...]] = (
    *_FIT_ARTIFACT_NAMES, "fit_manifest.json", *_TEST_ARTIFACT_NAMES,
)

@dataclass(frozen=True)
class _ThresholdCandidates:
    thresholds: FloatArray
    precision: FloatArray
    recall: FloatArray
    f1: FloatArray
    fpr: FloatArray
    tp: FloatArray
    tn: FloatArray
    fp: FloatArray
    fn: FloatArray


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _as_float_array(values: Any, *, name: str) -> FloatArray:
    array = np.asarray(values, dtype=np.float64)
    if array.ndim != 1:
        raise ValueError(f"{name} must be a one-dimensional array")
    if not np.all(np.isfinite(array)):
        raise ValueError(f"{name} contains non-finite values")
    return array


def _as_attack_array(values: Any, *, expected: int | None = None) -> BoolArray:
    raw = np.asarray(values)
    if raw.ndim != 1:
        raise ValueError("is_attack must be a one-dimensional array")
    if not np.all(np.isin(raw, [False, True])):
        raise ValueError("is_attack values must be boolean or zero/one")
    array = raw.astype(np.bool_, copy=False)
    if expected is not None and len(array) != expected:
        raise ValueError("scores and is_attack must have the same row count")
    return array


def scores_from_sklearn(model: Any, features: Any) -> FloatArray:
    """Return normalized anomaly scores, where higher means more anomalous."""

    # Keep this expression intentionally direct: sklearn's score_samples is
    # the canonical normality score and the public contract is its negation.
    return cast(FloatArray, -model.score_samples(features))


def _iter_csv_rows(path: Path) -> Iterator[list[str]]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            yield from csv.reader(stream, strict=True)
    except FileNotFoundError:
        raise FileNotFoundError(f"missing required dataset artifact: {path}") from None
    except (OSError, UnicodeError, csv.Error) as error:
        raise ValueError(f"could not read dataset artifact {path}: {error}") from None


def load_split(dataset_dir: str | Path, split: str) -> tuple[FloatArray, StringArray, BoolArray]:
    """Load one prepared split and its aligned metadata.

    The return value is ``(features, labels, is_attack)``.  Feature values are
    float64, labels are strings, and ``is_attack`` is boolean.  Headers and
    row ordering are checked exactly; no pandas inference is used.
    """

    if split not in _SPLITS:
        raise ValueError(f"unsupported split {split!r}; expected one of {_SPLITS}")
    root = Path(dataset_dir)
    feature_path = root / f"{split}_features.csv"
    metadata_path = root / f"{split}_metadata.csv"
    feature_rows = _iter_csv_rows(feature_path)
    metadata_rows = _iter_csv_rows(metadata_path)
    feature_header = next(feature_rows, None)
    metadata_header = next(metadata_rows, None)
    if feature_header is None:
        raise ValueError(f"dataset artifact has no header: {feature_path}")
    if metadata_header is None:
        raise ValueError(f"dataset artifact has no header: {metadata_path}")
    expected_features = list(FEATURES)
    if feature_header != expected_features:
        raise ValueError(
            f"feature header/order mismatch in {feature_path}: "
            f"expected {expected_features!r}, got {feature_header!r}"
        )
    if len(metadata_header) != len(set(metadata_header)) or any(not column for column in metadata_header):
        raise ValueError(f"invalid metadata header in {metadata_path}")
    if "label" not in metadata_header or "is_attack" not in metadata_header:
        raise ValueError(f"metadata header must contain label and is_attack: {metadata_path}")
    label_index = metadata_header.index("label")
    attack_index = metadata_header.index("is_attack")

    feature_data: list[list[float]] = []
    for row_number, row in enumerate(feature_rows, start=2):
        if len(row) != len(FEATURES):
            raise ValueError(f"feature column count mismatch in {feature_path} row {row_number}")
        converted: list[float] = []
        for column, raw in zip(FEATURES, row):
            if not raw.strip():
                raise ValueError(f"missing numeric value in {feature_path} row {row_number}, column {column}")
            try:
                value = float(raw)
            except ValueError:
                raise ValueError(
                    f"invalid numeric value in {feature_path} row {row_number}, column {column}"
                ) from None
            if not math.isfinite(value):
                raise ValueError(
                    f"non-finite numeric value in {feature_path} row {row_number}, column {column}"
                )
            converted.append(value)
        feature_data.append(converted)

    labels: list[str] = []
    attack_flags: list[bool] = []
    for row_number, row in enumerate(metadata_rows, start=2):
        if len(row) != len(metadata_header):
            raise ValueError(f"metadata column count mismatch in {metadata_path} row {row_number}")
        label = row[label_index].strip()
        if not label:
            raise ValueError(f"missing label in {metadata_path} row {row_number}")
        token = row[attack_index].strip().lower()
        if token not in {"true", "false", "0", "1"}:
            raise ValueError(
                f"is_attack must be true/false or 1/0 in {metadata_path} row {row_number}"
            )
        is_attack = token in {"true", "1"}
        if is_attack != (label != "BENIGN"):
            raise ValueError(f"label/is_attack alignment mismatch in {metadata_path} row {row_number}")
        labels.append(label)
        attack_flags.append(is_attack)

    if len(feature_data) != len(labels):
        raise ValueError(
            f"feature/metadata row count mismatch for {split}: "
            f"{len(feature_data)} != {len(labels)}"
        )
    features = np.asarray(feature_data, dtype=np.float64)
    if not feature_data:
        features = np.empty((0, len(FEATURES)), dtype=np.float64)
    return features, np.asarray(labels, dtype=str), np.asarray(attack_flags, dtype=bool)


def _metric_divide(numerator: float, denominator: float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def confusion_metrics(scores: Any, is_attack: Any, threshold: float) -> MetricMap:
    """Calculate metrics using ``scores >= threshold`` as the alert rule.

    Zero denominators produce zero.  ROC-AUC is zero when either class is
    absent; average precision is zero without attacks and one for all-attacks.
    ``pr_auc`` names the average-precision summary (not trapezoidal PR area).
    """

    score_array = _as_float_array(scores, name="scores")
    attack_array = _as_attack_array(is_attack, expected=len(score_array))
    if math.isnan(float(threshold)):
        raise ValueError("threshold must not be NaN")
    alert = score_array >= float(threshold)
    tp = int(np.count_nonzero(alert & attack_array))
    tn = int(np.count_nonzero(~alert & ~attack_array))
    fp = int(np.count_nonzero(alert & ~attack_array))
    fn = int(np.count_nonzero(~alert & attack_array))
    precision = _metric_divide(tp, tp + fp)
    recall = _metric_divide(tp, tp + fn)
    f1 = _metric_divide(2.0 * precision * recall, precision + recall)
    fpr = _metric_divide(fp, fp + tn)
    specificity = _metric_divide(tn, tn + fp)
    tpr = recall
    balanced_accuracy = (tpr + specificity) / 2.0
    if len(score_array) and np.any(attack_array):
        average_precision = float(average_precision_score(attack_array, score_array))
    else:
        average_precision = 0.0
    if np.any(attack_array) and np.any(~attack_array):
        roc_auc = float(roc_auc_score(attack_array.astype(int), score_array))
    else:
        roc_auc = 0.0
    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "F1": f1,
        "f1": f1,
        "FPR": fpr,
        "fpr": fpr,
        "TPR": tpr,
        "tpr": tpr,
        "specificity": specificity,
        "balanced_accuracy": balanced_accuracy,
        "average_precision": average_precision,
        "pr_auc": average_precision,
        "roc_auc": roc_auc,
        "threshold": float(threshold),
        "sample_count": len(score_array),
    }


def _no_alert_threshold(maximum: float) -> float:
    # The next representable float is unambiguously greater than every score.
    # sklearn's scores lie well inside the finite float64 range.  At float64's
    # extreme upper limit, +inf still has the correct no-alert semantics.
    with np.errstate(over="ignore"):
        return float(np.nextafter(maximum, np.inf))


def _threshold_candidates(scores: Any, is_attack: Any) -> _ThresholdCandidates:
    score_array = _as_float_array(scores, name="scores")
    attack_array = _as_attack_array(is_attack, expected=len(score_array))
    if len(score_array) == 0:
        raise ValueError("cannot select a threshold from an empty validation split")
    # One sort plus cumulative counts evaluates every unique score in O(n log n)
    # rather than rescanning millions of validation rows for each candidate.
    unique, inverse, counts = np.unique(score_array, return_inverse=True, return_counts=True)
    positive_counts = np.asarray(
        np.bincount(inverse, weights=attack_array, minlength=len(unique)), dtype=np.float64,
    )
    tp = np.cumsum(positive_counts[::-1])[::-1]
    fp = np.cumsum((counts - positive_counts)[::-1])[::-1]
    positives = int(np.count_nonzero(attack_array))
    negatives = len(attack_array) - positives
    recalls = tp / positives if positives else np.zeros(len(unique), dtype=np.float64)
    fprs = fp / negatives if negatives else np.zeros(len(unique), dtype=np.float64)
    precision = np.divide(tp, tp + fp, out=np.zeros(len(unique)), where=(tp + fp) != 0)
    f1_values = np.divide(
        2.0 * precision * recalls,
        precision + recalls,
        out=np.zeros(len(unique)),
        where=(precision + recalls) != 0,
    )
    no_alert = _no_alert_threshold(float(unique[-1]))
    candidates = np.append(unique, no_alert)
    recalls = np.append(recalls, 0.0)
    fprs = np.append(fprs, 0.0)
    f1_values = np.append(f1_values, 0.0)
    precision = np.append(precision, 0.0)
    tp = np.append(tp, 0.0)
    fp = np.append(fp, 0.0)
    return _ThresholdCandidates(
        candidates, precision, recalls, f1_values, fprs,
        tp, negatives - fp, fp, positives - tp,
    )


def _write_threshold_candidates(path: Path, candidates: _ThresholdCandidates) -> None:
    """Stream one row per score group, reusing the cumulative candidate arrays."""

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(["threshold", "precision", "recall", "F1", "FPR", "TPR", "TP", "TN", "FP", "FN"])
            for row in zip(
                candidates.thresholds, candidates.precision, candidates.recall,
                candidates.f1, candidates.fpr, candidates.tp, candidates.tn,
                candidates.fp, candidates.fn,
            ):
                threshold, precision, recall, f1, fpr, tp, tn, fp, fn = row
                writer.writerow([
                    float(threshold), float(precision), float(recall), float(f1),
                    float(fpr), float(recall), int(tp), int(tn), int(fp), int(fn),
                ])
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _select_threshold_details(
    scores: Any, is_attack: Any, max_false_positive_rate: float,
    candidate_output: Path | None = None,
) -> tuple[float, dict[str, Any]]:
    if not math.isfinite(max_false_positive_rate) or not 0.0 <= max_false_positive_rate <= 1.0:
        raise ValueError("max_false_positive_rate must be between zero and one")
    values = _threshold_candidates(scores, is_attack)
    candidates = values.thresholds
    recalls, fprs, f1_values = values.recall, values.fpr, values.f1
    indices = np.flatnonzero(fprs <= max_false_positive_rate)
    if len(indices):
        for metric, maximize in ((recalls, True), (f1_values, True), (fprs, False), (candidates, True)):
            best = np.max(metric[indices]) if maximize else np.min(metric[indices])
            indices = indices[metric[indices] == best]
        selection = "highest_recall_subject_to_fpr"
    else:
        indices = np.arange(len(candidates))
        for metric, maximize in ((fprs, False), (recalls, True), (f1_values, True), (candidates, True)):
            best = np.max(metric[indices]) if maximize else np.min(metric[indices])
            indices = indices[metric[indices] == best]
        selection = "fallback_lowest_fpr"
    chosen_index = int(indices[0])
    threshold = float(candidates[chosen_index])
    chosen = {
        "threshold": threshold,
        "recall": float(recalls[chosen_index]),
        "fpr": float(fprs[chosen_index]),
        "f1": float(f1_values[chosen_index]),
        "qualifies": bool(fprs[chosen_index] <= max_false_positive_rate),
    }
    details: dict[str, Any] = {
        "method": "validation_unique_scores_plus_no_alert",
        "selection": selection,
        "max_false_positive_rate": float(max_false_positive_rate),
        "candidate_count": len(candidates),
        "no_alert_threshold": float(candidates[-1]),
        "decision_rule": "anomaly_score >= threshold",
        "score_definition": _SCORE_DEFINITION,
        "selection_split": "validation",
        "test_used_for_selection": False,
        "selected": dict(chosen),
        "tie_break": ["recall", "f1", "lower_fpr", "higher_threshold"],
        "fallback_tie_break": ["lower_fpr", "recall", "f1", "higher_threshold"],
    }
    if candidate_output is not None:
        _write_threshold_candidates(candidate_output, values)
    return threshold, details


def select_validation_threshold(
    scores: Any,
    is_attack: Any,
    max_false_positive_rate: float = 0.01,
) -> float:
    """Select a deterministic validation-only threshold under the FPR cap."""

    threshold, _ = _select_threshold_details(scores, is_attack, max_false_positive_rate)
    return threshold


def feature_collision_summary(features: Any, labels: Any) -> dict[str, int]:
    """Summarize exact feature rows shared by more than one label."""

    values = np.asarray(features, dtype=np.float64)
    if values.ndim != 2:
        raise ValueError("features must be a two-dimensional array")
    if not np.all(np.isfinite(values)):
        raise ValueError("features contains non-finite values")
    label_values = np.asarray(labels, dtype=str)
    if label_values.ndim != 1 or len(label_values) != len(values):
        raise ValueError("features and labels must have aligned row counts")
    _, group_ids, group_sizes = np.unique(values, axis=0, return_inverse=True, return_counts=True)
    _, label_ids = np.unique(label_values, return_inverse=True)
    group_labels = np.unique(np.column_stack((group_ids, label_ids)), axis=0)
    label_counts = np.bincount(group_labels[:, 0], minlength=len(group_sizes))
    mixed = label_counts > 1
    benign_counts = np.bincount(group_ids[label_values == "BENIGN"], minlength=len(group_sizes))
    mixed_binary = (benign_counts > 0) & (benign_counts < group_sizes)
    return {
        "total_rows": len(values),
        "unique_feature_groups": len(group_sizes),
        "duplicate_rows": int(len(values) - len(group_sizes)),
        "mixed_label_groups": int(np.count_nonzero(mixed)),
        "mixed_label_rows": int(np.sum(group_sizes[mixed])),
        "mixed_attack_benign_groups": int(np.count_nonzero(mixed_binary)),
        "mixed_attack_benign_rows": int(np.sum(group_sizes[mixed_binary])),
    }


def _distribution(scores: Any) -> dict[str, int | float | None]:
    values = _as_float_array(scores, name="scores")
    if len(values) == 0:
        return {"count": 0, "min": None, "max": None, "mean": None, "stddev_population": None, "p01": None, "p05": None, "p25": None, "median": None, "p75": None, "p95": None, "p99": None}
    percentiles = np.percentile(values, [1, 5, 25, 50, 75, 95, 99])
    return {
        "count": len(values),
        "min": float(np.min(values)),
        "max": float(np.max(values)),
        "mean": float(np.mean(values)),
        "stddev_population": float(np.std(values)),
        "p01": float(percentiles[0]),
        "p05": float(percentiles[1]),
        "p25": float(percentiles[2]),
        "median": float(percentiles[3]),
        "p75": float(percentiles[4]),
        "p95": float(percentiles[5]),
        "p99": float(percentiles[6]),
    }


def _split_statistics(scores: FloatArray, labels: StringArray, is_attack: BoolArray) -> dict[str, Any]:
    return {
        "all": _distribution(scores),
        "benign": _distribution(scores[~is_attack]),
        "attack": _distribution(scores[is_attack]),
        "per_label": {
            label: _distribution(scores[labels == label])
            for label in sorted({str(value) for value in labels})
        },
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_payload(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def _write_json(path: Path, value: Any) -> None:
    payload = _json_payload(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _write_joblib(path: Path, value: Any) -> None:
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        joblib.dump(value, temporary)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _load_json(path: Path, *, required: bool = True) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except FileNotFoundError:
        if required:
            raise FileNotFoundError(f"missing required dataset artifact: {path}") from None
        return {}
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON artifact {path}: {error}") from None
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")  # noqa: TRY004 - invalid serialized data
    return cast(dict[str, Any], value)


def _git_commit() -> str | None:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, check=True, text=True, timeout=2
        )
    except (OSError, subprocess.SubprocessError):
        return None
    commit = completed.stdout.strip()
    return commit or None


def _versions() -> dict[str, str]:
    import matplotlib
    import scipy  # type: ignore[import-untyped]
    import sklearn  # type: ignore[import-untyped]

    return {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
        "scipy": scipy.__version__,
        "joblib": joblib.__version__,
        "matplotlib": matplotlib.__version__,
    }


def _validate_dataset_manifest(dataset_dir: Path) -> tuple[dict[str, Any], str]:
    path = dataset_dir / "dataset_manifest.json"
    manifest = _load_json(path)
    manifest_features = manifest.get("features")
    if manifest_features != list(FEATURES):
        raise ValueError(
            f"dataset manifest feature order mismatch: expected {list(FEATURES)!r}, got {manifest_features!r}"
        )
    preprocessing = manifest.get("preprocessing")
    preprocessing_kind = preprocessing.get("kind") if isinstance(preprocessing, dict) else preprocessing
    if preprocessing_kind != "none":
        raise ValueError("Isolation Forest baseline requires preprocessing=none")
    for field in ("artifact_sha256", "artifact_sizes_bytes", "counts", "label_composition"):
        if not isinstance(manifest.get(field), dict):
            raise ValueError(f"dataset manifest missing or malformed {field}")  # noqa: TRY004 - invalid serialized data
    _verify_input_artifact(dataset_dir, manifest, "preprocessing.json")
    if _load_json(dataset_dir / "preprocessing.json").get("kind") != "none":
        raise ValueError("Isolation Forest baseline requires prepared preprocessing=none")
    return manifest, _sha256(path)


def _verify_input_artifact(dataset_dir: Path, manifest: dict[str, Any], name: str) -> None:
    hashes = manifest.get("artifact_sha256")
    sizes = manifest.get("artifact_sizes_bytes")
    if not isinstance(hashes, dict) or not isinstance(sizes, dict):
        raise ValueError("dataset manifest missing artifact hashes or sizes")  # noqa: TRY004 - invalid serialized data
    expected_hash, expected_size = hashes.get(name), sizes.get(name)
    if (
        not isinstance(expected_hash, str) or len(expected_hash) != 64
        or any(character not in "0123456789abcdef" for character in expected_hash)
        or type(expected_size) is not int or expected_size < 0
    ):
        raise ValueError(f"dataset manifest missing or malformed hash/size for {name}")
    path = dataset_dir / name
    if not path.is_file():
        raise FileNotFoundError(f"missing required dataset artifact: {path}")
    if path.stat().st_size != expected_size or _sha256(path) != expected_hash:
        raise ValueError(f"dataset artifact hash/size mismatch with manifest: {name}")


def _load_verified_split(
    dataset_dir: Path, manifest: dict[str, Any], split: str,
) -> tuple[FloatArray, StringArray, BoolArray]:
    for kind in ("features", "metadata"):
        _verify_input_artifact(dataset_dir, manifest, f"{split}_{kind}.csv")
    features, labels, attacks = load_split(dataset_dir, split)
    counts = manifest.get("counts")
    split_counts = counts.get("split_valid_rows") if isinstance(counts, dict) else None
    expected_count = split_counts.get(split) if isinstance(split_counts, dict) else None
    if type(expected_count) is not int or expected_count < 0:
        raise ValueError(f"dataset manifest missing or malformed split count for {split}")
    if expected_count != len(features):
        raise ValueError(f"dataset manifest split count mismatch for {split}")
    all_composition = manifest.get("label_composition")
    expected = all_composition.get(split) if isinstance(all_composition, dict) else None
    if not isinstance(expected, dict) or any(
        not isinstance(label, str) or not label or type(count) is not int or count < 0
        for label, count in expected.items()
    ):
        raise ValueError(f"dataset manifest missing or malformed class composition for {split}")
    actual = dict(Counter(str(label) for label in labels))
    if expected != actual or sum(expected.values()) != expected_count:
        raise ValueError(f"dataset manifest class composition mismatch for {split}")
    return features, labels, attacks


def _per_label_metrics(labels: StringArray, is_attack: BoolArray, scores: FloatArray, threshold: float) -> dict[str, MetricMap]:
    result: dict[str, dict[str, float | int]] = {}
    for label in sorted({str(value) for value in labels if str(value) != "BENIGN"}):
        mask = labels == label
        attack_rows = int(np.count_nonzero(mask & is_attack))
        detected = int(np.count_nonzero(mask & is_attack & (scores >= threshold)))
        result[label] = {
            "support": int(np.count_nonzero(mask)),
            "attack_rows": attack_rows,
            "detected": detected,
            "missed": attack_rows - detected,
            "recall": _metric_divide(detected, attack_rows),
        }
    return result


def _per_label_binary_metrics(
    labels: StringArray, scores: FloatArray, threshold: float,
) -> dict[str, MetricMap]:
    benign = labels == "BENIGN"
    result = {"BENIGN": confusion_metrics(scores[benign], np.zeros(int(benign.sum()), dtype=bool), threshold)}
    for family in sorted({str(label) for label in labels if label != "BENIGN"}):
        population = benign | (labels == family)
        result[family] = confusion_metrics(scores[population], labels[population] == family, threshold)
    return result


def _representation_limits(features: FloatArray, labels: StringArray) -> dict[str, Any]:
    _, group_ids = np.unique(features, axis=0, return_inverse=True)
    benign_groups = np.unique(group_ids[labels == "BENIGN"])
    shared_attack = (labels != "BENIGN") & np.isin(group_ids, benign_groups)
    attacks = int(np.count_nonzero(labels != "BENIGN"))
    shared = int(np.count_nonzero(shared_attack))
    return {
        "audit_dtype": "float64",
        "attack_rows_sharing_exact_vector_with_benign": shared,
        "attack_rows": attacks,
        "fraction_of_attack_rows": _metric_divide(shared, attacks),
        "per_attack_family": {
            family: int(np.count_nonzero(shared_attack & (labels == family)))
            for family in sorted({str(label) for label in labels if label != "BENIGN"})
        },
        "identical_vectors_get_identical_scores": True,
        "limitation": (
            "Identical raw feature vectors produce identical model inputs and identical scores. "
            "Mixed BENIGN/attack labels on those vectors are not resolvable by this model."
        ),
    }


def _atomic_plot(path: Path, draw: Callable[[Any, Any], None]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    figure = plt.figure(figsize=(7, 5), dpi=120)
    temporary: Path | None = None
    try:
        draw(figure, plt)
        figure.tight_layout()
        with tempfile.NamedTemporaryFile("wb", suffix=".png", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
        figure.savefig(temporary, format="png")
        os.replace(temporary, path)
    finally:
        plt.close(figure)
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _write_score_plot(
    path: Path, title: str, scores: FloatArray, attack: BoolArray, threshold: float,
) -> None:
    def score_plot(figure: Any, plt: Any) -> None:
        axis = figure.add_subplot(1, 1, 1)
        benign = scores[~attack]
        attacks = scores[attack]
        bins = np.histogram_bin_edges(scores, bins=30) if len(scores) else 30
        if len(benign):
            axis.hist(benign, bins=bins, alpha=0.65, label="BENIGN")
        if len(attacks):
            axis.hist(attacks, bins=bins, alpha=0.65, label="ATTACK")
        axis.axvline(threshold, color="black", linestyle="--", label="locked threshold")
        axis.set(title=title, xlabel="anomaly score", ylabel="rows")
        axis.legend()

    _atomic_plot(path, score_plot)


def _write_test_plots(
    output_dir: Path, test_scores: FloatArray, test_attack: BoolArray,
    test_labels: StringArray, threshold: float,
) -> None:
    _write_score_plot(
        output_dir / "test_score_distribution.png",
        "Test score distribution", test_scores, test_attack, threshold,
    )

    def pr_plot(figure: Any, plt: Any) -> None:
        axis = figure.add_subplot(1, 1, 1)
        if np.any(test_attack) and np.any(~test_attack):
            precision, recall, _ = precision_recall_curve(test_attack.astype(int), test_scores)
            axis.plot(recall, precision)
        else:
            axis.text(0.5, 0.5, "PR curve requires both classes", ha="center", va="center")
        axis.set(title="Test precision-recall curve", xlabel="recall", ylabel="precision")
        axis.set_xlim(0, 1)
        axis.set_ylim(0, 1)

    def roc_plot(figure: Any, plt: Any) -> None:
        axis = figure.add_subplot(1, 1, 1)
        if np.any(test_attack) and np.any(~test_attack):
            fpr, tpr, _ = roc_curve(test_attack.astype(int), test_scores)
            axis.plot(fpr, tpr)
        else:
            axis.text(0.5, 0.5, "ROC curve requires both classes", ha="center", va="center")
        axis.plot([0, 1], [0, 1], linestyle=":", color="grey")
        axis.set(title="Test ROC curve", xlabel="false-positive rate", ylabel="true-positive rate")
        axis.set_xlim(0, 1)
        axis.set_ylim(0, 1)

    _atomic_plot(output_dir / "precision_recall_curve.png", pr_plot)
    _atomic_plot(output_dir / "roc_curve.png", roc_plot)

    def confusion_plot(figure: Any, plt: Any) -> None:
        axis = figure.add_subplot(1, 1, 1)
        alert = test_scores >= threshold
        matrix = np.array(
            [
                [np.count_nonzero(~alert & ~test_attack), np.count_nonzero(alert & ~test_attack)],
                [np.count_nonzero(~alert & test_attack), np.count_nonzero(alert & test_attack)],
            ],
            dtype=int,
        )
        image = axis.imshow(matrix, cmap="Blues")
        figure.colorbar(image, ax=axis)
        axis.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["normal", "alert"], yticklabels=["BENIGN", "ATTACK"], title="Test confusion matrix")
        for row in range(2):
            for column in range(2):
                axis.text(column, row, str(matrix[row, column]), ha="center", va="center")

    _atomic_plot(output_dir / "confusion_matrix.png", confusion_plot)

    def family_plot(figure: Any, plt: Any) -> None:
        axis = figure.add_subplot(1, 1, 1)
        families = sorted({str(label) for label in test_labels if str(label) != "BENIGN"})
        recalls: list[float] = []
        for family in families:
            mask = (test_labels == family) & test_attack
            recalls.append(
                _metric_divide(
                    int(np.count_nonzero(mask & (test_scores >= threshold))),
                    int(np.count_nonzero(mask)),
                )
            )
        if families:
            axis.bar(range(len(families)), recalls)
            axis.set_xticks(range(len(families)), families, rotation=45, ha="right")
            axis.set_ylim(0, 1)
        else:
            axis.text(0.5, 0.5, "no attack families", ha="center", va="center")
        axis.set(title="Test recall by attack family", ylabel="recall")

    _atomic_plot(output_dir / "per_attack_family_recall.png", family_plot)


def _prepare_output(output_dir: Path, *, fit: bool, evaluate: bool, force: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    names = _ARTIFACT_NAMES if fit else _TEST_ARTIFACT_NAMES
    existing_generated = [output_dir / name for name in names if (output_dir / name).exists() or (output_dir / name).is_symlink()]
    if existing_generated and not force:
        raise FileExistsError(
            "output artifacts already exist; pass --force (force=True) to replace them: "
            + ", ".join(path.name for path in existing_generated)
        )
    if force:
        # A replacement fit invalidates the previous lock and its evaluation.
        # A replacement evaluation preserves every fitted/validation artifact.
        for path in existing_generated:
            if path.is_file() or path.is_symlink():
                path.unlink()
            else:
                raise ValueError(f"generated artifact is not a regular file: {path}")


def _model_features(features: FloatArray) -> NDArray[np.float32]:
    with np.errstate(over="ignore"):
        result = features.astype(np.float32, copy=False)
    if not np.all(np.isfinite(result)):
        raise ValueError("finite feature values exceed the float32 model-input range")
    return result


def _model_input_with_audit(features: FloatArray) -> tuple[NDArray[np.float32], dict[str, Any]]:
    converted = _model_features(features)
    reconstructed = converted.astype(np.float64)
    error = np.abs(features - reconstructed)
    relative = np.divide(error, np.abs(features), out=np.zeros_like(error), where=features != 0)
    audit: dict[str, Any] = {
        "source_dtype": "float64", "model_input_dtype": "float32", "preprocessing": "none",
        "max_absolute_error": float(np.max(error)) if error.size else 0.0,
        "max_relative_error": float(np.max(relative)) if relative.size else 0.0,
        "packet_count_rounded": bool(np.any(features[:, 1] != reconstructed[:, 1])),
        "packet_count_rounded_rows": int(np.count_nonzero(features[:, 1] != reconstructed[:, 1])),
        "per_feature": {
            name: {
                "max_absolute_error": float(np.max(error[:, index])) if len(features) else 0.0,
                "max_relative_error": float(np.max(relative[:, index])) if len(features) else 0.0,
            }
            for index, name in enumerate(FEATURES)
        },
    }
    return converted, audit


def _artifact_provenance(output_dir: Path, names: Sequence[str]) -> tuple[dict[str, str], dict[str, int]]:
    hashes: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for name in sorted(names):
        path = output_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"missing required model/lock artifact: {path}")
        hashes[name], sizes[name] = _sha256(path), path.stat().st_size
    return hashes, sizes


def _fit_statistics_projection(statistics: dict[str, Any]) -> dict[str, Any]:
    # score_statistics gains a test section during evaluation.  Its validation
    # projection is immutable and is the scope of this artifact's fit receipt.
    return {key: value for key, value in statistics.items() if key != "test"}


def _verify_fit_receipt(output_dir: Path, dataset_hash: str) -> tuple[dict[str, Any], dict[str, Any]]:
    for name in ("model.joblib", "threshold.json"):
        if not (output_dir / name).is_file():
            raise FileNotFoundError(f"missing required model/threshold lock artifact: {output_dir / name}")
    receipt = _load_json(output_dir / "fit_manifest.json")
    if receipt.get("manifest_version") != "isolation_forest_fit_manifest.v1":
        raise ValueError("saved fit lock receipt has an unsupported version")
    if receipt.get("dataset_manifest_sha256") != dataset_hash:
        raise ValueError("saved fit dataset manifest SHA256 does not match the requested dataset")
    hashes, sizes = receipt.get("artifact_sha256"), receipt.get("artifact_sizes_bytes")
    if not isinstance(hashes, dict) or not isinstance(sizes, dict):
        raise ValueError("saved fit lock receipt is missing artifact hashes/sizes")  # noqa: TRY004 - invalid serialized data
    if set(hashes) != set(_FIT_ARTIFACT_NAMES) or set(sizes) != set(_FIT_ARTIFACT_NAMES):
        raise ValueError("saved fit lock receipt has an incomplete artifact set")
    if receipt.get("artifact_hash_scopes") != {
        "score_statistics.json": "validation-only JSON projection; omit test section",
    }:
        raise ValueError("saved fit lock receipt has invalid artifact hash scopes")
    statistics = _load_json(output_dir / "score_statistics.json")
    for name in _FIT_ARTIFACT_NAMES:
        path = output_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"missing required model/threshold lock artifact: {path}")
        if name == "score_statistics.json":
            payload = _json_payload(_fit_statistics_projection(statistics)).encode("utf-8")
            actual_hash, actual_size = hashlib.sha256(payload).hexdigest(), len(payload)
        else:
            actual_hash, actual_size = _sha256(path), path.stat().st_size
        if hashes[name] != actual_hash or sizes[name] != actual_size:
            raise ValueError(f"saved fit model/threshold lock artifact hash/size mismatch: {name}")
    if receipt.get("model_sha256") != hashes["model.joblib"]:
        raise ValueError("saved fit receipt model SHA256 does not match the fitted model")
    return receipt, _fit_statistics_projection(statistics)


def _validate_saved_counts(metadata: dict[str, Any]) -> None:
    counts, labels = metadata.get("split_counts"), metadata.get("label_counts")
    if (
        not isinstance(counts, dict)
        or set(counts) != {"train_normal", "validation", "validation_attack"}
        or any(type(value) is not int or value < 0 for value in counts.values())
        or counts["train_normal"] == 0 or counts["validation"] == 0
        or counts["validation_attack"] > counts["validation"]
        or metadata.get("fit_rows") != counts["train_normal"]
        or metadata.get("train_rows") != counts["train_normal"]
        or not isinstance(labels, dict) or set(labels) != {"train_normal", "validation"}
        or labels.get("train_normal") != {"BENIGN": counts["train_normal"]}
    ):
        raise ValueError("saved fitted model has missing or malformed split counts/composition")
    validation = labels.get("validation")
    if (
        not isinstance(validation, dict)
        or any(not isinstance(label, str) or not label or type(count) is not int or count <= 0 for label, count in validation.items())
        or sum(validation.values()) != counts["validation"]
        or sum(count for label, count in validation.items() if label != "BENIGN") != counts["validation_attack"]
    ):
        raise ValueError("saved fitted model has malformed validation class composition")
    conversion = metadata.get("numerical_conversion")
    if not isinstance(conversion, dict) or set(conversion) != {"train_normal", "validation"}:
        raise ValueError("saved fitted model is missing numeric conversion provenance")


def _load_fitted_run(
    output_dir: Path, dataset_hash: str,
) -> tuple[Any, dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Verify a local fit receipt and its lock before deserializing the model."""

    receipt, statistics = _verify_fit_receipt(output_dir, dataset_hash)
    metadata = _load_json(output_dir / "model_metadata.json")
    lock = _load_json(output_dir / "threshold.json")
    schema = _load_json(output_dir / "feature_schema.json")
    expected_versions = _versions()
    expected_parameters = IsolationForest(**DEFAULT_MODEL_PARAMETERS).get_params(deep=False)
    for name, artifact in (("model metadata", metadata), ("threshold lock", lock), ("feature schema", schema)):
        if artifact.get("dataset_manifest_sha256") != dataset_hash:
            raise ValueError(f"saved {name} dataset manifest SHA256 does not match the requested dataset")
        if artifact.get("features") != list(FEATURES) or artifact.get("preprocessing") != "none":
            raise ValueError(f"saved {name} feature order/preprocessing does not match the baseline")
    if metadata.get("schema_version") != "isolation_forest_model_metadata.v1":
        raise ValueError("saved model metadata has an unsupported version")
    _validate_saved_counts(metadata)
    if lock.get("schema_version") != "validation_threshold.v1" or schema.get("schema_version") != "model_feature_schema.v1":
        raise ValueError("saved threshold lock/feature schema has an unsupported version")
    if metadata.get("versions") != expected_versions:
        raise ValueError("saved model Python/numpy/sklearn versions do not match this runtime")
    if (
        metadata.get("python_version") != expected_versions["python"]
        or metadata.get("sklearn_version") != expected_versions["scikit_learn"]
        or metadata.get("seed") != 42
        or metadata.get("model_class") != "sklearn.ensemble.IsolationForest"
    ):
        raise ValueError("saved model version/seed/class provenance is inconsistent")
    for artifact in (metadata, schema):
        if artifact.get("loaded_dtype") != "float64" or artifact.get("model_input_dtype") != "float32":
            raise ValueError("saved model numeric input schema does not match the baseline")
    if (
        metadata.get("parameters") != DEFAULT_MODEL_PARAMETERS
        or metadata.get("resolved_parameters") != expected_parameters
    ):
        raise ValueError("saved model parameters do not match the baseline")
    if (
        metadata.get("score_definition") != _SCORE_DEFINITION
        or metadata.get("score_direction") != "higher_is_more_anomalous"
        or metadata.get("decision_rule") != "anomaly_score >= threshold"
    ):
        raise ValueError("saved model score semantics do not match the baseline")
    model_hash = receipt["model_sha256"]
    if metadata.get("model_sha256") != model_hash or lock.get("model_sha256") != model_hash:
        raise ValueError("saved threshold lock is not bound to this model SHA256")
    method = lock.get("threshold_method")
    if not isinstance(method, dict) or (
        method.get("method") != "validation_unique_scores_plus_no_alert"
        or method.get("selection_split") != "validation"
        or method.get("test_used_for_selection") is not False
        or method.get("max_false_positive_rate") != 0.01
        or method.get("score_definition") != _SCORE_DEFINITION
        or method.get("decision_rule") != "anomaly_score >= threshold"
        or method.get("tie_break") != ["recall", "f1", "lower_fpr", "higher_threshold"]
        or lock.get("selection_data_split") != "validation"
        or lock.get("test_used_for_selection") is not False
    ):
        raise ValueError("saved threshold lock has invalid validation-only provenance/policy")
    threshold = lock.get("threshold")
    selected = method.get("selected")
    if (
        not isinstance(threshold, (int, float)) or isinstance(threshold, bool)
        or not math.isfinite(threshold)
        or not isinstance(selected, dict) or selected.get("threshold") != threshold
        or statistics.get("threshold") != threshold
        or statistics.get("schema_version") != "score_statistics.v1"
        or statistics.get("score_definition") != _SCORE_DEFINITION
        or not isinstance(statistics.get("validation"), dict)
    ):
        raise ValueError("saved threshold lock has an invalid or inconsistent threshold")
    model_path = output_dir / "model.joblib"
    try:
        model = joblib.load(model_path)
    except Exception as error:  # noqa: BLE001 - concise local artifact failure
        raise ValueError(f"could not load trusted local model artifact {model_path}: {error}") from None
    if not isinstance(model, IsolationForest):
        raise ValueError("saved model is not a sklearn IsolationForest")  # noqa: TRY004 - invalid serialized data
    try:
        check_is_fitted(model, ["estimators_", "n_features_in_", "max_samples_"])
    except ValueError:
        raise ValueError("saved model is not fitted") from None
    if (
        model.get_params(deep=False) != expected_parameters
        or model.n_features_in_ != len(FEATURES)
        or len(model.estimators_) != DEFAULT_MODEL_PARAMETERS["n_estimators"]
        or model.max_samples_ != min(256, metadata["fit_rows"])
    ):
        raise ValueError("saved fitted model parameters/features do not match the baseline")
    return model, metadata, lock, statistics, receipt


def _peak_rss_bytes() -> int | None:
    try:
        import resource
    except ImportError:
        return None
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform == "darwin" else value * 1024)


def _fit_phase(
    dataset_dir: Path, output_dir: Path, manifest: dict[str, Any], dataset_hash: str,
) -> dict[str, Any]:
    timestamp, versions = _utc_now(), _versions()
    # Verify validation provenance before fitting too, without loading its
    # matrix beside training.  It is verified again when consumed below.
    for kind in ("features", "metadata"):
        _verify_input_artifact(dataset_dir, manifest, f"validation_{kind}.csv")
    train, train_labels, train_attack = _load_verified_split(dataset_dir, manifest, "train_normal")
    if not len(train) or not np.all((train_labels == "BENIGN") & ~train_attack):
        raise ValueError("train_normal must contain nonempty BENIGN rows only")
    train_input, train_conversion = _model_input_with_audit(train)
    train_count = len(train)
    model = IsolationForest(**DEFAULT_MODEL_PARAMETERS)
    started = time.perf_counter()
    model.fit(train_input)
    training_seconds = time.perf_counter() - started
    del train, train_input, train_labels, train_attack

    validation, labels, attacks = _load_verified_split(dataset_dir, manifest, "validation")
    if not len(validation):
        raise ValueError("cannot select a threshold from an empty validation split")
    validation_input, validation_conversion = _model_input_with_audit(validation)
    started = time.perf_counter()
    scores = _as_float_array(scores_from_sklearn(model, validation_input), name="validation scores")
    validation_scoring_seconds = time.perf_counter() - started
    if len(scores) != len(validation):
        raise ValueError("model produced an invalid validation score row count")
    threshold, method = _select_threshold_details(
        scores, attacks, 0.01, output_dir / "validation_threshold_candidates.csv",
    )
    metrics: dict[str, Any] = dict(confusion_metrics(scores, attacks, threshold))
    statistics = _split_statistics(scores, labels, attacks)
    metrics["score_distributions"] = statistics
    counts = {
        "train_normal": train_count, "validation": len(validation),
        "validation_attack": int(np.count_nonzero(attacks)),
    }
    label_counts = {
        "train_normal": {"BENIGN": train_count},
        "validation": dict(sorted(Counter(str(label) for label in labels).items())),
    }
    conversion = {"train_normal": train_conversion, "validation": validation_conversion}
    del validation, validation_input

    _write_joblib(output_dir / "model.joblib", model)
    model_hash = _sha256(output_dir / "model.joblib")
    metadata = {
        "schema_version": "isolation_forest_model_metadata.v1",
        "created_at_utc": timestamp, "dataset_manifest_sha256": dataset_hash,
        "model_sha256": model_hash, "features": list(FEATURES), "preprocessing": "none",
        "loaded_dtype": "float64", "model_input_dtype": "float32",
        "fit_rows": train_count, "train_rows": train_count,
        "split_counts": counts, "label_counts": label_counts, "seed": 42,
        "parameters": dict(DEFAULT_MODEL_PARAMETERS),
        "resolved_parameters": model.get_params(deep=False),
        "model_class": "sklearn.ensemble.IsolationForest",
        "model_implementation": "sklearn.ensemble.IsolationForest",
        "score_definition": _SCORE_DEFINITION, "score_direction": "higher_is_more_anomalous",
        "decision_rule": "anomaly_score >= threshold", "numerical_conversion": conversion,
        "versions": versions, "python_version": versions["python"],
        "sklearn_version": versions["scikit_learn"], "git_commit": _git_commit(),
    }
    _write_json(output_dir / "model_metadata.json", metadata)
    _write_json(output_dir / "feature_schema.json", {
        "schema_version": "model_feature_schema.v1", "features": list(FEATURES),
        "preprocessing": "none", "loaded_dtype": "float64", "model_input_dtype": "float32",
        "dataset_manifest_sha256": dataset_hash,
    })
    _write_json(output_dir / "validation_metrics.json", metrics)
    _write_json(output_dir / "score_statistics.json", {
        "schema_version": "score_statistics.v1", "threshold": threshold,
        "score_definition": _SCORE_DEFINITION, "validation": statistics,
    })
    _write_score_plot(
        output_dir / "validation_score_distribution.png", "Validation score distribution",
        scores, attacks, threshold,
    )
    _write_json(output_dir / "threshold.json", {
        "schema_version": "validation_threshold.v1", "created_at_utc": timestamp,
        "dataset_manifest_sha256": dataset_hash, "model_sha256": model_hash,
        "features": list(FEATURES), "preprocessing": "none", "threshold": threshold,
        "threshold_method": method, "selection_data_split": "validation",
        "test_used_for_selection": False,
    })
    hashes, sizes = _artifact_provenance(output_dir, _FIT_ARTIFACT_NAMES)
    _write_json(output_dir / "fit_manifest.json", {
        "manifest_version": "isolation_forest_fit_manifest.v1", "created_at_utc": timestamp,
        "dataset_manifest_sha256": dataset_hash, "model_sha256": model_hash,
        "artifact_sha256": hashes, "artifact_sizes_bytes": sizes,
        "artifact_hash_scopes": {"score_statistics.json": "validation-only JSON projection; omit test section"},
        # Observations vary per run; keep them out of numeric metrics/statistics.
        "runtime": {
            "training_seconds": training_seconds,
            "validation_scoring_seconds": validation_scoring_seconds,
            "peak_rss_bytes": _peak_rss_bytes(),
            "peak_rss_scope": "fit_process_lifetime",
        },
    })
    return {"threshold": threshold, "split_counts": counts}


def _evaluate_phase(
    dataset_dir: Path, output_dir: Path, manifest: dict[str, Any], dataset_hash: str,
) -> dict[str, Any]:
    # All fitted outputs and the threshold lock are verified before joblib and
    # before opening or hashing a held-out test artifact.  Validation input is
    # neither read nor rescored in this phase.
    model, metadata, lock, statistics, receipt = _load_fitted_run(output_dir, dataset_hash)
    threshold = float(lock["threshold"])
    test, labels, attacks = _load_verified_split(dataset_dir, manifest, "test")
    model_input, conversion = _model_input_with_audit(test)
    started = time.perf_counter()
    scores = (
        _as_float_array(scores_from_sklearn(model, model_input), name="test scores")
        if len(test) else np.empty(0, dtype=np.float64)
    )
    test_scoring_seconds = time.perf_counter() - started
    if len(scores) != len(test):
        raise ValueError("model produced an invalid test score row count")
    aggregate = confusion_metrics(scores, attacks, threshold)
    metrics: dict[str, Any] = dict(aggregate)
    metrics["feature_collision_summary"] = feature_collision_summary(test, labels)
    metrics["representation_limits"] = _representation_limits(test, labels)
    detection = _per_label_metrics(labels, attacks, scores, threshold)
    metrics["per_label_attack_detection"] = detection
    metrics["per_attack_family_recall"] = detection
    metrics["per_label_binary_metrics"] = _per_label_binary_metrics(labels, scores, threshold)
    metrics["per_label_binary_metrics_definition"] = (
        "BENIGN uses benign-only rows; each attack family uses that family as positive "
        "and BENIGN as negative, excluding all other attack families."
    )
    metrics["numerical_conversion"] = conversion
    test_statistics = _split_statistics(scores, labels, attacks)
    metrics["score_distributions"] = test_statistics
    statistics["test"] = test_statistics
    counts = dict(metadata["split_counts"])
    counts.update({"test": len(test), "test_attack": int(np.count_nonzero(attacks))})
    label_counts = dict(metadata["label_counts"])
    label_counts["test"] = dict(sorted(Counter(str(label) for label in labels).items()))
    del test, model_input

    _write_json(output_dir / "test_metrics.json", metrics)
    _write_json(output_dir / "score_statistics.json", statistics)
    _write_test_plots(output_dir, scores, attacks, labels, threshold)
    names = tuple(name for name in _ARTIFACT_NAMES if name != "evaluation_manifest.json")
    hashes, sizes = _artifact_provenance(output_dir, names)
    timings = receipt.get("runtime", {})
    runtime = {
        "training_seconds": timings.get("training_seconds"),
        "validation_scoring_seconds": timings.get("validation_scoring_seconds"),
        "test_scoring_seconds": test_scoring_seconds,
        "fit_timing_source": "fit_manifest.json",
        "fit_peak_rss_bytes": timings.get("peak_rss_bytes"),
        "peak_rss_bytes": _peak_rss_bytes(), "peak_rss_scope": "evaluation_process_lifetime",
        "model_size_bytes": sizes["model.joblib"],
    }
    _write_json(output_dir / "evaluation_manifest.json", {
        "manifest_version": "evaluation_manifest.v1", "created_at_utc": _utc_now(),
        "dataset_manifest_sha256": dataset_hash, "dataset_manifest": manifest,
        "model_sha256": receipt["model_sha256"], "features": list(FEATURES),
        "model_implementation": "sklearn.ensemble.IsolationForest",
        "preprocessing": "none", "seed": 42, "parameters": dict(DEFAULT_MODEL_PARAMETERS),
        "resolved_parameters": metadata["resolved_parameters"], "threshold_method": lock["threshold_method"],
        "split_counts": counts, "label_counts": label_counts,
        "score_definition": _SCORE_DEFINITION,
        "numerical_conversion": {**metadata["numerical_conversion"], "test": conversion},
        "representation_limits": metrics["representation_limits"],
        "metric_conventions": {"zero_denominator": 0.0, "roc_auc_without_both_classes": 0.0, "pr_auc": "average_precision"},
        "versions": metadata["versions"], "python_version": metadata["python_version"],
        "sklearn_version": metadata["sklearn_version"], "git_commit": _git_commit(),
        "runtime": runtime, "artifact_sha256": hashes, "artifact_sizes_bytes": sizes,
    })
    return {"threshold": threshold, "split_counts": counts, "test_metrics": aggregate}


def run_experiment(
    dataset_dir: str | Path, output_dir: str | Path,
    fit: bool, evaluate: bool, force: bool = False,
) -> dict[str, Any]:
    """Fit locks validation; evaluation reuses that lock and scores test once."""

    if not fit and not evaluate:
        raise ValueError("at least one of fit or evaluate must be true")
    dataset_root, destination = Path(dataset_dir).resolve(), Path(output_dir).resolve()
    if not dataset_root.is_dir():
        raise FileNotFoundError(f"dataset directory does not exist: {dataset_root}")
    if destination == dataset_root or dataset_root in destination.parents:
        raise ValueError("output directory must be outside the dataset directory")
    manifest, dataset_hash = _validate_dataset_manifest(dataset_root)
    _prepare_output(destination, fit=fit, evaluate=evaluate, force=force)
    summary: dict[str, Any] = {
        "output_dir": str(destination), "fit": bool(fit), "evaluate": bool(evaluate),
        "dataset_manifest_sha256": dataset_hash,
    }
    if fit:
        summary.update(_fit_phase(dataset_root, destination, manifest, dataset_hash))
    if evaluate:
        summary.update(_evaluate_phase(dataset_root, destination, manifest, dataset_hash))
    summary["artifacts"] = sorted(name for name in _ARTIFACT_NAMES if (destination / name).is_file())
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fit/evaluate the Intriqo Isolation Forest baseline")
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fit", action="store_true", help="fit BENIGN training rows and persist a validation threshold lock")
    parser.add_argument("--evaluate", action="store_true", help="reuse the saved validation lock and evaluate test once")
    parser.add_argument("--force", action="store_true", help="replace generated output artifacts")
    args = parser.parse_args(argv)
    try:
        result = run_experiment(args.dataset_dir, args.output_dir, args.fit, args.evaluate, args.force)
    except (FileNotFoundError, ValueError, OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
