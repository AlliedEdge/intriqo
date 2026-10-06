"""Controlled-corpus Isolation Forest v2 experiment.

This module is intentionally separate from the frozen v1 baseline.  It consumes
only the enrolled controlled native-v2 corpus, fits on the six BENIGN training
flows, selects one validation-only threshold, writes an immutable lock receipt,
and evaluates the held-out test split only after that lock exists.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import resource
import sys
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
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
    roc_auc_score,
)
from sklearn.utils.validation import check_is_fitted  # type: ignore[import-untyped]

from intriqo_ml.flow_features_v2 import FEATURES_V2
from intriqo_ml.models.isolation_forest import confusion_metrics, scores_from_sklearn

FloatArray = NDArray[np.float64]
BoolArray = NDArray[np.bool_]
Parameters = dict[str, Any]

FEATURES: Final[tuple[str, ...]] = tuple(FEATURES_V2)
MODEL_PARAMETERS: Final[Parameters] = {
    "n_estimators": 300,
    "max_samples": "auto",
    "contamination": "auto",
    "random_state": 42,
    "n_jobs": -1,
    "bootstrap": False,
    "max_features": 1.0,
    "warm_start": False,
}
SCORE_DEFINITION: Final[str] = "-model.score_samples(features)"
DECISION_RULE: Final[str] = "anomaly_score >= threshold"
EXPECTED_SPLITS: Final[tuple[str, ...]] = ("train_normal", "validation", "test")
SOURCE_MANIFEST_NAMES: Final[tuple[str, ...]] = (
    "completed_experiment_manifest.json",
    "completed_capture_manifest.json",
    "completed_split_definition.json",
    "corpus_status.json",
    "capture_provenance_summary.json",
    "lab_isolation_receipt.json",
    "host_boundary_receipt.json",
    "split_negative_checks.json",
    "capture_failures.json",
)
RUN_SOURCE_NAMES: Final[tuple[str, ...]] = (
    "dataset_manifest.json",
    "features.csv",
    "metadata.csv",
    "native_features_v2.jsonl",
    "alignment_report.jsonl",
    "alignment_report.json",
    "quality_report.json",
    "provenance_report.json",
    "artifact_hashes.json",
)
FIT_ARTIFACT_NAMES: Final[tuple[str, ...]] = (
    "model.joblib",
    "model_metadata.json",
    "feature_schema.json",
    "validation_threshold_candidates.csv",
    "validation_metrics.json",
    "validation_operating_points.json",
    "validation_score_distribution.png",
    "fit_score_statistics.json",
    "training_manifest.json",
    "validation_manifest.json",
    "fit_manifest.json",
    "threshold.json",
    "experiment_lock.json",
)
TEST_ARTIFACT_NAMES: Final[tuple[str, ...]] = (
    "test_metrics.json",
    "test_predictions.jsonl",
    "test_score_distribution.png",
    "test_scenario_metrics.json",
    "test_attack_family_metrics.json",
    "evaluation_manifest.json",
    "artifact_manifest.json",
)


@dataclass(frozen=True)
class CorpusRow:
    """One eligible native flow plus controller-owned ground truth."""

    features: tuple[float, ...]
    capture_id: str
    native_line_number: int
    engine_instance_id: str
    flow_id: str
    split: str
    label: str
    attack_family: str | None
    source_label_id: str
    scenario_id: str


@dataclass(frozen=True)
class ControlledCorpus:
    """Verified source rows and immutable provenance for one corpus."""

    rows: tuple[CorpusRow, ...]
    source_hashes: dict[str, str]
    source_sizes: dict[str, int]
    source_manifest_hashes: dict[str, str]
    split_definition_hash: str
    dataset_manifest_hash: str
    corpus_status: str

    def split(self, name: str) -> tuple[CorpusRow, ...]:
        if name not in EXPECTED_SPLITS:
            raise ValueError(f"unsupported split {name!r}")
        return tuple(row for row in self.rows if row.split == name)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_payload(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def _json_hash(value: Any) -> str:
    return hashlib.sha256(_json_payload(value).encode("utf-8")).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FileNotFoundError(f"missing required corpus artifact: {path}") from None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON artifact {path}: {error}") from None
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")  # noqa: TRY004 - invalid serialized data
    return cast(dict[str, Any], value)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(_json_payload(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _load_source_hashes(run_dir: Path, enrolled_dir: Path) -> tuple[dict[str, str], dict[str, int], dict[str, str]]:
    paths: dict[str, Path] = {}
    for name in SOURCE_MANIFEST_NAMES:
        paths[f"enrolled/{name}"] = enrolled_dir / name
    for name in RUN_SOURCE_NAMES:
        paths[f"run/{name}"] = run_dir / name
    hashes: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for key, path in paths.items():
        if not path.is_file():
            raise FileNotFoundError(f"missing required source artifact: {path}")
        hashes[key] = _sha256(path)
        sizes[key] = path.stat().st_size
    source_manifests = {
        key.removeprefix("enrolled/"): value
        for key, value in hashes.items()
        if key.startswith("enrolled/")
    }
    return hashes, sizes, source_manifests


def _verify_manifest_artifact_hashes(run_dir: Path, dataset_manifest: dict[str, Any]) -> None:
    hashes = dataset_manifest.get("artifact_sha256")
    if not isinstance(hashes, dict):
        raise ValueError("dataset manifest is missing artifact_sha256")  # noqa: TRY004 - invalid serialized data
    for name, expected in hashes.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            raise ValueError("dataset manifest has malformed artifact hash")  # noqa: TRY004 - invalid serialized data
        path = run_dir / name
        if not path.is_file() or _sha256(path) != expected:
            raise ValueError(f"controlled-v2 source artifact hash mismatch: {name}")


def _verify_replay_quality(quality: dict[str, Any]) -> None:
    expected_counts = {
        "capture_count": 12,
        "total_flows": 26,
        "benign_flows": 8,
        "attack_flows": 18,
    }
    counts = quality.get("counts")
    if counts != expected_counts:
        raise ValueError(f"controlled-v2 corpus counts mismatch: expected {expected_counts}, got {counts}")
    alignment = quality.get("alignment")
    if alignment != {"EXACT": 26, "PARTIAL": 0, "AMBIGUOUS": 0, "UNKNOWN": 0, "eligible_exact_rows": 26}:
        raise ValueError(f"controlled-v2 alignment quality gate failed: {alignment}")
    if quality.get("ready_for_model_training") is not True or quality.get("blockers") != []:
        raise ValueError("controlled-v2 quality report is not ready for model training")
    split_counts = quality.get("per_split")
    expected_splits = {
        "train_normal": {"total_flows": 6, "exact_flows": 6, "eligible_flows": 6},
        "validation": {"total_flows": 10, "exact_flows": 10, "eligible_flows": 10},
        "test": {"total_flows": 10, "exact_flows": 10, "eligible_flows": 10},
    }
    if split_counts != expected_splits:
        raise ValueError(f"controlled-v2 split quality gate failed: {split_counts}")
    replay = quality.get("replay")
    if not isinstance(replay, list) or len(replay) != 12:
        raise ValueError("controlled-v2 replay quality is missing captures")
    packet_total = 0
    for report in replay:
        if not isinstance(report, dict) or report.get("status") != "complete":
            raise ValueError("controlled-v2 replay is not complete")
        counters = report.get("counters")
        if not isinstance(counters, dict):
            raise ValueError("controlled-v2 replay counters are missing")  # noqa: TRY004 - invalid serialized data
        packet_total += int(counters.get("packets_parsed", -1))
        for key in (
            "packets_rejected",
            "packets_dropped",
            "packets_unsupported",
            "packets_truncated",
            "feature_records_dropped",
        ):
            if counters.get(key) != 0:
                raise ValueError(f"controlled-v2 replay counter {key} is nonzero")
    if packet_total != 525:
        raise ValueError(f"controlled-v2 packet replay count mismatch: expected 525, got {packet_total}")


def _parse_csv_rows(run_dir: Path, scenario_by_label: dict[str, dict[str, Any]]) -> tuple[CorpusRow, ...]:
    feature_path, metadata_path = run_dir / "features.csv", run_dir / "metadata.csv"
    with feature_path.open("r", encoding="utf-8-sig", newline="") as feature_stream, metadata_path.open(
        "r", encoding="utf-8-sig", newline=""
    ) as metadata_stream:
        feature_reader, metadata_reader = csv.reader(feature_stream, strict=True), csv.DictReader(metadata_stream)
        feature_header = next(feature_reader, None)
        if feature_header != list(FEATURES):
            raise ValueError(f"controlled-v2 feature order mismatch: expected {list(FEATURES)}, got {feature_header}")
        if metadata_reader.fieldnames is None:
            raise ValueError("controlled-v2 metadata has no header")
        if set(metadata_reader.fieldnames) != {
            "capture_id", "native_line_number", "engine_instance_id", "flow_id", "first_seen",
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "split",
            "label_status", "label", "attack_family", "source_label_id",
        }:
            raise ValueError("controlled-v2 metadata header is not the enrolled schema")
        rows: list[CorpusRow] = []
        for row_number, (feature_row, metadata) in enumerate(zip(feature_reader, metadata_reader, strict=True), start=2):
            if len(feature_row) != len(FEATURES):
                raise ValueError(f"controlled-v2 feature column count mismatch at row {row_number}")
            try:
                values = tuple(float(value) for value in feature_row)
            except ValueError as error:
                raise ValueError(f"controlled-v2 feature value is not numeric at row {row_number}") from error
            if not all(math.isfinite(value) and value >= 0.0 for value in values):
                raise ValueError(f"controlled-v2 feature row {row_number} is non-finite or negative")
            if metadata.get("label_status") != "EXACT":
                raise ValueError("controlled-v2 model input contains a non-EXACT row")
            label = metadata.get("label")
            if label not in {"BENIGN", "ATTACK"}:
                raise ValueError(f"controlled-v2 label is invalid at row {row_number}")
            attack_family = metadata.get("attack_family") or None
            if (label == "BENIGN" and attack_family is not None) or (label == "ATTACK" and attack_family is None):
                raise ValueError(f"controlled-v2 label/family mismatch at row {row_number}")
            source_label_id = metadata.get("source_label_id")
            if not source_label_id or source_label_id not in scenario_by_label:
                raise ValueError(f"controlled-v2 source label is not enrolled at row {row_number}")
            scenario = scenario_by_label[source_label_id]
            if metadata.get("split") != scenario.get("split") or label != scenario.get("label"):
                raise ValueError(f"controlled-v2 metadata disagrees with controller label at row {row_number}")
            try:
                native_line = int(metadata["native_line_number"])
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"controlled-v2 native line is invalid at row {row_number}") from error
            rows.append(
                CorpusRow(
                    features=values,
                    capture_id=str(metadata["capture_id"]),
                    native_line_number=native_line,
                    engine_instance_id=str(metadata["engine_instance_id"]),
                    flow_id=str(metadata["flow_id"]),
                    split=str(metadata["split"]),
                    label=label,
                    attack_family=attack_family,
                    source_label_id=source_label_id,
                    scenario_id=str(scenario["scenario_id"]),
                )
            )
        if next(feature_reader, None) is not None or next(metadata_reader, None) is not None:
            raise ValueError("controlled-v2 features and metadata have different row counts")
    if len(rows) != 26:
        raise ValueError(f"controlled-v2 enrolled row count mismatch: expected 26, got {len(rows)}")
    return tuple(rows)


def verify_corpus(
    run_dir: str | Path,
    enrolled_dir: str | Path | None = None,
) -> ControlledCorpus:
    """Verify the completed controlled corpus before any model operation.

    This is a hard gate.  It intentionally raises rather than repairing or
    regenerating any enrolled artifact.
    """

    run_root = Path(run_dir).resolve()
    if not run_root.is_dir():
        raise FileNotFoundError(f"controlled-v2 run directory does not exist: {run_root}")
    enrolled_root = Path(enrolled_dir).resolve() if enrolled_dir is not None else run_root.parent
    status = _read_json(enrolled_root / "corpus_status.json")
    if status.get("status") != "READY_FOR_V2_MODEL_TRAINING":
        raise ValueError(f"controlled-v2 corpus status is not ready: {status.get('status')}")
    if status.get("training_performed") is not False or status.get("model_artifact") is not None:
        raise ValueError("controlled-v2 corpus status indicates a prior model operation")

    experiment = _read_json(enrolled_root / "completed_experiment_manifest.json")
    if experiment.get("features") != list(FEATURES) or experiment.get("training_performed") is not False:
        raise ValueError("completed controlled-v2 experiment manifest is not frozen v2 provenance")
    scenarios = experiment.get("experiments")
    if not isinstance(scenarios, list) or len(scenarios) != 26:
        raise ValueError("completed controlled-v2 experiment manifest must contain 26 scenarios")
    label_counts = Counter(str(row.get("label")) for row in scenarios if isinstance(row, dict))
    if label_counts != Counter({"BENIGN": 8, "ATTACK": 18}):
        raise ValueError(f"completed controlled-v2 label counts mismatch: {label_counts}")
    scenario_by_label: dict[str, dict[str, Any]] = {}
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ValueError("completed controlled-v2 experiment manifest contains a malformed scenario")  # noqa: TRY004 - invalid serialized data
        source_label = scenario.get("source_label_id")
        if not isinstance(source_label, str) or source_label in scenario_by_label:
            raise ValueError("completed controlled-v2 source labels must be unique")
        scenario_by_label[source_label] = scenario

    capture_manifest = _read_json(enrolled_root / "completed_capture_manifest.json")
    captures = capture_manifest.get("captures")
    if not isinstance(captures, list) or len(captures) != 12 or any(
        not isinstance(row, dict) or row.get("status") != "CAPTURED" for row in captures
    ):
        raise ValueError("completed controlled-v2 capture manifest must contain 12 CAPTURED captures")
    capture_ids = {str(row.get("capture_id")) for row in captures}
    if len(capture_ids) != 12:
        raise ValueError("completed controlled-v2 capture IDs must be unique")

    split_definition = _read_json(enrolled_root / "completed_split_definition.json")
    if split_definition.get("random_row_split") is not False:
        raise ValueError("controlled-v2 split definition permits random row splitting")
    assignments = split_definition.get("assignments")
    if not isinstance(assignments, list) or len(assignments) != 12:
        raise ValueError("controlled-v2 split definition must assign all 12 captures")
    split_by_capture = {str(row.get("capture_id")): str(row.get("split")) for row in assignments if isinstance(row, dict)}
    if set(split_by_capture) != capture_ids:
        raise ValueError("controlled-v2 split definition does not match capture manifest")

    dataset_manifest = _read_json(run_root / "dataset_manifest.json")
    if (
        dataset_manifest.get("features") != list(FEATURES)
        or dataset_manifest.get("ready_for_model_training") is not True
        or dataset_manifest.get("training_performed") is not False
        or dataset_manifest.get("scores_generated") is not False
    ):
        raise ValueError("controlled-v2 dataset manifest is not an untouched ready corpus")
    _verify_manifest_artifact_hashes(run_root, dataset_manifest)
    quality = _read_json(run_root / "quality_report.json")
    _verify_replay_quality(quality)
    negative_checks = _read_json(enrolled_root / "split_negative_checks.json")
    if negative_checks.get("status") != "PASS":
        raise ValueError("controlled-v2 negative split leakage checks did not pass")

    rows = _parse_csv_rows(run_root, scenario_by_label)
    row_counts = Counter(row.split for row in rows)
    if row_counts != Counter({"train_normal": 6, "validation": 10, "test": 10}):
        raise ValueError(f"controlled-v2 split row counts mismatch: {row_counts}")
    if Counter(row.label for row in rows if row.split == "train_normal") != Counter({"BENIGN": 6}):
        raise ValueError("controlled-v2 training split must contain exactly six BENIGN flows")
    if {row.capture_id for row in rows} != capture_ids:
        raise ValueError("controlled-v2 feature rows do not cover the enrolled captures")
    for row in rows:
        if split_by_capture.get(row.capture_id) != row.split:
            raise ValueError(f"controlled-v2 row split disagrees with capture assignment: {row.capture_id}")

    alignment_path = run_root / "alignment_report.jsonl"
    alignment_rows = [
        json.loads(line)
        for line in alignment_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if len(alignment_rows) != 26 or any(row.get("match_status") != "EXACT" for row in alignment_rows):
        raise ValueError("controlled-v2 alignment report is not 26/26 EXACT")
    if any(not math.isfinite(value) for row in rows for value in row.features):
        raise ValueError("controlled-v2 feature matrix contains a non-finite value")

    source_hashes, source_sizes, source_manifest_hashes = _load_source_hashes(run_root, enrolled_root)
    return ControlledCorpus(
        rows=rows,
        source_hashes=source_hashes,
        source_sizes=source_sizes,
        source_manifest_hashes=source_manifest_hashes,
        split_definition_hash=source_hashes["enrolled/completed_split_definition.json"],
        dataset_manifest_hash=source_hashes["run/dataset_manifest.json"],
        corpus_status=str(status["status"]),
    )


def _array(rows: Sequence[CorpusRow]) -> tuple[FloatArray, BoolArray]:
    features = np.asarray([row.features for row in rows], dtype=np.float64)
    if features.ndim != 2 or features.shape[1] != len(FEATURES) or not np.all(np.isfinite(features)):
        raise ValueError("model input must be a finite two-dimensional nine-feature matrix")
    attacks = np.asarray([row.label == "ATTACK" for row in rows], dtype=bool)
    return features, attacks


def _model_input(features: FloatArray) -> NDArray[np.float32]:
    converted = features.astype(np.float32, copy=False)
    if not np.all(np.isfinite(converted)):
        raise ValueError("finite v2 feature values exceed the float32 model-input range")
    return converted


def _versions() -> dict[str, str]:
    import matplotlib
    import sklearn  # type: ignore[import-untyped]

    return {
        "python": platform.python_version(),
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
        "joblib": joblib.__version__,
        "matplotlib": matplotlib.__version__,
    }


def _peak_rss_bytes() -> int | None:
    try:
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (AttributeError, OSError):
        return None
    return int(value if sys.platform == "darwin" else value * 1024)


def _distribution(scores: FloatArray) -> dict[str, int | float | None]:
    if len(scores) == 0:
        return {
            "count": 0, "min": None, "max": None, "mean": None, "stddev_population": None,
            "p01": None, "p05": None, "p25": None, "median": None, "p75": None,
            "p95": None, "p99": None,
        }
    percentiles = np.percentile(scores, [1, 5, 25, 50, 75, 95, 99])
    return {
        "count": len(scores),
        "min": float(np.min(scores)),
        "max": float(np.max(scores)),
        "mean": float(np.mean(scores)),
        "stddev_population": float(np.std(scores)),
        "p01": float(percentiles[0]),
        "p05": float(percentiles[1]),
        "p25": float(percentiles[2]),
        "median": float(percentiles[3]),
        "p75": float(percentiles[4]),
        "p95": float(percentiles[5]),
        "p99": float(percentiles[6]),
    }


def _score_distributions(rows: Sequence[CorpusRow], scores: FloatArray) -> dict[str, Any]:
    labels = np.asarray([row.label for row in rows], dtype=str)
    attacks = labels == "ATTACK"
    return {
        "all": _distribution(scores),
        "benign": _distribution(scores[~attacks]),
        "attack": _distribution(scores[attacks]),
        "per_label": {label: _distribution(scores[labels == label]) for label in sorted(set(labels.tolist()))},
    }


def _metric_aucs(scores: FloatArray, attacks: BoolArray) -> dict[str, float]:
    return {
        "pr_auc": float(average_precision_score(attacks.astype(int), scores)) if np.any(attacks) else 0.0,
        "roc_auc": float(roc_auc_score(attacks.astype(int), scores))
        if np.any(attacks) and np.any(~attacks)
        else 0.0,
    }


def _candidate_thresholds(scores: FloatArray) -> FloatArray:
    if len(scores) == 0:
        raise ValueError("cannot select a threshold from an empty validation split")
    unique = np.unique(scores)
    return np.append(unique, np.nextafter(float(unique[-1]), np.inf))


def validation_threshold_candidates(scores: Any, attacks: Any) -> list[dict[str, Any]]:
    """Return complete unique-score operating points for validation."""

    score_values = np.asarray(scores, dtype=np.float64)
    attack_values = np.asarray(attacks, dtype=bool)
    if score_values.ndim != 1 or attack_values.ndim != 1 or len(score_values) != len(attack_values):
        raise ValueError("validation scores and labels must be aligned one-dimensional arrays")
    if not len(score_values) or not np.all(np.isfinite(score_values)):
        raise ValueError("validation scores must be non-empty and finite")
    candidates: list[dict[str, Any]] = []
    for threshold in _candidate_thresholds(score_values):
        metrics = confusion_metrics(score_values, attack_values, float(threshold))
        candidates.append(
            {
                "threshold": float(threshold),
                "TP": int(metrics["TP"]),
                "TN": int(metrics["TN"]),
                "FP": int(metrics["FP"]),
                "FN": int(metrics["FN"]),
                "precision": float(metrics["precision"]),
                "recall": float(metrics["recall"]),
                "TPR": float(metrics["TPR"]),
                "FPR": float(metrics["FPR"]),
                "specificity": float(metrics["specificity"]),
                "F1": float(metrics["F1"]),
                "balanced_accuracy": float(metrics["balanced_accuracy"]),
            }
        )
    return candidates


def select_validation_threshold(candidates: Sequence[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    """Apply the fixed zero-FP validation rule without consulting test data."""

    if not candidates:
        raise ValueError("cannot select a threshold from empty validation candidates")
    zero_fp = [row for row in candidates if row["FP"] == 0]
    zero_fp_with_detection = [row for row in zero_fp if row["TP"] > 0]
    if zero_fp_with_detection:
        selected = max(zero_fp_with_detection, key=lambda row: (row["recall"], row["threshold"]))
        method = "zero_false_positives_maximize_recall_then_highest_threshold"
    else:
        selected = max(
            candidates,
            key=lambda row: (row["F1"], -row["FPR"], row["threshold"]),
        )
        method = "fallback_maximize_f1_then_lower_fpr_then_highest_threshold"
    details = {
        "selection_method": method,
        "score_definition": SCORE_DEFINITION,
        "decision_rule": DECISION_RULE,
        "selection_split": "validation",
        "test_used_for_selection": False,
        "zero_false_positive_candidates": len(zero_fp),
        "zero_false_positive_candidates_with_detection": len(zero_fp_with_detection),
        "selected": dict(selected),
        "tie_break": ["recall", "highest_threshold"],
        "fallback_tie_break": ["F1", "lower_FPR", "highest_threshold"],
    }
    return float(selected["threshold"]), details


def _write_candidates(path: Path, candidates: Sequence[dict[str, Any]]) -> None:
    fields = (
        "threshold", "TP", "TN", "FP", "FN", "precision", "recall", "TPR", "FPR",
        "specificity", "F1", "balanced_accuracy",
    )
    output = [",".join(fields)]
    for row in candidates:
        output.append(",".join(str(row[field]) for field in fields))
    _write_text(path, "\n".join(output) + "\n")


def _atomic_plot(path: Path, draw: Any) -> None:
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


def _write_score_distribution(path: Path, title: str, rows: Sequence[CorpusRow], scores: FloatArray, threshold: float) -> None:
    def draw(figure: Any, plt: Any) -> None:
        axis = figure.add_subplot(1, 1, 1)
        attacks = np.asarray([row.label == "ATTACK" for row in rows], dtype=bool)
        bins = np.histogram_bin_edges(scores, bins=min(30, max(1, len(scores))))
        if np.any(~attacks):
            axis.hist(scores[~attacks], bins=bins, alpha=0.65, label="BENIGN")
        if np.any(attacks):
            axis.hist(scores[attacks], bins=bins, alpha=0.65, label="ATTACK")
        axis.axvline(threshold, color="black", linestyle="--", label="locked threshold")
        axis.set(title=title, xlabel="anomaly score", ylabel="flows")
        axis.legend()

    _atomic_plot(path, draw)


def _write_joblib(path: Path, model: Any) -> None:
    temporary: Path | None = None
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=f".{path.name}.", delete=False) as stream:
        temporary = Path(stream.name)
    try:
        joblib.dump(model, temporary)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _artifact_hashes(output_dir: Path, names: Iterable[str]) -> dict[str, dict[str, int | str]]:
    result: dict[str, dict[str, int | str]] = {}
    for name in sorted(set(names)):
        path = output_dir / name
        if not path.is_file():
            raise FileNotFoundError(f"missing experiment artifact: {path}")
        result[name] = {"sha256": _sha256(path), "size_bytes": path.stat().st_size}
    return result


def _manifest_rows(rows: Sequence[CorpusRow], source_hashes: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": "controlled_v2_model_row_manifest.v1",
        "features": list(FEATURES),
        "rows": [
            {
                "capture_id": row.capture_id,
                "native_line_number": row.native_line_number,
                "engine_instance_id": row.engine_instance_id,
                "flow_id": row.flow_id,
                "split": row.split,
                "label": row.label,
                "attack_family": row.attack_family,
                "source_label_id": row.source_label_id,
                "scenario_id": row.scenario_id,
                "feature_vector": list(row.features),
            }
            for row in rows
        ],
        "source_corpus_artifact_hashes": dict(sorted(source_hashes.items())),
    }


def _model_metadata(
    *,
    corpus: ControlledCorpus,
    model_hash: str,
    model_size: int,
    training_seconds: float,
    validation_scoring_seconds: float,
    train_rows: Sequence[CorpusRow],
    validation_rows: Sequence[CorpusRow],
) -> dict[str, Any]:
    versions = _versions()
    return {
        "schema_version": "controlled_v2_isolation_forest_model_metadata.v1",
        "created_at_utc": _utc_now(),
        "source_corpus_status": corpus.corpus_status,
        "source_manifest_hashes": dict(sorted(corpus.source_manifest_hashes.items())),
        "source_corpus_artifact_hashes": dict(sorted(corpus.source_hashes.items())),
        "split_definition_sha256": corpus.split_definition_hash,
        "dataset_manifest_sha256": corpus.dataset_manifest_hash,
        "features": list(FEATURES),
        "feature_schema": "contracts/features/flow_features_v2.json",
        "feature_order": list(FEATURES),
        "preprocessing": "NONE",
        "loaded_dtype": "float64",
        "model_input_dtype": "float32",
        "fit_rows": len(train_rows),
        "fit_flow_count": len(train_rows),
        "train_benign_count": sum(row.label == "BENIGN" for row in train_rows),
        "train_attack_count": sum(row.label == "ATTACK" for row in train_rows),
        "validation_rows": len(validation_rows),
        "validation_flow_count": len(validation_rows),
        "seed": 42,
        "random_seed": 42,
        "parameters": dict(MODEL_PARAMETERS),
        "resolved_parameters": IsolationForest(**MODEL_PARAMETERS).get_params(deep=False),
        "model_class": "sklearn.ensemble.IsolationForest",
        "score_definition": SCORE_DEFINITION,
        "score_direction": "higher_is_more_anomalous",
        "decision_rule": DECISION_RULE,
        "model_sha256": model_hash,
        "model_size_bytes": model_size,
        "training_seconds": training_seconds,
        "validation_scoring_seconds": validation_scoring_seconds,
        "peak_rss_bytes": _peak_rss_bytes(),
        "platform": platform.platform(),
        "versions": versions,
        "python_version": versions["python"],
        "sklearn_version": versions["scikit_learn"],
    }


def _authoritative_feature_schema() -> tuple[dict[str, Any], str]:
    contract_path = Path(__file__).resolve().parents[4] / "contracts" / "features" / "flow_features_v2.json"
    contract = _read_json(contract_path)
    definitions = contract.get("definitions")
    if not isinstance(definitions, dict) or not isinstance(definitions.get("FlowFeaturesV2"), dict):
        raise ValueError("authoritative v2 feature contract is missing FlowFeaturesV2")  # noqa: TRY004 - invalid serialized data
    feature_definition = definitions["FlowFeaturesV2"]
    properties = feature_definition.get("properties")
    required = feature_definition.get("required")
    if not isinstance(properties, dict) or tuple(properties) != FEATURES or required != list(FEATURES):
        raise ValueError("authoritative v2 feature contract does not preserve the frozen nine-feature order")
    contract_hash = _sha256(contract_path)
    schema = {
        "schema_version": "controlled_v2_model_feature_schema.v1",
        "contract_path": "contracts/features/flow_features_v2.json",
        "contract_sha256": contract_hash,
        "feature_schema": "flow_features.v2",
        "features": list(FEATURES),
        "feature_count": len(FEATURES),
        "preprocessing": "NONE",
        "loaded_dtype": "float64",
        "model_input_dtype": "float32",
    }
    return schema, contract_hash


def _per_flow_scores(rows: Sequence[CorpusRow], scores: FloatArray, threshold: float) -> list[dict[str, Any]]:
    if len(rows) != len(scores):
        raise ValueError("row and score counts differ")
    return [
        {
            "capture_id": row.capture_id,
            "scenario_id": row.scenario_id,
            "source_label_id": row.source_label_id,
            "native_line_number": row.native_line_number,
            "split": row.split,
            "ground_truth": row.label,
            "attack_family": row.attack_family,
            "model_score": float(score),
            "threshold": float(threshold),
            "predicted_label": "ATTACK" if score >= threshold else "BENIGN",
            "prediction": "ANOMALY" if score >= threshold else "NORMAL",
            "correct": bool((score >= threshold) == (row.label == "ATTACK")),
        }
        for row, score in zip(rows, scores, strict=True)
    ]


def aggregate_per_scenario(predictions: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate controller-owned scenario labels without deriving ground truth."""

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        scenario_id = row.get("scenario_id")
        if not isinstance(scenario_id, str) or not scenario_id:
            raise ValueError("prediction is missing scenario_id")
        groups[scenario_id].append(row)
    results: list[dict[str, Any]] = []
    for scenario_id in sorted(groups):
        rows = groups[scenario_id]
        labels = {row.get("ground_truth") for row in rows}
        if labels - {"BENIGN", "ATTACK"} or len(labels) != 1:
            raise ValueError(f"scenario {scenario_id} has inconsistent ground truth")
        truth = next(iter(labels))
        detected = sum(row.get("predicted_label") == "ATTACK" for row in rows)
        total = len(rows)
        results.append(
            {
                "scenario_id": scenario_id,
                "capture_id": rows[0].get("capture_id"),
                "split": rows[0].get("split"),
                "ground_truth": truth,
                "attack_family": rows[0].get("attack_family"),
                "total": total,
                "detected_as_anomaly": detected,
                "missed": total - detected if truth == "ATTACK" else 0,
                "false_positives": detected if truth == "BENIGN" else 0,
                "recall": detected / total if truth == "ATTACK" else None,
                "false_positive_rate": detected / total if truth == "BENIGN" else None,
                "small_sample_note": "single-flow scenario; descriptive only" if total < 2 else None,
            }
        )
    benign = [row for row in results if row["ground_truth"] == "BENIGN"]
    attacks = [row for row in results if row["ground_truth"] == "ATTACK"]
    return {
        "schema_version": "controlled_v2_scenario_metrics.v1",
        "rows": results,
        "benign": {
            "total": len(benign),
            "detected_as_anomaly": sum(int(row["detected_as_anomaly"]) for row in benign),
            "false_positive_rate": (
                sum(int(row["detected_as_anomaly"]) for row in benign) / sum(int(row["total"]) for row in benign)
                if benign else 0.0
            ),
            "small_sample_note": "one benign test flow; FPR is not statistically precise",
        },
        "attack": {
            "total": len(attacks),
            "detected": sum(int(row["detected_as_anomaly"]) for row in attacks),
            "missed": sum(int(row["missed"]) for row in attacks),
            "recall": (
                sum(int(row["detected_as_anomaly"]) for row in attacks) / sum(int(row["total"]) for row in attacks)
                if attacks else 0.0
            ),
            "small_sample_note": "nine test attack flows across two attack families; descriptive only",
        },
    }


def aggregate_per_attack_family(predictions: Sequence[dict[str, Any]]) -> dict[str, Any]:
    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in predictions:
        if row.get("ground_truth") != "ATTACK":
            continue
        family = row.get("attack_family")
        if not isinstance(family, str) or not family:
            raise ValueError("attack prediction is missing attack_family")
        families[family].append(row)
    return {
        "schema_version": "controlled_v2_attack_family_metrics.v1",
        "families": {
            family: {
                "total": len(rows),
                "detected": sum(row.get("predicted_label") == "ATTACK" for row in rows),
                "missed": sum(row.get("predicted_label") != "ATTACK" for row in rows),
                "recall": sum(row.get("predicted_label") == "ATTACK" for row in rows) / len(rows),
                "small_sample_note": "one or few test flows; descriptive only" if len(rows) < 3 else None,
            }
            for family, rows in sorted(families.items())
        },
    }


def _write_jsonl(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    _write_text(path, "".join(json.dumps(row, sort_keys=True, allow_nan=False) + "\n" for row in rows))


def _fit_phase(corpus: ControlledCorpus, output_dir: Path) -> dict[str, Any]:
    """Fit and lock validation without requesting the test split."""

    train_rows = corpus.split("train_normal")
    validation_rows = corpus.split("validation")
    if len(train_rows) != 6 or any(row.label != "BENIGN" for row in train_rows):
        raise ValueError("controlled-v2 training split must contain exactly six BENIGN flows")
    if len(validation_rows) != 10:
        raise ValueError("controlled-v2 validation split must contain exactly ten flows")
    train_features, _ = _array(train_rows)
    validation_features, validation_attack = _array(validation_rows)
    train_input, validation_input = _model_input(train_features), _model_input(validation_features)

    model = IsolationForest(**MODEL_PARAMETERS)
    started = time.perf_counter()
    model.fit(train_input)
    training_seconds = time.perf_counter() - started
    started = time.perf_counter()
    validation_scores = np.asarray(scores_from_sklearn(model, validation_input), dtype=np.float64)
    validation_scoring_seconds = time.perf_counter() - started
    if validation_scores.shape != (len(validation_rows),) or not np.all(np.isfinite(validation_scores)):
        raise ValueError("Isolation Forest produced invalid validation scores")

    candidates = validation_threshold_candidates(validation_scores, validation_attack)
    threshold, selection = select_validation_threshold(candidates)
    validation_aggregate = dict(confusion_metrics(validation_scores, validation_attack, threshold))
    validation_metrics = {
        "schema_version": "controlled_v2_validation_metrics.v1",
        **validation_aggregate,
        "flow_count": len(validation_rows),
        "benign_flows": sum(row.label == "BENIGN" for row in validation_rows),
        "attack_flows": sum(row.label == "ATTACK" for row in validation_rows),
        "score_distributions": _score_distributions(validation_rows, validation_scores),
        "selection": selection,
        "sample_size_warning": "validation contains ten flows and one benign flow; FPR is not statistically precise",
        "test_data_used": False,
    }
    validation_flow_scores = _per_flow_scores(validation_rows, validation_scores, threshold)
    schema, contract_hash = _authoritative_feature_schema()

    _write_joblib(output_dir / "model.joblib", model)
    model_hash = _sha256(output_dir / "model.joblib")
    model_size = (output_dir / "model.joblib").stat().st_size
    _write_json(output_dir / "feature_schema.json", schema)
    _write_json(
        output_dir / "model_metadata.json",
        _model_metadata(
            corpus=corpus,
            model_hash=model_hash,
            model_size=model_size,
            training_seconds=training_seconds,
            validation_scoring_seconds=validation_scoring_seconds,
            train_rows=train_rows,
            validation_rows=validation_rows,
        )
        | {"feature_contract_sha256": contract_hash},
    )
    _write_candidates(output_dir / "validation_threshold_candidates.csv", candidates)
    _write_json(
        output_dir / "validation_operating_points.json",
        {
            "schema_version": "controlled_v2_validation_operating_points.v1",
            "candidates": candidates,
            "selected": selection,
            "validation_flow_scores": validation_flow_scores,
            "test_data_used": False,
        },
    )
    _write_json(output_dir / "validation_metrics.json", validation_metrics)
    _write_json(
        output_dir / "fit_score_statistics.json",
        {
            "schema_version": "controlled_v2_fit_score_statistics.v1",
            "score_definition": SCORE_DEFINITION,
            "threshold": threshold,
            "validation": _score_distributions(validation_rows, validation_scores),
            "validation_flow_scores": validation_flow_scores,
            "test_data_used": False,
        },
    )
    _write_score_distribution(
        output_dir / "validation_score_distribution.png",
        "Controlled v2 validation score distribution",
        validation_rows,
        validation_scores,
        threshold,
    )

    training_manifest = _manifest_rows(train_rows, corpus.source_hashes)
    validation_manifest = _manifest_rows(validation_rows, corpus.source_hashes)
    _write_json(output_dir / "training_manifest.json", training_manifest)
    _write_json(output_dir / "validation_manifest.json", validation_manifest)
    training_manifest_hash = _sha256(output_dir / "training_manifest.json")
    validation_manifest_hash = _sha256(output_dir / "validation_manifest.json")
    threshold_payload = {
        "schema_version": "controlled_v2_validation_threshold.v1",
        "created_at_utc": _utc_now(),
        "threshold": threshold,
        "comparison_operator": ">=",
        "score_definition": SCORE_DEFINITION,
        "decision_rule": DECISION_RULE,
        "selection_method": selection["selection_method"],
        "selection_details": selection,
        "validation_dataset_hash": validation_manifest_hash,
        "validation_flow_ids": [row.flow_id for row in validation_rows],
        "validation_capture_ids": sorted({row.capture_id for row in validation_rows}),
        "model_sha256": model_hash,
        "test_used_for_selection": False,
    }
    _write_json(output_dir / "threshold.json", threshold_payload)

    fit_names = [name for name in FIT_ARTIFACT_NAMES if name not in {"fit_manifest.json", "experiment_lock.json"}]
    fit_artifacts = _artifact_hashes(output_dir, fit_names)
    fit_manifest = {
        "schema_version": "controlled_v2_fit_manifest.v1",
        "created_at_utc": _utc_now(),
        "experiment_configuration": {
            "algorithm": "Isolation Forest",
            "parameters": dict(MODEL_PARAMETERS),
            "preprocessing": "NONE",
            "random_seed": 42,
            "features": list(FEATURES),
        },
        "source_corpus_status": corpus.corpus_status,
        "source_manifest_hashes": dict(sorted(corpus.source_manifest_hashes.items())),
        "source_corpus_artifact_hashes": dict(sorted(corpus.source_hashes.items())),
        "dataset_manifest_sha256": corpus.dataset_manifest_hash,
        "split_definition_sha256": corpus.split_definition_hash,
        "feature_contract_sha256": contract_hash,
        "model_sha256": model_hash,
        "training_manifest_sha256": training_manifest_hash,
        "validation_manifest_sha256": validation_manifest_hash,
        "train_flow_count": len(train_rows),
        "validation_flow_count": len(validation_rows),
        "train_benign_count": len(train_rows),
        "train_attack_count": 0,
        "test_data_accessed": False,
        "fit_artifact_hashes": fit_artifacts,
        "runtime": {
            "training_seconds": training_seconds,
            "validation_scoring_seconds": validation_scoring_seconds,
            "peak_rss_bytes": _peak_rss_bytes(),
        },
    }
    _write_json(output_dir / "fit_manifest.json", fit_manifest)
    fit_manifest_hash = _sha256(output_dir / "fit_manifest.json")
    lock = {
        "schema_version": "controlled_v2_experiment_lock.v1",
        "status": "LOCKED_FOR_TEST_EVALUATION",
        "created_at_utc": _utc_now(),
        "model_sha256": model_hash,
        "threshold_sha256": _sha256(output_dir / "threshold.json"),
        "feature_schema_sha256": _sha256(output_dir / "feature_schema.json"),
        "fit_manifest_sha256": fit_manifest_hash,
        "training_manifest_sha256": training_manifest_hash,
        "validation_manifest_sha256": validation_manifest_hash,
        "split_definition_sha256": corpus.split_definition_hash,
        "dataset_manifest_sha256": corpus.dataset_manifest_hash,
        "experiment_configuration": fit_manifest["experiment_configuration"],
        "random_seed": 42,
        "test_data_accessed": False,
        "statement": "Model and validation threshold are immutable; test data has not been accessed.",
    }
    _write_json(output_dir / "experiment_lock.json", lock)
    return {
        "status": "READY_FOR_V2_MODEL_EVALUATION",
        "threshold": threshold,
        "model_sha256": model_hash,
        "threshold_sha256": _sha256(output_dir / "threshold.json"),
        "feature_schema_sha256": _sha256(output_dir / "feature_schema.json"),
        "training_manifest_sha256": training_manifest_hash,
        "validation_manifest_sha256": validation_manifest_hash,
        "validation_metrics": validation_aggregate,
        "fit_artifacts": sorted(name for name in FIT_ARTIFACT_NAMES if (output_dir / name).is_file()),
    }


def _verify_lock(corpus: ControlledCorpus, output_dir: Path) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    lock = _read_json(output_dir / "experiment_lock.json")
    if lock.get("schema_version") != "controlled_v2_experiment_lock.v1" or lock.get("status") != "LOCKED_FOR_TEST_EVALUATION":
        raise ValueError("controlled-v2 experiment lock is missing or has an invalid status")
    if lock.get("test_data_accessed") is not False:
        raise ValueError("controlled-v2 experiment lock does not prove test data was untouched")
    expected_hashes = {
        "model_sha256": output_dir / "model.joblib",
        "threshold_sha256": output_dir / "threshold.json",
        "feature_schema_sha256": output_dir / "feature_schema.json",
        "fit_manifest_sha256": output_dir / "fit_manifest.json",
        "training_manifest_sha256": output_dir / "training_manifest.json",
        "validation_manifest_sha256": output_dir / "validation_manifest.json",
    }
    for key, path in expected_hashes.items():
        if lock.get(key) != _sha256(path):
            raise ValueError(f"controlled-v2 lock hash mismatch: {key}")
    if lock.get("split_definition_sha256") != corpus.split_definition_hash or lock.get("dataset_manifest_sha256") != corpus.dataset_manifest_hash:
        raise ValueError("controlled-v2 lock source split/dataset hash mismatch")
    if lock.get("experiment_configuration") != {
        "algorithm": "Isolation Forest",
        "parameters": dict(MODEL_PARAMETERS),
        "preprocessing": "NONE",
        "random_seed": 42,
        "features": list(FEATURES),
    }:
        raise ValueError("controlled-v2 lock configuration does not match the fixed experiment")

    fit_manifest = _read_json(output_dir / "fit_manifest.json")
    for name, details in fit_manifest.get("fit_artifact_hashes", {}).items():
        if not isinstance(details, dict) or details.get("sha256") != _sha256(output_dir / name):
            raise ValueError(f"controlled-v2 fit artifact hash mismatch: {name}")
    threshold = _read_json(output_dir / "threshold.json")
    schema = _read_json(output_dir / "feature_schema.json")
    if schema.get("features") != list(FEATURES) or schema.get("feature_count") != 9 or schema.get("preprocessing") != "NONE":
        raise ValueError("controlled-v2 feature schema lock is invalid")
    if threshold.get("model_sha256") != lock.get("model_sha256") or threshold.get("test_used_for_selection") is not False:
        raise ValueError("controlled-v2 threshold is not bound to the locked model")
    model = joblib.load(output_dir / "model.joblib")
    if not isinstance(model, IsolationForest):
        raise ValueError("controlled-v2 model artifact is not an IsolationForest")  # noqa: TRY004 - invalid serialized data
    try:
        check_is_fitted(model, ["estimators_", "n_features_in_", "max_samples_"])
    except ValueError:
        raise ValueError("controlled-v2 model artifact is not fitted") from None
    expected_parameters = IsolationForest(**MODEL_PARAMETERS).get_params(deep=False)
    if model.get_params(deep=False) != expected_parameters or model.n_features_in_ != len(FEATURES):
        raise ValueError("controlled-v2 fitted model parameters do not match the fixed configuration")
    if len(model.estimators_) != MODEL_PARAMETERS["n_estimators"]:
        raise ValueError("controlled-v2 fitted model estimator count does not match the fixed configuration")
    return model, threshold, lock


def _evaluate_phase(corpus: ControlledCorpus, output_dir: Path) -> dict[str, Any]:
    """Verify the lock, then score the test split once."""

    model, threshold_payload, lock = _verify_lock(corpus, output_dir)
    threshold = float(threshold_payload["threshold"])
    test_rows = corpus.split("test")
    if len(test_rows) != 10:
        raise ValueError("controlled-v2 test split must contain exactly ten flows")
    test_features, test_attack = _array(test_rows)
    started = time.perf_counter()
    test_scores = np.asarray(scores_from_sklearn(model, _model_input(test_features)), dtype=np.float64)
    test_scoring_seconds = time.perf_counter() - started
    if test_scores.shape != (len(test_rows),) or not np.all(np.isfinite(test_scores)):
        raise ValueError("Isolation Forest produced invalid test scores")
    aggregate = dict(confusion_metrics(test_scores, test_attack, threshold))
    predictions = _per_flow_scores(test_rows, test_scores, threshold)
    scenario_metrics = aggregate_per_scenario(predictions)
    family_metrics = aggregate_per_attack_family(predictions)
    test_metrics = {
        "schema_version": "controlled_v2_test_metrics.v1",
        **aggregate,
        "flow_count": len(test_rows),
        "benign_flows": sum(row.label == "BENIGN" for row in test_rows),
        "attack_flows": sum(row.label == "ATTACK" for row in test_rows),
        "score_distributions": _score_distributions(test_rows, test_scores),
        "scenario_summary": scenario_metrics["benign"],
        "attack_summary": scenario_metrics["attack"],
        "test_data_used_for_model_selection": False,
        "small_sample_warning": (
            "test contains ten flows and one benign flow; metrics have extremely high variance and are descriptive only"
        ),
    }
    _write_json(output_dir / "test_metrics.json", test_metrics)
    _write_jsonl(output_dir / "test_predictions.jsonl", predictions)
    _write_json(output_dir / "test_scenario_metrics.json", scenario_metrics)
    _write_json(output_dir / "test_attack_family_metrics.json", family_metrics)
    _write_score_distribution(output_dir / "test_score_distribution.png", "Controlled v2 test score distribution", test_rows, test_scores, threshold)

    test_names = [name for name in TEST_ARTIFACT_NAMES if name not in {"evaluation_manifest.json", "artifact_manifest.json"}]
    evaluation_artifacts = _artifact_hashes(output_dir, [*FIT_ARTIFACT_NAMES, *test_names])
    evaluation_manifest = {
        "schema_version": "controlled_v2_evaluation_manifest.v1",
        "created_at_utc": _utc_now(),
        "status": "V2_MODEL_EVALUATED",
        "model_sha256": lock["model_sha256"],
        "threshold_sha256": lock["threshold_sha256"],
        "feature_schema_sha256": lock["feature_schema_sha256"],
        "experiment_lock_sha256": _sha256(output_dir / "experiment_lock.json"),
        "source_corpus_status": corpus.corpus_status,
        "source_manifest_hashes": dict(sorted(corpus.source_manifest_hashes.items())),
        "source_corpus_artifact_hashes": dict(sorted(corpus.source_hashes.items())),
        "dataset_manifest_sha256": corpus.dataset_manifest_hash,
        "split_definition_sha256": corpus.split_definition_hash,
        "features": list(FEATURES),
        "model_parameters": dict(MODEL_PARAMETERS),
        "preprocessing": "NONE",
        "score_definition": SCORE_DEFINITION,
        "threshold": threshold,
        "test_flow_count": len(test_rows),
        "test_benign_count": sum(row.label == "BENIGN" for row in test_rows),
        "test_attack_count": sum(row.label == "ATTACK" for row in test_rows),
        "test_data_accessed_only_after_lock": True,
        "test_evaluated_once": True,
        "runtime": {
            "test_scoring_seconds": test_scoring_seconds,
            "peak_rss_bytes": _peak_rss_bytes(),
            "model_size_bytes": (output_dir / "model.joblib").stat().st_size,
        },
        "artifact_hashes_before_final_manifest": evaluation_artifacts,
    }
    _write_json(output_dir / "evaluation_manifest.json", evaluation_manifest)
    final_names = [*FIT_ARTIFACT_NAMES, *TEST_ARTIFACT_NAMES]
    final_names.remove("artifact_manifest.json")
    final_names.remove("evaluation_manifest.json")
    final_artifacts = _artifact_hashes(output_dir, [*final_names, "evaluation_manifest.json"])
    _write_json(
        output_dir / "artifact_manifest.json",
        {
            "schema_version": "controlled_v2_artifact_manifest.v1",
            "created_at_utc": _utc_now(),
            "status": "V2_MODEL_EVALUATED",
            "artifact_sha256": final_artifacts,
            "source_manifest_sha256": dict(sorted(corpus.source_manifest_hashes.items())),
            "source_corpus_artifact_sha256": dict(sorted(corpus.source_hashes.items())),
            "source_corpus_artifact_sizes": dict(sorted(corpus.source_sizes.items())),
            "artifact_manifest_self_hash": None,
            "self_hash_note": "Self-hash is intentionally excluded to avoid a circular manifest.",
        },
    )
    return {
        "status": "V2_MODEL_EVALUATED",
        "threshold": threshold,
        "model_sha256": lock["model_sha256"],
        "threshold_sha256": lock["threshold_sha256"],
        "test_metrics": aggregate,
        "test_predictions": predictions,
        "artifact_manifest": _sha256(output_dir / "artifact_manifest.json"),
    }


def _prepare_output(output_dir: Path, *, fit: bool, evaluate: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if fit and any(path.is_file() for path in output_dir.iterdir()):
        raise FileExistsError(
            "controlled-v2 experiment output is not empty; create a new experiment version instead of replacing a lock"
        )
    if evaluate and any((output_dir / name).is_file() for name in TEST_ARTIFACT_NAMES):
        raise FileExistsError("controlled-v2 test evaluation artifacts already exist; test evaluation is one-time")


def run_experiment(
    run_dir: str | Path,
    output_dir: str | Path,
    *,
    fit: bool,
    evaluate: bool,
    enrolled_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Run fit -> validation -> lock -> test in the only permitted order."""

    if not fit and not evaluate:
        raise ValueError("at least one of fit or evaluate must be true")
    run_root, destination = Path(run_dir).resolve(), Path(output_dir).resolve()
    if destination == run_root or run_root in destination.parents:
        raise ValueError("model output must be outside the enrolled controlled-v2 corpus")
    _prepare_output(destination, fit=fit, evaluate=evaluate)
    corpus = verify_corpus(run_root, enrolled_dir)
    summary: dict[str, Any] = {
        "output_dir": str(destination),
        "corpus_status": corpus.corpus_status,
        "corpus_counts": {
            "captures": len({row.capture_id for row in corpus.rows}),
            "flows": len(corpus.rows),
            "benign": sum(row.label == "BENIGN" for row in corpus.rows),
            "attack": sum(row.label == "ATTACK" for row in corpus.rows),
        },
        "fit": fit,
        "evaluate": evaluate,
        "test_data_accessed_before_lock": False,
    }
    if fit:
        summary.update(_fit_phase(corpus, destination))
    if evaluate:
        summary.update(_evaluate_phase(corpus, destination))
        summary["test_data_accessed_before_lock"] = False
    summary["artifacts"] = sorted(path.name for path in destination.iterdir() if path.is_file())
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the controlled native-v2 Isolation Forest experiment")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--enrolled-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--fit", action="store_true", help="fit on BENIGN train flows and lock validation threshold")
    parser.add_argument("--evaluate", action="store_true", help="evaluate the held-out test split after the lock")
    args = parser.parse_args(argv)
    try:
        result = run_experiment(
            args.run_dir,
            args.output_dir,
            fit=args.fit,
            evaluate=args.evaluate,
            enrolled_dir=args.enrolled_dir,
        )
    except (FileNotFoundError, FileExistsError, OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
