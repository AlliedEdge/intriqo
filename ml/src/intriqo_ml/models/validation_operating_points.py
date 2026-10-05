"""Validation-only diagnostics for an existing, unchanged Isolation Forest lock.

FPR targets are caps, not interpolated ROC points.  Available score groups are
indivisible.  Diagnostic points maximize recall, then F1, lower FPR, and higher
threshold under each cap.  They never replace the primary threshold.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import numpy as np

from . import isolation_forest as baseline

DEFAULT_FPR_CAPS: tuple[float, ...] = (
    0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.02, 0.05, 0.10,
)
DIAGNOSTIC_FILES = ("validation_operating_points.csv", "validation_operating_points.json")
CSV_FIELDS = (
    "target_fpr", "threshold", "actual_fpr", "recall", "tpr", "precision", "f1",
    "tp", "tn", "fp", "fn", "balanced_accuracy", "maximum_recall_at_fpr_cap",
    "maximum_recall_threshold", "FTP-Patator_recall", "SSH-Patator_recall",
)


def _validated_scores_labels(scores: Any, labels: Any) -> tuple[baseline.FloatArray, baseline.StringArray]:
    values = baseline._as_float_array(scores, name="validation scores")
    names = np.asarray(labels, dtype=str)
    if names.ndim != 1 or len(names) != len(values):
        raise ValueError("validation scores and labels must have the same row count")
    if not len(values):
        raise ValueError("operating points require nonempty validation scores")
    if np.any(names == ""):
        raise ValueError("validation labels must not be empty")
    return values, names


def calculate_operating_points(
    scores: Any, labels: Any, fpr_caps: Sequence[float] = DEFAULT_FPR_CAPS,
) -> list[dict[str, Any]]:
    """Return best achievable shared-threshold validation points at FPR caps."""

    values, names = _validated_scores_labels(scores, labels)
    candidates = baseline._threshold_candidates(values, names != "BENIGN")
    families = sorted({str(name) for name in names if name != "BENIGN"})
    masks = {family: names == family for family in families}
    result: list[dict[str, Any]] = []
    for cap in fpr_caps:
        if not math.isfinite(cap) or not 0 <= cap <= 1:
            raise ValueError("FPR caps must be finite values between zero and one")
        eligible = np.flatnonzero(candidates.fpr <= cap)
        maximum_recall = float(np.max(candidates.recall[eligible]))
        for metric, maximize in (
            (candidates.recall, True), (candidates.f1, True),
            (candidates.fpr, False), (candidates.thresholds, True),
        ):
            best = np.max(metric[eligible]) if maximize else np.min(metric[eligible])
            eligible = eligible[metric[eligible] == best]
        index = int(eligible[0])
        threshold = float(candidates.thresholds[index])
        tp, tn, fp, fn = (int(field[index]) for field in (
            candidates.tp, candidates.tn, candidates.fp, candidates.fn,
        ))
        tpr = float(candidates.recall[index])
        specificity = baseline._metric_divide(tn, tn + fp)
        per_family: dict[str, dict[str, int | float]] = {}
        for family, mask in masks.items():
            support = int(np.count_nonzero(mask))
            detected = int(np.count_nonzero(mask & (values >= threshold)))
            per_family[family] = {
                "support": support, "detected": detected,
                "recall": baseline._metric_divide(detected, support),
            }
        point: dict[str, Any] = {
            "target_fpr": float(cap), "threshold": threshold,
            "actual_fpr": float(candidates.fpr[index]), "recall": tpr, "tpr": tpr,
            "precision": float(candidates.precision[index]), "f1": float(candidates.f1[index]),
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "balanced_accuracy": (tpr + specificity) / 2,
            "maximum_recall_at_fpr_cap": maximum_recall,
            "maximum_recall_threshold": threshold, "per_family": per_family,
        }
        for family in ("FTP-Patator", "SSH-Patator"):
            point[f"{family}_recall"] = per_family.get(family, {}).get("recall", 0.0)
        result.append(point)
    return result


def _score_percentiles(values: baseline.FloatArray) -> dict[str, Any]:
    summary: dict[str, Any] = dict(baseline._distribution(values))
    summary["p99_9"] = float(np.percentile(values, 99.9)) if len(values) else None
    return summary


def validation_diagnostics(
    scores: Any, labels: Any, features: Any, locked_threshold: float,
    fpr_caps: Sequence[float] = DEFAULT_FPR_CAPS,
) -> dict[str, Any]:
    """Analyze validation scores without fitting or changing any model/lock."""

    values, names = _validated_scores_labels(scores, labels)
    raw = np.asarray(features, dtype=np.float64)
    if raw.shape != (len(values), len(baseline.FEATURES)) or not np.all(np.isfinite(raw)):
        raise ValueError("validation features must be finite and aligned with scores")
    if not math.isfinite(locked_threshold):
        raise ValueError("locked threshold must be finite")
    model_input = baseline._model_features(raw)
    attacks = names != "BENIGN"
    locked = baseline.confusion_metrics(values, attacks, locked_threshold)
    return {
        "schema_version": "validation_operating_points.v1", "diagnostic_only": True,
        "split": "validation", "test_data_used": False,
        "features": list(baseline.FEATURES), "preprocessing": "none",
        "score_definition": "-model.score_samples(features)",
        "operating_point_policy": {
            "targets_are_fpr_caps": True, "interpolation": "none",
            "candidates": "unique_validation_scores_plus_no_alert",
            "tie_break": ["recall", "f1", "lower_fpr", "higher_threshold"],
            "same_threshold_for_all_attack_families": True,
            "primary_locked_threshold_unchanged": True,
        },
        "sample_count": len(values), "attack_count": int(np.count_nonzero(attacks)),
        "benign_count": int(np.count_nonzero(~attacks)),
        "ranking": {"roc_auc": locked["roc_auc"], "average_precision": locked["average_precision"], "pr_auc": locked["pr_auc"]},
        "locked_operating_point": {
            **locked,
            "attack_fraction_at_or_above": locked["recall"],
            "benign_fraction_at_or_above": locked["fpr"],
            "attack_fraction_strictly_above": baseline._metric_divide(
                int(np.count_nonzero(attacks & (values > locked_threshold))), int(np.count_nonzero(attacks)),
            ),
            "benign_fraction_strictly_above": baseline._metric_divide(
                int(np.count_nonzero(~attacks & (values > locked_threshold))), int(np.count_nonzero(~attacks)),
            ),
        },
        "score_distributions": {
            "benign": _score_percentiles(values[~attacks]),
            "attack": _score_percentiles(values[attacks]),
        },
        "operating_points": calculate_operating_points(values, names, fpr_caps),
        "representation_collisions": {
            "prepared_validation_float64": baseline.feature_collision_summary(raw, names),
            "prepared_validation_float32_model_input": baseline.feature_collision_summary(model_input, names),
            "representation_limits": baseline._representation_limits(raw, names),
            "interpretation": (
                "Identical three-feature vectors give identical model inputs and scores; "
                "one shared threshold cannot separate their BENIGN and attack labels. "
                "These collisions are a known information-loss limitation, not proof that "
                "they explain all poor low-FPR recall. Score ties can also occur without "
                "identical feature vectors."
            ),
        },
    }


def _verify_saved_candidates(path: Path, scores: baseline.FloatArray, labels: baseline.StringArray) -> None:
    saved = np.loadtxt(path, delimiter=",", skiprows=1, ndmin=2)
    current = baseline._threshold_candidates(scores, labels != "BENIGN")
    columns = np.column_stack((
        current.thresholds, current.precision, current.recall, current.f1,
        current.fpr, current.recall, current.tp, current.tn, current.fp, current.fn,
    ))
    if not np.array_equal(saved, columns):
        raise ValueError("recovered validation scores do not reproduce the locked candidate CSV")


def _write_points_csv(path: Path, points: list[dict[str, Any]]) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="", dir=path.parent, delete=False,
        ) as stream:
            temporary = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n", extrasaction="ignore")
            writer.writeheader()
            writer.writerows(points)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def run_validation_analysis(dataset_dir: str | Path, artifact_dir: str | Path, *, force: bool = False) -> dict[str, Any]:
    """Read a trusted fit and validation only; write two separate diagnostics.

    Per-row validation scores were not retained in the baseline artifacts.
    Recover them using the unchanged checkpoint and require exact reproduction
    of every saved candidate and metric before using per-family associations.
    """

    dataset, output = Path(dataset_dir).resolve(), Path(artifact_dir).resolve()
    if dataset == output or dataset in output.parents:
        raise ValueError("diagnostic artifact directory must be outside the dataset")
    if any((output / name).exists() for name in baseline._TEST_ARTIFACT_NAMES):
        raise ValueError("validation diagnostic requires a fit-only artifact directory")
    if not force and any((output / name).exists() for name in DIAGNOSTIC_FILES):
        raise FileExistsError("validation diagnostic artifacts already exist; use --force to replace only diagnostics")
    manifest, dataset_hash = baseline._validate_dataset_manifest(dataset)
    original_names = (*baseline._FIT_ARTIFACT_NAMES, "fit_manifest.json")
    original_hashes, original_sizes = baseline._artifact_provenance(output, original_names)
    model, metadata, lock, _, _ = baseline._load_fitted_run(output, dataset_hash)
    features, labels, _ = baseline._load_verified_split(dataset, manifest, "validation")
    scores = baseline.scores_from_sklearn(model, baseline._model_features(features))
    _verify_saved_candidates(output / "validation_threshold_candidates.csv", scores, labels)
    report = validation_diagnostics(scores, labels, features, float(lock["threshold"]))
    saved_metrics = baseline._load_json(output / "validation_metrics.json")
    current_metrics = baseline.confusion_metrics(scores, labels != "BENIGN", float(lock["threshold"]))
    if any(saved_metrics.get(key) != value for key, value in current_metrics.items()):
        raise ValueError("recovered validation scores do not reproduce the locked validation metrics")
    audit_path = dataset / "quality_audit.json"
    if audit_path.is_file():
        audit = baseline._load_json(audit_path)
        collisions = audit.get("feature_only_collisions", {})
        rows = collisions.get("mixed_label_by_source", [])
        report["representation_collisions"]["existing_quality_audit"] = {
            "path": str(audit_path), "sha256": baseline._sha256(audit_path),
            "scope": "valid source rows before exact-row deduplication; validation only",
            "validation_sources": [row for row in rows if row.get("split") == "validation"],
        }
    report["provenance"] = {
        "dataset_manifest_sha256": dataset_hash,
        "model_sha256": metadata["model_sha256"], "threshold_sha256": original_hashes["threshold.json"],
        "original_artifact_sha256": original_hashes, "original_artifact_sizes_bytes": original_sizes,
        "validation_feature_sha256": manifest["artifact_sha256"]["validation_features.csv"],
        "validation_metadata_sha256": manifest["artifact_sha256"]["validation_metadata.csv"],
        "scores_source": "unchanged checkpoint; exact verification against all saved validation candidates and metrics",
        "model_refitted": False, "fit_manifest_modified": False,
    }
    after_hashes, after_sizes = baseline._artifact_provenance(output, original_names)
    if after_hashes != original_hashes or after_sizes != original_sizes:
        raise ValueError("a protected fit artifact changed during validation analysis")
    csv_path = output / DIAGNOSTIC_FILES[0]
    _write_points_csv(csv_path, report["operating_points"])
    report["diagnostic_artifacts"] = {
        csv_path.name: {"sha256": baseline._sha256(csv_path), "size_bytes": csv_path.stat().st_size},
    }
    baseline._write_json(output / DIAGNOSTIC_FILES[1], report)
    final_hashes, final_sizes = baseline._artifact_provenance(output, original_names)
    if final_hashes != original_hashes or final_sizes != original_sizes:
        raise ValueError("a protected fit artifact changed while writing diagnostics")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validation-only diagnostic operating points; no refit or test access")
    parser.add_argument("--dataset-dir", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--force", action="store_true", help="replace only the two validation diagnostic files")
    args = parser.parse_args(argv)
    try:
        report = run_validation_analysis(args.dataset_dir, args.artifact_dir, force=args.force)
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(baseline._json_payload({
        "diagnostic_only": True, "locked_threshold": report["locked_operating_point"]["threshold"],
        "operating_points": report["operating_points"], "artifacts": list(DIAGNOSTIC_FILES),
    }), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
