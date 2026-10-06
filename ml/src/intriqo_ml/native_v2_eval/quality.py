"""Dataset-quality accounting for controlled native-v2 rows.

This module deliberately reports evidence and gates; it does not fit, score,
or import an Isolation Forest.
"""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from typing import Any

from intriqo_ml.flow_features_v2 import FEATURES_V2, FlowFeatureRecordV2

from .alignment import AlignmentRow
from .schema import CaptureManifest
from .splits import SplitValidation


def _feature_stats(
    records: list[FlowFeatureRecordV2],
) -> dict[str, dict[str, float | int | bool | None]]:
    result: dict[str, dict[str, float | int | bool | None]] = {}
    for name in FEATURES_V2:
        values = [float(getattr(record.features, name)) for record in records]
        result[name] = {
            "count": len(values),
            "finite": all(math.isfinite(value) for value in values),
            "min": min(values) if values else None,
            "max": max(values) if values else None,
            "mean": sum(values) / len(values) if values else None,
        }
    return result


def _vector_key(record: FlowFeatureRecordV2) -> str:
    return json.dumps(
        [getattr(record.features, name) for name in FEATURES_V2],
        separators=(",", ":"),
        allow_nan=False,
    )


def build_quality_report(
    *,
    records: list[tuple[str, int, FlowFeatureRecordV2]],
    alignment_rows: list[AlignmentRow],
    captures: CaptureManifest,
    split_validation: SplitValidation,
    replay_reports: list[dict[str, Any]] | tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    """Build a conservative, serializable quality report."""
    alignment_counts = Counter(row.match_status for row in alignment_rows)
    labels = Counter(row.label for row in alignment_rows if row.eligible and row.label is not None)
    families = Counter(
        row.attack_family
        for row in alignment_rows
        if row.eligible and row.attack_family is not None
    )
    # Preserve split counts by label as a second pass when the caller supplies
    # an assignment map in replay reports; unknown captures remain explicit.
    per_split: dict[str, dict[str, int]] = {
        name: {"total_flows": 0, "exact_flows": 0, "eligible_flows": 0}
        for name in ("train_normal", "validation", "test")
    }
    for row in alignment_rows:
        split = next(
            (
                report.get("split")
                for report in replay_reports
                if report.get("capture_id") == row.capture_id
            ),
            None,
        )
        if split not in per_split:
            continue
        per_split[split]["total_flows"] += 1
        if row.match_status == "EXACT":
            per_split[split]["exact_flows"] += 1
        if row.eligible:
            per_split[split]["eligible_flows"] += 1

    vectors: dict[str, list[AlignmentRow]] = defaultdict(list)
    for (_, _, record), row in zip(records, alignment_rows, strict=False):
        vectors[_vector_key(record)].append(row)
    duplicate_vectors = {
        key: {
            "count": len(rows),
            "labels": sorted({row.label for row in rows if row.label is not None}),
            "splits": sorted({
                report.get("split")
                for report in replay_reports
                for row in rows
                if report.get("capture_id") == row.capture_id
            }),
        }
        for key, rows in vectors.items()
        if len(rows) > 1
    }
    native_keys = [
        (capture_id, record.metadata.engine_instance_id, record.metadata.flow_id)
        for capture_id, _, record in records
    ]
    duplicate_native_keys = len(native_keys) - len(set(native_keys))
    blockers: list[str] = []
    if not captures.captures:
        blockers.append("no_controlled_capture_manifest_entries")
    if not records:
        blockers.append("no_native_v2_records")
    if any(report.get("status") != "complete" for report in replay_reports):
        blockers.append("native_replay_not_complete")
    if any(count for status, count in alignment_counts.items() if status != "EXACT"):
        blockers.append("non_exact_label_alignment_present")
    if not split_validation.valid:
        blockers.append("split_leakage_or_assignment_violation")
    status = "PASS" if not blockers else "BLOCKED_ON_CONTROLLED_CAPTURE"
    return {
        "schema_version": "controlled_quality_report.v1",
        "corpus_name": "CONTROLLED NATIVE INTRIQO EVALUATION",
        "status": status,
        "training_performed": False,
        "model_implementation": None,
        "scores_generated": False,
        "counts": {
            "total_flows": len(records),
            "benign_flows": labels.get("BENIGN", 0),
            "attack_flows": labels.get("ATTACK", 0),
            "capture_count": len(captures.captures),
        },
        "per_attack_family": dict(sorted(families.items())),
        "alignment": {
            "EXACT": alignment_counts.get("EXACT", 0),
            "PARTIAL": alignment_counts.get("PARTIAL", 0),
            "AMBIGUOUS": alignment_counts.get("AMBIGUOUS", 0),
            "UNKNOWN": alignment_counts.get("UNKNOWN", 0),
            "eligible_exact_rows": sum(1 for row in alignment_rows if row.eligible),
        },
        "per_split": per_split,
        "feature_distributions": _feature_stats([record for _, _, record in records]),
        "duplicate_analysis": {
            "duplicate_native_row_keys": duplicate_native_keys,
            "duplicate_feature_vector_count": len(duplicate_vectors),
            "feature_collisions": duplicate_vectors,
        },
        "replay": list(replay_reports),
        "split_validation": split_validation.as_dict(),
        "blockers": blockers,
        "ready_for_model_training": not blockers,
    }
