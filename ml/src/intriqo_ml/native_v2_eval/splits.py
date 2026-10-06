"""Capture-level split assignment and leakage checks."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .alignment import AlignmentRow
from .schema import CaptureManifest, SplitDefinition


@dataclass(frozen=True)
class SplitValidation:
    valid: bool
    violations: tuple[str, ...]
    split_counts: dict[str, int]

    def as_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "violations": list(self.violations),
            "split_counts": dict(self.split_counts),
        }


def _cross_split_violations(
    values: dict[str, set[str]], label: str
) -> list[str]:
    return [
        f"{label}:{value} appears in splits {sorted(splits)}"
        for value, splits in sorted(values.items())
        if len(splits) > 1
    ]


def validate_splits(
    captures: CaptureManifest,
    definition: SplitDefinition,
    alignment_rows: list[AlignmentRow] | tuple[AlignmentRow, ...] = (),
) -> SplitValidation:
    """Reject row-level or provenance-level split leakage.

    Repeated feature vectors are intentionally not a split violation; they are
    reported by the quality layer as representation collisions.
    """
    violations: list[str] = []
    capture_by_id = {row.capture_id: row for row in captures.captures}
    assignment = {row.capture_id: row.split for row in definition.assignments}
    for capture_id in capture_by_id:
        if capture_id not in assignment:
            violations.append(f"capture_without_split:{capture_id}")
    for capture_id in assignment:
        if capture_id not in capture_by_id:
            violations.append(f"split_without_capture:{capture_id}")

    by_group: dict[str, set[str]] = defaultdict(set)
    by_parent: dict[str, set[str]] = defaultdict(set)
    by_hash: dict[str, set[str]] = defaultdict(set)
    for capture_id, split in assignment.items():
        capture = capture_by_id.get(capture_id)
        if capture is None:
            continue
        by_group[capture.capture_group].add(split)
        if capture.parent_capture_id is not None:
            by_parent[capture.parent_capture_id].add(split)
        if capture.sha256 is not None:
            by_hash[capture.sha256].add(split)
    violations.extend(_cross_split_violations(by_group, "capture_group"))
    violations.extend(_cross_split_violations(by_parent, "parent_capture_id"))
    violations.extend(_cross_split_violations(by_hash, "pcap_sha256"))

    row_keys: set[tuple[str, str, str]] = set()
    label_splits: dict[str, set[str]] = defaultdict(set)
    split_counts: dict[str, int] = {name: 0 for name in ("train_normal", "validation", "test")}
    for row in alignment_rows:
        key = (row.capture_id, row.engine_instance_id, row.flow_id)
        if key in row_keys:
            violations.append(f"duplicate_native_row_key:{key}")
        row_keys.add(key)
        split = assignment.get(row.capture_id)
        if split is None:
            continue
        split_counts[split] += 1
        if row.source_label_id is not None:
            label_splits[row.source_label_id].add(split)
    violations.extend(_cross_split_violations(label_splits, "source_label_id"))

    # If a parent capture is represented by multiple child captures, overlapping
    # intervals cannot be separated safely.  Missing bounds are conservatively
    # treated as a violation when the same parent crosses splits.
    for parent_id, parent_splits in by_parent.items():
        if len(parent_splits) <= 1:
            continue
        children = [
            capture
            for capture in captures.captures
            if capture.parent_capture_id == parent_id
        ]
        if any(capture.capture_start is None or capture.capture_end is None for capture in children):
            violations.append(f"parent_time_overlap_unknown:{parent_id}")
            continue
        for index, left in enumerate(children):
            for right in children[index + 1 :]:
                if assignment.get(left.capture_id) == assignment.get(right.capture_id):
                    continue
                if left.capture_start <= right.capture_end and right.capture_start <= left.capture_end:
                    violations.append(
                        f"parent_time_overlap:{parent_id}:{left.capture_id}:{right.capture_id}"
                    )

    return SplitValidation(not violations, tuple(sorted(set(violations))), split_counts)
