"""Capture-level split and provenance leakage checks."""

from __future__ import annotations

from intriqo_ml.native_v2_eval.schema import (
    CaptureManifest,
    CaptureManifestEntry,
    SplitAssignment,
    SplitDefinition,
)
from intriqo_ml.native_v2_eval.splits import validate_splits


def capture(capture_id: str, group: str) -> CaptureManifestEntry:
    return CaptureManifestEntry(
        capture_id=capture_id, experiment_id="exp-1", status="CAPTURED",
        original_filename=f"{capture_id}.pcap", source_path=f"/tmp/{capture_id}.pcap",
        sha256="a" * 64, byte_size=12,
        capture_start="2026-10-06T00:00:00.000000000Z",
        capture_end="2026-10-06T00:00:01.000000000Z",
        interface="tap0", link_type="DLT_EN10MB", timestamp_resolution="microsecond",
        timezone="UTC", clock_synchronization="recorded", capture_group=group,
    )


def test_same_capture_group_cannot_cross_splits() -> None:
    captures = CaptureManifest(captures=(capture("cap-a", "group-1"), capture("cap-b", "group-1")))
    definition = SplitDefinition(assignments=(
        SplitAssignment(capture_id="cap-a", split="train_normal"),
        SplitAssignment(capture_id="cap-b", split="test"),
    ))
    result = validate_splits(captures, definition)
    assert result.valid is False
    assert any("capture_group:group-1" in value for value in result.violations)


def test_empty_design_has_no_row_split_or_leakage() -> None:
    result = validate_splits(CaptureManifest(), SplitDefinition())
    assert result.valid is True
    assert result.split_counts == {"train_normal": 0, "validation": 0, "test": 0}
