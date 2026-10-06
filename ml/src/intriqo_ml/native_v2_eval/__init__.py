"""Isolated controlled native-v2 evaluation corpus tooling.

No training, inference, threshold selection, or detector output is consumed by
this package.  Ground truth comes only from the experiment controller manifest.
"""

from .alignment import AlignmentRow, align_record, align_records
from .build import build_corpus
from .quality import build_quality_report
from .replay import ReplayResult, replay_native_v2
from .schema import (
    CaptureManifest,
    CaptureManifestEntry,
    DatasetManifest,
    ExperimentManifest,
    ExperimentScenario,
    SplitAssignment,
    SplitDefinition,
    load_model,
    sha256_file,
    write_model,
)
from .splits import SplitValidation, validate_splits

__all__ = [
    "AlignmentRow",
    "CaptureManifest",
    "CaptureManifestEntry",
    "DatasetManifest",
    "ExperimentManifest",
    "ExperimentScenario",
    "ReplayResult",
    "SplitAssignment",
    "SplitDefinition",
    "SplitValidation",
    "align_record",
    "align_records",
    "build_corpus",
    "build_quality_report",
    "load_model",
    "replay_native_v2",
    "sha256_file",
    "validate_splits",
    "write_model",
]
