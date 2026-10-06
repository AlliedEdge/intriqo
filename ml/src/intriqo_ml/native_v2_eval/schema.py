"""Schemas for the isolated controlled native-v2 evaluation corpus.

These models describe experiment intent and provenance only.  They are kept
outside the production feature and model modules so that a controller can
create independent ground truth without importing detector or ML code.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from intriqo_ml.flow_features import IPv4String, Timestamp, UInt16
from intriqo_ml.flow_features_v2 import FEATURES_V2, IAT_POLICY, SCHEMA_VERSION_V2

SplitName = Literal["train_normal", "validation", "test"]
Label = Literal["BENIGN", "ATTACK"]
AttackFamily = Literal[
    "SYN_FLOOD",
    "PORT_SCAN",
    "CONNECTION_RATE_ANOMALY",
    "PACKET_RATE_ANOMALY",
    "ASYMMETRIC_COMMUNICATION",
    "BURST_ANOMALY",
    "UNUSUAL_TCP_FLAGS",
    "OTHER_CONTROLLED_ANOMALY",
]
CaptureStatus = Literal["PLANNED", "CAPTURED"]
AlignmentStatus = Literal["EXACT", "PARTIAL", "AMBIGUOUS", "UNKNOWN"]
_Id = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
_Hash = Annotated[str, Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")]


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ExperimentScenario(_StrictModel):
    """One controller-owned ground-truth interval.

    Timestamps may be absent in a pre-capture manifest.  A completed capture
    must fill them before alignment; missing timestamps produce UNKNOWN rather
    than a guessed label.
    """

    experiment_id: _Id
    scenario_id: _Id
    split: SplitName
    label: Label
    attack_family: AttackFamily | None = None
    attacker_ip: IPv4String
    victim_ip: IPv4String
    capture_interface: str = Field(min_length=1, max_length=128)
    subnet: str = Field(min_length=1, max_length=64)
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"]
    source_port: UInt16 | None = None
    destination_port: UInt16 | None = None
    start_timestamp: Timestamp | None = None
    end_timestamp: Timestamp | None = None
    expected_flow_scope: Literal[
        "single_five_tuple",
        "attacker_victim_five_tuple",
        "attacker_victim_protocol",
    ]
    source_label_id: _Id
    ground_truth_source: Literal["experiment_controller_manifest.v1"] = (
        "experiment_controller_manifest.v1"
    )

    @model_validator(mode="after")
    def _validate_label_and_scope(self) -> ExperimentScenario:
        if self.label == "BENIGN" and self.attack_family is not None:
            raise ValueError("BENIGN scenario cannot have an attack family")
        if self.label == "ATTACK" and self.attack_family is None:
            raise ValueError("ATTACK scenario requires an attack family")
        if self.expected_flow_scope == "single_five_tuple" and (
            self.source_port is None or self.destination_port is None
        ):
            raise ValueError("single_five_tuple requires both ports")
        if (self.start_timestamp is None) != (self.end_timestamp is None):
            raise ValueError("scenario timestamps must be both present or both absent")
        if (
            self.start_timestamp is not None
            and self.end_timestamp is not None
            and self.end_timestamp < self.start_timestamp
        ):
            raise ValueError("scenario end precedes start")
        return self


class ExperimentManifest(_StrictModel):
    schema_version: Literal["controlled_experiment_manifest.v1"] = (
        "controlled_experiment_manifest.v1"
    )
    corpus_id: _Id
    corpus_name: Literal["CONTROLLED NATIVE INTRIQO EVALUATION"] = (
        "CONTROLLED NATIVE INTRIQO EVALUATION"
    )
    feature_schema: Literal["flow_features.v2"] = SCHEMA_VERSION_V2
    features: tuple[str, ...] = FEATURES_V2
    iat_policy: Literal["capture_order_nondecreasing_population.v1"] = IAT_POLICY
    alignment_policy_version: Literal["controlled_tuple_time_alignment.v1"] = (
        "controlled_tuple_time_alignment.v1"
    )
    timezone: str = Field(min_length=1, max_length=64)
    clock_synchronization: str = Field(min_length=1, max_length=256)
    experiments: tuple[ExperimentScenario, ...] = Field(min_length=1)
    training_performed: Literal[False] = False
    model_implementation: None = None
    scores_generated: Literal[False] = False
    threshold_selected: Literal[False] = False

    @model_validator(mode="after")
    def _validate_contract_and_ids(self) -> ExperimentManifest:
        if self.features != FEATURES_V2:
            raise ValueError("controlled corpus must use the frozen nine-feature v2 contract")
        scenario_ids = [row.scenario_id for row in self.experiments]
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("scenario_id must be unique")
        label_ids = [row.source_label_id for row in self.experiments]
        if len(set(label_ids)) != len(label_ids):
            raise ValueError("source_label_id must be unique")
        return self


class CaptureManifestEntry(_StrictModel):
    """Immutable provenance for one original PCAP.

    PLANNED entries are allowed only in a design manifest.  CAPTURED entries
    require the original file hash and capture facts; replay never overwrites
    the original file.
    """

    capture_id: _Id
    experiment_id: _Id
    status: CaptureStatus = "PLANNED"
    original_filename: str = Field(min_length=1, max_length=256)
    source_path: str = Field(min_length=1, max_length=1024)
    sha256: _Hash | None = None
    byte_size: int | None = Field(default=None, ge=0)
    capture_start: Timestamp | None = None
    capture_end: Timestamp | None = None
    interface: str = Field(min_length=1, max_length=128)
    link_type: str = Field(min_length=1, max_length=64)
    timestamp_resolution: str = Field(min_length=1, max_length=64)
    timezone: str = Field(min_length=1, max_length=64)
    clock_synchronization: str = Field(min_length=1, max_length=256)
    capture_group: _Id
    parent_capture_id: _Id | None = None
    original_preserved: bool = True
    source_label_ids: tuple[_Id, ...] = ()

    @model_validator(mode="after")
    def _validate_capture(self) -> CaptureManifestEntry:
        if self.status == "CAPTURED":
            required = (
                self.sha256,
                self.byte_size,
                self.capture_start,
                self.capture_end,
            )
            if any(value is None for value in required):
                raise ValueError("CAPTURED entry requires hash, size, and capture bounds")
            if self.capture_end < self.capture_start:  # type: ignore[operator]
                raise ValueError("capture end precedes capture start")
            if not self.original_preserved:
                raise ValueError("original PCAP must remain preserved")
        if self.sha256 is not None and self.status == "CAPTURED":
            # The regex enforces shape; this also documents that the field is
            # intended to be a SHA-256 digest, not a path or a weak checksum.
            int(self.sha256, 16)
        return self


class CaptureManifest(_StrictModel):
    schema_version: Literal["controlled_capture_manifest.v1"] = (
        "controlled_capture_manifest.v1"
    )
    captures: tuple[CaptureManifestEntry, ...] = ()

    @model_validator(mode="after")
    def _validate_ids_and_links(self) -> CaptureManifest:
        ids = [row.capture_id for row in self.captures]
        if len(set(ids)) != len(ids):
            raise ValueError("capture_id must be unique")
        known = set(ids)
        for row in self.captures:
            if row.parent_capture_id is not None and row.parent_capture_id not in known:
                raise ValueError("parent_capture_id must reference a capture in this manifest")
        return self


class SplitAssignment(_StrictModel):
    capture_id: _Id
    split: SplitName


class SplitDefinition(_StrictModel):
    schema_version: Literal["controlled_split_definition.v1"] = (
        "controlled_split_definition.v1"
    )
    policy: Literal["capture_and_parent_group_separation.v1"] = (
        "capture_and_parent_group_separation.v1"
    )
    assignments: tuple[SplitAssignment, ...] = ()
    random_row_split: Literal[False] = False
    leakage_checks: tuple[str, ...] = (
        "capture_id",
        "capture_group",
        "parent_capture_id",
        "pcap_sha256",
        "native_row_key",
        "source_label_id",
        "parent_time_overlap",
    )

    @model_validator(mode="after")
    def _validate_assignments(self) -> SplitDefinition:
        ids = [row.capture_id for row in self.assignments]
        if len(set(ids)) != len(ids):
            raise ValueError("each capture may have one split assignment")
        return self


class DatasetManifest(_StrictModel):
    schema_version: Literal["controlled_native_v2_dataset.v1"] = (
        "controlled_native_v2_dataset.v1"
    )
    dataset_id: _Id
    corpus_name: Literal["CONTROLLED NATIVE INTRIQO EVALUATION"] = (
        "CONTROLLED NATIVE INTRIQO EVALUATION"
    )
    feature_schema: Literal["flow_features.v2"] = SCHEMA_VERSION_V2
    features: tuple[str, ...] = FEATURES_V2
    status: Literal["CONTROLLED_DATASET_DESIGNED", "BLOCKED_ON_CONTROLLED_CAPTURE"]
    training_performed: Literal[False] = False
    model_implementation: None = None
    scores_generated: Literal[False] = False
    ready_for_model_training: bool = False
    experiment_manifest: str
    capture_manifest: str
    split_definition: str
    alignment_report: str
    quality_report: str
    provenance_report: str
    artifact_sha256: dict[str, _Hash | None] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _validate_contract(self) -> DatasetManifest:
        if self.features != FEATURES_V2:
            raise ValueError("dataset manifest must use the frozen nine-feature v2 contract")
        if self.status != "CONTROLLED_DATASET_DESIGNED" and self.ready_for_model_training:
            raise ValueError("blocked corpus cannot be ready for training")
        return self


T = TypeVar("T", bound=BaseModel)


def load_model(path: Path, model_type: type[T]) -> T:
    """Load one strict JSON manifest without accepting undocumented fields."""
    return model_type.model_validate_json(path.read_text(encoding="utf-8"))


def write_model(path: Path, model: BaseModel) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.model_dump_json(indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_json(value: object) -> str:
    """Canonical JSON for reports whose content is hashed or compared."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
