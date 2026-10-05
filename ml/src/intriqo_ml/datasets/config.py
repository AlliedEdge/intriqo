"""Closed, versioned preparation configuration; capture groups are not rows."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

FeatureName = Literal["duration_seconds", "packet_count", "packets_per_second"]
SplitName = Literal["train_normal", "validation", "test"]
FEATURES: tuple[FeatureName, ...] = (
    "duration_seconds",
    "packet_count",
    "packets_per_second",
)
SPLITS: tuple[SplitName, ...] = ("train_normal", "validation", "test")
DUPLICATE_POLICY = "exact_row_within_source_file.v1"
SOURCE = "https://www.unb.ca/cic/datasets/ids-2017.html"
CAPTURE_DAYS = {
    "Monday": "2017-07-03",
    "Tuesday": "2017-07-04",
    "Wednesday": "2017-07-05",
    "Thursday": "2017-07-06",
    "Friday": "2017-07-07",
}


class DatasetError(ValueError):
    """Concise payload-free preparation failure with a stable machine code."""

    def __init__(self, code: str) -> None:
        self.code = code
        # Codes are internal constants, never copied from input data.
        super().__init__(f"dataset preparation failed: {code}")


class _ConfigModel(BaseModel):
    model_config = ConfigDict(
        strict=True, extra="forbid", frozen=True, hide_input_in_errors=True
    )


class InputFile(_ConfigModel):
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    split: SplitName
    format: Literal["csv", "parquet"] = "csv"

    @field_validator("path")
    @classmethod
    def _relative_input(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\0" in value or "\\" in value:
            raise ValueError("input paths must stay inside the dataset root")
        if path.suffix.lower() not in {".csv", ".parquet"}:
            raise ValueError("only CSV or Parquet input is supported")
        if not any(
            path.name.startswith(day + "-") or path.name in {day + ".csv", day + ".parquet"}
            for day in CAPTURE_DAYS
        ):
            raise ValueError("CIC-IDS2017 capture-day filename required")
        return value

    @model_validator(mode="after")
    def _format_matches_path(self) -> InputFile:
        suffix = PurePosixPath(self.path).suffix.lower()
        expected = "parquet" if suffix == ".parquet" else "csv"
        if self.format != expected:
            raise ValueError("input format does not match filename extension")
        return self

    @property
    def capture_group(self) -> str:
        name = PurePosixPath(self.path).name
        return next(
            date
            for day, date in CAPTURE_DAYS.items()
            if name.startswith(day + "-") or name in {day + ".csv", day + ".parquet"}
        )

    @property
    def source_format(self) -> str:
        return self.format


class PreparationConfig(_ConfigModel):
    schema_version: Literal["dataset_preparation.v1"] = "dataset_preparation.v1"
    dataset_id: Literal["cicids2017_csv", "cicids2017"] = "cicids2017_csv"
    dataset_source: str = SOURCE
    dataset_version: Annotated[str, Field(min_length=1, max_length=200)]
    subset_description: Annotated[str, Field(min_length=1, max_length=2000)]
    files: Annotated[tuple[InputFile, ...], Field(min_length=3, max_length=128)]
    features: Annotated[tuple[FeatureName, ...], Field(min_length=1)] = FEATURES
    mapping_version: Literal["cicids2017_projection.v1"] = "cicids2017_projection.v1"
    duplicate_policy: Literal["exact_row_within_source_file.v1"] = "exact_row_within_source_file.v1"
    split_strategy: Literal["explicit_capture_day.v1"] = "explicit_capture_day.v1"
    split_seed: Annotated[int, Field(ge=0, le=4294967295)] = 42
    target_proportions: tuple[float, float, float] = (0.6, 0.2, 0.2)
    preprocessing: Literal["none", "standardize_train_only"] = "none"
    encoding: Literal["utf-8-sig", "latin-1"] = "utf-8-sig"
    max_rows: Annotated[int, Field(ge=1, le=10_000_000)] = 100_000
    max_record_bytes: Annotated[int, Field(ge=128, le=1_048_576)] = 65536
    max_file_bytes: Annotated[int, Field(ge=1, le=8_589_934_592)] = 2_147_483_648
    parquet_batch_size: Annotated[int, Field(ge=1024, le=1_000_000)] = 65536
    rejection_sample_limit: Annotated[int, Field(ge=0, le=10000)] = 100
    require_mixed_evaluation: bool = True
    include_test_statistics: bool = False
    timestamp_utc: str | None = None

    @field_validator("timestamp_utc")
    @classmethod
    def _utc_timestamp(cls, value: str | None) -> str | None:
        if value is not None:
            utc = (
                datetime.fromisoformat(value[:-1] + "+00:00")
                if value.endswith("Z")
                else None
            )
            if utc is None or utc.utcoffset() is None:
                raise ValueError("timestamp must be UTC with Z")
        return value

    @model_validator(mode="after")
    def _split_plan(self) -> PreparationConfig:
        if len(set(self.features)) != len(self.features):
            raise ValueError("feature selection contains duplicates")
        if len({file.path for file in self.files}) != len(self.files):
            raise ValueError("input file is listed more than once")
        groups: dict[str, SplitName] = {}
        for file in self.files:
            previous = groups.setdefault(file.capture_group, file.split)
            if previous != file.split:
                raise ValueError("one capture day cannot appear in multiple splits")
        if set(groups.values()) != set(SPLITS):
            raise ValueError(
                "train_normal, validation and test capture groups are required"
            )
        if any(not 0 < proportion < 1 for proportion in self.target_proportions):
            raise ValueError("target proportions must be positive fractions")
        if abs(sum(self.target_proportions) - 1) > 1e-9:
            raise ValueError("target proportions must sum to one")
        return self


def _unique_config(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DatasetError("invalid_config")
        result[key] = value
    return result


def load_config(path: Path) -> PreparationConfig:
    try:
        with path.open("rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise DatasetError("config_too_large")
        value = json.loads(raw, object_pairs_hook=_unique_config)
        # Validate JSON directly so strict tuple fields accept JSON arrays only.
        return PreparationConfig.model_validate_json(json.dumps(value))
    except DatasetError:
        raise
    except (OSError, ValueError, RecursionError, ValidationError):
        raise DatasetError("invalid_config") from None
