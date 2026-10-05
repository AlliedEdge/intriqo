"""Reproducible CSV/Parquet preparation without model fitting.

Input files are scanned independently. A first pass validates rows and fits
streaming training aggregates; a second pass writes split artifacts. No set of
all source rows is retained in memory.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import stat
import sys
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, cast

from .config import SPLITS, DatasetError, PreparationConfig, SplitName, load_config
from .mapping import InvalidRow, RowIssue, map_cicids2017_row


@dataclass(frozen=True)
class PreparedRow:
    values: tuple[float, ...]
    label: str
    is_attack: bool
    source_file: str
    source_line: int
    capture_group: str


@dataclass
class Quality:
    total_rows: int = 0
    valid_rows: int = 0
    invalid_rows: int = 0
    duplicate_rows: int = 0
    files_read: int = 0
    file_rows: dict[str, int] = field(default_factory=dict)
    file_valid_rows: dict[str, int] = field(default_factory=dict)
    file_invalid_rows: dict[str, int] = field(default_factory=dict)
    file_duplicate_rows: dict[str, int] = field(default_factory=dict)
    split_rows: Counter[str] = field(default_factory=Counter)
    split_valid_rows: Counter[str] = field(default_factory=Counter)
    split_attack_rows: Counter[str] = field(default_factory=Counter)
    label_rows: Counter[str] = field(default_factory=Counter)
    rejection_reasons: Counter[str] = field(default_factory=Counter)
    missing_value_counts: Counter[str] = field(default_factory=Counter)
    rejection_samples: list[dict[str, object]] = field(default_factory=list)

    def begin_file(self, path: str) -> None:
        self.files_read += 1
        self.file_rows[path] = 0
        self.file_valid_rows[path] = 0
        self.file_invalid_rows[path] = 0
        self.file_duplicate_rows[path] = 0

    def reject(
        self,
        split: str,
        reason: str,
        field_name: str,
        path: str,
        line: int,
        sample_limit: int,
    ) -> None:
        self.invalid_rows += 1
        self.file_invalid_rows[path] += 1
        self.rejection_reasons[reason] += 1
        if reason == "duplicate_row":
            self.duplicate_rows += 1
            self.file_duplicate_rows[path] += 1
        if reason == "missing_value":
            self.missing_value_counts[field_name] += 1
        if len(self.rejection_samples) < sample_limit:
            self.rejection_samples.append(
                {
                    "split": split,
                    "source_file": path,
                    "source_line": line,
                    "reason": reason,
                    "field": field_name,
                }
            )

    def accept(self, row: PreparedRow, split: SplitName) -> None:
        self.valid_rows += 1
        self.file_valid_rows[row.source_file] += 1
        self.split_valid_rows[split] += 1
        if row.is_attack:
            self.split_attack_rows[split] += 1
        self.label_rows[row.label] += 1

    def as_json(self) -> dict[str, object]:
        return {
            "total_rows": self.total_rows,
            "valid_rows": self.valid_rows,
            "invalid_rows": self.invalid_rows,
            "duplicate_rows": self.duplicate_rows,
            "files_read": self.files_read,
            "file_rows": dict(sorted(self.file_rows.items())),
            "file_valid_rows": dict(sorted(self.file_valid_rows.items())),
            "file_invalid_rows": dict(sorted(self.file_invalid_rows.items())),
            "file_duplicate_rows": dict(sorted(self.file_duplicate_rows.items())),
            "split_rows": dict(sorted(self.split_rows.items())),
            "split_valid_rows": dict(sorted(self.split_valid_rows.items())),
            "split_attack_rows": dict(sorted(self.split_attack_rows.items())),
            "label_rows": dict(sorted(self.label_rows.items())),
            "rejection_reasons": dict(sorted(self.rejection_reasons.items())),
            "missing_value_counts": dict(sorted(self.missing_value_counts.items())),
            "rejection_samples": self.rejection_samples,
        }


@dataclass(frozen=True)
class PreparationResult:
    output_dir: Path
    manifest: dict[str, object]
    processing_seconds: float


@dataclass
class NumericAccumulator:
    count: int = 0
    total: float = 0.0
    square_total: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf
    sample: list[float] = field(default_factory=list)

    def add(self, value: float) -> None:
        self.count += 1
        self.total += value
        self.square_total += value * value
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)
        # Deterministic bounded reservoir: this is for descriptive percentiles,
        # never model fitting. First values provide stable small-fixture results.
        if len(self.sample) < 10_000:
            self.sample.append(value)
        elif self.count % 9973 == 0:
            self.sample[(self.count // 9973) % len(self.sample)] = value

    def summary(self) -> dict[str, object]:
        if not self.count:
            return {"count": 0}
        values = sorted(self.sample)
        mean = self.total / self.count
        variance = max(0.0, self.square_total / self.count - mean * mean)

        def percentile(fraction: float) -> float:
            position = (len(values) - 1) * fraction
            lower, upper = math.floor(position), math.ceil(position)
            if lower == upper:
                return values[lower]
            return values[lower] + (values[upper] - values[lower]) * (position - lower)

        return {
            "count": self.count,
            "mean": mean,
            "median": median(values),
            "stddev_population": math.sqrt(variance),
            "min": self.minimum,
            "max": self.maximum,
            "p01": percentile(0.01),
            "p05": percentile(0.05),
            "p95": percentile(0.95),
            "p99": percentile(0.99),
            "percentiles_exact": self.count <= 10_000,
        }


@dataclass
class GroupStatistics:
    all: list[NumericAccumulator]
    benign: list[NumericAccumulator]
    attack: list[NumericAccumulator]

    @classmethod
    def create(cls, count: int) -> GroupStatistics:
        return cls(
            [NumericAccumulator() for _ in range(count)],
            [NumericAccumulator() for _ in range(count)],
            [NumericAccumulator() for _ in range(count)],
        )

    def add(self, row: PreparedRow) -> None:
        groups = [self.all, self.attack if row.is_attack else self.benign]
        for group in groups:
            for accumulator, value in zip(group, row.values):
                accumulator.add(value)

    def as_json(self, names: tuple[str, ...]) -> dict[str, object]:
        result: dict[str, object] = {}
        for label, group in (
            ("all", self.all), ("benign", self.benign), ("attack", self.attack)
        ):
            result[label] = {
                "count": group[0].count if group else 0,
                **{
                    name: accumulator.summary()
                    for name, accumulator in zip(names, group)
                },
            }
        return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_input(root: Path, relative: str, max_bytes: int) -> tuple[Path, str]:
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        raise DatasetError("input_path_escape") from None
    try:
        information = path.stat()
    except OSError:
        raise DatasetError("input_unreadable") from None
    if not stat.S_ISREG(information.st_mode):
        raise DatasetError("input_not_regular_file")
    if information.st_size > max_bytes:
        raise DatasetError("input_file_too_large")
    return path, relative


def _file_provenance(root: Path, relative: str, max_bytes: int) -> dict[str, object]:
    path, display_path = _safe_input(root, relative, max_bytes)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise DatasetError("input_unreadable") from None
    return {
        "path": display_path,
        "source_path": str(path),
        "bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def _fingerprint(path: str, row: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps([path, row], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def _normalise_parquet_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: ("" if value is None else str(value)) for key, value in row.items()}


def _row_from_mapping(
    row: dict[str, Any], relative: str, split: SplitName, line: int, config: PreparationConfig
) -> PreparedRow:
    mapped = map_cicids2017_row(row, config.features)
    return PreparedRow(mapped.values, mapped.label, mapped.is_attack, relative, line,
                       next(file.capture_group for file in config.files if file.path == relative))


def _record_rejection(
    error: InvalidRow | str,
    split: SplitName,
    path: str,
    line: int,
    quality: Quality | None,
    config: PreparationConfig,
) -> None:
    if quality is None:
        return
    if isinstance(error, InvalidRow):
        quality.reject(split, error.issue.code, error.issue.field, path, line, config.rejection_sample_limit)
    else:
        quality.reject(split, error, "row", path, line, config.rejection_sample_limit)


def _iter_csv(
    root: Path, file: Any, config: PreparationConfig, quality: Quality | None
) -> Iterator[PreparedRow]:
    path, relative = _safe_input(root, file.path, config.max_file_bytes)
    if quality is not None:
        quality.begin_file(relative)
    try:
        stream = path.open("rb")
    except OSError:
        raise DatasetError("input_unreadable") from None
    seen: set[str] = set()
    with stream:
        raw_header = stream.readline(config.max_record_bytes + 1)
        if not raw_header:
            raise DatasetError("empty_csv")
        try:
            header = [item.strip().lstrip("\ufeff") for item in next(
                csv.reader([raw_header.decode(config.encoding).rstrip("\r\n")], strict=True)
            )]
        except (StopIteration, UnicodeError, ValueError, csv.Error):
            raise DatasetError("invalid_csv") from None
        if len(header) != len(set(header)) or any(not item for item in header):
            raise DatasetError("invalid_header")
        if any(column not in header for column in ("Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Packets/s", "Label")):
            raise DatasetError("missing_required_columns")
        for line, raw in enumerate(stream, start=2):
            if quality is not None:
                quality.total_rows += 1
                quality.split_rows[file.split] += 1
                quality.file_rows[relative] += 1
                if quality.total_rows > config.max_rows:
                    raise DatasetError("row_limit_exceeded")
            if len(raw) > config.max_record_bytes:
                if not raw.endswith((b"\n", b"\r")):
                    for continuation in stream:
                        if continuation.endswith((b"\n", b"\r")):
                            break
                _record_rejection("record_too_large", file.split, relative, line, quality, config)
                continue
            try:
                values = next(csv.reader([raw.decode(config.encoding).rstrip("\r\n")], strict=True))
                if len(values) != len(header):
                    raise InvalidRow(RowIssue("malformed_csv", "row"))
                row = dict(zip(header, values))
                prepared = _row_from_mapping(row, relative, file.split, line, config)
                fingerprint = _fingerprint(relative, row)
                if fingerprint in seen:
                    _record_rejection("duplicate_row", file.split, relative, line, quality, config)
                    continue
                seen.add(fingerprint)
            except InvalidRow as error:
                _record_rejection(error, file.split, relative, line, quality, config)
                continue
            except (UnicodeError, ValueError, csv.Error, StopIteration):
                _record_rejection("malformed_csv", file.split, relative, line, quality, config)
                continue
            if quality is not None:
                quality.accept(prepared, file.split)
            yield prepared


def _iter_parquet(
    root: Path, file: Any, config: PreparationConfig, quality: Quality | None
) -> Iterator[PreparedRow]:
    try:
        from pyarrow import parquet  # type: ignore[import-untyped]
    except ImportError:
        raise DatasetError("parquet_dependency_missing") from None
    path, relative = _safe_input(root, file.path, config.max_file_bytes)
    try:
        parquet_file = parquet.ParquetFile(path)
        available_names = list(parquet_file.schema_arrow.names)
        available = set(available_names)
        required = {"Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Packets/s", "Label"}
        if not required.issubset(available):
            raise DatasetError("missing_required_columns")
        # Read the complete row for the documented exact-row duplicate policy.
        # Mapping still selects only the conservative three model features.
        columns = available_names
        if quality is not None:
            quality.begin_file(relative)
        seen: set[str] = set()
        line = 0
        for batch in parquet_file.iter_batches(columns=columns, batch_size=config.parquet_batch_size, use_threads=False):
            for raw_row in batch.to_pylist():
                line += 1
                if quality is not None:
                    quality.total_rows += 1
                    quality.split_rows[file.split] += 1
                    quality.file_rows[relative] += 1
                    if quality.total_rows > config.max_rows:
                        raise DatasetError("row_limit_exceeded")
                row = _normalise_parquet_row(raw_row)
                try:
                    prepared = _row_from_mapping(row, relative, file.split, line, config)
                except InvalidRow as error:
                    _record_rejection(error, file.split, relative, line, quality, config)
                    continue
                fingerprint = _fingerprint(relative, row)
                if fingerprint in seen:
                    _record_rejection("duplicate_row", file.split, relative, line, quality, config)
                    continue
                seen.add(fingerprint)
                if quality is not None:
                    quality.accept(prepared, file.split)
                yield prepared
    except DatasetError:
        raise
    except Exception:  # noqa: BLE001 - normalize all PyArrow reader failures
        raise DatasetError("malformed_parquet") from None


def _iter_source(
    root: Path, file: Any, config: PreparationConfig, quality: Quality | None
) -> Iterator[PreparedRow]:
    if file.source_format == "parquet":
        yield from _iter_parquet(root, file, config, quality)
    else:
        yield from _iter_csv(root, file, config, quality)


def _fit_preprocessing(train: GroupStatistics, names: tuple[str, ...], kind: str) -> dict[str, object]:
    if kind == "none":
        return {"version": "preprocessing.v1", "kind": "none", "features": list(names), "parameters": {}}
    parameters: dict[str, dict[str, float]] = {}
    for name, accumulator in zip(names, train.all):
        summary = accumulator.summary()
        mean = float(cast(float, summary["mean"]))
        stddev = float(cast(float, summary["stddev_population"]))
        parameters[name] = {"mean": mean, "stddev": stddev, "scale": stddev if stddev else 1.0}
    return {"version": "preprocessing.v1", "kind": kind, "features": list(names), "parameters": parameters}


def _transform(row: PreparedRow, preprocessing: dict[str, object], names: tuple[str, ...]) -> tuple[float, ...]:
    if preprocessing["kind"] == "none":
        return row.values
    parameters = cast(dict[str, dict[str, float]], preprocessing["parameters"])
    return tuple((value - parameters[name]["mean"]) / parameters[name]["scale"] for name, value in zip(names, row.values))


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _artifact_sizes(paths: Sequence[Path]) -> dict[str, int]:
    return {path.name: path.stat().st_size for path in sorted(paths, key=lambda item: item.name)}


def _artifact_hashes(paths: Sequence[Path]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(paths, key=lambda item: item.name):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[path.name] = digest.hexdigest()
    return result


def _assert_passes_match(first: Quality, second: Quality) -> None:
    fields = ("total_rows", "valid_rows", "invalid_rows", "duplicate_rows")
    if any(getattr(first, field) != getattr(second, field) for field in fields):
        raise DatasetError("input_changed_during_preparation")
    if (
        first.file_rows != second.file_rows
        or first.file_valid_rows != second.file_valid_rows
        or first.file_invalid_rows != second.file_invalid_rows
        or first.file_duplicate_rows != second.file_duplicate_rows
    ):
        raise DatasetError("input_changed_during_preparation")


def prepare_dataset(config: PreparationConfig, dataset_root: Path, output_dir: Path, *, force: bool = False) -> PreparationResult:
    started = time.perf_counter()
    root = dataset_root.resolve()
    if not root.is_dir():
        raise DatasetError("dataset_root_unreadable")
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if not force and any(output_dir.iterdir()):
        raise DatasetError("output_exists")
    if force:
        for child in output_dir.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink()
            else:
                raise DatasetError("output_not_flat")
    provenance = {
        file.path: _file_provenance(root, file.path, config.max_file_bytes)
        for file in config.files
    }
    quality = Quality()
    train_stats = GroupStatistics.create(len(config.features))
    for file in config.files:
        for row in _iter_source(root, file, config, quality):
            if file.split == "train_normal":
                train_stats.add(row)
    if not quality.split_valid_rows["train_normal"]:
        raise DatasetError("empty_train_normal")
    if quality.split_attack_rows["train_normal"]:
        raise DatasetError("train_contains_attack")
    for split in ("validation", "test"):
        count = quality.split_valid_rows[split]
        attacks = quality.split_attack_rows[split]
        if config.require_mixed_evaluation and (not count or not attacks or attacks == count):
            raise DatasetError("evaluation_not_mixed")
    preprocessing = _fit_preprocessing(train_stats, config.features, config.preprocessing)
    stats_by_split = {split: GroupStatistics.create(len(config.features)) for split in SPLITS}
    feature_headers = [str(feature) for feature in config.features]
    metadata_header = ["label", "is_attack", "source_file", "source_line", "capture_group"]
    feature_files: dict[str, Any] = {}
    metadata_files: dict[str, Any] = {}
    writers: dict[str, tuple[Any, Any]] = {}
    split_labels: dict[str, Counter[str]] = {split: Counter() for split in SPLITS}
    try:
        for split in SPLITS:
            feature_path = output_dir / f"{split}_features.csv.tmp"
            metadata_path = output_dir / f"{split}_metadata.csv.tmp"
            feature_files[split] = feature_path.open("w", encoding="utf-8", newline="")
            metadata_files[split] = metadata_path.open("w", encoding="utf-8", newline="")
            feature_writer = csv.writer(feature_files[split], lineterminator="\n")
            metadata_writer = csv.writer(metadata_files[split], lineterminator="\n")
            feature_writer.writerow(feature_headers)
            metadata_writer.writerow(metadata_header)
            writers[split] = (feature_writer, metadata_writer)
        second_quality = Quality()
        for file in config.files:
            for row in _iter_source(root, file, config, second_quality):
                split = file.split
                transformed = _transform(row, preprocessing, config.features)
                writers[split][0].writerow(transformed)
                writers[split][1].writerow([row.label, str(row.is_attack).lower(), row.source_file, row.source_line, row.capture_group])
                stats_by_split[split].add(row)
                split_labels[split][row.label] += 1
        _assert_passes_match(quality, second_quality)
    finally:
        for stream in [*feature_files.values(), *metadata_files.values()]:
            stream.close()
    for split in SPLITS:
        (output_dir / f"{split}_features.csv.tmp").replace(output_dir / f"{split}_features.csv")
        (output_dir / f"{split}_metadata.csv.tmp").replace(output_dir / f"{split}_metadata.csv")
    stats = {split: stats_by_split[split].as_json(config.features) for split in ("train_normal", "validation")}
    if config.include_test_statistics:
        stats["test"] = stats_by_split["test"].as_json(config.features)
    _write_json(output_dir / "quality.json", quality.as_json())
    _write_json(output_dir / "preprocessing.json", preprocessing)
    _write_json(output_dir / "statistics.json", stats)
    deterministic_artifacts = [
        output_dir / f"{split}_{kind}.csv"
        for split in SPLITS
        for kind in ("features", "metadata")
    ] + [
        output_dir / name for name in ("quality.json", "preprocessing.json", "statistics.json")
    ]
    manifest: dict[str, object] = {
        "manifest_version": "dataset_manifest.v1",
        "dataset_id": config.dataset_id,
        "dataset_source": config.dataset_source,
        "dataset_version": config.dataset_version,
        "subset_description": config.subset_description,
        "source_root": str(root),
        "selected_files": [file.model_dump() | {"capture_group": file.capture_group} | provenance[file.path] | {"rows_total": quality.file_rows[file.path], "rows_valid": quality.file_valid_rows[file.path], "rows_invalid": quality.file_invalid_rows[file.path], "duplicates": quality.file_duplicate_rows[file.path]} for file in config.files],
        "feature_mapping_version": config.mapping_version,
        "duplicate_policy": config.duplicate_policy,
        "features": list(config.features),
        "labels_separate_from_features": True,
        "label_column": "label",
        "evaluation_metadata_column": "is_attack",
        "split_seed": config.split_seed,
        "split_strategy": config.split_strategy,
        "target_proportions": list(config.target_proportions),
        "preprocessing": preprocessing,
        "counts": {"total_rows": quality.total_rows, "valid_rows": quality.valid_rows, "invalid_rows": quality.invalid_rows, "duplicate_rows": quality.duplicate_rows, "split_input_rows": dict(quality.split_rows), "split_valid_rows": dict(quality.split_valid_rows)},
        "label_composition": {split: dict(split_labels[split]) for split in SPLITS},
        "artifact_sha256": _artifact_hashes(deterministic_artifacts),
        "artifact_sizes_bytes": _artifact_sizes(deterministic_artifacts),
        "code_version": os.environ.get("INTRIQO_CODE_VERSION", "working-tree"),
        "model_implementation": None,
        "known_limitations": ["CICFlowMeter payload byte totals are not mapped to Intriqo IPv4 total-byte counters.", "CIC-IDS2017 TCP flag counts are excluded due to documented CICFlowMeter-V3 defects.", "Explicit capture-day groups are used; no row-wise random split is performed."],
    }
    _write_json(output_dir / "dataset_manifest.json", manifest)
    return PreparationResult(output_dir, manifest, time.perf_counter() - started)


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Prepare leakage-safe CIC-IDS2017 evaluation data")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--force", action="store_true", help="replace existing preparation artifacts")
    args = parser.parse_args(argv)
    try:
        result = prepare_dataset(load_config(args.config), args.dataset_root, args.output_dir, force=args.force)
    except DatasetError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"output_dir": str(result.output_dir), "counts": result.manifest["counts"], "processing_seconds": result.processing_seconds}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
