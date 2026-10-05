"""Small deterministic fixtures for dataset mapping and preparation."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pyarrow as pa
import pytest
from intriqo_ml.datasets import DatasetError, PreparationConfig, map_cicids2017_row
from intriqo_ml.datasets.config import InputFile, load_config
from intriqo_ml.datasets.mapping import InvalidRow, project_flow_features
from intriqo_ml.datasets.prepare import prepare_dataset
from pyarrow import parquet

HEADER = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Packets/s",
    "Label",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "SYN Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
]


def row(
    duration: str, forward: str, backward: str, label: str, *, rate: str | None = None
) -> list[str]:
    packets = int(forward) + int(backward)
    seconds = int(duration) / 1_000_000
    flow_rate = str(packets / seconds) if rate is None and seconds else (rate or "0")
    return [
        duration,
        forward,
        backward,
        flow_rate,
        label,
        "80",
        "40",
        "120",
        "1",
        "0",
        "0",
    ]


def write_csv(path: Path, rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(HEADER)
        writer.writerows(rows)


def write_parquet(path: Path, rows: list[list[str]]) -> None:
    columns = {
        name: [value for value in values]
        for name, values in zip(HEADER, zip(*rows))
    }
    parquet.write_table(pa.table(columns), path)


def write_fixture(root: Path) -> None:
    write_csv(
        root / "Monday-fixture.csv",
        [
            row("1000000", "1", "1", "BENIGN"),
            row("2000000", "2", "1", "BENIGN"),
            row("3000000", "3", "1", "BENIGN"),
            row("3000000", "3", "1", "BENIGN"),
            ["", "1", "1", "2", "BENIGN", "80", "40", "120", "1", "0", "0"],
        ],
    )
    write_csv(
        root / "Tuesday-fixture.csv",
        [
            row("4000000", "1", "1", "BENIGN"),
            row("5000000", "2", "1", "FTP-Patator"),
            row("6000000", "3", "1", "BENIGN"),
        ],
    )
    write_csv(
        root / "Wednesday-fixture.csv",
        [
            row("7000000", "1", "1", "BENIGN"),
            row("8000000", "2", "1", "DDoS"),
            row("9000000", "3", "1", "BENIGN"),
        ],
    )


def config() -> PreparationConfig:
    return PreparationConfig(
        dataset_version="fixture.cicids2017-projection.v1",
        subset_description="tiny deterministic test fixture",
        files=(
            InputFile(path="Monday-fixture.csv", split="train_normal"),
            InputFile(path="Tuesday-fixture.csv", split="validation"),
            InputFile(path="Wednesday-fixture.csv", split="test"),
        ),
        preprocessing="standardize_train_only",
        include_test_statistics=True,
        timestamp_utc="2026-01-01T00:00:00Z",
        max_rows=100,
        max_record_bytes=4096,
    )


def parquet_config() -> PreparationConfig:
    value = config().model_dump(mode="python")
    value["files"] = tuple(
        {**item, "path": item["path"].replace(".csv", ".parquet"), "format": "parquet"}
        for item in value["files"]
    )
    return PreparationConfig.model_validate(value)


def write_parquet_fixture(root: Path) -> None:
    write_parquet(
        root / "Monday-fixture.parquet",
        [
            row("1000000", "1", "1", "BENIGN"),
            row("2000000", "2", "1", "BENIGN"),
            row("3000000", "3", "1", "BENIGN"),
            row("3000000", "3", "1", "BENIGN"),
            ["", "1", "1", "2", "BENIGN", "80", "40", "120", "1", "0", "0"],
        ],
    )
    write_parquet(
        root / "Tuesday-fixture.parquet",
        [row("4000000", "1", "1", "BENIGN"), row("5000000", "2", "1", "FTP-Patator"), row("6000000", "3", "1", "BENIGN")],
    )
    write_parquet(
        root / "Wednesday-fixture.parquet",
        [row("7000000", "1", "1", "BENIGN"), row("8000000", "2", "1", "DDoS"), row("9000000", "3", "1", "BENIGN")],
    )


def test_mapping_is_explicit_and_units_are_converted() -> None:
    mapped = map_cicids2017_row(dict(zip(HEADER, row("2000000", "2", "1", "BENIGN"))))
    assert mapped.values == (2.0, 3.0, 1.5)
    assert mapped.label == "BENIGN" and not mapped.is_attack


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("Flow Duration", "", "missing_value"),
        ("Flow Packets/s", "NaN", "nonfinite"),
        ("Flow Packets/s", "Infinity", "nonfinite"),
        ("Flow Duration", "-1", "numeric_range"),
        ("Total Fwd Packets", "1.5", "fractional_count"),
        ("Total Backward Packets", "-1", "numeric_range"),
        ("Flow Packets/s", "99", "inconsistent_rate"),
    ],
)
def test_invalid_numeric_and_missing_values_are_rejected(
    field: str, value: str, code: str
) -> None:
    values = row("1000000", "1", "1", "BENIGN")
    values[HEADER.index(field)] = value
    with pytest.raises(InvalidRow) as caught:
        map_cicids2017_row(dict(zip(HEADER, values)))
    assert caught.value.issue.code == code


def test_feature_projection_does_not_add_columns() -> None:
    class Features:
        duration_seconds = 2.0
        packet_count = 3
        packets_per_second = 1.5

    class Record:
        features = Features()

    assert project_flow_features(Record()) == (2.0, 3.0, 1.5)  # type: ignore[arg-type]


def test_unsupported_feature_is_rejected() -> None:
    class Features:
        duration_seconds = 2.0

    class Record:
        features = Features()

    with pytest.raises(DatasetError, match="unsupported_feature"):
        project_flow_features(Record(), ("duration_seconds", "not_a_feature"))  # type: ignore[arg-type]


def test_config_rejects_group_crossing_and_invalid_paths() -> None:
    with pytest.raises(ValueError):
        PreparationConfig(
            dataset_version="x",
            subset_description="x",
            files=(
                InputFile(path="Monday-a.csv", split="train_normal"),
                InputFile(path="Monday-b.csv", split="validation"),
                InputFile(path="Wednesday-c.csv", split="test"),
            ),
        )
    with pytest.raises(ValueError):
        InputFile(path="../Monday-a.csv", split="train_normal")


def test_prepare_emits_separate_features_metadata_quality_manifest_and_stats(
    tmp_path: Path,
) -> None:
    write_fixture(tmp_path)
    output = tmp_path / "output"
    result = prepare_dataset(config(), tmp_path, output)
    manifest = result.manifest
    quality = json.loads((output / "quality.json").read_text())
    assert manifest["model_implementation"] is None
    assert manifest["labels_separate_from_features"] is True
    assert manifest["counts"]["total_rows"] == 11
    assert manifest["counts"]["valid_rows"] == 9
    assert manifest["counts"]["invalid_rows"] == 2
    assert manifest["counts"]["duplicate_rows"] == 1
    assert manifest["counts"]["split_valid_rows"] == {
        "train_normal": 3, "validation": 3, "test": 3,
    }
    assert all("sha256" in item for item in manifest["selected_files"])
    assert quality["rejection_reasons"] == {"duplicate_row": 1, "missing_value": 1}
    train_features = (output / "train_normal_features.csv").read_text()
    train_metadata = (output / "train_normal_metadata.csv").read_text()
    assert "label" not in train_features and "is_attack" not in train_features
    assert "BENIGN" in train_metadata
    assert all(
        line.split(",")[1] == "false" for line in train_metadata.splitlines()[1:]
    )
    preprocessing = json.loads((output / "preprocessing.json").read_text())
    assert preprocessing["kind"] == "standardize_train_only"
    assert preprocessing["parameters"]["duration_seconds"]["mean"] == pytest.approx(2.0)
    validation_metadata = (output / "validation_metadata.csv").read_text()
    test_metadata = (output / "test_metadata.csv").read_text()
    assert "true" in validation_metadata and "false" in validation_metadata
    assert "true" in test_metadata and "false" in test_metadata
    stats = json.loads((output / "statistics.json").read_text())
    assert stats["train_normal"]["benign"]["count"] == 3
    assert stats["validation"]["attack"]["count"] == 1
    assert stats["test"]["attack"]["count"] == 1


def test_parquet_preparation_matches_csv_projection_and_keeps_labels_separate(
    tmp_path: Path,
) -> None:
    csv_root = tmp_path / "csv"
    parquet_root = tmp_path / "parquet"
    csv_root.mkdir(); parquet_root.mkdir()
    write_fixture(csv_root)
    write_parquet_fixture(parquet_root)
    csv_output = tmp_path / "csv-output"
    parquet_output = tmp_path / "parquet-output"
    prepare_dataset(config(), csv_root, csv_output)
    result = prepare_dataset(parquet_config(), parquet_root, parquet_output)
    assert result.manifest["selected_files"][0]["format"] == "parquet"
    assert result.manifest["duplicate_policy"] == "exact_row_within_source_file.v1"
    for name in (
        "train_normal_features.csv", "validation_features.csv",
        "test_features.csv", "statistics.json",
    ):
        assert (csv_output / name).read_bytes() == (parquet_output / name).read_bytes(), name
    def metadata_semantics(path: Path) -> list[tuple[str, str, str]]:
        with path.open(newline="") as stream:
            rows = list(csv.reader(stream))[1:]
        return [(row[0], row[1], row[4]) for row in rows]

    assert metadata_semantics(parquet_output / "train_normal_metadata.csv") == metadata_semantics(
        csv_output / "train_normal_metadata.csv"
    )
    assert "label" not in (parquet_output / "train_normal_features.csv").read_text()
    assert "BENIGN" in (parquet_output / "train_normal_metadata.csv").read_text()


def test_parquet_missing_columns_and_malformed_file_are_rejected(tmp_path: Path) -> None:
    root = tmp_path / "parquet"
    root.mkdir()
    write_parquet_fixture(root)
    bad = {name: ["1"] for name in HEADER if name != "Label"}
    parquet.write_table(pa.table(bad), root / "Monday-fixture.parquet")
    with pytest.raises(DatasetError, match="missing_required_columns"):
        prepare_dataset(parquet_config(), root, tmp_path / "missing-columns")

    write_parquet_fixture(root)
    (root / "Tuesday-fixture.parquet").write_bytes(b"not parquet")
    with pytest.raises(DatasetError, match="malformed_parquet"):
        prepare_dataset(parquet_config(), root, tmp_path / "malformed")


def test_parquet_null_nonfinite_and_negative_values_are_counted(tmp_path: Path) -> None:
    root = tmp_path / "parquet"
    root.mkdir()
    write_parquet_fixture(root)
    invalid = [
        [None, "1", "1", "2", "BENIGN", "80", "40", "120", "1", "0", "0"],
        ["1000000", "1", "1", "nan", "BENIGN", "80", "40", "120", "1", "0", "0"],
        ["-1", "1", "1", "-2", "BENIGN", "80", "40", "120", "1", "0", "0"],
    ]
    invalid.append(row("1000000", "1", "1", "BENIGN"))
    parquet.write_table(pa.table({name: [values[i] for values in invalid] for i, name in enumerate(HEADER)}), root / "Monday-fixture.parquet")
    result = prepare_dataset(parquet_config(), root, tmp_path / "invalid-output")
    quality = json.loads((result.output_dir / "quality.json").read_text())
    assert quality["invalid_rows"] >= 3
    assert quality["rejection_reasons"]["missing_value"] >= 1
    assert quality["rejection_reasons"]["nonfinite"] >= 1
    assert quality["rejection_reasons"]["numeric_range"] >= 1


def test_same_input_and_fixed_config_are_byte_reproducible(tmp_path: Path) -> None:
    write_fixture(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    prepare_dataset(config(), tmp_path, first)
    prepare_dataset(config(), tmp_path, second)
    names = sorted(path.name for path in first.iterdir())
    assert names == sorted(path.name for path in second.iterdir())
    for name in names:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


def test_malformed_rows_are_counted_without_crashing(tmp_path: Path) -> None:
    write_fixture(tmp_path)
    with (tmp_path / "Monday-fixture.csv").open("a", encoding="utf-8") as stream:
        stream.write("malformed-only-one-column\n")
    result = prepare_dataset(config(), tmp_path, tmp_path / "output")
    quality = json.loads((result.output_dir / "quality.json").read_text())
    assert quality["rejection_reasons"]["malformed_csv"] == 1


def test_cli_config_load_and_force_behavior(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    write_fixture(tmp_path)
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(config().model_dump(mode="json")), encoding="utf-8"
    )
    loaded = load_config(config_path)
    assert loaded == config()
    output = tmp_path / "output"
    from intriqo_ml.datasets.prepare import main

    args = [
        "--config",
        str(config_path),
        "--dataset-root",
        str(tmp_path),
        "--output-dir",
        str(output),
    ]
    assert main(args) == 0
    assert "output_dir" in capsys.readouterr().out
    assert main(args) == 2
    assert "output_exists" in capsys.readouterr().err
    assert main(args + ["--force"]) == 0
