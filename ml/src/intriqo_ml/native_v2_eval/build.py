"""Build a controlled native-v2 corpus from captured PCAPs and manifests."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from intriqo_ml.flow_features_v2 import FEATURES_V2, project_flow_features_v2

from .alignment import AlignmentRow, align_records
from .quality import build_quality_report
from .replay import replay_native_v2
from .schema import (
    CaptureManifest,
    DatasetManifest,
    ExperimentManifest,
    SplitDefinition,
    load_model,
    sha256_file,
    write_model,
)
from .splits import validate_splits


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_alignment(path: Path, rows: list[AlignmentRow]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row.as_dict(), sort_keys=True) + "\n")


def _write_feature_outputs(
    output_dir: Path,
    records: list[tuple[str, int, Any]],
    alignment_rows: list[AlignmentRow],
    split_by_capture: dict[str, str],
) -> None:
    with (output_dir / "features.csv").open("w", newline="", encoding="utf-8") as feature_stream, (
        output_dir / "metadata.csv"
    ).open("w", newline="", encoding="utf-8") as metadata_stream:
        features = csv.writer(feature_stream, lineterminator="\n")
        metadata = csv.writer(metadata_stream, lineterminator="\n")
        features.writerow(FEATURES_V2)
        metadata.writerow(
            (
                "capture_id",
                "native_line_number",
                "engine_instance_id",
                "flow_id",
                "first_seen",
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "split",
                "label_status",
                "label",
                "attack_family",
                "source_label_id",
            )
        )
        for (capture_id, line_number, record), alignment in zip(
            records, alignment_rows, strict=True
        ):
            features.writerow(project_flow_features_v2(record))
            network = record.metadata.network
            metadata.writerow(
                (
                    capture_id,
                    line_number,
                    record.metadata.engine_instance_id,
                    record.metadata.flow_id,
                    record.metadata.first_seen,
                    record.metadata.timestamp,
                    network.src_ip,
                    network.dst_ip,
                    network.src_port,
                    network.dst_port,
                    network.protocol,
                    split_by_capture.get(capture_id, "UNASSIGNED"),
                    alignment.match_status,
                    alignment.label or "",
                    alignment.attack_family or "",
                    alignment.source_label_id or "",
                )
            )


def _write_native_jsonl(path: Path, records: list[tuple[str, int, Any]]) -> None:
    with path.open("w", encoding="utf-8") as stream:
        for _, _, record in records:
            stream.write(record.model_dump_json() + "\n")


def build_corpus(
    *,
    experiment_manifest_path: Path,
    capture_manifest_path: Path,
    split_definition_path: Path,
    output_dir: Path,
    engine: Path | None = None,
) -> dict[str, Any]:
    """Build derived artifacts without mutating any input manifest or PCAP."""
    experiment_manifest = load_model(experiment_manifest_path, ExperimentManifest)
    capture_manifest = load_model(capture_manifest_path, CaptureManifest)
    split_definition = load_model(split_definition_path, SplitDefinition)
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True)

    known_experiments = {row.experiment_id for row in experiment_manifest.experiments}
    unknown_capture_experiments = sorted(
        {
            entry.experiment_id
            for entry in capture_manifest.captures
            if entry.experiment_id not in known_experiments
        }
    )
    if unknown_capture_experiments:
        raise ValueError(
            "capture references undeclared experiment(s): "
            + ", ".join(unknown_capture_experiments)
        )

    split_by_capture = {
        assignment.capture_id: assignment.split for assignment in split_definition.assignments
    }
    split_validation = validate_splits(capture_manifest, split_definition)
    all_records: list[tuple[str, int, Any]] = []
    all_alignment: list[AlignmentRow] = []
    replay_reports: list[dict[str, Any]] = []
    captured_entries = [entry for entry in capture_manifest.captures if entry.status == "CAPTURED"]
    for entry in captured_entries:
        if engine is None:
            raise ValueError("engine is required when CAPTURED entries are present")
        pcap = Path(entry.source_path)
        if pcap.stat().st_size != entry.byte_size or sha256_file(pcap) != entry.sha256:
            raise ValueError(f"capture provenance mismatch: {entry.capture_id}")
        replay = replay_native_v2(
            capture_id=entry.capture_id,
            pcap=pcap,
            engine=engine,
            output_dir=output_dir / "replay" / entry.capture_id,
        )
        replay_report = dict(replay.report)
        replay_report["split"] = split_by_capture.get(entry.capture_id)
        replay_reports.append(replay_report)
        records = [(entry.capture_id, line, record) for line, record in replay.records]
        all_records.extend(records)
        all_alignment.extend(
            align_records(
                list(replay.records),
                capture_id=entry.capture_id,
                capture_experiment_id=entry.experiment_id,
                manifest=experiment_manifest,
            )
        )

    # Check native row and source-label leakage after rows exist.
    split_validation = validate_splits(capture_manifest, split_definition, all_alignment)
    _write_native_jsonl(output_dir / "native_features_v2.jsonl", all_records)
    _write_feature_outputs(output_dir, all_records, all_alignment, split_by_capture)
    _write_alignment(output_dir / "alignment_report.jsonl", all_alignment)
    quality = build_quality_report(
        records=all_records,
        alignment_rows=all_alignment,
        captures=capture_manifest,
        split_validation=split_validation,
        replay_reports=replay_reports,
    )
    _write_json(output_dir / "quality_report.json", quality)

    provenance = {
        "schema_version": "controlled_provenance_report.v1",
        "corpus_name": "CONTROLLED NATIVE INTRIQO EVALUATION",
        "original_pcaps_immutable": True,
        "captures": [entry.model_dump(mode="json") for entry in capture_manifest.captures],
        "replays": replay_reports,
        "unacquired_or_unrun": not bool(captured_entries),
    }
    _write_json(output_dir / "provenance_report.json", provenance)
    alignment_summary = {
        "schema_version": "controlled_alignment_report.v1",
        "row_file": "alignment_report.jsonl",
        "rows": len(all_alignment),
        "status_counts": {
            status: sum(1 for row in all_alignment if row.match_status == status)
            for status in ("EXACT", "PARTIAL", "AMBIGUOUS", "UNKNOWN")
        },
        "unknown_is_never_benign": True,
        "eligible_policy": "EXACT only",
    }
    _write_json(output_dir / "alignment_report.json", alignment_summary)
    _write_json(
        output_dir / "artifact_hashes.json",
        {
            name: sha256_file(output_dir / name)
            for name in (
                "native_features_v2.jsonl",
                "features.csv",
                "metadata.csv",
                "alignment_report.jsonl",
                "alignment_report.json",
                "quality_report.json",
                "provenance_report.json",
            )
        },
    )
    status = (
        "CONTROLLED_DATASET_DESIGNED"
        if captured_entries and quality["status"] == "PASS"
        else "BLOCKED_ON_CONTROLLED_CAPTURE"
    )
    manifest = DatasetManifest(
        dataset_id=experiment_manifest.corpus_id,
        status=status,
        ready_for_model_training=bool(quality["ready_for_model_training"]),
        experiment_manifest=str(experiment_manifest_path),
        capture_manifest=str(capture_manifest_path),
        split_definition=str(split_definition_path),
        alignment_report="alignment_report.jsonl",
        quality_report="quality_report.json",
        provenance_report="provenance_report.json",
        artifact_sha256={
            name: sha256_file(output_dir / name)
            for name in (
                "native_features_v2.jsonl",
                "features.csv",
                "metadata.csv",
                "alignment_report.jsonl",
                "alignment_report.json",
                "quality_report.json",
                "provenance_report.json",
                "artifact_hashes.json",
            )
        },
    )
    write_model(output_dir / "dataset_manifest.json", manifest)
    return manifest.model_dump(mode="json")
