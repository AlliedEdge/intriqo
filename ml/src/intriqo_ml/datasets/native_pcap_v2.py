"""Controlled <=1 MiB native PCAP prototype, not a labelled CIC training set.

No CICFlowMeter CSV/Parquet fields enter this pipeline. Labels require a separate
reviewed native-flow association policy; prototype output cannot be trained.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from intriqo_ml.flow_features_v2 import (
    FEATURES_V2,
    IAT_POLICY,
    parse_flow_feature_record_v2,
    project_flow_features_v2,
)

from .config import DatasetError


@dataclass(frozen=True)
class NativePrototypeResult:
    output_dir: Path
    flow_count: int


def prepare_native_pcap_v2(
    pcap: Path, engine: Path, output_dir: Path,
) -> NativePrototypeResult:
    """Replay a small controlled input and validate every emitted native record.

    Whole real capture/day processing and automatic label association are gated.
    Reject obvious held-out paths BEFORE opening them; no test split API exists.
    """
    if "wednesday" in str(pcap).lower() or "test" in pcap.parts:
        raise DatasetError("held_out_input_prohibited")
    if pcap.suffix.lower() != ".pcap":
        raise DatasetError("native_pcap_required")
    if not pcap.is_file() or pcap.stat().st_size > 1_048_576:
        raise DatasetError("controlled_pcap_size_limit")
    if not engine.is_file():
        raise DatasetError("engine_unavailable")
    if output_dir.exists():
        raise DatasetError("output_exists")
    output_dir.mkdir(parents=True)
    stream = output_dir / "native_features_v2.jsonl"
    command = [str(engine.resolve()), "--pcap", str(pcap.resolve()),
               "--feature-schema", "flow_features.v2", "--feature-output", str(stream.resolve()),
               "--output", str((output_dir / "events.jsonl").resolve()),
               "--flow-idle-timeout", "1", "--max-active-flows", "100000"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    shutdown = next((line for line in result.stdout.splitlines() if line.startswith("shutdown ")), "")
    counters = dict(token.split("=", 1) for token in shutdown.split() if "=" in token)
    if result.returncode != 0 or not all(counters.get(name) == "0" for name in (
        "feature_setup_failures", "feature_generation_failures", "feature_records_dropped",
        "feature_write_failures", "feature_validation_failures", "capture_errors",
        "packets_unsupported", "packets_truncated",
    )):
        raise DatasetError("native_feature_replay_failed")
    with stream.open("rb") as source:
        records = [parse_flow_feature_record_v2(line) for line in source]
    if not records:
        raise DatasetError("empty_native_feature_stream")
    if counters.get("feature_records_written") != str(len(records)):
        raise DatasetError("incomplete_native_feature_stream")
    with (output_dir / "features.csv").open("w", newline="") as feature_file, (
        output_dir / "metadata.csv"
    ).open("w", newline="") as metadata_file:
        features = csv.writer(feature_file)
        metadata = csv.writer(metadata_file)
        features.writerow(FEATURES_V2)
        metadata.writerow(("engine_instance_id", "flow_id", "first_seen", "timestamp",
                           "export_reason", "label_status"))
        for record in records:
            features.writerow(project_flow_features_v2(record))
            m = record.metadata
            metadata.writerow((m.engine_instance_id, m.flow_id, m.first_seen, m.timestamp,
                               m.export_reason, "UNLABELLED"))
    manifest = {
        "schema_version": "native_pcap_prototype.v2",
        "feature_schema": "flow_features.v2",
        "features": list(FEATURES_V2), "flow_count": len(records),
        "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "engine_sha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
        "iat_policy": IAT_POLICY, "flow_idle_timeout_seconds": 1,
        "max_active_flows": 100000, "preprocessing": "none",
        "row_policy": "retain every emitted native flow; no deduplication or repair",
        "training_ready": False, "label_status": "UNLABELLED",
        "official_cic_flow_alignment_established": False,
        "gate": "controlled prototype only; official native-flow labels and real capture provenance required",
        "artifact_sha256": {name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest()
                            for name in ("native_features_v2.jsonl", "features.csv", "metadata.csv")},
    }
    (output_dir / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return NativePrototypeResult(output_dir, len(records))


def main() -> None:
    parser = argparse.ArgumentParser(description="Small unlabelled native v2 PCAP prototype")
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare_native_pcap_v2(args.pcap, args.engine, args.output_dir)
    except (DatasetError, OSError, subprocess.SubprocessError, ValueError):
        parser.exit(1, "native v2 prototype failed; no training dataset declared\n")
    print(f"native_flows={result.flow_count} training_ready=false")


if __name__ == "__main__":
    main()
