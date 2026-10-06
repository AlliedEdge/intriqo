"""Run the existing C++ engine in explicit native-v2 PCAP mode."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from intriqo_ml.flow_features_v2 import (
    FlowFeatureRecordV2,
    iter_flow_feature_records_v2,
)

from .schema import sha256_file

_ZERO_REQUIRED = (
    "feature_setup_failures",
    "feature_generation_failures",
    "feature_records_dropped",
    "feature_write_failures",
    "feature_validation_failures",
    "capture_errors",
    "packets_unsupported",
    "packets_truncated",
)


@dataclass(frozen=True)
class ReplayResult:
    capture_id: str
    output_dir: Path
    records: tuple[tuple[int, FlowFeatureRecordV2], ...]
    parser_errors: tuple[dict[str, str | int], ...]
    report: dict[str, Any]


def _parse_shutdown(stdout: str) -> dict[str, str]:
    line = next((line for line in stdout.splitlines() if line.startswith("shutdown ")), "")
    return dict(token.split("=", 1) for token in line.split() if "=" in token)


def _int_counter(counters: dict[str, str], name: str) -> int | None:
    value = counters.get(name)
    if value is None or value == "N/A":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def replay_native_v2(
    *,
    capture_id: str,
    pcap: Path,
    engine: Path,
    output_dir: Path,
    flow_idle_timeout: float = 1.0,
    max_active_flows: int = 100_000,
) -> ReplayResult:
    """Replay one immutable PCAP and retain all parser/replay evidence."""
    if not pcap.is_file():
        raise FileNotFoundError(pcap)
    if not engine.is_file():
        raise FileNotFoundError(engine)
    if output_dir.exists():
        raise FileExistsError(output_dir)
    output_dir.mkdir(parents=True)
    stream = output_dir / "native_features_v2.jsonl"
    events = output_dir / "events.jsonl"
    command = [
        str(engine.resolve()),
        "--pcap",
        str(pcap.resolve()),
        "--feature-schema",
        "flow_features.v2",
        "--feature-output",
        str(stream.resolve()),
        "--output",
        str(events.resolve()),
        "--flow-idle-timeout",
        str(flow_idle_timeout),
        "--max-active-flows",
        str(max_active_flows),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    counters = _parse_shutdown(completed.stdout)
    records: list[tuple[int, FlowFeatureRecordV2]] = []
    parser_errors: list[dict[str, str | int]] = []
    if stream.exists():
        with stream.open("rb") as source:
            for line in iter_flow_feature_records_v2(source):
                if line.record is not None:
                    records.append((line.line_number, line.record))
                elif line.error is not None:
                    parser_errors.append({"line_number": line.line_number, "code": line.error.code})
    zero_failures = {
        name: _int_counter(counters, name) for name in _ZERO_REQUIRED
    }
    complete = (
        completed.returncode == 0
        and counters.get("status") == "complete"
        and bool(counters)
        and not parser_errors
        and all(value == 0 for value in zero_failures.values())
    )
    report: dict[str, Any] = {
        "schema_version": "controlled_native_replay.v1",
        "capture_id": capture_id,
        "status": "complete" if complete else "blocked",
        "exit_code": completed.returncode,
        "command": command,
        "pcap": {
            "path": str(pcap.resolve()),
            "original_filename": pcap.name,
            "byte_size": pcap.stat().st_size,
            "sha256": sha256_file(pcap),
        },
        "engine_sha256": sha256_file(engine),
        "counters": {
            name: _int_counter(counters, name)
            for name in (
                "packets_received",
                "packets_parsed",
                "packets_rejected",
                "packets_dropped",
                "packets_unsupported",
                "packets_truncated",
                "capture_errors",
                "flows_created",
                "flows_expired",
                "flows_flushed",
                "feature_records_generated",
                "feature_records_submitted",
                "feature_records_written",
                "feature_records_dropped",
                "feature_write_failures",
                "feature_validation_failures",
            )
        },
        "zero_failure_counters": zero_failures,
        "native_record_count": len(records),
        "parser_errors": parser_errors,
        "stdout_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr.encode()).hexdigest(),
    }
    (output_dir / "replay_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return ReplayResult(capture_id, output_dir, tuple(records), tuple(parser_errors), report)
