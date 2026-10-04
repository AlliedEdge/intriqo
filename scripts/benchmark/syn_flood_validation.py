#!/usr/bin/env python3
"""Run deterministic offline SYN-flood validation scenarios.

This harness has no third-party dependencies.  It writes checksummed PCAPs
using documentation-only addresses, runs the built engine through its PCAP
path, validates the JSON event contract and UUIDs, and stores redacted
measurements at the requested output path.  Live capture and Control Plane /
PostgreSQL validation are intentionally implemented by the opt-in pytest in
``tests/e2e/test_syn_flood_live.py``.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = ROOT / "engine" / "tests" / "fixtures"
sys.path.insert(0, str(FIXTURE_DIR))
from syn_flood_fixture import (  # noqa: E402
    PCAP_DESTINATION,
    PCAP_SOURCE,
    write_completed_handshake_pcap,
    write_control_pcap,
    write_syn_flood_pcap,
)


class ValidationError(RuntimeError):
    """A deterministic harness assertion failed."""


def _redact(text: str) -> str:
    text = re.sub(r"(?i)bearer\s+\S+", "Bearer <redacted>", text)
    text = re.sub(r"(?i)(token|password|secret)=\S+", r"\1=<redacted>", text)
    return re.sub(r"https?://[^\s'\"]+", "<redacted-url>", text)


def _parse_scalar(value: str) -> Any:
    if value == "N/A":
        return value
    if value in {"true", "false"}:
        return value == "true"
    try:
        return float(value) if any(char in value for char in ".eE") else int(value)
    except ValueError:
        return value


def _summary(output: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for line in output.splitlines():
        if not line.startswith("shutdown "):
            continue
        for token in line.split()[1:]:
            if "=" not in token:
                continue
            key, value = token.split("=", 1)
            result[key] = _parse_scalar(value)
        break
    if not result:
        raise ValidationError("engine did not emit a shutdown summary")
    return result


def _assert_uuid(value: Any) -> None:
    if not isinstance(value, str) or len(value) != 36 or str(uuid.UUID(value)) != value.lower():
        raise ValidationError(f"event_id is not a canonical UUID: {value!r}")
    if uuid.UUID(value).version != 4:
        raise ValidationError("event_id is not UUID v4")


def _validate_event(event: Any) -> None:
    if not isinstance(event, dict):
        raise ValidationError("event JSON value is not an object")
    required = {
        "event_id",
        "event_type",
        "severity",
        "timestamp",
        "source_address",
        "destination_address",
        "details",
    }
    missing = required.difference(event)
    if missing:
        raise ValidationError(f"event is missing fields: {sorted(missing)}")
    if set(event) - (required | {"description"}):
        raise ValidationError("event contains properties outside SecurityEvent v1")
    _assert_uuid(event["event_id"])
    if event["event_type"] not in {"SYN_FLOOD", "PORT_SCAN"}:
        raise ValidationError(f"unexpected event_type: {event['event_type']!r}")
    if event["severity"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValidationError(f"unexpected severity: {event['severity']!r}")
    if not isinstance(event["timestamp"], str):
        raise ValidationError("event timestamp is not a string")
    try:
        parsed_timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationError("event timestamp is not ISO-8601") from error
    if parsed_timestamp.tzinfo is None:
        raise ValidationError("event timestamp has no timezone")
    try:
        ipaddress.IPv4Address(event["source_address"])
        ipaddress.IPv4Address(event["destination_address"])
    except ipaddress.AddressValueError as error:
        raise ValidationError("event address is not IPv4") from error
    if not isinstance(event["details"], dict):
        raise ValidationError("event details is not an object")


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise ValidationError("engine did not create its JSONL output")
    events: list[dict[str, Any]] = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValidationError("engine output contains invalid JSON") from error
        _validate_event(event)
        events.append(event)
    return events


def _engine_candidates() -> list[Path]:
    configured = os.environ.get("INTRIQO_ENGINE_BINARY")
    if configured:
        return [Path(configured)]
    return [
        ROOT / "build" / "runtime-release" / "engine" / "intriqo-engine",
        ROOT / "build" / "runtime-release" / "intriqo-engine",
        ROOT / "engine" / "build" / "intriqo-engine",
        ROOT / "engine" / "build-syn" / "intriqo-engine",
    ]


def _resolve_engine(configured: str | None) -> Path:
    candidates = [Path(configured)] if configured else _engine_candidates()
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    searched = ", ".join(str(path) for path in candidates)
    raise ValidationError(f"engine binary not found; searched: {searched}")


def _case_command(engine: Path, pcap: Path, output: Path) -> list[str]:
    return [
        str(engine),
        "--pcap",
        str(pcap),
        "--sink",
        "file",
        "--output",
        str(output),
        "--portscan-window",
        "10",
        "--portscan-unique-port-threshold",
        "65535",
        "--portscan-minimum-attempts",
        "65535",
        "--synflood-window",
        "10",
        "--synflood-minimum-attempts",
        "20",
        "--synflood-minimum-rate",
        "10",
        "--synflood-incomplete-ratio",
        "0.9",
        "--synflood-minimum-incomplete",
        "20",
    ]


def _run_case(engine: Path, name: str, pcap: Path, expected: str, directory: Path) -> dict[str, Any]:
    output = directory / f"{name}.jsonl"
    output.unlink(missing_ok=True)
    command = _case_command(engine, pcap, output)
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    elapsed = time.monotonic() - started
    if completed.returncode != 0:
        detail = _redact(completed.stderr.strip())[-1000:]
        raise ValidationError(f"{name} engine exit={completed.returncode}: {detail}")
    summary = _summary(completed.stdout)
    events = _read_events(output)
    event_types = [event["event_type"] for event in events]
    if expected == "SYN_FLOOD":
        if len(events) != 1 or event_types != ["SYN_FLOOD"]:
            raise ValidationError(f"{name} expected one SYN_FLOOD event, got {event_types}")
        details = events[0]["details"]
        for key in (
            "detector",
            "connection_attempts",
            "initial_syn_attempts",
            "incomplete_handshakes",
            "incomplete_ratio",
            "rate_per_second",
            "window_seconds",
        ):
            if key not in details:
                raise ValidationError(f"{name} SYN_FLOOD details missing {key}")
        if details["detector"] != "syn_flood":
            raise ValidationError(f"{name} has unexpected detector detail")
        if details["connection_attempts"] < 20 or details["initial_syn_attempts"] < 20:
            raise ValidationError(f"{name} did not reach the attempt threshold")
        if details["incomplete_handshakes"] < 20 or details["incomplete_ratio"] < 0.9:
            raise ValidationError(f"{name} did not reach the incomplete threshold")
        if details["rate_per_second"] < 10:
            raise ValidationError(f"{name} did not reach the rate threshold")
        if events[0]["source_address"] != PCAP_SOURCE or events[0]["destination_address"] != PCAP_DESTINATION:
            raise ValidationError(f"{name} has unexpected event addresses")
        if summary.get("events_emitted") != 1 or summary.get("detections_fired") != 1:
            raise ValidationError(f"{name} emitted an unexpected number of events")
    else:
        if "SYN_FLOOD" in event_types:
            raise ValidationError(f"{name} unexpectedly emitted SYN_FLOOD")
        if events:
            raise ValidationError(f"{name} emitted unexpected events: {event_types}")
        if summary.get("events_emitted") != 0 or summary.get("detections_fired") != 0:
            raise ValidationError(f"{name} emitted unexpected detector metrics")

    if summary.get("flows_active") != 0 or summary.get("sink_failures") != 0:
        raise ValidationError(f"{name} did not drain cleanly")
    return {
        "scenario": name,
        "expected_event": expected,
        "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "pcap_bytes": pcap.stat().st_size,
        "duration_seconds": round(elapsed, 6),
        "event_count": len(events),
        "event_types": event_types,
        "event_ids": [event["event_id"] for event in events],
        "events": events,
        "summary": summary,
    }


def _build_fixture(name: str, path: Path) -> None:
    if name == "syn_flood":
        write_syn_flood_pcap(path)
    elif name == "completed_handshake":
        write_completed_handshake_pcap(path)
    elif name == "control":
        write_control_pcap(path)
    else:
        raise AssertionError(name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--engine",
        default=os.environ.get("INTRIQO_ENGINE_BINARY"),
        help="engine executable; defaults to INTRIQO_ENGINE_BINARY or common build paths",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "benchmarks" / "engine" / "results" / "syn_flood_validation.json",
        help="redacted JSON measurement output path",
    )
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        help="optional directory in which to retain generated PCAPs",
    )
    args = parser.parse_args()

    try:
        engine = _resolve_engine(args.engine)
    except ValidationError as error:
        parser.error(str(error))

    report: dict[str, Any] = {
        "harness": "syn_flood_validation",
        "engine": str(engine),
        "thresholds": {
            "minimum_attempts": 20,
            "minimum_rate_per_second": 10,
            "minimum_incomplete_handshakes": 20,
            "incomplete_ratio": 0.9,
        },
        "scenarios": [],
    }
    failures: list[str] = []
    temporary = None
    try:
        fixture_root = args.fixture_dir
        if fixture_root is None:
            temporary = tempfile.TemporaryDirectory(prefix="intriqo-syn-flood-")
            fixture_root = Path(temporary.name)
        fixture_root.mkdir(parents=True, exist_ok=True)
        for name, expected in (
            ("syn_flood", "SYN_FLOOD"),
            ("completed_handshake", "NONE"),
            ("control", "NONE"),
        ):
            pcap = fixture_root / f"{name}.pcap"
            try:
                _build_fixture(name, pcap)
                report["scenarios"].append(_run_case(engine, name, pcap, expected, fixture_root))
            except (OSError, subprocess.SubprocessError, ValidationError, ValueError) as error:
                failures.append(f"{name}: {_redact(str(error))}")
                report["scenarios"].append(
                    {
                        "scenario": name,
                        "status": "failed",
                        "error": _redact(str(error)),
                        "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest()
                        if pcap.exists()
                        else None,
                    }
                )
    finally:
        if temporary is not None:
            temporary.cleanup()

    report["status"] = "failed" if failures else "passed"
    if failures:
        report["failures"] = failures
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"status={report['status']} scenarios={len(report['scenarios'])}")
    print(f"results={args.output}")
    if failures:
        for failure in failures:
            print(f"failure={failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
