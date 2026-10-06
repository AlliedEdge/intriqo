#!/usr/bin/env python3
"""Controller for one gated controlled-v2 capture episode.

The controller owns intent and provenance.  It never reads native features or
detector output to make a label.  A scenario is captured only after topology
verification passes, and the first benign episode is intended to be replayed
and checked by the existing ML harness before any attack scenario is run.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

import pcap
import topology


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = ROOT / "ml" / "artifacts" / "feature-analysis" / "controlled-v2"
RAW_DEFAULT = Path("/tmp/opencode/intriqo-controlled-v2/raw")
HOST_RAW_ROOT = os.environ.get("INTRIQO_V2_HOST_RAW_ROOT")
SCENARIO_ORDER = (
    "train-benign-tcp",
    "train-benign-http",
    "train-benign-udp",
    "train-benign-dns",
    "train-benign-long",
    "train-benign-bursty",
    "validation-benign-asymmetric",
    "validation-syn-flood",
    "validation-port-scan",
    "test-benign-mixed",
    "test-syn-flood",
    "test-port-scan",
)


class ControllerError(RuntimeError):
    """A safety gate or immutable-provenance check failed."""


def _utc_now() -> str:
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.partial")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _host_path(path: Path) -> Path:
    """Translate the container's /raw mount to the host provenance path."""
    if HOST_RAW_ROOT and path.is_absolute() and str(path).startswith("/raw/"):
        return Path(HOST_RAW_ROOT) / Path(str(path)[len("/raw/") :])
    return path


def _timestamp_from_ns(value: int) -> str:
    seconds, nanoseconds = divmod(int(value), 1_000_000_000)
    moment = _datetime.datetime.fromtimestamp(seconds, _datetime.timezone.utc)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{nanoseconds:09d}Z"


def _base_manifest() -> dict[str, Any]:
    source = ARTIFACT_DIR / "experiment_manifest.json"
    if not source.is_file():
        raise ControllerError(f"missing planned experiment manifest: {source}")
    return _read_json(source)


def _planned_manifest() -> dict[str, Any]:
    preserved = ARTIFACT_DIR / "experiment_manifest_pre_capture.json"
    if not preserved.exists():
        _write_json(preserved, _base_manifest())
    return _read_json(preserved)


def _find_scenario(planned: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    rows = [row for row in planned.get("experiments", []) if row.get("scenario_id") == scenario_id]
    if len(rows) != 1:
        raise ControllerError(f"scenario must have exactly one planned row: {scenario_id}")
    return dict(rows[0])


def _run(argv: list[str], *, stdout: Path | None = None) -> subprocess.CompletedProcess[str]:
    output = subprocess.PIPE if stdout is None else stdout.open("w", encoding="utf-8")
    try:
        return subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT if stdout is not None else subprocess.PIPE,
            text=True,
            check=False,
        )
    finally:
        if stdout is not None:
            output.close()  # type: ignore[union-attr]


def _namespace_command(namespace: str, *args: str) -> list[str]:
    return ["ip", "netns", "exec", namespace, *args]


def _start_capture(
    *,
    namespace: str,
    interface: str,
    output: Path,
    ready: Path,
    receipt: Path,
    logs: Path,
) -> subprocess.Popen[str]:
    command = _namespace_command(
        namespace,
        topology.sys.executable,
        str(Path(__file__).with_name("capture.py")),
        "--interface",
        interface,
        "--output",
        str(output),
        "--ready-file",
        str(ready),
        "--receipt-file",
        str(receipt),
        "--max-duration",
        "30",
    )
    log = logs.open("w", encoding="utf-8")
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    process._intriqo_log = log  # type: ignore[attr-defined]
    return process


def _wait_ready(processes: Iterable[subprocess.Popen[str]], files: Iterable[Path]) -> None:
    deadline = time.monotonic() + 5.0
    files = tuple(files)
    processes = tuple(processes)
    while time.monotonic() < deadline:
        if all(path.is_file() for path in files):
            return
        for process in processes:
            if process.poll() is not None:
                raise ControllerError("capture process exited before readiness")
        time.sleep(0.05)
    raise ControllerError("capture readiness timeout")


def _stop_capture(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    log = getattr(process, "_intriqo_log", None)
    if log is not None:
        log.close()


def _start_endpoint(scenario: dict[str, Any], raw_dir: Path) -> subprocess.Popen[str] | None:
    if scenario["label"] != "BENIGN":
        return None
    destination_port = int(scenario["destination_port"])
    command = _namespace_command(
        "iqv2-victim",
        topology.sys.executable,
        str(Path(__file__).with_name("traffic.py")),
        "endpoint",
        "--tcp-port",
        str(destination_port),
        "--udp-port",
        str(destination_port),
        "--duration",
        "8",
        "--max-requests",
        "64",
    )
    log = (raw_dir / f"{scenario['experiment_id']}.endpoint.log").open("w", encoding="utf-8")
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )
    process._intriqo_log = log  # type: ignore[attr-defined]
    time.sleep(0.25)
    if process.poll() is not None:
        log.close()
        raise ControllerError(f"victim endpoint exited before {scenario['scenario_id']}")
    return process


def _stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    log = getattr(process, "_intriqo_log", None)
    if log is not None:
        log.close()


def _traffic_command(scenario: dict[str, Any]) -> list[str]:
    script = str(Path(__file__).with_name("traffic.py"))
    scenario_id = scenario["scenario_id"]
    if scenario_id in {"train-benign-tcp", "train-benign-http", "train-benign-long", "train-benign-bursty", "validation-benign-asymmetric", "test-benign-mixed"}:
        counts = {
            "train-benign-tcp": 1,
            "train-benign-http": 5,
            "train-benign-long": 4,
            "train-benign-bursty": 8,
            "validation-benign-asymmetric": 3,
            "test-benign-mixed": 8,
        }
        rates = {"train-benign-long": 2.0, "train-benign-bursty": 20.0, "test-benign-mixed": 10.0}
        return _namespace_command(
            "iqv2-attacker",
            topology.sys.executable,
            script,
            "tcp",
            "--destination-port",
            str(scenario["destination_port"]),
            "--source-port",
            str(scenario["source_port"]),
            "--count",
            str(counts[scenario_id]),
            "--rate",
            str(rates.get(scenario_id, 20.0)),
            "--timeout",
            "5",
        )
    if scenario_id in {"train-benign-udp", "train-benign-dns"}:
        count = 1 if scenario_id == "train-benign-udp" else 5
        return _namespace_command(
            "iqv2-attacker",
            topology.sys.executable,
            script,
            "udp",
            "--destination-port",
            str(scenario["destination_port"]),
            "--source-port",
            str(scenario["source_port"]),
            "--count",
            str(count),
            "--rate",
            "20",
            "--timeout",
            "1",
        )
    if scenario["attack_family"] == "SYN_FLOOD":
        return _namespace_command(
            "iqv2-attacker",
            topology.sys.executable,
            script,
            "syn-flood",
            "--destination-port",
            str(scenario["destination_port"]),
            "--source-port",
            "43001" if scenario_id.startswith("validation") else "43002",
            "--count",
            "80",
            "--rate",
            "100",
        )
    if scenario["attack_family"] == "PORT_SCAN":
        return _namespace_command(
            "iqv2-attacker",
            topology.sys.executable,
            script,
            "port-scan",
            "--ports",
            "10080-10087",
            "--repeats",
            "2",
            "--source-port-start",
            "44000" if scenario_id.startswith("validation") else "44100",
            "--rate",
            "40",
            "--duration",
            "1.0",
        )
    raise ControllerError(f"no bounded traffic plan for {scenario_id}")


def _run_traffic(scenario: dict[str, Any], raw_dir: Path) -> dict[str, Any]:
    receipt_path = raw_dir / f"{scenario['experiment_id']}.traffic.json"
    completed = _run(_traffic_command(scenario), stdout=raw_dir / f"{scenario['experiment_id']}.traffic.log")
    if completed.returncode != 0:
        raise ControllerError(
            f"traffic command failed for {scenario['scenario_id']}: "
            f"{(completed.stderr or '').strip()}"
        )
    log_text = (raw_dir / f"{scenario['experiment_id']}.traffic.log").read_text(encoding="utf-8")
    lines = [line for line in log_text.splitlines() if line.strip().startswith("{")]
    if not lines:
        raise ControllerError("traffic receipt was not emitted")
    receipt = json.loads(lines[-1])
    _write_json(receipt_path, receipt)
    return receipt


def _pair_counts(observation: dict[str, Any]) -> dict[str, int]:
    counts = observation.get("protocol_direction_counts", {})
    return {
        "attacker_to_victim": sum(
            int(counts.get(protocol, {}).get("attacker_to_victim", 0))
            for protocol in ("TCP", "UDP", "ICMP")
        ),
        "victim_to_attacker": sum(
            int(counts.get(protocol, {}).get("victim_to_attacker", 0))
            for protocol in ("TCP", "UDP", "ICMP")
        ),
    }


def _validate_visibility(
    scenario: dict[str, Any], observations: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    monitor = observations["monitor"]
    attacker = observations["attacker"]
    victim = observations["victim"]
    monitor_pair = _pair_counts(monitor)
    attacker_pair = _pair_counts(attacker)
    victim_pair = _pair_counts(victim)
    bidirectional = monitor_pair["attacker_to_victim"] > 0 and monitor_pair["victim_to_attacker"] > 0
    matches_endpoints = monitor_pair == attacker_pair == victim_pair
    expected_supported = monitor_pair["attacker_to_victim"] + monitor_pair["victim_to_attacker"]
    result = {
        "scenario_id": scenario["scenario_id"],
        "sender_packet_count": sum(attacker_pair.values()),
        "receiver_packet_count": sum(victim_pair.values()),
        "monitor_packet_count": sum(monitor_pair.values()),
        "sender_direction_counts": attacker_pair,
        "receiver_direction_counts": victim_pair,
        "monitor_direction_counts": monitor_pair,
        "bidirectional_monitor_visibility": bidirectional,
        "endpoint_monitor_counts_match": matches_endpoints,
        "unsupported_or_unexpected": {
            role: {
                "unsupported_packets": int(value.get("unsupported_packets", 0)),
                "unexpected_ip_packets": int(value.get("unexpected_ip_packets", 0)),
            }
            for role, value in observations.items()
        },
        "supported_pair_packet_count": expected_supported,
        "status": "PASS" if bidirectional and matches_endpoints else "BLOCKED",
    }
    if result["status"] != "PASS":
        raise ControllerError(
            "capture visibility gate failed; monitor must match both endpoint captures "
            f"for {scenario['scenario_id']}"
        )
    return result


def _flow_rows(scenario: dict[str, Any], monitor: dict[str, Any]) -> list[dict[str, Any]]:
    flows = [
        flow
        for flow in monitor.get("five_tuple_bounds", [])
        if flow.get("source_address") == "10.77.0.10"
        and flow.get("destination_address") == "10.77.0.20"
        and flow.get("protocol") == scenario["protocol"]
    ]
    if not flows:
        raise ControllerError(f"no normalized controller flow for {scenario['scenario_id']}")
    if scenario["label"] == "BENIGN":
        if len(flows) != 1:
            raise ControllerError(f"benign scenario produced {len(flows)} flows, expected one")
        flow = flows[0]
        if flow["source_port"] != scenario["source_port"] or flow["destination_port"] != scenario["destination_port"]:
            raise ControllerError(f"benign five-tuple mismatch for {scenario['scenario_id']}")
    rows: list[dict[str, Any]] = []
    for index, flow in enumerate(sorted(flows, key=lambda value: tuple(value["five_tuple"]))):
        label_id = scenario["source_label_id"] if len(flows) == 1 else f"{scenario['source_label_id']}-flow-{index + 1:03d}"
        row = dict(scenario)
        row.update(
            {
                "scenario_id": f"{scenario['scenario_id']}-flow-{index + 1:03d}" if len(flows) > 1 else scenario["scenario_id"],
                "source_port": int(flow["source_port"]),
                "destination_port": int(flow["destination_port"]),
                "start_timestamp": _timestamp_from_ns(int(flow["first_timestamp_ns"])),
                "end_timestamp": _timestamp_from_ns(int(flow["last_timestamp_ns"])),
                "expected_flow_scope": "single_five_tuple",
                "source_label_id": label_id,
            }
        )
        rows.append(row)
    return rows


def _final_manifest(
    planned: dict[str, Any], captured_rows: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    experiments: list[dict[str, Any]] = []
    for planned_row in planned["experiments"]:
        experiments.extend(captured_rows.get(planned_row["experiment_id"], [dict(planned_row)]))
    result = dict(planned)
    result["experiments"] = experiments
    return result


def _capture_entry(
    *,
    capture_id: str,
    scenario: dict[str, Any],
    monitor_pcap: Path,
    monitor_receipt: dict[str, Any],
    monitor_observation: dict[str, Any],
    source_label_ids: list[str],
) -> dict[str, Any]:
    return {
        "capture_id": capture_id,
        "experiment_id": scenario["experiment_id"],
        "status": "CAPTURED",
        "original_filename": monitor_pcap.name,
        "source_path": str(_host_path(monitor_pcap)),
        "sha256": monitor_observation["sha256"],
        "byte_size": monitor_observation["byte_size"],
        "capture_start": monitor_receipt["started_at"],
        "capture_end": monitor_receipt["ended_at"],
        "interface": "tap-intriqo-v2",
        "link_type": "Ethernet (DLT_EN10MB=1)",
        "timestamp_resolution": monitor_observation["timestamp_resolution"],
        "timezone": "UTC",
        "clock_synchronization": (
            "single Linux kernel CLOCK_REALTIME source; "
            f"capture timestamp source={monitor_receipt['timestamp_source']}; "
            f"kernel clocksource={monitor_receipt['clock_source']}"
        ),
        "capture_group": capture_id,
        "parent_capture_id": None,
        "original_preserved": True,
        "source_label_ids": source_label_ids,
    }


def _update_artifacts(
    *,
    planned: dict[str, Any],
    captures: list[dict[str, Any]],
    captured_rows: dict[str, list[dict[str, Any]]],
    visibility: dict[str, Any],
) -> None:
    final = _final_manifest(planned, captured_rows)
    _write_json(ARTIFACT_DIR / "experiment_manifest.json", final)
    capture_manifest = {"schema_version": "controlled_capture_manifest.v1", "captures": captures}
    _write_json(ARTIFACT_DIR / "capture_manifest.json", capture_manifest)
    assignments = [
        {"capture_id": entry["capture_id"], "split": next(row["split"] for row in planned["experiments"] if row["experiment_id"] == entry["experiment_id"])}
        for entry in captures
    ]
    _write_json(
        ARTIFACT_DIR / "split_definition.json",
        {
            "schema_version": "controlled_split_definition.v1",
            "policy": "capture_and_parent_group_separation.v1",
            "assignments": assignments,
            "random_row_split": False,
            "leakage_checks": [
                "capture_id",
                "capture_group",
                "parent_capture_id",
                "pcap_sha256",
                "native_row_key",
                "source_label_id",
                "parent_time_overlap",
            ],
        },
    )
    _write_json(
        ARTIFACT_DIR / "capture_hashes.json",
        {
            "schema_version": "controlled_capture_hashes.v1",
            "immutable_originals": True,
            "captures": [
                {
                    "capture_id": entry["capture_id"],
                    "source_path": entry["source_path"],
                    "byte_size": entry["byte_size"],
                    "sha256": entry["sha256"],
                }
                for entry in captures
            ],
        },
    )
    visibility_path = ARTIFACT_DIR / "capture_visibility_receipt.json"
    previous_visibility: dict[str, Any] = {}
    if visibility_path.exists():
        previous = _read_json(visibility_path)
        if isinstance(previous, dict) and isinstance(previous.get("episodes"), dict):
            previous_visibility = dict(previous["episodes"])
    previous_visibility.update(visibility)
    _write_json(
        visibility_path,
        {"schema_version": "controlled_capture_visibility.v1", "episodes": previous_visibility},
    )


def run_episode(scenario_id: str, raw_root: Path) -> dict[str, Any]:
    planned = _planned_manifest()
    scenario = _find_scenario(planned, scenario_id)
    existing_manifest = _read_json(ARTIFACT_DIR / "capture_manifest.json")
    captures = list(existing_manifest.get("captures", []))
    if any(entry.get("experiment_id") == scenario["experiment_id"] for entry in captures):
        raise ControllerError(f"scenario already captured: {scenario_id}")

    capture_id = f"cap-{scenario_id}-{uuid.uuid4().hex[:12]}"
    raw_dir = raw_root / capture_id
    raw_dir.mkdir(parents=True, exist_ok=False)
    intent = {
        "schema_version": "controlled_controller_intent.v1",
        "created_before_traffic_utc": _utc_now(),
        "experiment": scenario,
        "capture_id": capture_id,
        "capture_interface": "tap-intriqo-v2",
        "raw_directory": str(raw_dir),
        "traffic_command": _traffic_command(scenario),
        "labels_source": "controller intent manifest; never detector output",
    }
    intent_dir = ARTIFACT_DIR / "intents"
    intent_path = intent_dir / f"{scenario_id}.json"
    if intent_path.exists():
        raise ControllerError(f"immutable intent already exists: {intent_path}")
    _write_json(intent_path, intent)

    setup_result = topology.setup()
    if setup_result.get("status") != "PASS":
        raise ControllerError(f"topology setup blocked: {setup_result.get('errors')}")
    try:
        isolation = topology.verify()
        _write_json(ARTIFACT_DIR / "lab_isolation_receipt.json", isolation)
        if isolation.get("status") != "PASS":
            raise ControllerError("isolation verification failed; no traffic was generated")

        paths = {
            "monitor": ("iqv2-monitor", "tap-intriqo-v2"),
            "attacker": ("iqv2-attacker", "lab0"),
            "victim": ("iqv2-victim", "lab0"),
        }
        processes: dict[str, subprocess.Popen[str]] = {}
        ready_files: list[Path] = []
        for role, (namespace, interface) in paths.items():
            output = raw_dir / f"{capture_id}-{role}.pcap"
            ready = raw_dir / f"{capture_id}-{role}.ready.json"
            receipt = raw_dir / f"{capture_id}-{role}.receipt.json"
            process = _start_capture(
                namespace=namespace,
                interface=interface,
                output=output,
                ready=ready,
                receipt=receipt,
                logs=raw_dir / f"{capture_id}-{role}.capture.log",
            )
            processes[role] = process
            ready_files.append(ready)
        endpoint: subprocess.Popen[str] | None = None
        try:
            _wait_ready(processes.values(), ready_files)
            endpoint = _start_endpoint(scenario, raw_dir)
            traffic_receipt = _run_traffic(scenario, raw_dir)
        finally:
            _stop_process(endpoint)
            for process in processes.values():
                _stop_capture(process)

        observations = {
            role: pcap.inspect_pcap(raw_dir / f"{capture_id}-{role}.pcap")
            for role in ("monitor", "attacker", "victim")
        }
        visibility = _validate_visibility(scenario, observations)
        monitor_receipt = _read_json(raw_dir / f"{capture_id}-monitor.receipt.json")
        rows = _flow_rows(scenario, observations["monitor"])
        entry = _capture_entry(
            capture_id=capture_id,
            scenario=scenario,
            monitor_pcap=raw_dir / f"{capture_id}-monitor.pcap",
            monitor_receipt=monitor_receipt,
            monitor_observation=observations["monitor"],
            source_label_ids=[row["source_label_id"] for row in rows],
        )
        captures.append(entry)
        captured_rows: dict[str, list[dict[str, Any]]] = {}
        existing_final = _read_json(ARTIFACT_DIR / "experiment_manifest.json")
        for row in existing_final.get("experiments", []):
            if row.get("start_timestamp") is not None:
                captured_rows.setdefault(row["experiment_id"], []).append(row)
        captured_rows[scenario["experiment_id"]] = rows
        _update_artifacts(
            planned=planned,
            captures=captures,
            captured_rows=captured_rows,
            visibility={scenario_id: visibility},
        )
        _write_json(
            raw_dir / "episode_receipt.json",
            {
                "schema_version": "controlled_episode_receipt.v1",
                "status": "PASS",
                "capture_id": capture_id,
                "experiment_id": scenario["experiment_id"],
                "scenario_id": scenario_id,
                "intent_path": str(intent_path),
                "traffic": traffic_receipt,
                "visibility": visibility,
                "pcaps": observations,
                "controller_ground_truth": rows,
                "original_monitor_pcap_immutable": True,
            },
        )
        return {
            "status": "PASS",
            "capture_id": capture_id,
            "scenario_id": scenario_id,
            "raw_dir": str(raw_dir),
            "visibility": visibility,
            "flow_count": len(rows),
        }
    finally:
        final_isolation = topology.verify()
        current = _read_json(ARTIFACT_DIR / "lab_isolation_receipt.json")
        current["before_cleanup"] = final_isolation
        _write_json(ARTIFACT_DIR / "lab_isolation_receipt.json", current)
        cleanup = topology.cleanup()
        current["cleanup"] = cleanup
        _write_json(ARTIFACT_DIR / "lab_isolation_receipt.json", current)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-id", choices=SCENARIO_ORDER, required=True)
    parser.add_argument("--raw-root", type=Path, default=RAW_DEFAULT)
    args = parser.parse_args(argv)
    try:
        result = run_episode(args.scenario_id, args.raw_root)
    except (ControllerError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        result = {"status": "BLOCKED", "error": str(exc), "scenario_id": args.scenario_id}
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
