#!/usr/bin/env python3
"""Matched raw-PCAP A/B/C feature boundary measurement; no ML or remote traffic."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "engine/tests/fixtures"))
from syn_flood_fixture import _tcp_ipv4_frame  # noqa: E402


def write_input(path: Path, packets: int, flows_per_cycle: int, packets_per_flow: int) -> int:
    if packets % (flows_per_cycle * packets_per_flow):
        raise ValueError("packets must be divisible by flows-per-cycle * packets-per-flow")
    if not 1 <= flows_per_cycle <= 10000 or packets_per_flow < 1:
        raise ValueError("invalid controlled flow cardinality")
    cycles = packets // (flows_per_cycle * packets_per_flow)
    frames = []
    for index in range(flows_per_cycle):
        frames.append(tuple(_tcp_ipv4_frame(
            "192.0.2.10", "198.51.100.20", 20000 + index, 1 + index,
            100, 0, flags, index,
        ) for flags in (2, 16)))
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        for cycle in range(cycles):
            for index, flow in enumerate(frames):
                for packet_index in range(packets_per_flow):
                    # Flow cohorts retire using packet time after a >1-second gap.
                    fraction = (index * packets_per_flow + packet_index) * 1000
                    if fraction >= 1_000_000_000:
                        raise ValueError("cycle timestamp span must be below one second")
                    frame = flow[0 if packet_index == 0 else 1]
                    output.write(struct.pack("<IIII", 1700000000 + cycle * 2,
                                             fraction, len(frame), len(frame)))
                    output.write(frame)
    return cycles * flows_per_cycle


def parse_output(text: str) -> dict[str, int | float | str]:
    result = {}
    for line in text.splitlines():
        if line.startswith("sample "):
            continue
        for key, raw in re.findall(r"([a-z_]+)=([^ \n]+)", line):
            try:
                result[key] = float(raw) if any(c in raw for c in ".eE") else int(raw)
            except ValueError:
                result[key] = raw
    return result


def require_release(build: Path) -> None:
    if "CMAKE_BUILD_TYPE:STRING=Release" not in (build / "CMakeCache.txt").read_text():
        raise ValueError("benchmarks require a Release build")


def measure(binary: Path, source: Path, mode: str, target: Path, capacity: int,
            expected_packets: int, expected_flows: int, baseline: bool = False):
    args = [str(binary), "--pcap", str(source), "--with-syn-flood",
            "--flow-idle-timeout", "1", "--max-active-flows", "100000"]
    if not baseline:
        args += ["--feature-mode", mode]
        if mode == "file":
            args += ["--feature-output", str(target), "--feature-queue-capacity", str(capacity)]
    run = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)
    if run.returncode:
        raise RuntimeError("benchmark process failed; inspect local build/runtime")
    data = parse_output(run.stdout)
    assert data["packets_processed"] == expected_packets
    assert data["flows_created"] == expected_flows and data["flows_active"] == 0
    assert data["sink_failures"] == data["packets_rejected"] == 0
    if mode != "off":
        assert data["feature_records_generated"] == expected_flows
        assert data["feature_generation_failures"] == data["feature_setup_failures"] == 0
    if mode == "file":
        assert data["feature_records_submitted"] == expected_flows
        assert data["feature_records_written"] + data["feature_records_dropped"] == expected_flows
        assert data["feature_queue_depth"] == 0
        line_count = 0
        digest = hashlib.sha256()
        with target.open("rb") as stream:
            for line in stream:
                digest.update(line)
                line_count += 1
                assert json.loads(line)["schema_version"] == "flow_features.v1"
        assert line_count == data["feature_records_written"]
        data["jsonl_bytes"] = target.stat().st_size
        data["jsonl_sha256"] = digest.hexdigest()
    return {"command": args, "metrics": data}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build/flow-release")
    parser.add_argument("--baseline-build", type=Path, required=True)
    parser.add_argument("--packets", type=int, default=1_000_000)
    parser.add_argument("--flows-per-cycle", type=int, default=1000)
    parser.add_argument("--packets-per-flow", type=int, default=50)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--queue-capacity", type=int, default=4096)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "benchmarks/engine/results/flow-features-v1.json")
    args = parser.parse_args()
    args.output = args.output.resolve()
    if args.repeats < 1 or args.packets < 1 or not 1 <= args.queue_capacity <= 65536:
        parser.error("positive sizes/repeats and queue-capacity 1..65536 required")
    for build in (args.build, args.baseline_build):
        require_release(build)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    source = args.output.with_suffix(".pcap")
    destinations = [args.output, source,
                    args.output.with_name(f"{args.output.stem}-warm-C_file.jsonl")]
    destinations.extend(args.output.with_name(f"{args.output.stem}-C_file-{i + 1}.jsonl")
                        for i in range(args.repeats))
    if any(path.exists() for path in destinations):
        parser.error("result artifacts already exist; choose a new --output path")
    expected_flows = write_input(source, args.packets, args.flows_per_cycle, args.packets_per_flow)
    affinity = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else []
    if affinity:
        # Packet processor plus feature worker; same allowance for every variant.
        os.sched_setaffinity(0, affinity[:2])
    binary = args.build.resolve() / "engine/intriqo-runtime-benchmark"
    baseline = args.baseline_build.resolve() / "engine/intriqo-runtime-benchmark"
    results = {key: [] for key in ("A_existing", "disabled_candidate", "B_generate", "C_file")}
    variants = [("A_existing", baseline, "off", True),
                ("disabled_candidate", binary, "off", False),
                ("B_generate", binary, "generate", False),
                ("C_file", binary, "file", False)]
    # Warm each variant once, then alternate order to avoid always favoring A.
    for index, (name, executable, mode, old) in enumerate(variants):
        measure(executable, source, mode, args.output.with_name(f"{args.output.stem}-warm-{name}.jsonl"),
                args.queue_capacity, args.packets, expected_flows, old)
    for repetition in range(args.repeats):
        order = variants if repetition % 2 == 0 else list(reversed(variants))
        for name, executable, mode, old in order:
            target = args.output.with_name(f"{args.output.stem}-{name}-{repetition + 1}.jsonl")
            results[name].append(measure(executable, source, mode, target, args.queue_capacity,
                                         args.packets, expected_flows, old))
        # Preserve completed measurements if later reporting/host inspection fails.
        args.output.with_suffix(".checkpoint.json").write_text(json.dumps(results, indent=2) + "\n")
    medians = {}
    for name, runs in results.items():
        common = set.intersection(*(set(run["metrics"]) for run in runs))
        medians[name] = {key: statistics.median(run["metrics"][key] for run in runs)
                         for key in sorted(common)
                         if all(type(run["metrics"][key]) in (int, float) for run in runs)}
    cpu_model = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name")), "unavailable")
    report = {
        "benchmark_version": "flow_feature_boundary.v1",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "cpu_model": cpu_model,
                 "affinity": affinity[:2], "compiler": subprocess.check_output(
                     ["c++", "--version"], text=True).splitlines()[0]},
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "input": {"path": str(source.relative_to(ROOT)), "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "packets": args.packets, "flows": expected_flows,
                  "flows_per_cycle": args.flows_per_cycle, "packets_per_flow": args.packets_per_flow,
                  "historical_timestamps": True, "live_traffic": False},
        "queue_capacity": args.queue_capacity, "repeats": args.repeats,
        "medians": medians, "runs": results,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"output": str(args.output.relative_to(ROOT)), "medians": medians}, indent=2))


if __name__ == "__main__":
    main()
