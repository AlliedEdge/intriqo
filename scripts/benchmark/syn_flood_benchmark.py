#!/usr/bin/env python3
"""Matched Release-only detector cost measurement; never transmits traffic."""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import tempfile
from pathlib import Path

from runtime_benchmark import ROOT, command, fields, metadata, write_pcap


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--packets", type=int, default=1_000_000)
    parser.add_argument("--ports", type=int, default=1_000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.packets < 1 or not 1 <= args.ports <= 65_535 or args.repeats < 3:
        parser.error("positive packets, 1..65535 ports, and at least 3 repeats required")
    build = args.build.resolve()
    binary = build / "engine" / "intriqo-runtime-benchmark"
    report = {"environment": metadata(build), "packets": args.packets,
              "ports": args.ports, "repeats": args.repeats,
              "sink": "FileEventSink(/dev/null)", "runs": [], "medians": {}}
    report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(dir="/tmp/opencode", prefix="syn-bench-") as directory:
        fixture = Path(directory) / "input.pcap"
        write_pcap(fixture, args.packets, args.ports)
        report["pcap_sha256"] = hashlib.sha256(fixture.read_bytes()).hexdigest()
        for mode in ("synthetic", "pcap"):
            source = (["--synthetic", "--synthetic-packets", str(args.packets),
                       "--synthetic-unique-ports", str(args.ports)]
                      if mode == "synthetic" else ["--pcap", str(fixture)])
            # Alternate A/B order to reduce one-sided warmup/drift bias.
            for repeat in range(args.repeats):
                order = (False, True) if repeat % 2 == 0 else (True, False)
                for enabled in order:
                    output = command([str(binary), *source,
                                      *(["--with-syn-flood"] if enabled else [])], timeout=120)
                    parsed = fields(output)
                    counts = parsed["counts"]
                    assert counts["packets_processed"] == args.packets
                    assert counts["sink_failures"] == counts["detector_errors"] == 0
                    assert counts["flows_active"] == counts["detector_state_observations"] == 0
                    report["runs"].append({"mode": mode, "syn_flood_enabled": enabled,
                                           "repeat": repeat + 1, "raw_output": output, **parsed})
            metrics = {}
            for enabled in (False, True):
                runs = [r for r in report["runs"] if r["mode"] == mode
                        and r["syn_flood_enabled"] == enabled]
                medians = {}
                for group in ("counts", "rates", "resources"):
                    for key, value in runs[0][group].items():
                        if isinstance(value, (int, float)):
                            medians[f"{group}.{key}"] = statistics.median(r[group][key] for r in runs)
                metrics["candidate" if enabled else "baseline"] = medians
            baseline = metrics["baseline"]["rates.packets_per_second"]
            candidate = metrics["candidate"]["rates.packets_per_second"]
            metrics["throughput_reduction_percent"] = 100 * (baseline - candidate) / baseline
            report["medians"][mode] = metrics
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["medians"], indent=2))
    print(f"results={args.output.relative_to(ROOT) if args.output.is_relative_to(ROOT) else args.output}")


if __name__ == "__main__":
    main()
