#!/usr/bin/env python3
"""Standard-library checks for measurement integrity; no capture privilege needed."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import reliability_benchmark as reliability


class ReliabilityTests(unittest.TestCase):
    def test_exclusive_results_and_unique_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            first = reliability.ReportFile(path)
            try:
                first.save({"preserved": True})
                with self.assertRaises(FileExistsError):
                    reliability.ReportFile(path)
                self.assertEqual(json.loads(path.read_text()), {"preserved": True})
            finally:
                first.close()
            self.assertNotEqual(reliability.unique_output(directory), reliability.unique_output(directory))
        with self.assertRaises(ValueError):
            reliability.ReportFile(reliability.ROOT / "benchmarks/engine/results/runtime.json")

    def test_legacy_counts_do_not_become_separate_or_kernel_counts(self):
        result = {"wall_seconds": 1, "reported": {
            "counts": {"packets_received": 100, "packets_parsed": 90, "packets_dropped": 10, "events_emitted": 1},
            "latency": {"samples": 1, "mean_ms": 2}}}
        measured = reliability.measurement(result, offered=100, expected_scans=1)
        self.assertEqual(measured["counter_completeness"], "legacy-incomplete-combined-counts")
        self.assertIsNone(measured["kernel_ps_recv"])
        self.assertIsNone(measured["processed_packets"])
        self.assertIsNone(measured["capture_drops"])
        self.assertIsNone(measured["packet_latency_p99_ms"])
        self.assertIsNone(measured["event_latency_p99_ms"])
        result["reported"]["counts"].update(packets_seen=220, packets_captured=110, packets_processed=110,
                                             capture_drops=0, capture_statistics_available=True)
        self.assertEqual(reliability.measurement(result, 100)["kernel_ps_recv"], 220)
        result["reported"]["counts"]["capture_statistics_available"] = "false"
        unavailable = reliability.measurement(result, 100)
        self.assertIsNone(unavailable["kernel_ps_recv"])
        self.assertIsNone(unavailable["capture_drops"])

    def test_known_scan_json_contract_and_duplicate_uuid(self):
        events = [{"event_id": str(uuid.uuid4()), "event_type": "PORT_SCAN",
                   "timestamp": f"2023-11-14T22:13:{seconds}.009Z",
                   "source_address": "10.0.0.1", "destination_address": "198.51.100.20",
                   "details": {"unique_destination_ports": 10, "connection_attempts": 10}}
                  for seconds in (20, 40)]
        record = {"passed": True, "observed_events": 2, "events": events}
        reliability.validate_correctness(record)
        events[1]["event_id"] = events[0]["event_id"]
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            reliability.validate_correctness(record)

    def test_actual_pid_samples_stream_without_array(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.jsonl"
            monitor = reliability.ProcessMonitor(os.getpid(), path, 0.02)
            monitor.begin()
            time.sleep(0.06)
            result = monitor.finish()
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertGreaterEqual(len(records), 3)
            self.assertEqual(result["host_pid"], os.getpid())
            self.assertGreater(result["initial_rss_kib"], 0)
            self.assertEqual(result["samples_retained_in_memory"], 0)
            self.assertNotIn("samples", result)
            self.assertEqual(len(records), result["sample_count"])

    def test_output_reader_keeps_raw_samples_and_only_final_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.Popen([sys.executable, "-c",
                "import json; print('capture_ready=true'); "
                "[print(json.dumps({'type':'sample','index':i})) for i in range(1000)]; "
                "print(json.dumps({'type':'summary','status':'complete'}))"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            reader = reliability.OutputReader(process, Path(directory))
            reader.start()
            process.wait(timeout=10)
            result = reader.finish()
            self.assertTrue(reader.ready.is_set())
            self.assertEqual(result["state_soak_summary"]["status"], "complete")
            self.assertEqual(len(Path(result["stdout_file"]).read_text().splitlines()), 1002)
            self.assertNotIn("samples", reader.__dict__)

    def test_bad_json_does_not_discard_remaining_raw_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            process = subprocess.Popen([sys.executable, "-c",
                "print('{malformed'); print('{\"type\":\"summary\",\"status\":\"failed\"}')"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            reader = reliability.OutputReader(process, Path(directory))
            reader.start()
            process.wait(timeout=10)
            result = reader.finish()
            self.assertIsNotNone(result["output_parse_error"])
            self.assertEqual(result["state_soak_summary"]["status"], "failed")
            self.assertEqual(len(Path(result["stdout_file"]).read_text().splitlines()), 2)

    def test_final_engine_rss_not_inherited_ru_maxrss(self):
        resources = {"initial_rss_kib": 2000, "peak_sampled_rss_kib": 4000, "final_rss_kib": 3000}
        reliability.reconcile_resources(resources, {"reported": {"resources": {
            "resident_rss_kib": 4500, "max_rss_kib": 660000, "cpu_user_seconds": 0.2}}})
        self.assertEqual(resources["final_rss_kib"], 4500)
        self.assertEqual(resources["peak_sampled_rss_kib"], 4500)
        self.assertFalse(resources["legacy_ru_maxrss_used_as_sample"])
        self.assertEqual(resources["engine_reported_cpu_user_seconds"], 0.2)

    def test_baseline_is_durable_before_candidate_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate_path = Path(directory) / "candidate.json"
            baseline_path = Path(directory) / "baseline.json"
            order = []

            def run_build(build, args, report, output, raw, legacy_mode, fixture):
                order.append(report["label"])
                if not legacy_mode:
                    baseline = json.loads(baseline_path.read_text())
                    self.assertEqual(baseline["status"], "complete")
                    self.assertTrue(report["baseline_saved_before_candidate"])
                    self.assertEqual(report["baseline_report_sha256"], reliability.sha256_file(baseline_path))
                report["status"] = "complete"
                output.save(report)

            with patch.object(reliability, "binary_path", return_value=Path("/bin/true")), \
                    patch.object(reliability.legacy, "metadata", return_value={"build_type": "Release"}), \
                    patch.object(reliability, "run_build", side_effect=run_build), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = reliability.main(["--build", str(Path(directory) / "new"),
                    "--baseline-build", str(Path(directory) / "old"), "--packets", "10",
                    "--output", str(candidate_path), "--baseline-output", str(baseline_path)])
            self.assertEqual(result, 0)
            self.assertEqual(order, ["baseline", "candidate"])

    def test_long_duration_and_increasing_rates_validation(self):
        self.assertEqual(reliability.parse_args(["--live-soak", "--duration-seconds", "3600"]).duration_seconds, 3600)
        self.assertEqual(reliability.parse_rates("100,1000,10000,0"), [100, 1000, 10000, 0])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            reliability.parse_args(["--repeats", "2"])
        with self.assertRaises(Exception):
            reliability.parse_rates("1000,100,0")

    def test_existing_baseline_is_referenced_without_being_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline_path = Path(directory) / "baseline.json"
            baseline_path.write_text(json.dumps({"schema_version": 2, "status": "complete",
                "binary_sha256": reliability.sha256_file("/bin/true")}))
            original = baseline_path.read_bytes()
            candidate_path = Path(directory) / "candidate.json"
            calls = []

            def run_build(build, args, report, output, raw, legacy_mode, fixture):
                calls.append(legacy_mode)
                self.assertFalse(legacy_mode)
                self.assertTrue(report["baseline_reused"])
                report["status"] = "complete"
                output.save(report)

            with patch.object(reliability, "binary_path", return_value=Path("/bin/true")), \
                    patch.object(reliability.legacy, "metadata", return_value={"build_type": "Release"}), \
                    patch.object(reliability, "run_build", side_effect=run_build), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(reliability.main(["--build", str(Path(directory) / "new"),
                    "--baseline-build", str(Path(directory) / "old"), "--packets", "10",
                    "--baseline-report", str(baseline_path), "--output", str(candidate_path)]), 0)
            self.assertEqual(calls, [False])
            self.assertEqual(baseline_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
