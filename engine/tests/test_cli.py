"""Standard-library CLI regression tests, registered with CTest."""
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ENGINE = sys.argv.pop(1)


class CliTests(unittest.TestCase):
    def run_engine(self, *args, env=None):
        return subprocess.run([ENGINE, *args], capture_output=True, text=True,
                              env=env, timeout=10, check=False)

    def test_help_and_invalid_configuration(self):
        self.assertEqual(self.run_engine("--help").returncode, 0)
        for args in [[], ["--synthetic", "--pcap", "missing"],
                     ["--synthetic", "--filter", "tcp"],
                     ["--synthetic", "--synthetic-packets", "0"],
                     ["--synthetic", "--portscan-window", "nan"],
                     ["--synthetic", "--portscan-window", "inf"],
                     ["--synthetic", "--portscan-unique-port-threshold", "65536"],
                     ["--interface", "lo", "--snaplen", "16777217"],
                     ["--interface", "lo", "--capture-buffer-bytes", "0"],
                     ["--interface", "lo", "--capture-timeout-ms", "0"],
                     ["--synthetic", "--max-active-flows", "0"],
                     ["--synthetic", "--max-tracked-sources", "0"],
                     ["--synthetic", "--flow-idle-timeout", "inf"],
                     ["--synthetic", "--sink", "invalid"]]:
            with self.subTest(args=args):
                self.assertEqual(self.run_engine(*args).returncode, 2)

    def test_synthetic_emits_real_jsonl_and_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.jsonl"
            run = self.run_engine("--synthetic", "--output", str(output))
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertIn("startup status=running", run.stdout)
            self.assertIn("packets_parsed=10", run.stdout)
            self.assertIn("events_emitted=1", run.stdout)
            import json
            event = json.loads(output.read_text().strip())
            self.assertEqual(event["event_type"], "PORT_SCAN")

    def test_event_queue_help_and_invalid_capacity(self):
        help_run = self.run_engine("--help")
        self.assertEqual(help_run.returncode, 0)
        self.assertIn("--event-queue-capacity", help_run.stdout)
        self.assertIn("INTRIQO_EVENT_QUEUE_CAPACITY", help_run.stdout)
        self.assertIn("synchronous delivery", help_run.stdout)
        self.assertIn("queued delivery", help_run.stdout)
        for capacity in ["-1", "not-a-number", "1.5", "1000001", "999999999999999999999999"]:
            with self.subTest(capacity=capacity, source="cli"):
                env = os.environ | {"INTRIQO_EVENT_QUEUE_CAPACITY": "0"}
                run = self.run_engine("--synthetic", "--output", "/dev/null",
                                      "--event-queue-capacity", capacity, env=env)
                self.assertEqual(run.returncode, 2)
                self.assertIn("--event-queue-capacity requires a non-negative integer", run.stderr)
                self.assertNotIn("startup status=running", run.stdout)
            with self.subTest(capacity=capacity, source="environment"):
                env = os.environ | {"INTRIQO_EVENT_QUEUE_CAPACITY": capacity}
                run = self.run_engine("--synthetic", "--output", "/dev/null", env=env)
                self.assertEqual(run.returncode, 2)
                self.assertIn("INTRIQO_EVENT_QUEUE_CAPACITY requires a non-negative integer", run.stderr)

    def test_default_and_zero_event_queue_are_synchronous(self):
        env = dict(os.environ)
        env.pop("INTRIQO_EVENT_QUEUE_CAPACITY", None)
        for capacity_args in [[], ["--event-queue-capacity", "0"]]:
            with self.subTest(args=capacity_args), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "events.jsonl"
                run = self.run_engine("--synthetic", "--output", str(output),
                                      *capacity_args, env=env)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn("event_queue_capacity=0", run.stdout)
                self.assertIn("delivery_mode=synchronous", run.stdout)
                shutdown = next(line for line in run.stdout.splitlines()
                                if line.startswith("shutdown "))
                self.assertIn("events_emitted=1", shutdown)
                self.assertIn("sink_failures=0", shutdown)
                import json
                events = [json.loads(line) for line in output.read_text().splitlines()]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["event_type"], "PORT_SCAN")

    def test_positive_event_queue_drains_real_file_events(self):
        env = os.environ | {"INTRIQO_EVENT_QUEUE_CAPACITY": "0"}
        for capacity in ["1", "4"]:
            with self.subTest(capacity=capacity), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "events.jsonl"
                run = self.run_engine("--synthetic", "--synthetic-packets", "10",
                                      "--output", str(output), "--event-queue-capacity", capacity,
                                      env=env)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn(f"event_queue_capacity={capacity}", run.stdout)
                self.assertIn("delivery_mode=queued", run.stdout)
                shutdown = next(line for line in run.stdout.splitlines()
                                if line.startswith("shutdown "))
                self.assertIn("status=complete", shutdown)
                self.assertIn("packets_parsed=10", shutdown)
                self.assertIn("events_emitted=1", shutdown)
                self.assertIn("sink_failures=0", shutdown)
                import json
                events = [json.loads(line) for line in output.read_text().splitlines()]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["event_type"], "PORT_SCAN")

    def test_event_queue_environment_and_cli_precedence(self):
        for env_capacity, cli_capacity, expected_capacity in [
                ("4", None, "4"), ("4", "0", "0"), ("0", "1", "1"),
                ("invalid", "1", "1"), ("", None, "0")]:
            with self.subTest(env=env_capacity, cli=cli_capacity):
                env = os.environ | {"INTRIQO_EVENT_QUEUE_CAPACITY": env_capacity}
                args = [] if cli_capacity is None else ["--event-queue-capacity", cli_capacity]
                run = self.run_engine("--synthetic", "--output", "/dev/null", *args, env=env)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertIn(f"event_queue_capacity={expected_capacity}", run.stdout)
                delivery_mode = "synchronous" if expected_capacity == "0" else "queued"
                self.assertIn(f"delivery_mode={delivery_mode}", run.stdout)
                shutdown = next(line for line in run.stdout.splitlines()
                                if line.startswith("shutdown "))
                self.assertIn("events_emitted=1", shutdown)
                self.assertIn("sink_failures=0", shutdown)

    def test_state_configuration_environment_and_overrides(self):
        env = os.environ | {"INTRIQO_MAX_ACTIVE_FLOWS": "2",
                            "INTRIQO_FLOW_IDLE_TIMEOUT_SECONDS": "2",
                            "INTRIQO_PORTSCAN_MAX_SOURCES": "1",
                            "INTRIQO_PORTSCAN_MAX_OBSERVATIONS": "2"}
        run = self.run_engine("--synthetic", "--output", "/dev/null", env=env)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("flows_evicted=8", run.stdout)
        self.assertIn("peak_active_flows=2", run.stdout)
        self.assertIn("events_emitted=1", run.stdout)
        run = self.run_engine("--synthetic", "--output", "/dev/null",
                              "--max-active-flows", "20", env=env)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("max_active_flows=20", run.stdout)

    def test_capture_errors_are_actionable(self):
        run = self.run_engine("--pcap", "/no/such/intriqo.pcap", "--output", "/dev/null")
        self.assertEqual(run.returncode, 1)
        self.assertIn("cannot open file", run.stderr)
        self.assertIn("shutdown status=error", run.stdout)

    def test_file_sink_initialization_failure_is_reported(self):
        run = self.run_engine("--synthetic", "--output", "/no/such/intriqo/events.jsonl")
        self.assertEqual(run.returncode, 1)
        self.assertIn("event sink initialization failed", run.stderr)
        self.assertIn("packets_received=0", run.stdout)
        self.assertIn("sink_failures=1", run.stdout)

    def test_sigint_and_sigterm_flush_and_exit_successfully(self):
        for sig in [signal.SIGINT, signal.SIGTERM]:
            with self.subTest(signal=sig):
                process = subprocess.Popen([ENGINE, "--synthetic", "--synthetic-packets",
                                            "1000000000", "--output", "/dev/null"],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(timeout=5), "no startup output")
                    self.assertIn(b"startup status=starting", process.stdout.readline())
                    process.send_signal(sig)
                    out, err = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 0, err)
                    self.assertIn(b"shutdown status=interrupted", out)
                    self.assertIn(b"flows_active=0", out)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()

    def test_http_delivery_and_failure_without_token_logging(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            status = 201

            def do_POST(self):
                received.append((self.path, self.headers.get("Authorization"),
                                 self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(self.status)
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            env = os.environ | {"INTRIQO_CONTROL_PLANE_URL": f"http://127.0.0.1:{server.server_port}",
                                "INTRIQO_CONTROL_PLANE_TOKEN": "local-test-token",
                                "INTRIQO_CONTROL_PLANE_ENDPOINT": "/api/v1/events"}
            run = self.run_engine("--synthetic", "--sink", "http", env=env)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(received[0][0:2], ("/api/v1/events", "Bearer local-test-token"))
            self.assertNotIn("local-test-token", run.stdout + run.stderr)
            Handler.status = 500
            run = self.run_engine("--synthetic", "--sink", "http", env=env)
            self.assertEqual(run.returncode, 1)
            self.assertIn("HTTP 500", run.stderr)
            self.assertIn("events_emitted=0", run.stdout)
            self.assertIn("sink_failures=1", run.stdout)
            for status in [201, 500]:
                with self.subTest(delivery_mode="queued", status=status):
                    Handler.status = status
                    received.clear()
                    run = self.run_engine("--synthetic", "--sink", "http",
                                          "--event-queue-capacity", "1", env=env)
                    self.assertEqual(run.returncode, 0 if status == 201 else 1, run.stderr)
                    self.assertEqual(len(received), 1)
                    self.assertEqual(received[0][0:2], ("/api/v1/events", "Bearer local-test-token"))
                    import json
                    self.assertEqual(json.loads(received[0][2])["event_type"], "PORT_SCAN")
                    self.assertIn("delivery_mode=queued", run.stdout)
                    self.assertNotIn("local-test-token", run.stdout + run.stderr)
                    self.assertNotIn(env["INTRIQO_CONTROL_PLANE_URL"], run.stdout + run.stderr)
                    shutdown = next(line for line in run.stdout.splitlines()
                                    if line.startswith("shutdown "))
                    self.assertIn(f"events_emitted={1 if status == 201 else 0}", shutdown)
                    self.assertIn(f"sink_failures={0 if status == 201 else 1}", shutdown)
                    if status == 500:
                        self.assertIn("HTTP 500", run.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
