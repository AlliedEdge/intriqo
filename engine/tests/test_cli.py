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
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
