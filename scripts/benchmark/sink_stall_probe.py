#!/usr/bin/env python3
"""Controlled local HTTP sink-stall measurement; no remote hosts or credentials.

Uses the real IDS CLI and ordinary loopback TCP/UDP. The temporary localhost
HTTP responder acknowledges test events after a configured delay; this probes
backpressure, not FastAPI persistence (that is covered by the live E2E test).
"""
import argparse
import json
import signal
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import reliability_benchmark as measure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=measure.ROOT / "build/hardening-final-release")
    parser.add_argument("--docker-image", choices=["ubuntu:26.04"])
    parser.add_argument("--event-queue-capacity", type=int, default=0)
    parser.add_argument("--duration-seconds", type=float, default=3.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 0 <= args.event_queue_capacity <= 1000000 or not 0 < args.duration_seconds <= 3600:
        parser.error("queue capacity must be 0..1000000 and duration must be 0..3600 seconds (positive)")
    output = measure.ReportFile(args.output or measure.unique_output(label="sink-stall-v2"))
    report = {"schema_version": 2, "scope": "local-real-IDS-HTTP-sink-stall",
              "metadata": measure.legacy.metadata(args.build), "stages": [], "status": "running",
              "event_queue_capacity": args.event_queue_capacity, "duration_seconds": args.duration_seconds}
    raw = output.path.parent / (output.path.stem + "-raw")
    raw.mkdir(exist_ok=False)
    binary = measure.binary_path(args.build, "intriqo-engine")
    report["binary_sha256"] = measure.sha256_file(binary)
    output.save(report)
    try:
        for index, delay in enumerate((0.0, 0.5, 1.0)):
            delivered = []

            class Responder(BaseHTTPRequestHandler):
                def do_POST(self):
                    payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    assert uuid.UUID(payload["event_id"]).version == 4
                    assert payload["event_type"] == "PORT_SCAN"
                    time.sleep(delay)
                    self.send_response(201)
                    self.end_headers()
                    # Bounded one-known-scan evidence, not an event queue.
                    if len(delivered) < 2:
                        delivered.append(payload["event_id"])

                def log_message(self, *_args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Responder)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            workload = measure.LocalWorkload(True)
            process = None
            try:
                options = ["--interface", "lo", "--no-promiscuous", "--filter", workload.bpf(),
                           "--sink", "http", "--control-plane-url", f"http://127.0.0.1:{server.server_port}",
                           "--event-queue-capacity", str(args.event_queue_capacity)]
                config = SimpleNamespace(docker_image=args.docker_image, sample_interval_ms=100)
                process = measure.BenchmarkProcess(binary, options, raw / f"delay-{index}", config,
                                                   use_docker=bool(args.docker_image))
                process.wait_ready()
                offered = workload.offer(100000, args.duration_seconds)
                time.sleep(0.3)
                if process.container:
                    measure.legacy.command(["docker", "kill", "--signal", "TERM", process.container], timeout=10)
                else:
                    process.process.send_signal(signal.SIGTERM)
                result = process.finish(timeout=10)
                result.update(http_ack_delay_seconds=delay, workload=offered,
                              http_events_acknowledged=len(delivered))
                report["stages"].append(result)
                output.save(report)
                if result["exit_code"] != 0:
                    raise RuntimeError("IDS sink probe exited with failure; raw evidence retained")
                print(delay, result["reported"]["counts"], flush=True)
            finally:
                if process:
                    process.abort()
                workload.close()
                server.shutdown()
                server.server_close()
                server_thread.join()
        report["status"] = "complete"
        output.save(report)
        print("result:", output.path)
    except Exception as error:
        report["status"], report["error"] = "failed", str(error)
        output.save(report)
        raise
    finally:
        output.close()


if __name__ == "__main__":
    main()
