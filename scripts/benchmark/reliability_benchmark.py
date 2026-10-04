#!/usr/bin/env python3
"""Streaming baseline-first runtime reliability measurements (schema v2).

Standard library only. Offline fixtures reuse runtime_benchmark.write_pcap.
Live traffic is ordinary local sockets from 127.0.0.1 to 127.0.0.2, filtered
to one UDP port plus an optional ten-port TCP scan. No raw injection or remote
targets. Raw stdout/stderr/resource samples stream to exclusive new files.
"""
import argparse
import hashlib
import json
import math
import os
import selectors
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

import runtime_benchmark as legacy

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = 2
LOOPBACK_STATISTICS = (
    "Linux libpcap ps_recv counts filter-matching packets presented to the capture "
    "socket, potentially including both loopback skb directions. It is not UDP "
    "sends, callbacks, or unique wire packets. ps_drop counts capture socket/kernel "
    "buffer drops; ps_ifdrop is separate and may be unavailable. Never infer exact "
    "offered loss from ps_recv, or divide it by two as a guarantee."
)


def unique_output(directory=None, label="reliability"):
    directory = directory or ROOT / "benchmarks/engine/results"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return Path(directory) / f"{label}-{stamp}-{uuid.uuid4().hex[:12]}.json"


class ReportFile:
    """Reserve once with O_EXCL; checkpoints use only our already-owned fd."""
    def __init__(self, path):
        self.path = Path(path).resolve()
        if self.path == (ROOT / "benchmarks/engine/results/runtime.json").resolve():
            raise ValueError("runtime.json belongs to the existing driver; choose a new result path")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = self.path.open("x", encoding="utf-8")

    def save(self, report):
        self.file.seek(0)
        json.dump(report, self.file, indent=2, allow_nan=False)
        self.file.write("\n")
        self.file.truncate()
        self.file.flush()
        os.fsync(self.file.fileno())

    def close(self):
        self.file.close()


def binary_path(build, name="intriqo-runtime-benchmark"):
    build = Path(build).resolve()
    for candidate in (build / "engine" / name, build / name):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError(f"executable {name} missing in {build}")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_process_sample(pid):
    """Read the engine host PID, never a docker client's resource usage."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # Fields after final ')' start at field 3. utime/stime: 14/15, RSS: 24.
        values = stat[stat.rfind(")") + 2:].split()
        if values[0] == "Z":
            return None
        ticks = os.sysconf("SC_CLK_TCK")
        rss_kib = int(values[21]) * os.sysconf("SC_PAGE_SIZE") // 1024
        high_water = None
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmHWM:"):
                high_water = int(line.split()[1])
            elif line.startswith("VmRSS:"):
                rss_kib = int(line.split()[1])
        return {"host_pid": pid, "rss_kib": rss_kib,
                "process_high_water_rss_kib": high_water,
                "cpu_user_seconds": int(values[11]) / ticks,
                "cpu_system_seconds": int(values[12]) / ticks,
                "process_start_ticks": int(values[19])}
    except (OSError, ValueError, IndexError):
        return None


class ProcessMonitor:
    """Only first/last/peak and counters retained; samples stream to disk."""
    def __init__(self, pid, path, interval):
        self.pid, self.path, self.interval = pid, Path(path), interval
        self.stop_event = threading.Event()
        self.initial = self.final = self.peak = self.error = None
        self.samples = 0
        self.start = time.monotonic()
        self.file = self.path.open("x", encoding="utf-8")
        self.thread = threading.Thread(target=self._run, name="engine-proc-monitor", daemon=True)

    def begin(self):
        self._sample("initial")
        self.thread.start()

    def _sample(self, phase):
        sample = read_process_sample(self.pid)
        if sample is None:
            return
        if self.initial and sample["process_start_ticks"] != self.initial["process_start_ticks"]:
            raise RuntimeError("engine PID reused; refusing to sample another process")
        sample.update({"schema_version": SCHEMA_VERSION, "type": "process_sample",
                       "phase": phase, "elapsed_seconds": time.monotonic() - self.start})
        if self.initial is None:
            self.initial = sample
        self.final = sample
        self.peak = max(self.peak or 0, sample["rss_kib"])
        self.samples += 1
        self.file.write(json.dumps(sample, allow_nan=False) + "\n")
        self.file.flush()

    def _run(self):
        try:
            while not self.stop_event.wait(self.interval):
                self._sample("periodic")
        except Exception as error:
            self.error = str(error)

    def finish(self):
        self.stop_event.set()
        self.thread.join()
        try:
            self._sample("final-if-still-alive")
        finally:
            self.file.close()
        initial, final = self.initial or {}, self.final or {}
        seconds = final.get("elapsed_seconds", 0) - initial.get("elapsed_seconds", 0)
        user = final.get("cpu_user_seconds", 0) - initial.get("cpu_user_seconds", 0)
        system = final.get("cpu_system_seconds", 0) - initial.get("cpu_system_seconds", 0)
        return {"host_pid": self.pid, "source": f"/proc/{self.pid}/stat-and-status",
                "initial_rss_kib": initial.get("rss_kib"), "peak_sampled_rss_kib": self.peak,
                "final_rss_kib": final.get("rss_kib"),
                "process_high_water_rss_kib": final.get("process_high_water_rss_kib"),
                "cpu_user_seconds": user if self.initial else None,
                "cpu_system_seconds": system if self.initial else None,
                "sampled_cpu_utilization_percent": 100 * (user + system) / seconds if seconds > 0 else None,
                "sample_count": self.samples, "samples_retained_in_memory": 0,
                "sampled_cpu_span_seconds": seconds,
                "cpu_scope": "delta-between-first-and-last-actual-PID-samples; final-runtime-CPU-is-reported-separately",
                "sample_interval_seconds": self.interval, "sample_file": str(self.path),
                "initial_scope": "first-actual-alive-engine-PID-snapshot",
                "final_scope": "last-actual-alive-PID-snapshot; runtime report supplies post-flush RSS when present",
                "peak_scope": "sampled-resident-RSS; VmHWM-is-separate-process-high-water",
                "monitor_error": self.error}


def validate_correctness(record):
    events = record.get("events", [])
    if not record.get("passed") or record.get("observed_events") != 2 or len(events) != 2:
        raise RuntimeError("state soak known scan did not emit exactly two events")
    identifiers = set()
    for index, event in enumerate(events):
        identifier = uuid.UUID(event["event_id"])
        if identifier.version != 4 or identifier.variant != uuid.RFC_4122:
            raise RuntimeError("invalid event UUID")
        identifiers.add(identifier)
        expected = "2023-11-14T22:13:" + ("20.009Z" if index == 0 else "40.009Z")
        if (event.get("timestamp") != expected or event.get("event_type") != "PORT_SCAN" or
                event.get("source_address") != "10.0.0.1" or
                event.get("destination_address") != "198.51.100.20" or
                event.get("details", {}).get("unique_destination_ports") != 10 or
                event.get("details", {}).get("connection_attempts") != 10):
            raise RuntimeError("event JSON contract/timestamp/scan counts mismatch")
    if len(identifiers) != 2:
        raise RuntimeError("duplicate event UUID")


class OutputReader:
    """Drain both pipes continuously; retain only final groups and two events."""
    def __init__(self, process, directory):
        self.stdout_path, self.stderr_path = directory / "stdout.txt", directory / "stderr.txt"
        self.ready = threading.Event()
        self.groups = {}
        self.json_summary = self.correctness = self.error = None
        self.files = [self.stdout_path.open("xb"), self.stderr_path.open("xb")]
        self.threads = [threading.Thread(target=self._read, args=(process.stdout, self.files[0], True), daemon=True),
                        threading.Thread(target=self._read, args=(process.stderr, self.files[1], False), daemon=True)]

    def start(self):
        for thread in self.threads:
            thread.start()

    def _read(self, pipe, output, parse):
        try:
            for line in iter(pipe.readline, b""):
                output.write(line)
                output.flush()
                if not parse:
                    continue
                try:
                    text = line.decode("utf-8", errors="replace").strip()
                    if "capture_ready=true" in text:
                        self.ready.set()
                    if text.startswith("shutdown "):
                        self.groups.update(legacy.fields("counts " + text.removeprefix("shutdown ")))
                    self.groups.update(legacy.fields(text))
                    if text.startswith("{"):
                        record = json.loads(text)
                        if record.get("type") == "summary":
                            self.json_summary = record
                        elif record.get("type") == "correctness":
                            validate_correctness(record)
                            self.correctness = record
                except Exception as error:
                    # A malformed record must not stop draining or discard the
                    # remaining raw evidence (or give the child SIGPIPE).
                    self.error = self.error or str(error)
        except Exception as error:
            self.error = str(error)
        finally:
            output.close()
            pipe.close()

    def finish(self):
        for thread in self.threads:
            thread.join(timeout=10)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("benchmark output pipes did not close")
        return {"stdout_file": str(self.stdout_path), "stderr_file": str(self.stderr_path),
                "reported": self.groups, "state_soak_summary": self.json_summary,
                "correctness": self.correctness, "output_parse_error": self.error}


def public_libraries(binary):
    """Mount exact public system-library files, never source or home trees."""
    output = legacy.command(["ldd", str(binary)])
    libraries, loader = {}, None
    for line in output.splitlines():
        words = line.split()
        if "not found" in line:
            raise RuntimeError(f"missing benchmark library: {line.strip()}")
        if len(words) >= 3 and words[1] == "=>" and words[2].startswith("/"):
            soname, path = words[0], Path(words[2]).resolve()
        elif words and words[0].startswith("/"):
            path, soname = Path(words[0]).resolve(), Path(words[0]).name
        else:
            continue
        if not (str(path).startswith("/usr/lib/") or str(path).startswith("/lib/")):
            raise RuntimeError(f"Docker launcher accepts public system libraries only: {path}")
        if not path.is_file() or "/" in soname:
            raise RuntimeError("invalid system library mapping")
        libraries[soname] = path
        if "ld-linux" in soname:
            loader = soname
    if not loader:
        raise RuntimeError("Docker launcher requires a dynamically linked Linux executable")
    return libraries, loader


def docker_command(binary, options, image, name):
    if image != "ubuntu:26.04":
        raise ValueError("ephemeral launcher restricted to existing ubuntu:26.04")
    legacy.command(["docker", "image", "inspect", image])
    libraries, loader = public_libraries(binary)
    command = ["docker", "run", "--rm", "--pull=never", "--name", name, "--network", "host",
               "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--security-opt", "no-new-privileges",
               "--read-only", "--user", "0", "-v", f"{binary.resolve()}:/benchmark:ro"]
    for soname, library in sorted(libraries.items()):
        command += ["-v", f"{library}:/host-lib/{soname}:ro"]
    return command + ["--entrypoint", f"/host-lib/{loader}", image,
                      "--library-path", "/host-lib", "/benchmark", *options]


class BenchmarkProcess:
    def __init__(self, binary, options, directory, args, use_docker=False):
        directory.mkdir(parents=True, exist_ok=False)
        self.container = f"intriqo-reliability-{uuid.uuid4().hex[:12]}" if use_docker else None
        self.command = docker_command(binary, options, args.docker_image, self.container) if self.container else [str(binary), *options]
        self.process = self.reader = self.monitor = self.result = None
        self.started = time.monotonic()
        try:
            self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.reader = OutputReader(self.process, directory)
            self.reader.start()
            pid = self.process.pid
            if self.container:
                deadline, pid = time.monotonic() + 10, 0
                while time.monotonic() < deadline and self.process.poll() is None:
                    inspect = subprocess.run(["docker", "inspect", "--format", "{{.State.Pid}}", self.container],
                                             capture_output=True, text=True, timeout=2, check=False)
                    if inspect.returncode == 0:
                        pid = int(inspect.stdout.strip() or 0)
                        if pid > 0 and read_process_sample(pid):
                            break
                    time.sleep(0.02)
                if pid <= 0:
                    raise RuntimeError("cannot resolve engine host PID via docker inspect")
            self.monitor = ProcessMonitor(pid, directory / "process-samples.jsonl", args.sample_interval_ms / 1000)
            self.monitor.begin()
        except Exception:
            self.abort()
            raise

    def wait_ready(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.reader.ready.wait(0.02):
                return
            if self.process.poll() is not None:
                break
        raise RuntimeError(f"capture not ready; inspect {self.reader.stderr_path} (NET_RAW/libpcap required)")

    def finish(self, timeout):
        if self.result is not None:
            return self.result
        self.process.wait(timeout=timeout)
        resources = self.monitor.finish()
        self.monitor = None
        captured_output = self.reader.finish()
        reconcile_resources(resources, captured_output)
        self.result = {"command": self.command, "exit_code": self.process.returncode,
                       "wall_seconds": time.monotonic() - self.started,
                       "resources": resources, **captured_output}
        return self.result

    def abort(self):
        if self.container and self.process and self.process.poll() is None:
            subprocess.run(["docker", "stop", "--time", "2", self.container],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8, check=False)
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.monitor:
            self.monitor.finish()
            self.monitor = None
        if self.reader:
            self.reader.finish()


def reconcile_resources(resources, captured_output):
    reported = captured_output.get("reported", {}).get("resources", {})
    summary = captured_output.get("state_soak_summary") or {}
    final = summary.get("final_rss_kib", reported.get("final_rss_kib", reported.get("resident_rss_kib")))
    if isinstance(final, (int, float)) and final >= 0:
        resources["final_rss_kib"] = final
        resources["final_scope"] = "actual engine-reported post-flush resident RSS"
        resources["peak_sampled_rss_kib"] = max(resources.get("peak_sampled_rss_kib") or 0, final)
    for key in ("initial_rss_kib", "peak_sampled_rss_kib", "process_high_water_rss_kib"):
        value = summary.get(key, reported.get(key))
        if isinstance(value, (int, float)) and value >= 0:
            resources[key] = max(resources.get(key) or 0, value) if key == "peak_sampled_rss_kib" else value
            if key == "initial_rss_kib":
                resources["initial_scope"] = "engine-reported-initial-runtime-snapshot"
    # Keep the final benchmark's full-interval CPU measurements separate from
    # /proc sampling deltas. Never treat legacy ru_maxrss as an RSS sample:
    # on Linux it may include an inherited launcher pre-exec high-water.
    resources["engine_reported_cpu_user_seconds"] = summary.get("cpu_user_seconds", reported.get("cpu_user_seconds"))
    resources["engine_reported_cpu_system_seconds"] = summary.get("cpu_system_seconds", reported.get("cpu_system_seconds"))
    resources["engine_reported_cpu_utilization_percent"] = summary.get("cpu_utilization_percent", reported.get("cpu_utilization_percent"))
    resources["legacy_ru_maxrss_used_as_sample"] = False


def detector_options():
    return ["--portscan-window", "10", "--portscan-unique-port-threshold", "10", "--portscan-minimum-attempts", "10"]


def advanced_options(args, help_text, legacy_mode):
    if legacy_mode:
        return []
    requested = [("--capture-timeout-ms", args.capture_timeout_ms),
                 ("--sample-interval-ms", args.sample_interval_ms),
                 ("--flow-idle-timeout", args.flow_idle_timeout),
                 ("--max-active-flows", args.max_active_flows)]
    options = []
    for flag, value in requested:
        if flag in help_text:
            options += [flag, str(value)]
    if args.capture_immediate:
        if "--capture-immediate" not in help_text:
            raise RuntimeError("candidate benchmark does not support --capture-immediate")
        options += ["--capture-immediate"]
    return options


def measurement(result, offered=None, expected_scans=None):
    groups = result.get("reported", {})
    counts, rates, latency = groups.get("counts", {}), groups.get("rates", {}), groups.get("latency", {})
    seconds = rates.get("wall_seconds", result.get("wall_seconds", 0))
    captured, processed = counts.get("packets_captured"), counts.get("packets_processed")
    complete = captured is not None and processed is not None and "capture_drops" in counts
    statistics_available = counts.get("capture_statistics_available") in (True, 1, "true", "1")
    events = counts.get("events_emitted")
    p99 = latency.get("p99_ms")
    if not isinstance(p99, (int, float)):
        p99 = None
    return {"counter_completeness": "separate-capture-parser-processing-drop-counters" if complete else "legacy-incomplete-combined-counts",
            "offered_udp_datagrams": offered,
            "kernel_ps_recv": counts.get("packets_seen") if complete and statistics_available and offered is not None else None,
            "captured_callbacks": captured, "processed_packets": processed,
            "legacy_received_or_callback_count": counts.get("packets_received") if not complete else None,
            "legacy_parsed_count": counts.get("packets_parsed") if not complete else None,
            "capture_drops": counts.get("capture_drops") if statistics_available else None,
            "interface_drops": counts.get("interface_drops") if statistics_available else None,
            "legacy_combined_drops": counts.get("packets_dropped") if not complete else None,
            "capture_statistics_available": counts.get("capture_statistics_available"),
            "captured_packets_per_second": captured / seconds if captured is not None and seconds > 0 else None,
            "processed_packets_per_second": processed / seconds if processed is not None and seconds > 0 else None,
            "events_emitted": events,
            "detection_events_per_second": events / seconds if events is not None and seconds > 0 else None,
            "known_scan_expected_events": expected_scans,
            "known_scan_event_delivery_fraction": events / expected_scans if events is not None and expected_scans else None,
            "known_scan_exactly_once_observed": events == expected_scans if events is not None and expected_scans else None,
            "packet_latency_p99_ms": None,
            "packet_latency_p99_status": "N/A: per-packet capture/processing timestamp pairs are not measured",
            "event_latency_p99_ms": p99,
            "event_latency_scope": "capture-to-engine-observer; limited emitted-event samples, not packet P99 or isolated transport",
            "event_latency_sample_count": latency.get("samples"),
            "event_latency_p99_status": "measured-limited-event-samples" if p99 is not None else "N/A: benchmark did not report a measured event P99"}


class LocalWorkload:
    """One bounded UDP receiver and optionally ten local TCP listener ports."""
    def __init__(self, tcp_scan):
        self.stop_event = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.2", 0))
        self.udp.settimeout(0.05)
        self.udp_port = self.udp.getsockname()[1]
        self.sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sender.bind(("127.0.0.1", 0))
        self.sender.setblocking(False)
        self.listeners, self.threads = [], []
        self.received = 0
        self.tcp = {"attempted": 0, "connected": 0, "errors": 0}
        self.scanner = None
        try:
            if tcp_scan:
                self._reserve_tcp()
            self.threads = [threading.Thread(target=self._drain_udp, daemon=True)]
            if self.listeners:
                self.threads.append(threading.Thread(target=self._drain_tcp, daemon=True))
            for thread in self.threads:
                thread.start()
        except Exception:
            self.close()
            raise

    def _reserve_tcp(self):
        for _ in range(100):
            first = 40000 + int(uuid.uuid4().hex[:4], 16) % 18000
            try:
                for port in range(first, first + 10):
                    listener = socket.socket()
                    self.listeners.append(listener)
                    listener.bind(("127.0.0.2", port))
                    listener.listen(16)
                    listener.setblocking(False)
                return
            except OSError:
                for listener in self.listeners:
                    listener.close()
                self.listeners.clear()
        raise RuntimeError("cannot reserve ten local TCP listener ports")

    def bpf(self):
        narrow = f"src host 127.0.0.1 and dst host 127.0.0.2 and udp and dst port {self.udp_port}"
        if self.listeners:
            first = self.listeners[0].getsockname()[1]
            narrow = f"({narrow}) or (src host 127.0.0.1 and dst host 127.0.0.2 and tcp and tcp[13] & 2 != 0 and dst portrange {first}-{first+9})"
        return narrow

    def _drain_udp(self):
        while not self.stop_event.is_set():
            try:
                self.udp.recvfrom(2048)
                self.received += 1
            except (TimeoutError, BlockingIOError):
                pass
            except OSError:
                return

    def _drain_tcp(self):
        with selectors.DefaultSelector() as selector:
            for listener in self.listeners:
                selector.register(listener, selectors.EVENT_READ)
            while not self.stop_event.is_set():
                for key, _ in selector.select(0.05):
                    try:
                        connection, _ = key.fileobj.accept()
                        connection.close()
                    except (BlockingIOError, OSError):
                        pass

    def _scan(self, delay):
        if self.stop_event.wait(delay):
            return
        for listener in self.listeners:
            if self.stop_event.is_set():
                return
            self.tcp["attempted"] += 1
            try:
                with socket.socket() as connection:
                    connection.settimeout(0.05)
                    connection.bind(("127.0.0.1", 0))
                    connection.connect(listener.getsockname())
                    self.tcp["connected"] += 1
            except OSError:
                self.tcp["errors"] += 1

    def offer(self, rate, duration):
        if self.listeners:
            self.scanner = threading.Thread(target=self._scan, args=(min(0.25, duration / 4),), daemon=True)
            self.scanner.start()
        started = time.monotonic()
        deadline = started + duration
        count, errors, attempts = 0, 0, 0
        # Payload timestamps are ordinary data, not measured processing timestamp
        # pairs. They cannot justify a packet-latency claim.
        padding = b"intriqo-local-reliability".ljust(48, b"\0")
        while time.monotonic() < deadline:
            if rate > 0:
                due = started + attempts / rate
                now = time.monotonic()
                if due >= deadline:
                    break
                if due > now:
                    time.sleep(min(due - now, 0.001))
                    continue
            payload = struct.pack("!QQ", attempts, time.monotonic_ns()) + padding
            attempts += 1
            try:
                if self.sender.sendto(payload, ("127.0.0.2", self.udp_port)) == len(payload):
                    count += 1
                else:
                    errors += 1
            except OSError:
                errors += 1
        elapsed = time.monotonic() - started
        if self.scanner:
            self.scanner.join(timeout=2)
        return {"target_offered_udp_packets_per_second": rate,
                "target_rate_mode": "unpaced" if rate == 0 else "paced",
                "offered_udp_datagrams": count, "send_attempts": attempts, "send_errors": errors,
                "offered_count_scope": "successful ordinary UDP sendto calls, not kernel ps_recv",
                "workload_seconds": elapsed,
                "achieved_offered_udp_packets_per_second": count / elapsed if elapsed > 0 else None,
                "receiver_udp_datagrams_at_workload_end": self.received,
                "tcp_scan": dict(self.tcp),
                "known_scan_expected_events": 1 if self.listeners and self.tcp["connected"] == 10 else None,
                "payload_bytes": 64, "source": "127.0.0.1", "destination": "127.0.0.2",
                "udp_destination_port": self.udp_port}

    def close(self):
        self.stop_event.set()
        if self.scanner:
            self.scanner.join(timeout=2)
        for thread in self.threads:
            thread.join(timeout=1)
        self.sender.close()
        self.udp.close()
        for listener in self.listeners:
            listener.close()


def offline_stage(binary, fixture, args, directory, mode, run, legacy_mode, help_text=""):
    options = (["--synthetic", "--synthetic-packets", str(args.packets), "--synthetic-unique-ports", str(args.ports)]
               if mode == "synthetic" else ["--pcap", str(fixture)])
    if not legacy_mode:
        for flag, value in (("--sample-interval-ms", args.sample_interval_ms),
                            ("--flow-idle-timeout", args.flow_idle_timeout),
                            ("--max-active-flows", args.max_active_flows)):
            if flag in help_text:
                options += [flag, str(value)]
    process = BenchmarkProcess(binary, options + detector_options(), directory, args)
    try:
        result = process.finish(timeout=120)
        result.update({"stage": "offline", "mode": mode, "repeat": run,
                       "legacy_mode": legacy_mode, "input_packets": args.packets,
                       "input_unique_ports": args.ports})
        result["measurement"] = measurement(result)
        return result
    finally:
        process.abort()


def live_stage(binary, args, directory, rate, duration, help_text, legacy_mode, stage):
    workload, process = LocalWorkload(not args.no_tcp_scan), None
    try:
        capture_duration = min(3600, duration + args.drain_seconds)
        workload_duration = min(duration, capture_duration - args.drain_seconds)
        options = ["--interface", "lo", "--filter", workload.bpf(), "--duration-seconds", str(capture_duration)]
        options += detector_options() + advanced_options(args, help_text, legacy_mode)
        process = BenchmarkProcess(binary, options, directory, args, use_docker=bool(args.docker_image))
        process.wait_ready()
        offered = workload.offer(rate, workload_duration)
        result = process.finish(timeout=args.drain_seconds + 15)
        offered["receiver_udp_datagrams_after_drain"] = workload.received
        result.update({"stage": stage, "mode": "live", "legacy_mode": legacy_mode,
                       "workload": offered, "capture_interface": "lo", "capture_filter": workload.bpf(),
                       "capture_duration_seconds": capture_duration, "workload_duration_seconds": workload_duration,
                       "requested_workload_duration_seconds": duration,
                        "requested_capture_immediate": args.capture_immediate if not legacy_mode else True,
                        "capture_mode": "immediate" if legacy_mode or args.capture_immediate else "buffered",
                       "requested_capture_timeout_ms": args.capture_timeout_ms,
                       "capture_timeout_ms": args.capture_timeout_ms if "--capture-timeout-ms" in options else "binary-default-100",
                       "loopback_kernel_statistics_semantics": LOOPBACK_STATISTICS,
                       "captured_includes": "filtered UDP plus filtered TCP SYN packets; TCP retransmissions possible",
                       "resource_sampling_target": "actual-engine-host-PID-from-docker-inspect" if args.docker_image else "engine-process-PID"})
        result["measurement"] = measurement(result, offered["offered_udp_datagrams"], offered["known_scan_expected_events"])
        return result
    finally:
        if process:
            process.abort()
        workload.close()


def state_stage(build, args, directory):
    binary = binary_path(build, "intriqo-state-soak")
    options = ["--duration-seconds", str(args.duration_seconds), "--rate", str(args.state_rate),
               "--sample-interval-ms", str(args.sample_interval_ms),
               "--max-active-flows", str(args.max_active_flows),
               "--max-tracked-sources", str(args.max_tracked_sources),
               "--max-tracked-observations", str(args.max_tracked_observations),
               "--flow-idle-timeout", str(args.flow_idle_timeout), "--ports", str(max(10, args.ports))]
    if args.state_sources:
        options += ["--sources", str(args.state_sources)]
    process = BenchmarkProcess(binary, options, directory, args)
    try:
        result = process.finish(timeout=args.duration_seconds + 30)
        result.update({"stage": "state-soak", "mode": "ordinary-raw-fixture-bytes-no-injection",
                       "latency_p99_ms": None, "latency_status": "N/A: logical fixture timestamps"})
        if result["correctness"] is None or result["state_soak_summary"] is None:
            result["output_parse_error"] = result["output_parse_error"] or "missing correctness or summary JSONL record"
        return result
    finally:
        process.abort()


def run_build(build, args, report, output, raw_directory, legacy_mode, fixture):
    binary = binary_path(build)
    help_text = legacy.command([str(binary), "--help"], timeout=15)
    report["metadata"] = legacy.metadata(build)
    report["metadata_git_state_scope"] = "measurement checkout; binary SHA256 identifies the actual executable"
    report["binary"] = str(binary)
    report["binary_sha256"] = sha256_file(binary)
    report["legacy_mode"] = legacy_mode
    report["legacy_counter_note"] = "Older received/parsed/dropped counts may combine stages; separate captured/processed/drop data remain null." if legacy_mode else None
    report["status"] = "running"
    output.save(report)

    def retain(result):
        report["stages"].append(result)
        output.save(report)
        print(f"{report['label']} {result['stage']} {result['mode']}: exit={result['exit_code']} raw={result['stdout_file']}", flush=True)
        if result["exit_code"] != 0 or result.get("output_parse_error"):
            raise RuntimeError(f"stage failed; raw output retained in {result['stdout_file']}")

    if args.offline:
        for mode in ("synthetic", "pcap"):
            for run in range(1, args.repeats + 1):
                retain(offline_stage(binary, fixture, args, raw_directory / f"offline-{mode}-{run}", mode, run, legacy_mode, help_text))
    if args.live_overload:
        for index, rate in enumerate(args.rates):
            retain(live_stage(binary, args, raw_directory / f"live-overload-{index+1}-{rate:g}", rate,
                              args.overload_duration_seconds, help_text, legacy_mode, "live-overload"))
    if args.live_soak:
        retain(live_stage(binary, args, raw_directory / "live-soak", args.soak_rate,
                          args.duration_seconds, help_text, legacy_mode, "live-soak"))
    if args.state_soak:
        if legacy_mode:
            report["state_soak_baseline_note"] = "Baseline has no state-soak executable; comparable baseline runtime stages are retained above."
        else:
            retain(state_stage(build, args, raw_directory / "state-soak"))
    report["status"] = "complete"
    output.save(report)


def parse_rates(text):
    try:
        rates = [float(item) for item in text.split(",")]
    except ValueError as error:
        raise argparse.ArgumentTypeError("rates must be a comma-separated finite number list") from error
    if (len(rates) < 2 or rates[-1] != 0 or any(not math.isfinite(r) or r <= 0 or r > 10000000 for r in rates[:-1]) or
            any(a >= b for a, b in zip(rates[:-1], rates[1:-1]))):
        raise argparse.ArgumentTypeError("rates must increase gradually, with a final 0 for unpaced")
    return rates


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build/runtime-release")
    parser.add_argument("--baseline-build", type=Path, default=ROOT / "build/hardening-baseline")
    parser.add_argument("--output", type=Path, help="exclusive new report path; default UTC+UUID filename")
    parser.add_argument("--baseline-output", type=Path, help="exclusive baseline report saved before candidate execution")
    parser.add_argument("--baseline-report", type=Path, help="reuse a completed schema-v2 baseline; referenced, never rewritten")
    parser.add_argument("--offline", action="store_true", help="synthetic and PCAP repeats (default when no stage requested)")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--packets", type=int, default=100000)
    parser.add_argument("--ports", type=int, default=1000)
    parser.add_argument("--live-overload", action="store_true")
    parser.add_argument("--rates", type=parse_rates, default=parse_rates("100,1000,10000,0"))
    parser.add_argument("--overload-duration-seconds", type=float, default=3)
    parser.add_argument("--live-soak", action="store_true")
    parser.add_argument("--state-soak", action="store_true")
    parser.add_argument("--duration-seconds", type=float, default=300, help="live/state soak duration, >0..3600; CI accepts 1..3")
    parser.add_argument("--soak-rate", type=float, default=10000)
    parser.add_argument("--state-rate", type=float, default=10000)
    parser.add_argument("--state-sources", type=int, default=0, help="0 = two times detector source capacity plus one")
    parser.add_argument("--sample-interval-ms", type=int, default=1000)
    parser.add_argument("--capture-immediate", action="store_true", help="candidate only; baseline keeps its original forced immediate mode")
    parser.add_argument("--capture-timeout-ms", type=int, default=100)
    parser.add_argument("--drain-seconds", type=float, default=0.5)
    parser.add_argument("--flow-idle-timeout", type=float, default=60)
    parser.add_argument("--max-active-flows", type=int, default=100000)
    parser.add_argument("--max-tracked-sources", type=int, default=4096)
    parser.add_argument("--max-tracked-observations", type=int, default=100000)
    parser.add_argument("--no-tcp-scan", action="store_true", help="disable known ten-port scan during UDP load")
    parser.add_argument("--docker-image", choices=["ubuntu:26.04"], help="optional existing ephemeral NET_RAW image; never pulled")
    args = parser.parse_args(argv)
    if not (3 <= args.repeats <= 20 and 0 < args.packets <= 10000000 and 0 < args.ports <= 65535):
        parser.error("repeats must be 3..20, packets 1..10000000, ports 1..65535")
    positive = (args.duration_seconds, args.overload_duration_seconds, args.flow_idle_timeout, args.drain_seconds)
    rates = (args.soak_rate, args.state_rate)
    if any(not math.isfinite(v) or v <= 0 for v in positive) or any(not math.isfinite(v) or v < 0 or v > 10000000 for v in rates):
        parser.error("durations/timeouts must be finite positive, rates finite 0..10000000")
    if args.duration_seconds > 3600 or args.overload_duration_seconds > 60 or args.drain_seconds > 10:
        parser.error("soak duration <=3600, overload interval <=60, drain <=10 seconds")
    if not 20 <= args.sample_interval_ms <= 60000 or not 1 <= args.capture_timeout_ms <= 60000:
        parser.error("sample interval 20..60000ms; capture timeout 1..60000ms")
    if (not 1 <= args.max_active_flows <= 10000000 or not 1 <= args.max_tracked_sources <= 8388607 or
            not 1 <= args.max_tracked_observations <= 10000000 or not 0 <= args.state_sources <= 16777215):
        parser.error("capacities/source cardinality outside tool limits")
    if not any((args.offline, args.live_overload, args.live_soak, args.state_soak)):
        args.offline = True
    if args.state_soak and not any((args.offline, args.live_overload, args.live_soak)):
        args.offline = True # Always retain an actual comparable baseline stage.
    args.build, args.baseline_build = args.build.resolve(), args.baseline_build.resolve()
    if args.build == args.baseline_build:
        parser.error("baseline and candidate build directories must differ")
    return args


def new_report(label, args):
    return {"schema_version": SCHEMA_VERSION, "label": label, "status": "pending",
            "utc_started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "measurement_order": "baseline increasing loads, baseline saved, candidate increasing loads",
            "sink": "real FileEventSink(/dev/null), JSON serialization/file transport included",
            "packet_latency_p99": "N/A unless actual packet timestamp pairs are measured",
            "samples_storage": "streaming files; no whole-run resource/packet sample arrays",
            "baseline_is_legacy": label == "baseline",
            "configuration": {"repeats": args.repeats, "packets": args.packets, "ports": args.ports,
                              "overload_target_rates": args.rates, "overload_interval_seconds": args.overload_duration_seconds,
                              "soak_seconds": args.duration_seconds, "sample_interval_ms": args.sample_interval_ms},
            "stages": []}


def main(argv=None):
    args = parse_args(argv)
    output_path = args.output or unique_output()
    baseline_path = args.baseline_report or args.baseline_output or unique_output(Path(output_path).parent, "reliability-baseline")
    saved_baseline = None
    if args.baseline_report:
        if args.baseline_output:
            raise ValueError("choose baseline-report or baseline-output, not both")
        saved_baseline = json.loads(args.baseline_report.read_text())
        if saved_baseline.get("schema_version") != SCHEMA_VERSION or saved_baseline.get("status") != "complete":
            raise ValueError("reused baseline must be a completed schema-v2 report")
        if saved_baseline.get("binary_sha256") != sha256_file(binary_path(args.baseline_build)):
            raise ValueError("reused baseline executable hash differs")
    if Path(output_path).resolve() == Path(baseline_path).resolve():
        raise ValueError("candidate and baseline result paths must differ")
    binary_path(args.baseline_build)
    binary_path(args.build)
    if args.state_soak:
        binary_path(args.build, "intriqo-state-soak")
    legacy.metadata(args.baseline_build)
    legacy.metadata(args.build)
    candidate_file = ReportFile(output_path)
    baseline_file = None
    candidate, baseline = new_report("candidate", args), new_report("baseline", args)
    candidate["baseline_report_file"] = str(Path(baseline_path).resolve())
    candidate["status"] = "waiting-for-baseline"
    candidate_file.save(candidate)
    current, current_file = baseline, None
    try:
        if saved_baseline is None:
            baseline_file = ReportFile(baseline_path)
            current_file = baseline_file
        raw = candidate_file.path.parent / (candidate_file.path.stem + "-raw")
        raw.mkdir(exist_ok=False)
        temp_root = "/tmp/opencode" if Path("/tmp/opencode").is_dir() else None
        with tempfile.TemporaryDirectory(prefix="intriqo-reliability-", dir=temp_root) as directory:
            fixture = Path(directory) / "input.pcap"
            legacy.write_pcap(fixture, args.packets, args.ports)
            digest = sha256_file(fixture)
            baseline["fixture_sha256"] = candidate["fixture_sha256"] = digest
            print("baseline result:", baseline_path, flush=True)
            if saved_baseline is None:
                run_build(args.baseline_build, args, baseline, baseline_file, raw / "baseline", True, fixture)
            else:
                baseline = saved_baseline
                candidate["baseline_reused"] = True
                candidate["baseline_comparison_scope"] = "previous completed baseline stages; inspect durations/configuration, not necessarily a matched soak"
            # Baseline is complete and fsynced before any candidate measurement.
            candidate["baseline_saved_before_candidate"] = True
            candidate["baseline_report_sha256"] = sha256_file(baseline_path)
            candidate["baseline_completed_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            current, current_file = candidate, candidate_file
            candidate_file.save(candidate)
            run_build(args.build, args, candidate, candidate_file, raw / "candidate", False, fixture)
        print("candidate result:", candidate_file.path, flush=True)
        return 0
    except (Exception, KeyboardInterrupt) as error:
        current["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        current["error"] = str(error) or type(error).__name__
        if current_file:
            current_file.save(current)
        if current is baseline:
            candidate["status"], candidate["error"] = "not-run-baseline-failed", current["error"]
            candidate_file.save(candidate)
        print(f"error: {current['error']}; measurements retained in {candidate_file.path}", flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    finally:
        candidate_file.close()
        if baseline_file:
            baseline_file.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        import sys
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
