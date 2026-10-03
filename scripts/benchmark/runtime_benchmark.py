#!/usr/bin/env python3
"""Reproducible Release runtime benchmark; optional authorized loopback workload.

Only standard-library dependencies. Raw results go to an ignored results folder.
No interface privileges are needed for synthetic/PCAP. --live requires NET_RAW
or --docker-image for an ephemeral local validation process, not deployment.
"""
import argparse
import hashlib
import json
import os
import platform
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

ROOT = Path(__file__).resolve().parents[2]


def command(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, check=True, **kwargs).stdout.strip()


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def write_pcap(path, count, ports):
    """Checksummed documentation-address TCP SYN fixture; never injected."""
    source, target = socket.inet_aton("192.0.2.10"), socket.inet_aton("198.51.100.20")
    with path.open("wb") as out:
        out.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index in range(count):
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, index & 65535, 0x4000, 64, 6, 0, source, target)
            ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
            tcp = struct.pack("!HHIIHHHH", 49152, index % ports + 1, index & 0xffffffff, 0, 0x5002, 64240, 0, 0)
            pseudo = source + target + struct.pack("!BBH", 0, 6, 20)
            tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
            frame = bytes.fromhex("0200000000020200000000010800") + ip + tcp
            out.write(struct.pack("<IIII", 1700000000 + index // 1000, index % 1000 * 1000, 54, 54))
            out.write(frame)


def fields(output):
    result = {}
    for line in output.splitlines():
        if line.startswith(("counts ", "rates ", "resources ", "latency ")):
            group, *values = line.split()
            result[group] = {}
            for value in values:
                if "=" not in value:
                    continue
                key, raw = value.split("=", 1)
                try:
                    parsed = float(raw) if any(c in raw for c in ".eE") else int(raw)
                except ValueError:
                    parsed = raw
                result[group][key] = parsed
    return result


def metadata(build):
    cache = (build / "CMakeCache.txt").read_text()
    entries = dict(line.split("=", 1) for line in cache.splitlines() if "=" in line and not line.startswith(("#", "//")))
    compiler = entries["CMAKE_CXX_COMPILER:FILEPATH"]
    if entries.get("CMAKE_BUILD_TYPE:STRING") != "Release":
        raise RuntimeError("benchmark requires a Release build")
    cpu = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))
    ram = next(line.split(":", 1)[1].strip() for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemTotal:"))
    return {"cpu_model": cpu, "ram": ram, "os": platform.platform(),
            "os_distribution": platform.freedesktop_os_release().get("PRETTY_NAME", "unknown"), "kernel": platform.release(),
            "compiler": compiler, "compiler_version": command([compiler, "--version"]).splitlines()[0],
            "build_type": "Release", "git_commit": command(["git", "rev-parse", "HEAD"], cwd=ROOT),
            "git_dirty": bool(command(["git", "status", "--porcelain"], cwd=ROOT)),
            "utc_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "cpu_affinity": sorted(os.sched_getaffinity(0))}


def offline(binary, pcap, args):
    results = []
    detector = ["--portscan-window", "10", "--portscan-unique-port-threshold", "10", "--portscan-minimum-attempts", "10"]
    for mode in ("synthetic", "pcap"):
        source = ["--synthetic", "--synthetic-packets", str(args.packets), "--synthetic-unique-ports", str(args.ports)] if mode == "synthetic" else ["--pcap", str(pcap)]
        for run in range(args.repeats):
            output = command([str(binary), *source, *detector], timeout=120)
            results.append({"mode": mode, "run": run+1, **fields(output)})
    return results


def live(binary, args):
    listeners, threads = [], []
    stop = threading.Event()
    container = None
    process = None
    try:
        for _ in range(100):
            first = 40000 + int(uuid.uuid4().hex[:4], 16) % 19000
            try:
                for port in range(first, first+10):
                    listener = socket.socket()
                    listeners.append(listener)
                    listener.bind(("127.0.0.2", port))
                    listener.listen(128)
                    listener.settimeout(0.1)
                break
            except OSError:
                for listener in listeners:
                    listener.close()
                listeners.clear()
        if len(listeners) != 10:
            raise RuntimeError("cannot reserve local listeners")

        def drain(listener):
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                    connection.close()
                except TimeoutError:
                    pass
                except OSError:
                    return
        for listener in listeners:
            thread = threading.Thread(target=drain, args=(listener,), daemon=True)
            thread.start()
            threads.append(thread)
        # Capture real SYNs only, excluding ACK/FIN/RST traffic from workload.
        bpf = f"tcp and tcp[13] & 2 != 0 and src host 127.0.0.1 and dst host 127.0.0.2 and dst portrange {first}-{first+9}"
        options = ["--interface", "lo", "--filter", bpf, "--duration-seconds", "3"]
        if args.docker_image:
            container = f"intriqo-live-benchmark-{uuid.uuid4().hex[:12]}"
            cmd = ["docker", "run", "--rm", "--name", container, "--network", "host", "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--user", "0",
                   "-v", f"{binary.resolve()}:/benchmark:ro", "-v", "/usr/lib/x86_64-linux-gnu:/host-lib:ro",
                   "--entrypoint", "/host-lib/ld-linux-x86-64.so.2", args.docker_image,
                   "--library-path", "/host-lib", "/benchmark", *options]
        else:
            cmd = [str(binary), *options]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = b""
        deadline = time.monotonic() + 15
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while b"capture_ready=true" not in output and time.monotonic() < deadline:
                if selector.select(0.1):
                    chunk = os.read(process.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    output += chunk
        if b"capture_ready=true" not in output:
            raise RuntimeError("live capture not ready; check NET_RAW/libpcap")
        offered = 0
        started = time.monotonic()
        for index in range(args.live_connections):
            with socket.socket() as connection:
                connection.settimeout(0.5)
                connection.bind(("127.0.0.1", 0))
                connection.connect(("127.0.0.2", first + index % 10))
                offered += 1
        workload_seconds = time.monotonic() - started
        tail, errors = process.communicate(timeout=15)
        if process.returncode != 0:
            raise RuntimeError(f"live benchmark failed: {errors.decode()}")
        return {"mode": "live", "workload": "authorized-loopback-TCP-SYN-only-filter", "connections_offered": offered,
                "capture_interface": "lo", "capture_filter": bpf, "snaplen": 65535,
                "capture_buffer_bytes": 16777216, "promiscuous": False, "duration_seconds": 3,
                "workload_generation_seconds": workload_seconds, **fields((output+tail).decode())}
    finally:
        stop.set()
        if container:
            subprocess.run(["docker", "stop", "--time", "3", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
        if process and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        for listener in listeners:
            listener.close()
        for thread in threads:
            thread.join(timeout=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build/runtime-release")
    parser.add_argument("--packets", type=int, default=100000)
    parser.add_argument("--ports", type=int, default=1000)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks/engine/results/runtime.json")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--live-connections", type=int, default=1000)
    parser.add_argument("--docker-image", help="optional x86_64 Linux local validation launcher")
    args = parser.parse_args()
    if not 0 < args.packets <= 10000000 or not 0 < args.ports <= 65535 or not 0 < args.repeats <= 20:
        parser.error("packets must be 1..10000000, ports 1..65535, repeats 1..20")
    if not 0 < args.live_connections <= 10000:
        parser.error("live connections must be 1..10000")
    binary = args.build.resolve() / "engine/intriqo-runtime-benchmark"
    if not binary.exists():
        binary = args.build.resolve() / "intriqo-runtime-benchmark"
    report = {"metadata": metadata(args.build), "detector": {"name": "port_scan", "window_seconds": 10,
        "unique_port_threshold": 10, "minimum_attempts": 10}, "input_packets": args.packets, "input_unique_ports": args.ports,
        "sink": "FileEventSink(/dev/null), JSON serialization/file transport included"}
    with tempfile.TemporaryDirectory(prefix="intriqo-benchmark-") as directory:
        fixture = Path(directory) / "input.pcap"
        write_pcap(fixture, args.packets, args.ports)
        report["pcap_sha256"] = hashlib.sha256(fixture.read_bytes()).hexdigest()
        report["runs"] = offline(binary, fixture, args)
    if args.live:
        report["runs"].append(live(binary, args))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    for run in report["runs"]:
        print(run["mode"], run["counts"], run["rates"], run["resources"], run["latency"])
    print("results:", args.output)


if __name__ == "__main__":
    main()
