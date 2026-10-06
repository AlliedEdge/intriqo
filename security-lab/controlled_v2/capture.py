#!/usr/bin/env python3
"""Write an immutable classic nanosecond Ethernet PCAP from one interface.

This is intentionally a small passive capture process for the controlled-v2
lab.  It does not open an IP socket, route traffic, or transform frames.  The
capture is written to a temporary name and atomically renamed only after the
process has closed and fsynced the completed PCAP.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import json
import os
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any


SNAPLEN = 65535
DLT_EN10MB = 1
ETH_P_ALL = 0x0003
PCAP_NANO_LITTLE_ENDIAN = 0xA1B23C4D


def utc_ns() -> int:
    return time.time_ns()


def utc_timestamp(value_ns: int) -> str:
    seconds, nanoseconds = divmod(int(value_ns), 1_000_000_000)
    value = _datetime.datetime.fromtimestamp(seconds, _datetime.timezone.utc)
    return f"{value:%Y-%m-%dT%H:%M:%S}.{nanoseconds:09d}Z"


def _clock_source() -> str:
    try:
        return Path("/sys/devices/system/clocksource/clocksource0/current_clocksource").read_text(
            encoding="ascii"
        ).strip()
    except OSError:
        return "unavailable"


def _write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.partial")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _write_pcap_header(stream: Any) -> None:
    stream.write(
        struct.pack(
            "<IHHiiii",
            PCAP_NANO_LITTLE_ENDIAN,
            2,
            4,
            0,
            0,
            SNAPLEN,
            DLT_EN10MB,
        )
    )


def _kernel_timestamp_ns(message: list[tuple[int, int, bytes]]) -> int | None:
    # SO_TIMESTAMPNS supplies a kernel CLOCK_REALTIME timespec.  On the
    # 64-bit Linux hosts used by this lab it is two native long-sized values.
    for level, kind, data in message:
        if level != socket.SOL_SOCKET:
            continue
        timestamp_kind = getattr(socket, "SO_TIMESTAMPNS", 35)
        if kind != timestamp_kind or len(data) < 16:
            continue
        seconds, nanoseconds = struct.unpack("=qq", data[:16])
        if seconds >= 0 and 0 <= nanoseconds < 1_000_000_000:
            return seconds * 1_000_000_000 + nanoseconds
    return None


def capture(
    *,
    interface: str,
    output: Path,
    ready_file: Path,
    receipt_file: Path,
    max_duration: float,
) -> dict[str, Any]:
    if interface not in {"tap-intriqo-v2", "lab0"}:
        raise ValueError("capture interface must be tap-intriqo-v2 or lab0")
    if max_duration <= 0 or max_duration > 120:
        raise ValueError("max_duration must be between 0 and 120 seconds")

    output.parent.mkdir(parents=True, exist_ok=True)
    ready_file.parent.mkdir(parents=True, exist_ok=True)
    receipt_file.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.partial")
    try:
        temporary.unlink()
    except FileNotFoundError:
        pass

    stop = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    start_ns = utc_ns()
    timestamp_source = "SO_TIMESTAMPNS" if hasattr(socket, "SOL_SOCKET") else "CLOCK_REALTIME"
    frames = 0
    bytes_captured = 0
    receive_errors = 0

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.setsockopt(socket.SOL_SOCKET, getattr(socket, "SO_TIMESTAMPNS", 35), 1)
    sock.bind((interface, 0))
    sock.settimeout(0.2)
    ready = {
        "interface": interface,
        "started_at": utc_timestamp(start_ns),
        "timestamp_source": timestamp_source,
        "clock_source": _clock_source(),
        "timezone": "UTC",
        "pid": os.getpid(),
    }
    _write_json(ready_file, ready)

    try:
        with temporary.open("wb") as stream:
            _write_pcap_header(stream)
            stream.flush()
            os.fsync(stream.fileno())
            deadline = time.monotonic() + max_duration
            while not stop and time.monotonic() < deadline:
                try:
                    frame, ancillary, _flags, _address = sock.recvmsg(SNAPLEN, 256)
                except socket.timeout:
                    continue
                except OSError:
                    receive_errors += 1
                    if stop:
                        break
                    raise
                timestamp_ns = _kernel_timestamp_ns(ancillary) or utc_ns()
                if len(frame) > SNAPLEN:
                    frame = frame[:SNAPLEN]
                stream.write(
                    struct.pack(
                        "<IIII",
                        timestamp_ns // 1_000_000_000,
                        timestamp_ns % 1_000_000_000,
                        len(frame),
                        len(frame),
                    )
                )
                stream.write(frame)
                frames += 1
                bytes_captured += len(frame)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        sock.close()
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

    end_ns = utc_ns()
    result: dict[str, Any] = {
        "schema_version": "controlled_capture_process.v1",
        "interface": interface,
        "output": str(output),
        "started_at": utc_timestamp(start_ns),
        "ended_at": utc_timestamp(end_ns),
        "timestamp_source": timestamp_source,
        "clock_source": _clock_source(),
        "timezone": "UTC",
        "timestamp_resolution": "nanosecond",
        "link_type": "Ethernet",
        "link_type_number": DLT_EN10MB,
        "frames_written": frames,
        "frame_bytes_written": bytes_captured,
        "receive_errors": receive_errors,
        "stopped_by_signal": stop,
    }
    _write_json(receipt_file, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--receipt-file", type=Path, required=True)
    parser.add_argument("--max-duration", type=float, default=20.0)
    args = parser.parse_args(argv)
    try:
        result = capture(
            interface=args.interface,
            output=args.output,
            ready_file=args.ready_file,
            receipt_file=args.receipt_file,
            max_duration=args.max_duration,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
