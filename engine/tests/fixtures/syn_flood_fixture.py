#!/usr/bin/env python3
"""Dependency-free SYN-flood validation fixtures.

The PCAP helpers write classic Ethernet/IPv4/TCP packets with valid IPv4 and
TCP checksums.  PCAP addresses are documentation-only (192.0.2.10 and
198.51.100.20) and the files are never transmitted.

The optional command-line raw generator has deliberately narrower behaviour:
it can send exactly 120 initial SYNs, over 1.5 seconds, only from
127.0.0.1 to 127.0.0.2.  The caller supplies only the destination port.  It
is intended for the opt-in local validation test and requires NET_RAW.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import time
from pathlib import Path
from typing import Iterable


PCAP_SOURCE = "192.0.2.10"
PCAP_DESTINATION = "198.51.100.20"
PCAP_DESTINATION_PORT = 443
LIVE_SOURCE = "127.0.0.1"
LIVE_DESTINATION = "127.0.0.2"
LIVE_SYN_COUNT = 120
LIVE_DURATION_SECONDS = 1.5

_ETHERNET = bytes.fromhex("0200000000010200000000020800")
_TCP_PROTOCOL = 6
_PCAP_EPOCH_US = 1_700_000_000_000_000


def checksum(data: bytes) -> int:
    """Return the RFC 1071 one's-complement checksum for *data*."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _tcp_ipv4_frame(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    identification: int,
) -> bytes:
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
    tcp = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence & 0xFFFFFFFF,
        acknowledgement & 0xFFFFFFFF,
        (5 << 12) | flags,
        65535,
        0,
        0,
    )
    pseudo_header = source_bytes + destination_bytes + struct.pack(
        "!BBH", 0, _TCP_PROTOCOL, len(tcp)
    )
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo_header + tcp)) + tcp[18:]

    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        identification & 0xFFFF,
        0x4000,
        64,
        _TCP_PROTOCOL,
        0,
        source_bytes,
        destination_bytes,
    )
    ip_header = ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]
    return _ETHERNET + ip_header + tcp


def _write_pcap(path: Path, records: Iterable[tuple[int, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        # Classic little-endian PCAP, Ethernet link type, 65535 snaplen.
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp_us, frame in records:
            seconds, fraction = divmod(timestamp_us, 1_000_000)
            output.write(struct.pack("<IIII", seconds, fraction, len(frame), len(frame)))
            output.write(frame)


def _spread_offsets(count: int, duration_seconds: float) -> list[int]:
    if count <= 0:
        raise ValueError("count must be positive")
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be positive")
    duration_us = round(duration_seconds * 1_000_000)
    return [
        round(duration_us * index / (count - 1)) if count > 1 else 0
        for index in range(count)
    ]


def write_half_open_pcap(
    path: Path,
    *,
    count: int = LIVE_SYN_COUNT,
    duration_seconds: float = LIVE_DURATION_SECONDS,
) -> None:
    """Write initial SYNs with unique source ports and no responses."""
    if 20_000 + count > 65_536:
        raise ValueError("count does not fit in the deterministic source-port range")
    records = []
    for index, offset_us in enumerate(_spread_offsets(count, duration_seconds)):
        source_port = 20_000 + index
        records.append(
            (
                _PCAP_EPOCH_US + offset_us,
                _tcp_ipv4_frame(
                    PCAP_SOURCE,
                    PCAP_DESTINATION,
                    source_port,
                    PCAP_DESTINATION_PORT,
                    0x10000000 + index,
                    0,
                    0x02,
                    index + 1,
                ),
            )
        )
    _write_pcap(path, records)


def write_syn_flood_pcap(
    path: Path,
    *,
    count: int = LIVE_SYN_COUNT,
    duration_seconds: float = LIVE_DURATION_SECONDS,
) -> None:
    """Write a deterministic, checksummed half-open SYN-flood PCAP."""
    write_half_open_pcap(path, count=count, duration_seconds=duration_seconds)


def write_completed_handshake_pcap(
    path: Path,
    *,
    count: int = 30,
    duration_seconds: float = LIVE_DURATION_SECONDS,
) -> None:
    """Write complete SYN, SYN-ACK, ACK exchanges below no-alert semantics."""
    if 20_000 + count > 65_536:
        raise ValueError("count does not fit in the deterministic source-port range")
    records = []
    for index, offset_us in enumerate(_spread_offsets(count, duration_seconds)):
        source_port = 20_000 + index
        client_sequence = 0x20000000 + index * 17
        server_sequence = 0x30000000 + index * 19
        first = _PCAP_EPOCH_US + offset_us
        records.extend(
            [
                (
                    first,
                    _tcp_ipv4_frame(
                        PCAP_SOURCE,
                        PCAP_DESTINATION,
                        source_port,
                        PCAP_DESTINATION_PORT,
                        client_sequence,
                        0,
                        0x02,
                        2 * index + 1,
                    ),
                ),
                (
                    first + 1_000,
                    _tcp_ipv4_frame(
                        PCAP_DESTINATION,
                        PCAP_SOURCE,
                        PCAP_DESTINATION_PORT,
                        source_port,
                        server_sequence,
                        client_sequence + 1,
                        0x12,
                        2 * index + 2,
                    ),
                ),
                (
                    first + 2_000,
                    _tcp_ipv4_frame(
                        PCAP_SOURCE,
                        PCAP_DESTINATION,
                        source_port,
                        PCAP_DESTINATION_PORT,
                        client_sequence + 1,
                        server_sequence + 1,
                        0x10,
                        2 * index + 3,
                    ),
                ),
            ]
        )
    _write_pcap(path, records)


def write_control_pcap(
    path: Path,
    *,
    count: int = 19,
    duration_seconds: float = LIVE_DURATION_SECONDS,
) -> None:
    """Write a below-threshold control capture with no SYN-flood response."""
    write_half_open_pcap(path, count=count, duration_seconds=duration_seconds)


def _validate_live_port(destination_port: int) -> None:
    if not 1 <= destination_port <= 65535:
        raise ValueError("destination_port must be in 1..65535")


def send_loopback_syn_flood(destination_port: int) -> None:
    """Send the fixed loopback-only raw SYN workload used by the live test."""
    _validate_live_port(destination_port)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as raw:
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        for index, offset in enumerate(
            _spread_offsets(LIVE_SYN_COUNT, LIVE_DURATION_SECONDS)
        ):
            target = started + offset / 1_000_000
            while True:
                remaining = target - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.01))
            source_port = 30_000 + index
            frame = _tcp_ipv4_frame(
                LIVE_SOURCE,
                LIVE_DESTINATION,
                source_port,
                destination_port,
                0x40000000 + index,
                0,
                0x02,
                index + 1,
            )
            # IPPROTO_RAW consumes the IPv4 packet; the Ethernet header is for
            # PCAP fixtures only and must not be sent through this socket.
            raw.sendto(frame[len(_ETHERNET) :], (LIVE_DESTINATION, destination_port))
    elapsed = time.monotonic() - started
    if elapsed < 1.3:
        raise RuntimeError("loopback SYN workload completed before its 1.3 second minimum")
    print(f"raw_syn_sent={LIVE_SYN_COUNT} duration_seconds={elapsed:.3f}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-syn-burst", action="store_true")
    parser.add_argument("--destination-port", type=int)
    parser.add_argument("path", nargs="?", type=Path)
    args = parser.parse_args()
    if args.raw_syn_burst:
        if args.path is not None or args.destination_port is None:
            parser.error("--raw-syn-burst requires only --destination-port")
        send_loopback_syn_flood(args.destination_port)
        return 0
    if args.path is None or args.destination_port is not None:
        parser.error("a PCAP output path is required")
    write_syn_flood_pcap(args.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
