"""Controlled Ethernet/IPv4 traffic for the real C++ feature boundary test.

Writes PCAP input, never feature JSON. All addresses are documentation ranges;
the packets are replayed from a file, never transmitted. TCP construction and
checksums reuse the existing SYN-flood fixture utilities.
"""

from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path

from syn_flood_fixture import _tcp_ipv4_frame, checksum

EPOCH_NS = 1_700_000_000_123_456_789


def _tcp(flow: int, *, reverse: bool = False, flags: int = 0x10) -> bytes:
    client = f"192.0.2.{9 + flow}"
    server = f"198.51.100.{19 + flow}"
    source_port = {1: 41000, 3: 43000, 5: 45000}[flow]
    destination_port = {1: 443, 3: 8080, 5: 8443}[flow]
    if reverse:
        client, server = server, client
        source_port, destination_port = destination_port, source_port
    return _tcp_ipv4_frame(
        client, server, source_port, destination_port,
        sequence=100, acknowledgement=101, flags=flags, identification=flow,
    )


def _udp(flow: int, payload: bytes, *, reverse: bool = False) -> bytes:
    source = ipaddress.IPv4Address(f"192.0.2.{9 + flow}").packed
    destination = ipaddress.IPv4Address(f"198.51.100.{19 + flow}").packed
    source_port = {2: 42000, 4: 44000}[flow]
    destination_port = {2: 5353, 4: 53}[flow]
    if reverse:
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 17, len(udp))
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 0xFFFF) + udp[8:]
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), flow, 0x4000,
        64, 17, 0, source, destination,
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000010200000000020800") + ip + udp


def write_flow_feature_pcap(path: Path) -> None:
    """Write 13 packets in five independent flows with nanosecond timestamps.

    A: full handshake, two FINs, final ACK (6 x 40 IPv4 bytes).
    B: bidirectional UDP (32 + 35 bytes).
    C: mid-capture ACK, reverse RST/ACK (2 x 40 bytes, no handshake inferred).
    D: bidirectional UDP (32 + 36 bytes) after a gap that expires A/B/C.
    E: one initial SYN (40 bytes). D/E remain for EOF shutdown flush.
    """
    packets = [
        (0, _tcp(1, flags=0x02)),
        (50_000_000, _udp(2, b"abcd")),
        (100_000_001, _tcp(1, reverse=True, flags=0x12)),
        (125_000_000, _tcp(3)),
        (200_000_003, _tcp(1)),
        (300_000_007, _udp(2, b"reverse", reverse=True)),
        (400_000_009, _tcp(1, flags=0x11)),
        (500_000_011, _tcp(1, reverse=True, flags=0x11)),
        (600_000_013, _tcp(1)),
        (700_000_017, _tcp(3, reverse=True, flags=0x14)),
        (3_000_000_023, _udp(4, b"abcd")),
        (3_250_000_031, _udp(4, b"response", reverse=True)),
        (3_500_000_000, _tcp(5, flags=0x02)),
    ]
    with path.open("wb") as output:
        # Classic little-endian nanosecond PCAP, Ethernet, no capture truncation.
        output.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        for offset, frame in packets:
            seconds, nanoseconds = divmod(EPOCH_NS + offset, 1_000_000_000)
            output.write(struct.pack("<IIII", seconds, nanoseconds, len(frame), len(frame)))
            output.write(frame)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate controlled flow-feature PCAP input")
    parser.add_argument("file", type=Path)
    write_flow_feature_pcap(parser.parse_args().file)
