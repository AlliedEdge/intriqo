#!/usr/bin/env python3
"""Dependency-free, provenance-preserving classic Ethernet PCAP inspector.

Only classic PCAP is accepted (not pcapng).  The parser understands both
little- and big-endian files and both microsecond and nanosecond timestamp
magic values.  Every complete Ethernet record contributes to ``packet_count``
 and to ``raw_packet_hashes``.  Non-IPv4 Ethernet frames and unsupported IP
 protocols are reported explicitly rather than silently discarded; a
 structurally truncated transport header is rejected because it cannot provide
 trustworthy flow bounds. IPv4 packets involving addresses outside the
 controlled pair are retained in unexpected-IP counts.

The inspector is an evidence reader, not a detector.  The only normalized
flows are directional attacker/victim five-tuples for 10.77.0.10 and
10.77.0.20.  Labels must come from the controller's intent manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
import sys
from pathlib import Path
from typing import Any


ATTACKER_IP = "10.77.0.10"
VICTIM_IP = "10.77.0.20"
DLT_EN10MB = 1
_GLOBAL_HEADER_SIZE = 24
_RECORD_HEADER_SIZE = 16


class PcapError(ValueError):
    """Raised for a malformed, truncated, or unsupported PCAP container."""


def _magic(data: bytes) -> tuple[str, str]:
    if data == b"\xd4\xc3\xb2\xa1":
        return "<", "microsecond"
    if data == b"\xa1\xb2\xc3\xd4":
        return ">", "microsecond"
    if data == b"\x4d\x3c\xb2\xa1":
        return "<", "nanosecond"
    if data == b"\xa1\xb2\x3c\x4d":
        return ">", "nanosecond"
    raise PcapError("not a classic PCAP (unknown magic)")


def _hex_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _empty_direction_counts() -> dict[str, int]:
    return {"attacker_to_victim": 0, "victim_to_attacker": 0, "unexpected": 0}


def _protocol_name(number: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(number, f"IP_{number}")


def _tuple_key(
    source: str, destination: str, source_port: int, destination_port: int, protocol: str
) -> tuple[str, str, int, int, str]:
    return (source, destination, int(source_port), int(destination_port), protocol)


def _json_tuple(value: tuple[str, str, int, int, str]) -> list[Any]:
    return [value[0], value[1], value[2], value[3], value[4]]


def _parse_ipv4(
    frame: bytes,
) -> tuple[str, str, int, int, str, int] | None:
    """Parse a complete Ethernet IPv4 transport tuple.

    The last value is the IPv4 protocol number.  ``None`` means the frame is
    not an IPv4 packet.  A ``PcapError`` means it claims to be IPv4 but is
    truncated or structurally malformed and cannot provide trustworthy flow
    bounds.
    """

    if len(frame) < 14:
        raise PcapError("truncated Ethernet header")
    ethernet_type = struct.unpack("!H", frame[12:14])[0]
    if ethernet_type != 0x0800:
        return None
    ip_packet = frame[14:]
    if len(ip_packet) < 20:
        raise PcapError("truncated IPv4 header")
    version_ihl = ip_packet[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(ip_packet) < ihl:
        raise PcapError("truncated IPv4 options/header")
    total_length = struct.unpack("!H", ip_packet[2:4])[0]
    if total_length < ihl or total_length > len(ip_packet):
        raise PcapError("truncated IPv4 packet")
    ip_packet = ip_packet[:total_length]
    source = str(ipaddress.ip_address(ip_packet[12:16]))
    destination = str(ipaddress.ip_address(ip_packet[16:20]))
    protocol_number = ip_packet[9]
    protocol = _protocol_name(protocol_number)
    payload = ip_packet[ihl:]
    if protocol_number == 6:
        if len(payload) < 20:
            raise PcapError("truncated TCP header")
        source_port, destination_port = struct.unpack("!HH", payload[:4])
        data_offset = (payload[12] >> 4) * 4
        if data_offset < 20 or data_offset > len(payload):
            raise PcapError("truncated TCP options/header")
    elif protocol_number == 17:
        if len(payload) < 8:
            raise PcapError("truncated UDP header")
        source_port, destination_port, udp_length = struct.unpack("!HHH", payload[:6])
        if udp_length < 8 or udp_length > len(payload):
            raise PcapError("truncated UDP datagram")
    elif protocol_number == 1:
        if len(payload) < 4:
            raise PcapError("truncated ICMP header")
        source_port = destination_port = 0
    else:
        # The IP tuple is useful for accounting, but it is not a supported
        # transport tuple and therefore is returned with its protocol number.
        source_port = destination_port = 0
    return source, destination, source_port, destination_port, protocol, protocol_number


def _frame_entry(
    timestamp_ns: int,
    frame_number: int,
    frame: bytes,
    tuple_data: tuple[str, str, int, int, str, int] | None,
) -> dict[str, Any]:
    return {
        "packet_number": frame_number,
        "timestamp_ns": timestamp_ns,
        "frame_length": len(frame),
        "sha256": _hex_digest(frame),
        "ipv4": tuple_data is not None,
    }


def inspect_pcap(path: str | Path) -> dict[str, Any]:
    """Inspect one immutable classic Ethernet PCAP and return JSON data.

    The returned object contains only JSON primitives (dict/list/string/int/
    bool); callers may serialize it directly.  Input bytes are read once and
    never rewritten.  Structural capture truncation is a hard error because a
    partial record cannot provide trustworthy flow bounds.  Complete frames
    with unsupported protocols or unexpected IP endpoints remain represented
    in the accounting fields.
    """

    source_path = Path(path)
    try:
        raw = source_path.read_bytes()
    except OSError as exc:
        raise PcapError(f"could not read PCAP: {source_path}") from exc
    original_size = len(raw)
    original_sha256 = _hex_digest(raw)
    if original_size < _GLOBAL_HEADER_SIZE:
        raise PcapError("truncated PCAP global header")
    endian, resolution = _magic(raw[:4])
    try:
        version_major, version_minor, thiszone, sigfigs, snaplen, link_type = struct.unpack(
            endian + "HHiiii", raw[4:24]
        )
    except struct.error as exc:  # guarded by the size check, retained defensively
        raise PcapError("invalid PCAP global header") from exc
    if (version_major, version_minor) not in {(2, 4), (2, 3)}:
        raise PcapError(f"unsupported PCAP version {version_major}.{version_minor}")
    if snaplen <= 0:
        raise PcapError("invalid PCAP snaplen")
    if link_type != DLT_EN10MB:
        raise PcapError(f"unsupported link type {link_type}; expected Ethernet (1)")

    protocol_counts = {name: _empty_direction_counts() for name in ("TCP", "UDP", "ICMP")}
    unsupported_protocol_counts: dict[str, int] = {}
    five_tuples: dict[tuple[str, str, int, int, str], dict[str, Any]] = {}
    raw_packet_hashes: list[str] = []
    raw_packets: list[dict[str, Any]] = []
    unexpected_ip_packets = 0
    unsupported_packets = 0
    unsupported_link_packets = 0
    malformed_packet_count = 0
    timestamps: list[int] = []
    position = _GLOBAL_HEADER_SIZE
    packet_number = 0
    while position < original_size:
        if original_size - position < _RECORD_HEADER_SIZE:
            raise PcapError("truncated PCAP packet header")
        ts_sec, ts_fraction, included_length, original_length = struct.unpack(
            endian + "IIII", raw[position : position + _RECORD_HEADER_SIZE]
        )
        position += _RECORD_HEADER_SIZE
        if included_length > snaplen:
            raise PcapError("PCAP included length exceeds snaplen")
        if included_length > original_length:
            raise PcapError("PCAP included length exceeds original length")
        if included_length != original_length:
            # A record with a smaller captured length is explicitly truncated;
            # accepting it would create false packet/flow bounds.
            raise PcapError("truncated captured packet (included != original length)")
        if original_size - position < included_length:
            raise PcapError("truncated PCAP packet payload")
        frame = raw[position : position + included_length]
        position += included_length
        packet_number += 1
        if resolution == "microsecond":
            if ts_fraction >= 1_000_000:
                raise PcapError("invalid microsecond timestamp fraction")
            timestamp_ns = ts_sec * 1_000_000_000 + ts_fraction * 1_000
        else:
            if ts_fraction >= 1_000_000_000:
                raise PcapError("invalid nanosecond timestamp fraction")
            timestamp_ns = ts_sec * 1_000_000_000 + ts_fraction
        timestamps.append(timestamp_ns)
        raw_hash = _hex_digest(frame)
        raw_packet_hashes.append(raw_hash)
        # A complete PCAP record is not necessarily a complete network frame.
        # Such a capture cannot provide trustworthy bounds, so fail closed on
        # truncated Ethernet/IPv4/transport headers.  Complete non-IPv4 and
        # complete unsupported-protocol frames are accounted below instead.
        tuple_data = _parse_ipv4(frame)
        raw_packets.append(_frame_entry(timestamp_ns, packet_number, frame, tuple_data))
        if tuple_data is None:
            unsupported_packets += 1
            if len(frame) < 14 or (len(frame) >= 14 and struct.unpack("!H", frame[12:14])[0] != 0x0800):
                unsupported_link_packets += 1
            continue

        source, destination, source_port, destination_port, protocol, proto_number = tuple_data
        if source not in {ATTACKER_IP, VICTIM_IP} or destination not in {ATTACKER_IP, VICTIM_IP}:
            unexpected_ip_packets += 1
            direction = "unexpected"
        elif source == ATTACKER_IP and destination == VICTIM_IP:
            direction = "attacker_to_victim"
        elif source == VICTIM_IP and destination == ATTACKER_IP:
            direction = "victim_to_attacker"
        else:
            # Same-endpoint packets are unexpected and must not normalize.
            unexpected_ip_packets += 1
            direction = "unexpected"

        if protocol in protocol_counts:
            protocol_counts[protocol][direction] += 1
        else:
            unsupported_packets += 1
            unsupported_protocol_counts[protocol] = unsupported_protocol_counts.get(protocol, 0) + 1
            continue
        if direction == "unexpected":
            continue

        if direction == "attacker_to_victim":
            normalized = _tuple_key(source, destination, source_port, destination_port, protocol)
        else:
            normalized = _tuple_key(VICTIM_IP, ATTACKER_IP, source_port, destination_port, protocol)
            # Reverse packets map to the forward attacker's tuple by swapping
            # transport endpoints.  ICMP ports are both zero.
            normalized = _tuple_key(ATTACKER_IP, VICTIM_IP, destination_port, source_port, protocol)
        flow = five_tuples.get(normalized)
        if flow is None:
            flow = {
                "five_tuple": _json_tuple(normalized),
                "source_address": normalized[0],
                "destination_address": normalized[1],
                "source_port": normalized[2],
                "destination_port": normalized[3],
                "protocol": normalized[4],
                "first_timestamp_ns": timestamp_ns,
                "last_timestamp_ns": timestamp_ns,
                "start_ns": timestamp_ns,
                "end_ns": timestamp_ns,
                "packet_count": 0,
                "forward_packet_count": 0,
                "reverse_packet_count": 0,
            }
            five_tuples[normalized] = flow
        flow["first_timestamp_ns"] = min(flow["first_timestamp_ns"], timestamp_ns)
        flow["last_timestamp_ns"] = max(flow["last_timestamp_ns"], timestamp_ns)
        flow["start_ns"] = flow["first_timestamp_ns"]
        flow["end_ns"] = flow["last_timestamp_ns"]
        flow["packet_count"] += 1
        if direction == "attacker_to_victim":
            flow["forward_packet_count"] += 1
        else:
            flow["reverse_packet_count"] += 1

    if position != original_size:
        raise PcapError("PCAP parser did not consume the complete file")

    if timestamps:
        time_bounds: dict[str, int | None] = {
            "start_ns": min(timestamps),
            "end_ns": max(timestamps),
        }
    else:
        time_bounds = {"start_ns": None, "end_ns": None}
    # Sorting makes evidence stable independent of Python dictionary insertion
    # details while retaining capture order in raw_packet_hashes/raw_packets.
    flow_list = [five_tuples[key] for key in sorted(five_tuples)]
    protocol_direction_counts = {
        name: dict(protocol_counts[name]) for name in ("TCP", "UDP", "ICMP")
    }
    result: dict[str, Any] = {
        "path": str(source_path),
        "original_size": original_size,
        "byte_size": original_size,
        "sha256": original_sha256,
        "original_sha256": original_sha256,
        "link_type": link_type,
        "link_type_name": "Ethernet",
        "timestamp_resolution": resolution,
        "time_bounds": time_bounds,
        "packet_count": packet_number,
        "raw_frame_count": packet_number,
        "raw_frames": packet_number,
        "protocol_direction_counts": protocol_direction_counts,
        "protocol_counts": protocol_direction_counts,
        "five_tuple_bounds": flow_list,
        "flow_count": len(flow_list),
        "raw_packet_hashes": raw_packet_hashes,
        "raw_frame_hashes": raw_packet_hashes,
        "raw_packets": raw_packets,
        "unexpected_ip_packets": unexpected_ip_packets,
        "unexpected_ip_packet_count": unexpected_ip_packets,
        # ``unsupported_packets`` is the total; the two component fields make
        # it possible to distinguish a complete non-IPv4 Ethernet frame from
        # a complete IPv4 frame whose protocol is outside this inspector's
        # TCP/UDP/ICMP scope.
        "unsupported_packets": unsupported_packets,
        "unsupported_packet_count": unsupported_packets,
        "unsupported_link_packets": unsupported_link_packets,
        "unsupported_protocol_counts": unsupported_protocol_counts,
        "malformed_packet_count": malformed_packet_count,
        "fixed_attacker": ATTACKER_IP,
        "fixed_victim": VICTIM_IP,
        "labels_source": "controller intent manifest",
    }
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    inspect = sub.add_parser("inspect", help="inspect one classic Ethernet PCAP")
    inspect.add_argument("inspect_path")
    # ``pcap.py file.pcap`` is a useful backwards-compatible shorthand.
    parser.add_argument("root_path", nargs="?")
    return parser


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    # Subparsers normally reserve the first token for a command.  Normalize a
    # bare ``pcap.py capture.pcap`` invocation to the documented inspect
    # command before argparse sees it.
    if values and values[0] not in {"inspect", "-h", "--help"}:
        values.insert(0, "inspect")
    args = _parser().parse_args(values)
    path = args.inspect_path if args.command == "inspect" else args.root_path
    if not path:
        print("usage: pcap.py inspect PATH", file=sys.stderr)
        return 2
    try:
        result = inspect_pcap(path)
    except (PcapError, OSError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by CLI users
    raise SystemExit(main())
