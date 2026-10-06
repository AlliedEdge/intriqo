#!/usr/bin/env python3
"""Small, bounded traffic harness for the controlled v2 laboratory.

The module deliberately has no dependency on packet libraries.  The only raw
packets it can create are IPv4/TCP SYN packets from the fixed attacker address
to the fixed victim address.  The command line interface prints one JSON
receipt, which is intended to be stored by the controller next to its intent
manifest.  It does not infer labels from traffic or from a detector.

The harness is intentionally conservative about the network it is run in:
clients require exactly ``lo`` and ``lab0``, the expected address on ``lab0``,
and a connected route for 10.77.0.0/24 with no default route.  Those checks are
performed immediately before a client opens a socket or sends a raw packet.
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import ipaddress
import json
import select
import socket
import struct
import subprocess
import sys
import time
from typing import Sequence


ATTACKER_IP = "10.77.0.10"
VICTIM_IP = "10.77.0.20"
LAB_NETWORK = ipaddress.ip_network("10.77.0.0/24")
LAB_INTERFACE = "lab0"
LOOPBACK_INTERFACE = "lo"
MAX_PACKETS = 256
MAX_RATE = 200.0
MAX_PORTS = 32
DEFAULT_RATE = 100.0
DEFAULT_TCP_SOURCE_PORT = 41000
DEFAULT_UDP_SOURCE_PORT = 42000
DEFAULT_FLOOD_DESTINATION_PORT = 65535
DEFAULT_PAYLOAD = b"intriqo-controlled-v2-benign\n"

# Names used by controller code that prefers explicit limit constants.
MAX_PACKET_COUNT = MAX_PACKETS
MAX_PACKETS_PER_SECOND = MAX_RATE


class TrafficError(RuntimeError):
    """Raised when the controlled traffic preconditions are not met."""


def _utc_now() -> str:
    """Return a controller-friendly UTC wall-clock timestamp."""

    return _datetime.datetime.now(_datetime.timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _receipt(
    scenario: str,
    start: str,
    end: str,
    request_count: int,
    **details: object,
) -> dict[str, object]:
    """Build the common JSON receipt.

    ``start_time``/``end_time`` are the stable controller fields.  The
    ``started_at``/``ended_at`` aliases make the receipt convenient for tools
    that use the usual provenance naming without changing the source of time.
    """

    result: dict[str, object] = {
        "scenario": scenario,
        "start_time": start,
        "end_time": end,
        "start_utc": start,
        "end_utc": end,
        "started_at": start,
        "ended_at": end,
        "request_count": int(request_count),
        "interface": LAB_INTERFACE,
    }
    result.update(details)
    return result


def _run_ip(*args: str) -> str:
    """Run ``ip`` without invoking a shell and return its output."""

    try:
        completed = subprocess.run(
            ["ip", *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise TrafficError("unable to verify the lab network with ip") from exc
    return completed.stdout


def _interfaces() -> set[str]:
    """Return the kernel's interface names without relying on ``ip``."""

    try:
        return {name for _, name in socket.if_nameindex()}
    except OSError as exc:
        raise TrafficError("unable to enumerate network interfaces") from exc


def _has_expected_address(address: str) -> bool:
    # ``ip -o`` is used rather than guessing from /proc: unlike /proc/fib_trie
    # it preserves the interface association and works in network namespaces.
    output = _run_ip("-o", "-4", "addr", "show", "dev", LAB_INTERFACE)
    expected = ipaddress.ip_address(address)
    for line in output.splitlines():
        fields = line.split()
        try:
            token = fields[fields.index("inet") + 1]
            actual = ipaddress.ip_interface(token).ip
        except (ValueError, IndexError):
            continue
        if actual == expected:
            return True
    return False


def _routes_are_lab_only() -> bool:
    output = _run_ip("-4", "route", "show")
    saw_lab_route = False
    for line in output.splitlines():
        fields = line.split()
        if not fields:
            continue
        destination = fields[0]
        if destination == "default":
            return False
        # A route on another interface is outside the controlled namespace's
        # intended egress even when its destination happens to be lab-local.
        if destination == "10.77.0.0/24":
            saw_lab_route = True
            if "dev" not in fields or fields[fields.index("dev") + 1] != LAB_INTERFACE:
                return False
            continue
        # ``ip`` may print a host route as 10.77.0.10/32 for an address.  It
        # is harmless only when it is also on lab0 and inside the subnet.
        try:
            route = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            # Ignore route attributes that are not destinations only if this
            # is not a normal route line.  A normal unknown destination is a
            # failed safety check.
            return False
        if not route.subnet_of(LAB_NETWORK):
            return False
        if "dev" not in fields or fields[fields.index("dev") + 1] != LAB_INTERFACE:
            return False
    return saw_lab_route


def verify_lab(expected_address: str) -> None:
    """Verify the exact network namespace required by a traffic client.

    The function intentionally fails closed.  It is public so a controller or
    an integration test can run the same check without sending traffic.
    """

    try:
        expected = str(ipaddress.ip_address(expected_address))
    except ValueError as exc:
        raise TrafficError("invalid expected lab address") from exc
    if _interfaces() != {LOOPBACK_INTERFACE, LAB_INTERFACE}:
        raise TrafficError("lab client requires exactly lo and lab0 interfaces")
    if not _has_expected_address(expected):
        raise TrafficError(f"{LAB_INTERFACE} does not have address {expected}")
    if not _routes_are_lab_only():
        raise TrafficError("lab routes must contain only 10.77.0.0/24 and no default")


def _validate_port(port: int, name: str = "port") -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise TrafficError(f"{name} must be an integer from 1 to 65535")
    return port


def _validate_rate(rate: float) -> float:
    try:
        value = float(rate)
    except (TypeError, ValueError) as exc:
        raise TrafficError("rate must be numeric") from exc
    if not 0.0 < value <= MAX_RATE:
        raise TrafficError(f"rate must be greater than zero and at most {MAX_RATE:g}/s")
    return value


def _validate_packet_count(count: int) -> int:
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_PACKETS:
        raise TrafficError(f"packet count must be between 1 and {MAX_PACKETS}")
    return count


def _validate_duration(duration: float) -> float:
    try:
        value = float(duration)
    except (TypeError, ValueError) as exc:
        raise TrafficError("duration must be numeric") from exc
    # There is deliberately no infinite/zero-duration mode.  A generous
    # upper bound prevents a typo from leaving a lab process around forever.
    if not 0.0 < value <= 3600.0:
        raise TrafficError("duration must be greater than zero and at most 3600 seconds")
    return value


def _pace(previous: float | None, rate: float) -> float:
    """Sleep until the next rate slot and return its monotonic timestamp."""

    now = time.monotonic()
    if previous is not None:
        target = previous + (1.0 / rate)
        if target > now:
            time.sleep(target - now)
            now = time.monotonic()
    return now


def _bind_client(sock: socket.socket, source_port: int) -> None:
    _validate_port(source_port, "source port")
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((ATTACKER_IP, source_port))
    except OSError as exc:
        raise TrafficError(f"could not bind controlled source port {source_port}") from exc


def _target_is_fixed(target: str) -> None:
    if target != VICTIM_IP:
        raise TrafficError(f"target is fixed to {VICTIM_IP}")


def send_tcp_benign(
    destination_port: int,
    *,
    source_port: int = DEFAULT_TCP_SOURCE_PORT,
    count: int = 1,
    payload: bytes = DEFAULT_PAYLOAD,
    timeout: float = 2.0,
    rate: float = DEFAULT_RATE,
    target: str = VICTIM_IP,
) -> dict[str, object]:
    """Send deterministic bounded TCP request/echo traffic to the victim."""

    _target_is_fixed(target)
    destination_port = _validate_port(destination_port, "destination port")
    source_port = _validate_port(source_port, "source port")
    count = _validate_packet_count(count)
    rate = _validate_rate(rate)
    if not isinstance(payload, bytes) or not payload or len(payload) > 4096:
        raise TrafficError("payload must be 1..4096 bytes")
    timeout = _validate_duration(timeout)
    verify_lab(ATTACKER_IP)
    start = _utc_now()
    sent = 0
    received = 0
    previous: float | None = None
    try:
        # Keep one deterministic source port for the bounded request sequence.
        # The endpoint echoes each length-delimited write and keeps the
        # connection open, avoiding TIME_WAIT collisions between requests.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            _bind_client(sock, source_port)
            sock.settimeout(timeout)
            sock.connect((VICTIM_IP, destination_port))
            for index in range(count):
                previous = _pace(previous, rate)
                # Prefixing the ordinal makes every request deterministic and
                # distinct while keeping it independent of wall time.
                message = payload + struct.pack("!I", index)
                sock.sendall(message)
                sent += 1
                while True:
                    echoed = sock.recv(65536)
                    if not echoed:
                        break
                    received += len(echoed)
                    if len(echoed) >= len(message):
                        break
                # The inner loop has consumed this request's echo.  A
                # separate break is unnecessary: the connection is reused.
    except (OSError, socket.timeout) as exc:
        raise TrafficError("TCP benign request sequence failed") from exc
    end = _utc_now()
    return _receipt(
        "BENIGN_TCP",
        start,
        end,
        sent,
        packet_count=sent,
        response_bytes=received,
        source_address=ATTACKER_IP,
        destination_address=VICTIM_IP,
        source_port=source_port,
        destination_port=destination_port,
    )


def send_udp_echo(
    destination_port: int,
    *,
    source_port: int = DEFAULT_UDP_SOURCE_PORT,
    count: int = 1,
    payload: bytes = DEFAULT_PAYLOAD,
    timeout: float = 2.0,
    rate: float = DEFAULT_RATE,
    target: str = VICTIM_IP,
) -> dict[str, object]:
    """Send deterministic bounded UDP datagrams and receive their echoes."""

    _target_is_fixed(target)
    destination_port = _validate_port(destination_port, "destination port")
    source_port = _validate_port(source_port, "source port")
    count = _validate_packet_count(count)
    rate = _validate_rate(rate)
    if not isinstance(payload, bytes) or not payload or len(payload) > 65507:
        raise TrafficError("payload must be 1..65507 bytes")
    timeout = _validate_duration(timeout)
    verify_lab(ATTACKER_IP)
    start = _utc_now()
    sent = 0
    echoed = 0
    previous: float | None = None
    for index in range(count):
        previous = _pace(previous, rate)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                _bind_client(sock, source_port)
                sock.settimeout(timeout)
                message = payload + struct.pack("!I", index)
                sock.sendto(message, (VICTIM_IP, destination_port))
                sent += 1
                try:
                    response, _ = sock.recvfrom(65535)
                    echoed += len(response)
                except socket.timeout:
                    pass
        except OSError as exc:
            raise TrafficError(f"UDP echo request {index + 1} failed") from exc
    end = _utc_now()
    return _receipt(
        "BENIGN_UDP",
        start,
        end,
        sent,
        packet_count=sent,
        response_bytes=echoed,
        source_address=ATTACKER_IP,
        destination_address=VICTIM_IP,
        source_port=source_port,
        destination_port=destination_port,
    )


def send_icmp(
    *, count: int = 1, timeout: float = 2.0, target: str = VICTIM_IP
) -> dict[str, object]:
    """Optionally invoke the platform ``ping`` command for the fixed victim."""

    _target_is_fixed(target)
    count = _validate_packet_count(count)
    timeout = _validate_duration(timeout)
    # ICMP is a client action too, so it receives exactly the same namespace
    # gate as TCP/UDP.  ``ping`` itself is never allowed to choose a target.
    verify_lab(ATTACKER_IP)
    start = _utc_now()
    command = ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), VICTIM_IP]
    try:
        completed = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        raise TrafficError("ping command is unavailable") from exc
    if completed.returncode != 0:
        raise TrafficError("controlled ping failed")
    end = _utc_now()
    return _receipt(
        "BENIGN_ICMP", start, end, count,
        packet_count=count,
        source_address=ATTACKER_IP,
        destination_address=VICTIM_IP,
    )


def internet_checksum(data: bytes) -> int:
    """Return the one's-complement checksum used by IPv4 and TCP."""

    if len(data) % 2:
        data += b"\0"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_tcp_syn(
    source_port: int,
    destination_port: int,
    *,
    sequence: int = 0,
    identification: int = 0,
    source: str = ATTACKER_IP,
    destination: str = VICTIM_IP,
) -> bytes:
    """Build one checksummed IPv4/TCP SYN packet for the fixed lab pair."""

    if source != ATTACKER_IP or destination != VICTIM_IP:
        raise TrafficError("raw packets are restricted to the fixed lab pair")
    source_port = _validate_port(source_port, "source port")
    destination_port = _validate_port(destination_port, "destination port")
    if not 0 <= sequence <= 0xFFFFFFFF or not 0 <= identification <= 0xFFFF:
        raise TrafficError("sequence and identification must fit their wire fields")
    source_bytes = ipaddress.ip_address(source).packed
    destination_bytes = ipaddress.ip_address(destination).packed

    tcp_without_checksum = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        0,
        5 << 4,
        0x02,  # SYN
        64240,
        0,
        0,
    )
    pseudo_header = struct.pack("!4s4sBBH", source_bytes, destination_bytes, 0, socket.IPPROTO_TCP, len(tcp_without_checksum))
    tcp_checksum = internet_checksum(pseudo_header + tcp_without_checksum)
    tcp = tcp_without_checksum[:16] + struct.pack("!H", tcp_checksum) + tcp_without_checksum[18:]
    total_length = 20 + len(tcp)
    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        0x4000,  # do not fragment; this packet is always 40 bytes
        64,
        socket.IPPROTO_TCP,
        0,
        source_bytes,
        destination_bytes,
    )
    ip_checksum = internet_checksum(ip_without_checksum)
    ip_header = ip_without_checksum[:10] + struct.pack("!H", ip_checksum) + ip_without_checksum[12:]
    return ip_header + tcp


def _raw_sender() -> socket.socket:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock
    except OSError as exc:
        raise TrafficError("raw IPv4 packet generation requires CAP_NET_RAW") from exc


def send_syn_flood(
    destination_port: int = DEFAULT_FLOOD_DESTINATION_PORT,
    *,
    source_port: int = 43000,
    count: int = 120,
    rate: float = DEFAULT_RATE,
    target: str = VICTIM_IP,
) -> dict[str, object]:
    """Send repeated SYNs for one five-tuple to a caller-selected closed port.

    The destination must be kept closed by the victim/controller.  The sender
    does not probe it (probing would add an uncontrolled connection); the
    resulting RST traffic from a closed destination is what gives the episode
    its normal bidirectional evidence.
    """

    _target_is_fixed(target)
    destination_port = _validate_port(destination_port, "destination port")
    source_port = _validate_port(source_port, "source port")
    count = _validate_packet_count(count)
    rate = _validate_rate(rate)
    verify_lab(ATTACKER_IP)
    start = _utc_now()
    sent = 0
    previous: float | None = None
    try:
        with _raw_sender() as sock:
            for sequence in range(count):
                previous = _pace(previous, rate)
                packet = build_ipv4_tcp_syn(
                    source_port,
                    destination_port,
                    sequence=sequence,
                    identification=sequence & 0xFFFF,
                )
                sock.sendto(packet, (VICTIM_IP, 0))
                sent += 1
    except OSError as exc:
        raise TrafficError("raw SYN flood send failed") from exc
    end = _utc_now()
    return _receipt(
        "SYN_FLOOD", start, end, sent,
        packet_count=sent,
        source_address=ATTACKER_IP,
        destination_address=VICTIM_IP,
        source_port=source_port,
        destination_port=destination_port,
        repeated_five_tuple=True,
        destination_must_be_closed=True,
        rate_per_second=rate,
    )


def parse_port_spec(spec: str) -> list[int]:
    """Parse a deterministic comma-separated port/range specification."""

    if not isinstance(spec, str) or not spec.strip():
        raise TrafficError("port specification cannot be empty")
    values: list[int] = []
    seen: set[int] = set()
    for raw_part in spec.split(","):
        part = raw_part.strip()
        if not part:
            raise TrafficError("empty port in specification")
        if "-" in part:
            bits = part.split("-")
            if len(bits) != 2:
                raise TrafficError(f"invalid port range {part!r}")
            try:
                first, last = int(bits[0]), int(bits[1])
            except ValueError as exc:
                raise TrafficError(f"invalid port range {part!r}") from exc
            if first > last:
                raise TrafficError("port ranges must be ascending")
            if last - first + 1 > MAX_PORTS:
                raise TrafficError(f"port list must contain at most {MAX_PORTS} ports")
            candidates = range(first, last + 1)
        else:
            try:
                candidates = (int(part),)
            except ValueError as exc:
                raise TrafficError(f"invalid port {part!r}") from exc
        for port in candidates:
            _validate_port(port)
            if port not in seen:
                values.append(port)
                seen.add(port)
    if not values or len(values) > MAX_PORTS:
        raise TrafficError(f"port list must contain 1..{MAX_PORTS} unique ports")
    return values


def send_port_scan(
    ports: Sequence[int] | str,
    *,
    repeats: int = 2,
    source_port_start: int = 44000,
    rate: float = DEFAULT_RATE,
    duration: float | None = None,
    target: str = VICTIM_IP,
) -> dict[str, object]:
    """Send at least two SYNs for every unique source/destination pair.

    Source ports are deterministic and increment once per destination port;
    repetitions retain the exact pair.  No pair is reused for another target
    because the target is fixed before the namespace check.
    """

    _target_is_fixed(target)
    if isinstance(ports, str):
        port_list = parse_port_spec(ports)
    else:
        port_list = []
        seen: set[int] = set()
        for value in ports:
            port = _validate_port(value, "scan port")
            if port not in seen:
                port_list.append(port)
                seen.add(port)
        if not port_list or len(port_list) > MAX_PORTS:
            raise TrafficError(f"scan requires 1..{MAX_PORTS} unique ports")
    if isinstance(repeats, bool) or not isinstance(repeats, int):
        raise TrafficError("repeats must be an integer")
    if repeats < 2:
        raise TrafficError("port scan requires at least two SYNs per pair")
    total = len(port_list) * repeats
    _validate_packet_count(total)
    source_port_start = _validate_port(source_port_start, "source port start")
    # Avoid wraparound and duplicate source ports.  The entire source range is
    # intentionally small and deterministic.
    if source_port_start + len(port_list) - 1 > 65535:
        raise TrafficError("source port range exceeds 65535")
    rate = _validate_rate(rate)
    if duration is None:
        duration_value = max(1.0 / rate, (total - 1) / rate)
    else:
        duration_value = _validate_duration(duration)
    if duration_value <= 0:
        raise TrafficError("scan duration must be positive")
    verify_lab(ATTACKER_IP)
    start = _utc_now()
    sent = 0
    previous: float | None = None
    # A requested positive duration is honored when it is longer than the
    # minimum interval permitted by the rate cap.  This keeps short scans
    # finite while ensuring that an explicitly paced episode has a real
    # positive capture interval.
    effective_rate = rate
    if total > 1 and duration is not None:
        effective_rate = min(rate, (total - 1) / duration_value)
    sequence = 0
    try:
        with _raw_sender() as sock:
            for destination_port in port_list:
                source_port = source_port_start + port_list.index(destination_port)
                for _ in range(repeats):
                    previous = _pace(previous, effective_rate)
                    packet = build_ipv4_tcp_syn(
                        source_port,
                        destination_port,
                        sequence=sequence,
                        identification=sequence & 0xFFFF,
                    )
                    sock.sendto(packet, (VICTIM_IP, 0))
                    sent += 1
                    sequence += 1
    except OSError as exc:
        raise TrafficError("raw port-scan send failed") from exc
    end = _utc_now()
    pairs = [
        {"source_port": source_port_start + index, "destination_port": port}
        for index, port in enumerate(port_list)
    ]
    return _receipt(
        "PORT_SCAN", start, end, sent,
        packet_count=sent,
        source_address=ATTACKER_IP,
        destination_address=VICTIM_IP,
        ports=port_list,
        repeats_per_pair=repeats,
        unique_pairs=pairs,
        duration_seconds=duration_value,
        rate_per_second=effective_rate,
    )


def serve_endpoint(
    *,
    tcp_port: int = 8080,
    udp_port: int = 8081,
    duration: float = 30.0,
    max_requests: int = MAX_PACKETS,
    bind_address: str = VICTIM_IP,
) -> dict[str, object]:
    """Serve bounded TCP and UDP echo endpoints on the victim address."""

    if bind_address != VICTIM_IP:
        raise TrafficError(f"endpoint address is fixed to {VICTIM_IP}")
    tcp_port = _validate_port(tcp_port, "TCP port")
    udp_port = _validate_port(udp_port, "UDP port")
    duration = _validate_duration(duration)
    max_requests = _validate_packet_count(max_requests)
    # Verify the endpoint namespace as well.  It must not silently become an
    # internet-facing service if a caller starts it in the wrong namespace.
    verify_lab(VICTIM_IP)
    start = _utc_now()
    requests = 0
    tcp_listener: socket.socket | None = None
    udp_socket: socket.socket | None = None
    clients: list[socket.socket] = []
    selector = None
    try:
        tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_listener.bind((VICTIM_IP, tcp_port))
        tcp_listener.listen(16)
        tcp_listener.setblocking(False)
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_socket.bind((VICTIM_IP, udp_port))
        udp_socket.setblocking(False)
        selector = select.poll()
        selector.register(tcp_listener, select.POLLIN)
        selector.register(udp_socket, select.POLLIN)
        deadline = time.monotonic() + duration
        while requests < max_requests and time.monotonic() < deadline:
            remaining = max(0.0, deadline - time.monotonic())
            events = selector.poll(int(min(remaining, 0.25) * 1000))
            for fd, event in events:
                if not (event & select.POLLIN):
                    continue
                if tcp_listener is not None and fd == tcp_listener.fileno():
                    try:
                        connection, _ = tcp_listener.accept()
                        connection.setblocking(False)
                        clients.append(connection)
                        with connection:
                            while requests < max_requests and time.monotonic() < deadline:
                                # Keep a long-lived controlled flow open across
                                # intentional idle gaps; the controller's
                                # episode duration is the outer bound.
                                wait = max(0.0, min(1.0, deadline - time.monotonic()))
                                readable, _, _ = select.select([connection], [], [], wait)
                                if not readable:
                                    break
                                data = connection.recv(65536)
                                if not data:
                                    break
                                connection.sendall(data)
                                requests += 1
                    except OSError:
                        continue
                elif udp_socket is not None and fd == udp_socket.fileno():
                    try:
                        data, address = udp_socket.recvfrom(65535)
                        if data:
                            udp_socket.sendto(data, address)
                            requests += 1
                    except OSError:
                        continue
                if requests >= max_requests:
                    break
    except OSError as exc:
        raise TrafficError("could not bind controlled echo endpoint") from exc
    finally:
        if selector is not None:
            try:
                if tcp_listener is not None:
                    selector.unregister(tcp_listener)
                if udp_socket is not None:
                    selector.unregister(udp_socket)
            except (OSError, KeyError):
                pass
        for client in clients:
            try:
                client.close()
            except OSError:
                pass
        if tcp_listener is not None:
            tcp_listener.close()
        if udp_socket is not None:
            udp_socket.close()
    end = _utc_now()
    return _receipt(
        "ENDPOINT", start, end, requests,
        request_count=requests,
        tcp_port=tcp_port,
        udp_port=udp_port,
        bind_address=VICTIM_IP,
        max_requests=max_requests,
    )


# Descriptive aliases are kept small and make the public API easy to discover.
run_syn_flood = send_syn_flood
run_port_scan = send_port_scan
send_benign_tcp = send_tcp_benign
run_endpoint = serve_endpoint
build_tcp_syn_packet = build_ipv4_tcp_syn
tcp_checksum = internet_checksum
verify_lab_network = verify_lab


def _payload(value: str) -> bytes:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise argparse.ArgumentTypeError("payload must be ASCII") from exc


def _positive_duration(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("duration must be numeric") from exc
    if not 0.0 < result <= 3600.0:
        raise argparse.ArgumentTypeError("duration must be >0 and <=3600")
    return result


def _bounded_count(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("count must be an integer") from exc
    if not 1 <= result <= MAX_PACKETS:
        raise argparse.ArgumentTypeError(f"count must be 1..{MAX_PACKETS}")
    return result


def _bounded_rate(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("rate must be numeric") from exc
    if not 0 < result <= MAX_RATE:
        raise argparse.ArgumentTypeError(f"rate must be >0 and <= {MAX_RATE:g}")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    endpoint = sub.add_parser("endpoint", help="serve bounded victim TCP/UDP echo")
    endpoint.add_argument("--tcp-port", type=int, default=8080)
    endpoint.add_argument("--udp-port", type=int, default=8081)
    endpoint.add_argument("--duration", type=_positive_duration, default=30.0)
    endpoint.add_argument("--max-requests", type=_bounded_count, default=MAX_PACKETS)

    tcp = sub.add_parser("tcp", aliases=["benign-tcp"], help="send benign TCP echo requests")
    tcp.add_argument("--destination-port", type=int, required=True)
    tcp.add_argument("--source-port", type=int, default=DEFAULT_TCP_SOURCE_PORT)
    tcp.add_argument("--count", type=_bounded_count, default=1)
    tcp.add_argument("--rate", type=_bounded_rate, default=DEFAULT_RATE)
    tcp.add_argument("--timeout", type=_positive_duration, default=2.0)
    tcp.add_argument("--payload", type=_payload, default=DEFAULT_PAYLOAD)

    udp = sub.add_parser("udp", aliases=["benign-udp"], help="send benign UDP echo requests")
    udp.add_argument("--destination-port", type=int, required=True)
    udp.add_argument("--source-port", type=int, default=DEFAULT_UDP_SOURCE_PORT)
    udp.add_argument("--count", type=_bounded_count, default=1)
    udp.add_argument("--rate", type=_bounded_rate, default=DEFAULT_RATE)
    udp.add_argument("--timeout", type=_positive_duration, default=2.0)
    udp.add_argument("--payload", type=_payload, default=DEFAULT_PAYLOAD)

    icmp = sub.add_parser("icmp", help="send bounded ping requests")
    icmp.add_argument("--count", type=_bounded_count, default=1)
    icmp.add_argument("--timeout", type=_positive_duration, default=2.0)

    flood = sub.add_parser("syn-flood", aliases=["SYN_FLOOD"], help="send bounded raw SYNs")
    flood.add_argument("--destination-port", type=int, default=DEFAULT_FLOOD_DESTINATION_PORT)
    flood.add_argument("--source-port", type=int, default=43000)
    flood.add_argument("--count", type=_bounded_count, default=120)
    flood.add_argument("--rate", type=_bounded_rate, default=DEFAULT_RATE)

    scan = sub.add_parser("port-scan", aliases=["PORT_SCAN"], help="send bounded raw port scan")
    scan.add_argument("--ports", required=True, help="comma-separated ports and/or ranges")
    scan.add_argument("--repeats", type=int, default=2)
    scan.add_argument("--source-port-start", type=int, default=44000)
    scan.add_argument("--rate", type=_bounded_rate, default=DEFAULT_RATE)
    scan.add_argument("--duration", type=_positive_duration)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "endpoint":
            result = serve_endpoint(
                tcp_port=args.tcp_port,
                udp_port=args.udp_port,
                duration=args.duration,
                max_requests=args.max_requests,
            )
        elif args.command in {"tcp", "benign-tcp"}:
            result = send_tcp_benign(
                args.destination_port,
                source_port=args.source_port,
                count=args.count,
                payload=args.payload,
                timeout=args.timeout,
                rate=args.rate,
            )
        elif args.command in {"udp", "benign-udp"}:
            result = send_udp_echo(
                args.destination_port,
                source_port=args.source_port,
                count=args.count,
                payload=args.payload,
                timeout=args.timeout,
                rate=args.rate,
            )
        elif args.command == "icmp":
            result = send_icmp(count=args.count, timeout=args.timeout)
        elif args.command in {"syn-flood", "SYN_FLOOD"}:
            result = send_syn_flood(
                args.destination_port,
                source_port=args.source_port,
                count=args.count,
                rate=args.rate,
            )
        elif args.command in {"port-scan", "PORT_SCAN"}:
            result = send_port_scan(
                args.ports,
                repeats=args.repeats,
                source_port_start=args.source_port_start,
                rate=args.rate,
                duration=args.duration,
            )
        else:  # pragma: no cover - argparse enforces the command set
            raise TrafficError("unknown command")
    except TrafficError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by CLI users
    raise SystemExit(main())
