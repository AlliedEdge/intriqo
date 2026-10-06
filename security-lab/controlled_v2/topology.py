#!/usr/bin/env python3
"""Private, four-namespace topology for controlled-v2 evaluations.

The controller deliberately does not create links in the controller's network
namespace.  A veth pair is created from one of the lab namespaces and its peer
is moved directly to another lab namespace.  The controller therefore only
uses the initial namespace for the named-netns control operations.

This module has no third-party dependencies.  It is intended to be run as
root in the dedicated ``--network none`` container described by the lab
documentation.
"""

from __future__ import annotations

import datetime as _datetime
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence


TOPOLOGY_VERSION = 2

NAMESPACE_NAMES = (
    "iqv2-attacker",
    "iqv2-victim",
    "iqv2-switch",
    "iqv2-monitor",
)

INTERFACE_ALLOWLISTS = {
    "iqv2-attacker": ("lo", "lab0"),
    "iqv2-victim": ("lo", "lab0"),
    "iqv2-switch": ("lo", "sw-a", "sw-v", "br-intriqo-v2", "mirror-out"),
    "iqv2-monitor": ("lo", "tap-intriqo-v2"),
}

ENDPOINTS = {
    "iqv2-attacker": {
        "address": "10.77.0.10",
        "mac": "02:77:00:00:00:10",
        "peer_address": "10.77.0.20",
        "peer_mac": "02:77:00:00:00:20",
    },
    "iqv2-victim": {
        "address": "10.77.0.20",
        "mac": "02:77:00:00:00:20",
        "peer_address": "10.77.0.10",
        "peer_mac": "02:77:00:00:00:10",
    },
}

SWITCH_NAMESPACE = "iqv2-switch"
BRIDGE_NAME = "br-intriqo-v2"
MIRROR_OUT = "mirror-out"
MONITOR_INTERFACE = "tap-intriqo-v2"
LAB_NETWORK = ipaddress.ip_network("10.77.0.0/24")
ROUTE_GET_TARGET = "203.0.113.1"

DEFAULT_STATE_FILE = "/run/iqv2-controlled-v2-topology.json"
STATE_ENVIRONMENT_VARIABLE = "INTRIQO_V2_STATE_FILE"


class TopologyError(RuntimeError):
    """A configuration operation could not be completed safely."""


def _state_file() -> str:
    return os.environ.get(STATE_ENVIRONMENT_VARIABLE, DEFAULT_STATE_FILE)


def _utc_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["TZ"] = "UTC"
    environment["LC_ALL"] = "C"
    return environment


def _result(
    argv: Sequence[str],
    returncode: int,
    stdout: str = "",
    stderr: str = "",
    error: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "argv": list(argv),
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
    }
    if error is not None:
        value["error"] = error
    return value


def _run(
    argv: Sequence[str],
    *,
    namespace: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run one command without a shell and retain all evidence."""

    command = list(argv)
    if namespace is not None:
        command = ["ip", "netns", "exec", namespace, *command]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=dict(environment) if environment is not None else _utc_environment(),
        )
    except (OSError, ValueError) as exc:
        return _result(command, 127, error=f"{type(exc).__name__}: {exc}")
    return _result(command, completed.returncode, completed.stdout, completed.stderr)


def _command_succeeded(command: Mapping[str, Any]) -> bool:
    return command.get("returncode") == 0


def _json_stdout(command: Mapping[str, Any]) -> Any:
    if not _command_succeeded(command):
        raise TopologyError(
            f"command failed ({command.get('returncode')}): "
            f"{' '.join(str(item) for item in command.get('argv', []))}: "
            f"{str(command.get('stderr', '')).strip()}"
        )
    try:
        return json.loads(str(command.get("stdout", "")))
    except (TypeError, json.JSONDecodeError) as exc:
        raise TopologyError(
            f"invalid JSON from {' '.join(str(item) for item in command.get('argv', []))}"
        ) from exc


def _require_commands(required: Iterable[str]) -> None:
    missing = [name for name in required if shutil.which(name) is None]
    if missing:
        raise TopologyError(f"required command(s) unavailable: {', '.join(missing)}")


def _require_root() -> None:
    if not sys.platform.startswith("linux"):
        raise TopologyError("controlled-v2 topology requires Linux")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise TopologyError("controlled-v2 topology requires root")


def _namespace_names() -> set[str]:
    command = _run(["ip", "netns", "list"])
    if not _command_succeeded(command):
        raise TopologyError(f"cannot list network namespaces: {command.get('stderr', '')}")
    names: set[str] = set()
    for line in str(command.get("stdout", "")).splitlines():
        line = line.strip()
        if line:
            names.add(line.split()[0])
    return names


def _namespace_probe(namespace: str) -> dict[str, Any]:
    """Observe net/time namespace identities and a single monotonic clock."""

    script = (
        "import datetime,json,os,time;"
        "clock=getattr(time,'CLOCK_MONOTONIC_RAW',time.CLOCK_MONOTONIC);"
        "source='CLOCK_MONOTONIC_RAW' if hasattr(time,'CLOCK_MONOTONIC_RAW') else 'CLOCK_MONOTONIC';"
        "print(json.dumps({"
        "'net_namespace_inode':os.stat('/proc/self/ns/net').st_ino,"
        "'time_namespace_inode':os.stat('/proc/self/ns/time').st_ino,"
        "'clock_source':source,"
        "'clock_id':clock,"
        "'clock_ns':time.clock_gettime_ns(clock),"
        "'timezone':'UTC',"
        "'environment_tz':os.environ.get('TZ'),"
        "'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()"
        "}))"
    )
    command = _run(
        [sys.executable, "-c", script],
        namespace=namespace,
        environment=_utc_environment(),
    )
    value = _json_stdout(command)
    if not isinstance(value, dict):
        raise TopologyError(f"namespace probe for {namespace} did not return an object")
    return value


def _run_namespace(namespace: str, args: Sequence[str]) -> dict[str, Any]:
    return _run(args, namespace=namespace, environment=_utc_environment())


def _run_ip(namespace: str, args: Sequence[str]) -> dict[str, Any]:
    return _run_namespace(namespace, ["ip", *args])


def _run_tc(namespace: str, args: Sequence[str]) -> dict[str, Any]:
    return _run_namespace(namespace, ["tc", *args])


def _must_run(namespace: str, args: Sequence[str], description: str) -> dict[str, Any]:
    command = _run_namespace(namespace, args)
    if not _command_succeeded(command):
        raise TopologyError(
            f"{description} failed: {str(command.get('stderr', '')).strip()}"
        )
    return command


def _must_ip(namespace: str, args: Sequence[str], description: str) -> dict[str, Any]:
    return _must_run(namespace, ["ip", *args], description)


def _must_tc(namespace: str, args: Sequence[str], description: str) -> dict[str, Any]:
    return _must_run(namespace, ["tc", *args], description)


def _load_state() -> dict[str, Any] | None:
    try:
        with open(_state_file(), "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise TopologyError(f"cannot read ownership marker: {exc}") from exc
    if not isinstance(value, dict):
        raise TopologyError("ownership marker is not a JSON object")
    return value


def _write_state(namespace_inodes: Mapping[str, Any]) -> None:
    path = _state_file()
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, mode=0o755, exist_ok=True)
    payload = {
        "version": TOPOLOGY_VERSION,
        "topology": "controlled_v2",
        "namespaces": list(NAMESPACE_NAMES),
        "namespace_inodes": {name: int(namespace_inodes[name]) for name in NAMESPACE_NAMES},
        "created_utc": _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
    }
    descriptor, temporary = tempfile.mkstemp(prefix=".iqv2-topology-", dir=parent, text=True)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _remove_state() -> None:
    try:
        os.unlink(_state_file())
    except FileNotFoundError:
        return
    except OSError as exc:
        raise TopologyError(f"cannot remove ownership marker: {exc}") from exc


def _state_matches_namespaces(state: Mapping[str, Any], probes: Mapping[str, Mapping[str, Any]]) -> bool:
    if state.get("version") != TOPOLOGY_VERSION or state.get("topology") != "controlled_v2":
        return False
    if tuple(state.get("namespaces", ())) != NAMESPACE_NAMES:
        return False
    recorded = state.get("namespace_inodes")
    if not isinstance(recorded, Mapping):
        return False
    for name in NAMESPACE_NAMES:
        try:
            if int(recorded[name]) != int(probes[name]["net_namespace_inode"]):
                return False
        except (KeyError, TypeError, ValueError):
            return False
    return True


def _link_kind(link: Mapping[str, Any]) -> str | None:
    linkinfo = link.get("linkinfo")
    if isinstance(linkinfo, Mapping) and linkinfo.get("info_kind"):
        return str(linkinfo["info_kind"])
    # link_type is the ARPHRD family (usually ether), not the kernel device
    # kind. Detailed output below exposes linkinfo.info_kind.
    if link.get("link_type") == "loopback":
        return "loopback"
    value = link.get("type")
    return str(value) if value else None


def _link_name(link: Mapping[str, Any]) -> str | None:
    value = link.get("ifname")
    return str(value) if value is not None else None


def _link_is_up(link: Mapping[str, Any]) -> bool:
    flags = link.get("flags")
    if isinstance(flags, list):
        return "UP" in flags
    return str(link.get("operstate", "")).upper() == "UP"


def _normalise_mac(value: Any) -> str:
    return str(value or "").lower()


def _addr_entries(addr_json: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if not isinstance(addr_json, list):
        return entries
    for link in addr_json:
        if not isinstance(link, Mapping):
            continue
        name = _link_name(link)
        values = link.get("addr_info", [])
        if not name or not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, Mapping):
                item = dict(value)
                item["dev"] = name
                entries.append(item)
    return entries


def _route_is_external(route: Mapping[str, Any]) -> bool:
    destination = route.get("dst", "default")
    if destination in (None, "default", "0.0.0.0/0", "::/0"):
        return True
    text = str(destination)
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            return not network.subnet_of(LAB_NETWORK)
        return ipaddress.ip_address(text) not in LAB_NETWORK
    except ValueError:
        return True


def _route_unsafe(route: Mapping[str, Any], allowed_devices: set[str]) -> str | None:
    route_type = route.get("type")
    if route_type not in (None, "unicast", "local", "broadcast"):
        return f"unexpected-route-type:{route_type}"
    destination = route.get("dst", "default")
    device = route.get("dev")
    if device == "lo" and destination not in (None, "default"):
        try:
            if ipaddress.ip_network(str(destination), strict=False).subnet_of(
                ipaddress.ip_network("127.0.0.0/8")
            ):
                return None
        except ValueError:
            pass
    if _route_is_external(route):
        return "external-or-default-destination"
    for key in ("gateway", "via", "nexthops", "multipath", "encap", "nhid"):
        if key in route and route.get(key) not in (None, [], ""):
            return f"gateway-or-forwarding-field:{key}"
    if device is not None and str(device) not in allowed_devices and str(device) != "lo":
        return f"unexpected-device:{device}"
    return None


def _rules_unsafe(rules: Any) -> list[str]:
    problems: list[str] = []
    if not isinstance(rules, list):
        return ["rules-not-a-list"]
    allowed_priorities = {0, 32766, 32767}
    allowed_tables = {"local", "main", "default", 253, 254, 255, "253", "254", "255"}
    for rule in rules:
        if not isinstance(rule, Mapping):
            problems.append("non-object-rule")
            continue
        priority = rule.get("priority")
        try:
            priority_value = int(priority)
        except (TypeError, ValueError):
            problems.append(f"invalid-priority:{priority}")
            priority_value = -1
        if priority_value not in allowed_priorities:
            problems.append(f"unexpected-priority:{priority}")
        table = rule.get("table", rule.get("lookup"))
        if table not in allowed_tables:
            problems.append(f"unexpected-table:{table}")
        for field in (
            "goto",
            "suppress_prefixlength",
            "suppress_ifgroup",
            "fwmark",
            "iif",
            "oif",
            "uidrange",
        ):
            if field in rule:
                problems.append(f"unexpected-policy-field:{field}")
        for field in ("from", "to", "src", "dst"):
            if field not in rule:
                continue
            value = str(rule[field])
            if value not in ("all", "0.0.0.0/0", "::/0"):
                problems.append(f"restricted-{field}:{value}")
    return problems


def _tc_filters(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if isinstance(payload, Mapping):
        for key in ("filters", "filter"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
    return []


def _tc_actions(value: Any) -> list[Mapping[str, Any]]:
    """Extract action objects while counting each actual action once."""

    actions: list[Mapping[str, Any]] = []
    if isinstance(value, Mapping):
        if str(value.get("kind", "")).lower() == "mirred":
            actions.append(value)
            return actions
        direct = value.get("actions")
        if isinstance(direct, list):
            for item in direct:
                actions.extend(_tc_actions(item))
        return actions
    if isinstance(value, list):
        for item in value:
            actions.extend(_tc_actions(item))
    return actions


def _tc_action_details(action: Mapping[str, Any]) -> tuple[str | None, str | None]:
    mode = action.get("eaction") or action.get("action") or action.get("mirred_action")
    target = (
        action.get("ifname")
        or action.get("dev")
        or action.get("device")
        or action.get("to_dev")
    )
    nested = action.get("mirred")
    if isinstance(nested, Mapping):
        mode = mode or nested.get("eaction") or nested.get("action")
        target = target or nested.get("ifname") or nested.get("dev") or nested.get("device") or nested.get("to_dev")
    return (str(mode).lower() if mode is not None else None, str(target) if target is not None else None)


def _tc_summary(payload: Any) -> dict[str, Any]:
    filters = _tc_filters(payload)
    matchall = 0
    actions: list[dict[str, Any]] = []
    for item in filters:
        if str(item.get("kind", "")).lower() == "matchall" and (
            item.get("handle") is not None or isinstance(item.get("options"), Mapping)
        ):
            matchall += 1
        options = item.get("options")
        actions_value = options if isinstance(options, Mapping) else item
        for action in _tc_actions(actions_value):
            mode, target = _tc_action_details(action)
            actions.append({"mode": mode, "target": target, "raw": dict(action)})
    return {
        "filter_count": matchall,
        "matchall_count": matchall,
        "actions": actions,
        "mirror_action_count": sum(
            1 for action in actions if action["mode"] == "mirror" and action["target"] == MIRROR_OUT
        ),
    }


def _text_tc_summary(text: str) -> dict[str, Any]:
    # JSON is authoritative.  This text summary is retained as an independent
    # human-readable check and catches a broken/empty JSON renderer.
    matchall_count = len(
        re.findall(r"^filter .*\bmatchall\b.*\bhandle\b", text, flags=re.IGNORECASE | re.MULTILINE)
    )
    mirred_count = len(re.findall(r"\bmirred\b", text, flags=re.IGNORECASE))
    target_count = text.lower().count(MIRROR_OUT)
    mirror_count = len(re.findall(r"\bmirror\b", text, flags=re.IGNORECASE))
    return {
        "matchall_count": matchall_count,
        "mirred_count": mirred_count,
        "target_count": target_count,
        "mirror_word_count": mirror_count,
        "raw": text,
    }


def _set_sysctl(namespace: str, key: str, value: int) -> None:
    # Use the namespace's procfs directly instead of assuming procps is
    # installed in the dedicated container.  ``ip`` and ``tc`` are the only
    # external networking tools required by this helper.
    proc_path = "/proc/sys/" + key.replace(".", "/")
    script = (
        "from pathlib import Path;"
        f"Path({proc_path!r}).write_text({str(value)!r}, encoding='ascii')"
    )
    _must_run(namespace, [sys.executable, "-c", script], f"set {key}")


def _sysctl_keys(namespace: str) -> list[str]:
    links = INTERFACE_ALLOWLISTS[namespace]
    keys = [
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.forwarding",
        "net.ipv6.conf.all.disable_ipv6",
        "net.ipv6.conf.default.disable_ipv6",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
        "net.ipv6.conf.all.autoconf",
        "net.ipv6.conf.default.autoconf",
        "net.ipv6.conf.all.accept_ra",
        "net.ipv6.conf.default.accept_ra",
    ]
    for link in links:
        keys.extend(
            (
                f"net.ipv4.conf.{link}.forwarding",
                f"net.ipv6.conf.{link}.disable_ipv6",
                f"net.ipv6.conf.{link}.autoconf",
                f"net.ipv6.conf.{link}.accept_ra",
            )
        )
    return keys


def _configure_sysctls(namespace: str) -> None:
    zero_keys = [
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.forwarding",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
        "net.ipv6.conf.all.autoconf",
        "net.ipv6.conf.default.autoconf",
        "net.ipv6.conf.all.accept_ra",
        "net.ipv6.conf.default.accept_ra",
    ]
    for key in zero_keys:
        _set_sysctl(namespace, key, 0)
    for link in INTERFACE_ALLOWLISTS[namespace]:
        _set_sysctl(namespace, f"net.ipv4.conf.{link}.forwarding", 0)
        _set_sysctl(namespace, f"net.ipv6.conf.{link}.disable_ipv6", 1)
        _set_sysctl(namespace, f"net.ipv6.conf.{link}.autoconf", 0)
        _set_sysctl(namespace, f"net.ipv6.conf.{link}.accept_ra", 0)
    _set_sysctl(namespace, "net.ipv6.conf.all.disable_ipv6", 1)
    _set_sysctl(namespace, "net.ipv6.conf.default.disable_ipv6", 1)


def _create_pair(source: str, peer_name: str, target: str, target_name: str) -> None:
    _must_ip(
        source,
        ["link", "add", peer_name, "type", "veth", "peer", "name", target_name],
        f"create veth {peer_name}/{target_name}",
    )
    _must_ip(
        source,
        ["link", "set", "dev", target_name, "netns", target],
        f"move {target_name} to {target}",
    )


def _setup_links() -> None:
    # Creation starts and ends in private namespaces.  The target peer names
    # are temporary only until they are renamed in the switch/monitor netns.
    # Temporary peer names must fit Linux's 15-character IFNAMSIZ limit.
    _create_pair("iqv2-attacker", "lab0", "iqv2-switch", "a-peer")
    _create_pair("iqv2-victim", "lab0", "iqv2-switch", "v-peer")
    _must_ip(
        SWITCH_NAMESPACE,
        ["link", "set", "dev", "a-peer", "name", "sw-a"],
        "rename attacker switch port",
    )
    _must_ip(
        SWITCH_NAMESPACE,
        ["link", "set", "dev", "v-peer", "name", "sw-v"],
        "rename victim switch port",
    )

    _create_pair(SWITCH_NAMESPACE, MIRROR_OUT, "iqv2-monitor", "m-peer")
    _must_ip(
        "iqv2-monitor",
        ["link", "set", "dev", "m-peer", "name", MONITOR_INTERFACE],
        "rename monitor capture port",
    )

    _must_ip(
        SWITCH_NAMESPACE,
        ["link", "add", "name", BRIDGE_NAME, "type", "bridge"],
        "create lab bridge",
    )
    _must_ip(
        SWITCH_NAMESPACE,
        ["link", "set", "dev", "sw-a", "master", BRIDGE_NAME],
        "attach attacker port",
    )
    _must_ip(
        SWITCH_NAMESPACE,
        ["link", "set", "dev", "sw-v", "master", BRIDGE_NAME],
        "attach victim port",
    )

    # Apply the safety sysctls while every data link is still down.  This
    # prevents IPv6 link-local/autoconfiguration traffic during link bring-up.
    for namespace in NAMESPACE_NAMES:
        _configure_sysctls(namespace)

    for namespace in NAMESPACE_NAMES:
        _must_ip(namespace, ["link", "set", "dev", "lo", "up"], f"bring up {namespace}/lo")

    _must_ip(SWITCH_NAMESPACE, ["link", "set", "dev", BRIDGE_NAME, "up"], "bring up bridge")
    _must_ip(SWITCH_NAMESPACE, ["link", "set", "dev", "sw-a", "up"], "bring up sw-a")
    _must_ip(SWITCH_NAMESPACE, ["link", "set", "dev", "sw-v", "up"], "bring up sw-v")
    _must_ip(SWITCH_NAMESPACE, ["link", "set", "dev", MIRROR_OUT, "up"], "bring up mirror-out")
    _must_ip("iqv2-monitor", ["link", "set", "dev", MONITOR_INTERFACE, "up"], "bring up monitor port")

    for namespace, endpoint in ENDPOINTS.items():
        _must_ip(
            namespace,
            ["link", "set", "dev", "lab0", "address", endpoint["mac"]],
            f"set {namespace} MAC",
        )
        _must_ip(
            namespace,
            ["address", "add", f"{endpoint['address']}/24", "dev", "lab0"],
            f"set {namespace} address",
        )
        _must_ip(namespace, ["link", "set", "dev", "lab0", "up"], f"bring up {namespace}/lab0")
        _must_ip(
            namespace,
            [
                "neigh",
                "replace",
                endpoint["peer_address"],
                "lladdr",
                endpoint["peer_mac"],
                "nud",
                "permanent",
                "dev",
                "lab0",
            ],
            f"install {namespace} permanent neighbor",
        )

    for port, preference in (("sw-a", "100"), ("sw-v", "101")):
        _must_tc(
            SWITCH_NAMESPACE,
            ["qdisc", "add", "dev", port, "clsact"],
            f"install clsact on {port}",
        )
        _must_tc(
            SWITCH_NAMESPACE,
            [
                "filter",
                "add",
                "dev",
                port,
                "ingress",
                "pref",
                preference,
                "matchall",
                "action",
                "mirred",
                "egress",
                "mirror",
                "dev",
                MIRROR_OUT,
            ],
            f"install ingress mirror on {port}",
        )


def _safe_delete_namespaces(
    names: Sequence[str], expected_inodes: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Delete only names created by this controller and matching their inode."""

    deleted: list[str] = []
    refused: list[str] = []
    errors: list[str] = []
    for name in names:
        if name not in NAMESPACE_NAMES:
            refused.append(name)
            continue
        if expected_inodes is not None:
            try:
                probe = _namespace_probe(name)
                if int(probe["net_namespace_inode"]) != int(expected_inodes[name]):
                    refused.append(name)
                    continue
            except (KeyError, TopologyError, TypeError, ValueError) as exc:
                refused.append(name)
                errors.append(f"{name}: cannot establish ownership: {exc}")
                continue
        command = _run(["ip", "netns", "del", name])
        if _command_succeeded(command):
            deleted.append(name)
        else:
            errors.append(f"{name}: {str(command.get('stderr', '')).strip()}")
    return {"deleted": deleted, "refused": refused, "errors": errors}


def _parse_namespace_data(namespace: str) -> tuple[dict[str, Any], list[str]]:
    """Collect all namespace-local observations and return blockers."""

    data: dict[str, Any] = {}
    blockers: list[str] = []
    try:
        data["identity"] = _namespace_probe(namespace)
    except TopologyError as exc:
        blockers.append(f"{namespace}: namespace identity probe: {exc}")

    links_command = _run_ip(namespace, ["-j", "-d", "link", "show"])
    try:
        data["links"] = _json_stdout(links_command)
    except TopologyError as exc:
        blockers.append(f"{namespace}: links: {exc}")
        data["links"] = []

    addresses_command = _run_ip(namespace, ["-j", "addr", "show"])
    try:
        data["addresses"] = _json_stdout(addresses_command)
    except TopologyError as exc:
        blockers.append(f"{namespace}: addresses: {exc}")
        data["addresses"] = []

    for family, args in (
        ("ipv4", ["-j", "-4", "route", "show", "table", "all"]),
        ("ipv6", ["-j", "-6", "route", "show", "table", "all"]),
        ("rules", ["-j", "rule", "show"]),
    ):
        command = _run_ip(namespace, args)
        try:
            data[family] = _json_stdout(command)
        except TopologyError as exc:
            blockers.append(f"{namespace}: {family}: {exc}")
            data[family] = []

    sysctls: dict[str, Any] = {}
    for key in _sysctl_keys(namespace):
        proc_path = "/proc/sys/" + key.replace(".", "/")
        script = f"from pathlib import Path; print(Path({proc_path!r}).read_text(encoding='ascii').strip())"
        command = _run_namespace(namespace, [sys.executable, "-c", script])
        if not _command_succeeded(command):
            blockers.append(f"{namespace}: sysctl {key}: {str(command.get('stderr', '')).strip()}")
            continue
        value = str(command.get("stdout", "")).strip().splitlines()
        if not value:
            blockers.append(f"{namespace}: sysctl {key}: empty value")
            continue
        sysctls[key] = value[-1].strip()
    data["sysctls"] = sysctls

    if namespace in ENDPOINTS:
        neighbors_command = _run_ip(namespace, ["-j", "neigh", "show", "dev", "lab0"])
        try:
            data["neighbors"] = _json_stdout(neighbors_command)
        except TopologyError as exc:
            blockers.append(f"{namespace}: neighbors: {exc}")
            data["neighbors"] = []

    if namespace == SWITCH_NAMESPACE:
        bridge_command = _run_namespace(namespace, ["bridge", "-j", "link", "show"])
        if _command_succeeded(bridge_command):
            try:
                data["bridge_link"] = json.loads(str(bridge_command.get("stdout", "")))
            except json.JSONDecodeError:
                data["bridge_link"] = []
                blockers.append("iqv2-switch: bridge link output was not JSON")
        else:
            # ip -j link data below independently proves master membership;
            # retaining this command's failure makes the limitation visible.
            data["bridge_link"] = []
            data["bridge_link_error"] = str(bridge_command.get("stderr", "")).strip()

        for port in ("sw-a", "sw-v"):
            qdisc_command = _run_tc(namespace, ["-j", "qdisc", "show", "dev", port])
            filter_json_command = _run_tc(namespace, ["-j", "filter", "show", "dev", port, "ingress"])
            filter_text_command = _run_tc(namespace, ["filter", "show", "dev", port, "ingress"])
            try:
                qdisc = _json_stdout(qdisc_command)
            except TopologyError as exc:
                blockers.append(f"iqv2-switch: {port} qdisc: {exc}")
                qdisc = []
            try:
                filters = _json_stdout(filter_json_command)
            except TopologyError as exc:
                blockers.append(f"iqv2-switch: {port} tc JSON filter: {exc}")
                filters = []
            data.setdefault("tc", {})[port] = {
                "qdisc": qdisc,
                "filters_json": filters,
                "filters_text": str(filter_text_command.get("stdout", "")),
                "filter_text_command": filter_text_command,
                "qdisc_ok": isinstance(qdisc, list)
                and sum(1 for item in qdisc if isinstance(item, Mapping) and item.get("kind") == "clsact") == 1,
                "json_summary": _tc_summary(filters),
                "text_summary": _text_tc_summary(str(filter_text_command.get("stdout", ""))),
            }
            if not _command_succeeded(filter_text_command):
                blockers.append(f"iqv2-switch: {port} tc text filter failed")

    return data, blockers


def _check_namespace_data(namespace: str, data: Mapping[str, Any]) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    expected_names = set(INTERFACE_ALLOWLISTS[namespace])
    links = data.get("links", [])
    link_by_name = {
        _link_name(item): item
        for item in links
        if isinstance(item, Mapping) and _link_name(item) is not None
    }
    actual_names = set(link_by_name)
    checks["exact_interface_allowlist"] = actual_names == expected_names
    checks["links_up"] = all(_link_is_up(item) for item in link_by_name.values()) and checks["exact_interface_allowlist"]

    expected_kinds = {"lo": "loopback"}
    if namespace in ENDPOINTS:
        expected_kinds["lab0"] = "veth"
    elif namespace == SWITCH_NAMESPACE:
        expected_kinds.update({"sw-a": "veth", "sw-v": "veth", BRIDGE_NAME: "bridge", MIRROR_OUT: "veth"})
    else:
        expected_kinds[MONITOR_INTERFACE] = "veth"
    checks["interface_kinds"] = all(
        name in link_by_name and _link_kind(link_by_name[name]) == kind
        for name, kind in expected_kinds.items()
    )

    addresses = _addr_entries(data.get("addresses"))
    address_set = {
        (
            str(item.get("dev")),
            str(item.get("family")),
            str(item.get("local")),
            int(item.get("prefixlen", -1)),
        )
        for item in addresses
        if item.get("local") is not None
    }
    expected_addresses: set[tuple[str, str, str, int]] = set()
    expected_addresses.add(("lo", "inet", "127.0.0.1", 8))
    if namespace in ENDPOINTS:
        expected_addresses.add(("lab0", "inet", ENDPOINTS[namespace]["address"], 24))
    checks["exact_addresses"] = address_set == expected_addresses
    checks["no_ipv6_addresses"] = not any(item.get("family") == "inet6" for item in addresses)

    if namespace in ENDPOINTS and "lab0" in link_by_name:
        checks["endpoint_mac"] = _normalise_mac(link_by_name["lab0"].get("address")) == ENDPOINTS[namespace]["mac"]
    else:
        checks["endpoint_mac"] = namespace not in ENDPOINTS

    ipv4_routes = data.get("ipv4", [])
    ipv6_routes = data.get("ipv6", [])
    allowed_devices = {"lab0"} if namespace in ENDPOINTS else set()
    route_problems: list[str] = []
    if not isinstance(ipv4_routes, list):
        route_problems.append("ipv4-routes-not-a-list")
        ipv4_routes = []
    for route in ipv4_routes:
        if isinstance(route, Mapping):
            problem = _route_unsafe(route, allowed_devices)
            if problem:
                route_problems.append(problem)
        else:
            route_problems.append("non-object-ipv4-route")
    if ipv6_routes not in ([], None):
        route_problems.append("ipv6-routes-present")
    checks["isolated_routes"] = not route_problems
    checks["no_gateway_default_or_external_routes"] = not route_problems
    checks["route_problems"] = route_problems
    if namespace in ENDPOINTS:
        checks["connected_lab_route"] = any(
            isinstance(route, Mapping)
            and str(route.get("dst")) == "10.77.0.0/24"
            and str(route.get("dev")) == "lab0"
            for route in ipv4_routes
        )
    else:
        checks["connected_lab_route"] = not any(
            isinstance(route, Mapping) and str(route.get("dev")) != "lo"
            for route in ipv4_routes
        )

    rule_problems = _rules_unsafe(data.get("rules", []))
    checks["isolated_rules"] = not rule_problems
    checks["rule_problems"] = rule_problems

    sysctls = data.get("sysctls", {})
    required_zero = [
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.forwarding",
        "net.ipv6.conf.all.forwarding",
        "net.ipv6.conf.default.forwarding",
        "net.ipv6.conf.all.autoconf",
        "net.ipv6.conf.default.autoconf",
        "net.ipv6.conf.all.accept_ra",
        "net.ipv6.conf.default.accept_ra",
    ]
    checks["forwarding_off"] = all(sysctls.get(key) == "0" for key in required_zero) and all(
        sysctls.get(f"net.ipv4.conf.{link}.forwarding") == "0"
        for link in INTERFACE_ALLOWLISTS[namespace]
    )
    checks["ipv6_disabled_and_autoconf_off"] = all(
        sysctls.get(key) == expected
        for link in INTERFACE_ALLOWLISTS[namespace]
        for key, expected in (
            (f"net.ipv6.conf.{link}.disable_ipv6", "1"),
            (f"net.ipv6.conf.{link}.autoconf", "0"),
            (f"net.ipv6.conf.{link}.accept_ra", "0"),
        )
    ) and all(
        sysctls.get(key) == expected
        for key, expected in (
            ("net.ipv6.conf.all.disable_ipv6", "1"),
            ("net.ipv6.conf.default.disable_ipv6", "1"),
            ("net.ipv6.conf.all.accept_ra", "0"),
            ("net.ipv6.conf.default.accept_ra", "0"),
        )
    )

    if namespace in ENDPOINTS:
        neighbors = data.get("neighbors", [])
        expected = ENDPOINTS[namespace]
        neighbor_values: list[tuple[str, str, tuple[str, ...]]] = []
        if isinstance(neighbors, list):
            for item in neighbors:
                if isinstance(item, Mapping):
                    state = item.get("state", [])
                    if isinstance(state, str):
                        state_tuple = (state.upper(),)
                    elif isinstance(state, list):
                        state_tuple = tuple(str(value).upper() for value in state)
                    else:
                        state_tuple = ()
                    neighbor_values.append(
                        (
                            str(item.get("dst")),
                            _normalise_mac(item.get("lladdr")),
                            state_tuple,
                        )
                    )
        checks["permanent_peer_neighbor"] = neighbor_values == [
            (expected["peer_address"], expected["peer_mac"], ("PERMANENT",))
        ]
    else:
        checks["permanent_peer_neighbor"] = True

    if namespace == SWITCH_NAMESPACE:
        bridge_index = link_by_name.get(BRIDGE_NAME, {}).get("ifindex")
        port_masters = {
            name: link_by_name.get(name, {}).get("master")
            for name in ("sw-a", "sw-v", MIRROR_OUT)
        }
        members = sorted(
            name
            for name, item in link_by_name.items()
            if item.get("master") is not None and name != BRIDGE_NAME
        )
        checks["bridge_membership"] = (
            bridge_index is not None
            and set(members) == {"sw-a", "sw-v"}
            and all(
                port_masters[name] == BRIDGE_NAME
                or str(port_masters[name]) == str(bridge_index)
                for name in ("sw-a", "sw-v")
            )
            and port_masters[MIRROR_OUT] is None
        )
        checks["bridge_members"] = members
        checks["bridge_port_masters"] = port_masters
        tc_data = data.get("tc", {})
        tc_ok = True
        for port in ("sw-a", "sw-v"):
            port_data = tc_data.get(port, {}) if isinstance(tc_data, Mapping) else {}
            summary = port_data.get("json_summary", {})
            text_summary = port_data.get("text_summary", {})
            port_ok = (
                port_data.get("qdisc_ok") is True
                and summary.get("filter_count") == 1
                and summary.get("matchall_count") == 1
                and summary.get("mirror_action_count") == 1
                and len(summary.get("actions", [])) == 1
                and text_summary.get("matchall_count") == 1
                and text_summary.get("mirred_count") == 1
                and text_summary.get("target_count") == 1
            )
            tc_ok = tc_ok and port_ok
        checks["tc_ingress_mirror_exactly_once"] = tc_ok
    else:
        checks["bridge_membership"] = namespace != SWITCH_NAMESPACE
        checks["tc_ingress_mirror_exactly_once"] = namespace != SWITCH_NAMESPACE

    checks["all_local_checks"] = all(
        value
        for key, value in checks.items()
        if key
        not in {"route_problems", "rule_problems", "bridge_members", "bridge_port_masters"}
    )
    return checks


def _route_get(namespace: str) -> dict[str, Any]:
    """Ask the kernel for a route only; this never transmits a packet."""

    command = _run_ip(namespace, ["-j", "route", "get", ROUTE_GET_TARGET])
    output = str(command.get("stdout", ""))
    route_failed = not _command_succeeded(command)
    error_text = str(command.get("stderr", "")).lower()
    parsed: Any = None
    if output.strip():
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError:
            parsed = output.strip()
    kernel_unreachable = (
        "unreachable" in error_text
        or "no route" in error_text
        or "unreachable" in output.lower()
        or "no route" in output.lower()
    )
    no_route_output = parsed in (None, "") or (
        isinstance(parsed, str)
        and ("unreachable" in parsed.lower() or "no route" in parsed.lower())
    )
    return {
        "target": ROUTE_GET_TARGET,
        "command": command,
        "failed_without_probe": route_failed and kernel_unreachable and no_route_output,
        "parsed": parsed,
        "method": "ip route get (kernel lookup only; no probe sent)",
    }


def _collect_evidence(*, require_ownership: bool) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "operation": "verify",
        "topology": "controlled_v2",
        "status": "BLOCKED",
        "host_network": {
            "modified": False,
            "link_operations_are_namespace_scoped": True,
        },
        "namespace_names": [],
        "namespaces": {},
        "checks": {},
        "errors": [],
        "clock": {
            "source": "CLOCK_MONOTONIC_RAW",
            "timezone": "UTC",
            "route_get_is_non_probe": True,
        },
    }
    errors: list[str] = evidence["errors"]
    try:
        _require_root()
        _require_commands(("ip", "tc"))
        names = _namespace_names()
    except TopologyError as exc:
        errors.append(str(exc))
        return evidence

    evidence["namespace_names"] = sorted(names)
    missing = [name for name in NAMESPACE_NAMES if name not in names]
    if missing:
        errors.append(f"missing owned namespace(s): {', '.join(missing)}")
    probes: dict[str, Mapping[str, Any]] = {}
    for namespace in NAMESPACE_NAMES:
        if namespace not in names:
            continue
        data, data_errors = _parse_namespace_data(namespace)
        evidence["namespaces"][namespace] = data
        errors.extend(data_errors)
        identity = data.get("identity")
        if isinstance(identity, Mapping):
            probes[namespace] = identity

    if len(probes) == len(NAMESPACE_NAMES):
        net_inodes = [probes[name].get("net_namespace_inode") for name in NAMESPACE_NAMES]
        time_inodes = [probes[name].get("time_namespace_inode") for name in NAMESPACE_NAMES]
        clock_sources = [probes[name].get("clock_source") for name in NAMESPACE_NAMES]
        clock_ids = [probes[name].get("clock_id") for name in NAMESPACE_NAMES]
        clock_values = [probes[name].get("clock_ns") for name in NAMESPACE_NAMES]
        evidence["namespace_inodes"] = {
            "network": dict(zip(NAMESPACE_NAMES, net_inodes)),
            "time": dict(zip(NAMESPACE_NAMES, time_inodes)),
        }
        evidence["clock"] = {
            "source": clock_sources[0],
            "clock_ids": dict(zip(NAMESPACE_NAMES, clock_ids)),
            "observations_ns": dict(zip(NAMESPACE_NAMES, clock_values)),
            "same_time_namespace_inode": len(set(time_inodes)) == 1,
            "same_clock_source": len(set(clock_sources)) == 1,
            "same_clock_id": len(set(clock_ids)) == 1,
            "utc_environment": all(
                probes[name].get("timezone") == "UTC" and probes[name].get("environment_tz") == "UTC"
                for name in NAMESPACE_NAMES
            ),
        }
        evidence["checks"]["unique_network_namespace_inodes"] = len(set(net_inodes)) == len(net_inodes)
        evidence["checks"]["shared_time_namespace_and_clock"] = (
            evidence["clock"]["same_time_namespace_inode"]
            and evidence["clock"]["same_clock_source"]
            and evidence["clock"]["same_clock_id"]
            and evidence["clock"]["utc_environment"]
        )
        evidence["checks"]["monotonic_observations"] = all(
            isinstance(value, int) for value in clock_values
        ) and all(
            clock_values[index] <= clock_values[index + 1]
            for index in range(len(clock_values) - 1)
        )
    else:
        evidence["checks"]["unique_network_namespace_inodes"] = False
        evidence["checks"]["shared_time_namespace_and_clock"] = False
        evidence["checks"]["monotonic_observations"] = False

    for namespace, data in evidence["namespaces"].items():
        try:
            checks = _check_namespace_data(namespace, data)
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            checks = {"all_local_checks": False, "malformed_observation": str(exc)}
            errors.append(f"{namespace}: malformed topology observation: {exc}")
        evidence["checks"][namespace] = checks
        if not checks.get("all_local_checks", False):
            errors.append(f"{namespace}: one or more topology checks failed")

        route_get = _route_get(namespace)
        data["route_get"] = route_get
        if not route_get["failed_without_probe"]:
            errors.append(f"{namespace}: route get to {ROUTE_GET_TARGET} did not fail without a probe")

    state: dict[str, Any] | None = None
    if require_ownership:
        try:
            state = _load_state()
            if state is None:
                errors.append("ownership marker is missing; refusing to validate as owned topology")
            elif len(probes) != len(NAMESPACE_NAMES) or not _state_matches_namespaces(state, probes):
                errors.append("ownership marker does not match current namespace identities")
            else:
                evidence["ownership"] = {
                    "marker": _state_file(),
                    "owned": True,
                    "recorded_namespace_inodes": state.get("namespace_inodes"),
                }
        except TopologyError as exc:
            errors.append(str(exc))
    else:
        evidence["ownership"] = {"marker": _state_file(), "owned": False, "preflight": True}

    evidence["status"] = "PASS" if not errors else "BLOCKED"
    return evidence


def setup() -> dict[str, Any]:
    """Create and verify the owned controlled-v2 topology."""

    base: dict[str, Any] = {
        "operation": "setup",
        "topology": "controlled_v2",
        "status": "BLOCKED",
        "errors": [],
    }
    created: list[str] = []
    created_inodes: dict[str, Any] = {}
    try:
        _require_root()
        _require_commands(("ip", "tc"))
        existing = _namespace_names()
        conflicts = sorted(set(NAMESPACE_NAMES).intersection(existing))
        if conflicts:
            raise TopologyError(
                f"refusing setup because namespace name(s) already exist: {', '.join(conflicts)}"
            )
        if os.path.exists(_state_file()):
            raise TopologyError(
                f"ownership marker already exists at {_state_file()}; refusing ambiguous setup"
            )

        for namespace in NAMESPACE_NAMES:
            command = _run(["ip", "netns", "add", namespace])
            if not _command_succeeded(command):
                raise TopologyError(
                    f"create {namespace} failed: {str(command.get('stderr', '')).strip()}"
                )
            created.append(namespace)
            probe = _namespace_probe(namespace)
            created_inodes[namespace] = probe["net_namespace_inode"]

        _setup_links()
        verification = _collect_evidence(require_ownership=False)
        base["verification"] = verification
        if verification.get("status") != "PASS":
            raise TopologyError("post-setup verification failed")
        _write_state(created_inodes)
        base["ownership"] = {
            "marker": _state_file(),
            "owned": True,
            "namespace_inodes": created_inodes,
        }
        base["status"] = "PASS"
        return base
    except (TopologyError, OSError, ValueError, KeyError) as exc:
        base["errors"].append(str(exc))
        if created:
            base["rollback"] = _safe_delete_namespaces(created, created_inodes)
        return base


def verify() -> dict[str, Any]:
    """Return parsed isolation evidence, passing only for the owned topology."""

    return _collect_evidence(require_ownership=True)


def cleanup() -> dict[str, Any]:
    """Remove only the exact topology recorded by the ownership marker."""

    result: dict[str, Any] = {
        "operation": "cleanup",
        "topology": "controlled_v2",
        "status": "BLOCKED",
        "errors": [],
    }
    try:
        _require_root()
        _require_commands(("ip", "tc"))
        state = _load_state()
        if state is None:
            raise TopologyError("ownership marker is missing; refusing cleanup")
        if state.get("version") != TOPOLOGY_VERSION or state.get("topology") != "controlled_v2":
            raise TopologyError("ownership marker has an unexpected topology or version")
        expected = state.get("namespace_inodes")
        if not isinstance(expected, Mapping):
            raise TopologyError("ownership marker has no namespace identities")
        names = _namespace_names()
        missing = [name for name in NAMESPACE_NAMES if name not in names]
        if missing:
            raise TopologyError(f"refusing cleanup; owned namespace(s) missing: {', '.join(missing)}")

        # Validation is intentionally performed before any deletion.  A
        # modified topology is evidence of unexpected configuration, not an
        # invitation to delete it.
        verification = _collect_evidence(require_ownership=True)
        result["verification"] = verification
        if verification.get("status") != "PASS":
            raise TopologyError("refusing cleanup because topology verification failed")

        deletion = _safe_delete_namespaces(NAMESPACE_NAMES, expected)
        result["deletion"] = deletion
        if deletion["refused"] or deletion["errors"]:
            raise TopologyError("one or more owned namespaces could not be safely deleted")
        remaining = _namespace_names()
        if any(name in remaining for name in NAMESPACE_NAMES):
            raise TopologyError("one or more owned namespaces remain after cleanup")
        _remove_state()
        result["status"] = "PASS"
        return result
    except (TopologyError, OSError, ValueError, KeyError) as exc:
        result["errors"].append(str(exc))
        return result


def _emit(value: Mapping[str, Any]) -> None:
    json.dump(value, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    operations = {"setup": setup, "verify": verify, "cleanup": cleanup}
    if len(args) != 1 or args[0] not in operations:
        _emit(
            {
                "operation": args[0] if args else None,
                "topology": "controlled_v2",
                "status": "BLOCKED",
                "errors": ["usage: topology.py {setup|verify|cleanup}"],
            }
        )
        return 2
    value = operations[args[0]]()
    _emit(value)
    return 0 if value.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
