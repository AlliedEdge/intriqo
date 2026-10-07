#!/usr/bin/env python3
"""Private, four-namespace topology for controlled-v2 evaluations.

The controller deliberately does not create links in the controller's network
namespace.  A veth pair is created from one of the lab namespaces and its peer
is moved directly to another lab namespace.  The controller therefore only
uses the initial namespace for the named-netns control operations.

The controlled-v2 profile has no links in the controller's network namespace.
The explicit demo profile additionally creates one host-only management veth
in that namespace so the monitor-side HTTP sink can reach the host Control
Plane; it never attaches that link to the attack bridge or a default route.

This module has no third-party dependencies.  It is intended to be run as
root in the dedicated ``--network none`` container described by the lab
documentation, except for the host-side management link required by the demo
profile.
"""

from __future__ import annotations

import datetime as _datetime
import ipaddress
import json
import os
import re
import signal
import time
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence


class TopologyError(RuntimeError):
    """A configuration operation could not be completed safely."""


TOPOLOGY_VERSION = 2
PROFILE_ENVIRONMENT_VARIABLE = "INTRIQO_LAB_PROFILE"
STATE_ENVIRONMENT_VARIABLE = "INTRIQO_V2_STATE_FILE"
GENERIC_STATE_ENVIRONMENT_VARIABLE = "INTRIQO_LAB_STATE_FILE"

# The demo profile intentionally uses the same private addresses and attack
# link layout as controlled-v2.  Its ownership names and capture interface
# differ, and it adds only a host-only management veth for the existing HTTP
# sink, so the existing traffic and detector contracts remain applicable.
CONTROLLED_V2_PROFILE = {
    "name": "controlled_v2",
    "namespaces": (
        "iqv2-attacker",
        "iqv2-victim",
        "iqv2-switch",
        "iqv2-monitor",
    ),
    "interfaces": {
        "iqv2-attacker": ("lo", "lab0"),
        "iqv2-victim": ("lo", "lab0"),
        "iqv2-switch": ("lo", "sw-a", "sw-v", "br-intriqo-v2", "mirror-out"),
        "iqv2-monitor": ("lo", "tap-intriqo-v2"),
    },
    "endpoints": {
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
    },
    "switch": "iqv2-switch",
    "attacker": "iqv2-attacker",
    "victim": "iqv2-victim",
    "monitor": "iqv2-monitor",
    "bridge": "br-intriqo-v2",
    "mirror_out": "mirror-out",
    "monitor_interface": "tap-intriqo-v2",
    "state_file": "/run/iqv2-controlled-v2-topology.json",
}

DEMO_PROFILE = {
    "name": "demo",
    "namespaces": (
        "intriqo-attacker",
        "intriqo-victim",
        "intriqo-switch",
        "intriqo-monitor",
    ),
    "interfaces": {
        "intriqo-attacker": ("lo", "lab0"),
        "intriqo-victim": ("lo", "lab0"),
        "intriqo-switch": ("lo", "sw-a", "sw-v", "br-intriqo", "mirror-out"),
        "intriqo-monitor": ("lo", "tap-intriqo", "sensor-mgmt"),
    },
    "endpoints": {
        "intriqo-attacker": {
            "address": "10.77.0.10",
            "mac": "02:77:00:00:00:10",
            "peer_address": "10.77.0.20",
            "peer_mac": "02:77:00:00:00:20",
        },
        "intriqo-victim": {
            "address": "10.77.0.20",
            "mac": "02:77:00:00:00:20",
            "peer_address": "10.77.0.10",
            "peer_mac": "02:77:00:00:00:10",
        },
    },
    "switch": "intriqo-switch",
    "attacker": "intriqo-attacker",
    "victim": "intriqo-victim",
    "monitor": "intriqo-monitor",
    "bridge": "br-intriqo",
    "mirror_out": "mirror-out",
    "monitor_interface": "tap-intriqo",
    # A host-only management veth lets the sensor's existing HTTP sink reach
    # the host Control Plane without putting the attack bridge on any physical
    # or default-route network.  It is not part of the observed lab network.
    "host_management_interface": "intriqo-mgmt",
    "monitor_management_interface": "sensor-mgmt",
    "host_management_address": "169.254.77.1",
    "monitor_management_address": "169.254.77.2",
    "management_network": "169.254.77.0/30",
    "state_file": "/run/intriqo-demo-topology.json",
}

PROFILES = {profile["name"]: profile for profile in (CONTROLLED_V2_PROFILE, DEMO_PROFILE)}

# These names remain module-level for compatibility with the controlled-v2
# controller and its tests.  _select_profile updates them only when an
# explicitly requested profile is selected.
ACTIVE_PROFILE_NAME = "controlled_v2"
ACTIVE_PROFILE: Mapping[str, Any] = CONTROLLED_V2_PROFILE
NAMESPACE_NAMES: tuple[str, ...] = ()
INTERFACE_ALLOWLISTS: dict[str, tuple[str, ...]] = {}
ENDPOINTS: dict[str, dict[str, str]] = {}
SWITCH_NAMESPACE = ""
BRIDGE_NAME = ""
MIRROR_OUT = ""
MONITOR_INTERFACE = ""
HOST_MANAGEMENT_INTERFACE = ""
MONITOR_MANAGEMENT_INTERFACE = ""
HOST_MANAGEMENT_ADDRESS = ""
MONITOR_MANAGEMENT_ADDRESS = ""
MANAGEMENT_NETWORK = ipaddress.ip_network("169.254.77.0/30")
LAB_NETWORK = ipaddress.ip_network("10.77.0.0/24")
ROUTE_GET_TARGET = "203.0.113.1"
DEFAULT_STATE_FILE = ""


def _select_profile(name: str) -> None:
    """Select a known profile without changing its network contract."""

    global ACTIVE_PROFILE_NAME, ACTIVE_PROFILE, NAMESPACE_NAMES
    global INTERFACE_ALLOWLISTS, ENDPOINTS, SWITCH_NAMESPACE
    global BRIDGE_NAME, MIRROR_OUT, MONITOR_INTERFACE, DEFAULT_STATE_FILE
    global ATTACKER_NAMESPACE, VICTIM_NAMESPACE, MONITOR_NAMESPACE
    global HOST_MANAGEMENT_INTERFACE, MONITOR_MANAGEMENT_INTERFACE
    global HOST_MANAGEMENT_ADDRESS, MONITOR_MANAGEMENT_ADDRESS, MANAGEMENT_NETWORK
    profile = PROFILES.get(name)
    if profile is None:
        raise TopologyError(
            f"unknown topology profile {name!r}; expected one of {', '.join(sorted(PROFILES))}"
        )
    ACTIVE_PROFILE_NAME = str(profile["name"])
    ACTIVE_PROFILE = profile
    NAMESPACE_NAMES = tuple(profile["namespaces"])
    INTERFACE_ALLOWLISTS = dict(profile["interfaces"])
    ENDPOINTS = {name: dict(value) for name, value in profile["endpoints"].items()}
    SWITCH_NAMESPACE = str(profile["switch"])
    ATTACKER_NAMESPACE = str(profile["attacker"])
    VICTIM_NAMESPACE = str(profile["victim"])
    MONITOR_NAMESPACE = str(profile["monitor"])
    BRIDGE_NAME = str(profile["bridge"])
    MIRROR_OUT = str(profile["mirror_out"])
    MONITOR_INTERFACE = str(profile["monitor_interface"])
    HOST_MANAGEMENT_INTERFACE = str(profile.get("host_management_interface", ""))
    MONITOR_MANAGEMENT_INTERFACE = str(profile.get("monitor_management_interface", ""))
    HOST_MANAGEMENT_ADDRESS = str(profile.get("host_management_address", ""))
    MONITOR_MANAGEMENT_ADDRESS = str(profile.get("monitor_management_address", ""))
    MANAGEMENT_NETWORK = ipaddress.ip_network(str(profile.get("management_network", "169.254.77.0/30")))
    DEFAULT_STATE_FILE = str(profile["state_file"])


# Importing this module must never select the demo profile from ambient
# environment state.  The controller and the historical controlled-v2 runner
# therefore retain their exact default topology; callers select ``demo`` via
# an explicit function argument or CLI option.
_select_profile("controlled_v2")


def _state_file() -> str:
    if ACTIVE_PROFILE_NAME == "demo":
        return os.environ.get(
            GENERIC_STATE_ENVIRONMENT_VARIABLE,
            os.environ.get(STATE_ENVIRONMENT_VARIABLE, DEFAULT_STATE_FILE),
        )
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


def _must_host(args: Sequence[str], description: str) -> dict[str, Any]:
    command = _run(args, environment=_utc_environment())
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
        "topology": ACTIVE_PROFILE_NAME,
        "namespaces": list(NAMESPACE_NAMES),
        "namespace_inodes": {name: int(namespace_inodes[name]) for name in NAMESPACE_NAMES},
        "created_utc": _datetime.datetime.now(_datetime.timezone.utc).isoformat(),
    }
    if ACTIVE_PROFILE_NAME == "demo":
        payload["profile"] = "demo"
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
    if state.get("version") != TOPOLOGY_VERSION or state.get("topology") != ACTIVE_PROFILE_NAME:
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
            return not (network.subnet_of(LAB_NETWORK) or network.subnet_of(MANAGEMENT_NETWORK))
        address = ipaddress.ip_address(text)
        return address not in LAB_NETWORK and address not in MANAGEMENT_NETWORK
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


def _demo_alias(namespace: str, interface: str, inode: Any) -> str:
    return f"intriqo-demo:{int(inode)}:{namespace}:{interface}"


def _tag_demo_link(namespace: str, interface: str) -> None:
    inode = _namespace_probe(namespace)["net_namespace_inode"]
    _must_ip(namespace, ["link", "set", "dev", interface, "alias", _demo_alias(namespace, interface, inode)], "tag owned demo link")


def _create_host_management_link() -> None:
    _must_host(
        ["ip", "link", "add", HOST_MANAGEMENT_INTERFACE, "type", "veth", "peer", "name", MONITOR_MANAGEMENT_INTERFACE],
        "create host-only sensor management veth",
    )
    _must_host(
        ["ip", "link", "set", "dev", MONITOR_MANAGEMENT_INTERFACE, "netns", MONITOR_NAMESPACE],
        "move sensor management veth into monitor namespace",
    )
    _must_host(
        ["ip", "link", "set", "dev", HOST_MANAGEMENT_INTERFACE, "alias", f"intriqo-demo-host:{HOST_MANAGEMENT_INTERFACE}"],
        "tag host-only sensor management veth",
    )
    _must_host(
        ["ip", "address", "add", f"{HOST_MANAGEMENT_ADDRESS}/30", "dev", HOST_MANAGEMENT_INTERFACE],
        "address host-only sensor management veth",
    )
    _must_host(["ip", "link", "set", "dev", HOST_MANAGEMENT_INTERFACE, "up"], "bring up host-only sensor management veth")
    _must_ip(
        MONITOR_NAMESPACE,
        ["address", "add", f"{MONITOR_MANAGEMENT_ADDRESS}/30", "dev", MONITOR_MANAGEMENT_INTERFACE],
        "address sensor management veth",
    )
    _must_ip(
        MONITOR_NAMESPACE,
        ["link", "set", "dev", MONITOR_MANAGEMENT_INTERFACE, "up"],
        "bring up sensor management veth",
    )


def _delete_host_management_link() -> None:
    if ACTIVE_PROFILE_NAME != "demo":
        return
    command = _run(["ip", "link", "show", "dev", HOST_MANAGEMENT_INTERFACE])
    if _command_succeeded(command):
        _must_host(["ip", "link", "del", "dev", HOST_MANAGEMENT_INTERFACE], "remove host-only sensor management veth")
def _setup_links() -> None:
    # Creation starts and ends in private namespaces.  The target peer names
    # are temporary only until they are renamed in the switch/monitor netns.
    # Temporary peer names must fit Linux's 15-character IFNAMSIZ limit.
    _create_pair(ATTACKER_NAMESPACE, "lab0", SWITCH_NAMESPACE, "a-peer")
    _create_pair(VICTIM_NAMESPACE, "lab0", SWITCH_NAMESPACE, "v-peer")
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

    _create_pair(SWITCH_NAMESPACE, MIRROR_OUT, MONITOR_NAMESPACE, "m-peer")
    _must_ip(
        MONITOR_NAMESPACE,
        ["link", "set", "dev", "m-peer", "name", MONITOR_INTERFACE],
        "rename monitor capture port",
    )

    if ACTIVE_PROFILE_NAME == "demo":
        # The only host-facing link is a point-to-point management veth.  It is
        # deliberately outside 10.77.0.0/24 and has no forwarding/default
        # route, so it cannot carry attacker/victim traffic to the host LAN.
        _create_host_management_link()

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
    _must_ip(MONITOR_NAMESPACE, ["link", "set", "dev", MONITOR_INTERFACE, "up"], "bring up monitor port")

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
    if ACTIVE_PROFILE_NAME == "demo":
        for namespace, interfaces in INTERFACE_ALLOWLISTS.items():
            for interface in interfaces:
                if interface != "lo":
                    _tag_demo_link(namespace, interface)


def _safe_delete_namespaces(
    names: Sequence[str],
    expected_inodes: Mapping[str, Any] | None = None,
    *,
    refuse_processes: bool = False,
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
        if refuse_processes:
            try:
                pids = _namespace_pids(name)
            except TopologyError as exc:
                refused.append(name)
                errors.append(f"{name}: cannot establish process ownership: {exc}")
                continue
            if pids:
                refused.append(name)
                errors.append(f"{name}: nonowned process(es) retain namespace: {pids}")
                continue
        command = _run(["ip", "netns", "del", name])
        if _command_succeeded(command):
            deleted.append(name)
        else:
            errors.append(f"{name}: {str(command.get('stderr', '')).strip()}")
    return {"deleted": deleted, "refused": refused, "errors": errors}


def _namespace_pids(namespace: str) -> list[int]:
    """Return processes currently attached to a named namespace."""

    command = _run(["ip", "netns", "pids", namespace])
    if not _command_succeeded(command):
        raise TopologyError(
            f"cannot inspect processes in {namespace}: {str(command.get('stderr', '')).strip()}"
        )
    pids: list[int] = []
    for token in str(command.get("stdout", "")).split():
        try:
            pid = int(token)
        except ValueError:
            continue
        if pid > 0:
            pids.append(pid)
    return sorted(set(pids))


def _processes_for_namespace_inode(inode: Any) -> list[int]:
    """Find processes retaining a namespace even after its name is gone."""

    try:
        expected = int(inode)
    except (TypeError, ValueError):
        return []
    processes: list[int] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            if os.stat(f"/proc/{entry}/ns/net").st_ino == expected:
                processes.append(int(entry))
        except (FileNotFoundError, PermissionError, OSError, ValueError):
            continue
    return sorted(set(processes))


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

    # Missing demo interfaces are repairable.  Still read all namespace-wide
    # controls and every control for interfaces that actually exist.
    existing_links = {_link_name(item) for item in data["links"] if isinstance(item, Mapping)}
    sysctls: dict[str, Any] = {}
    keys = _sysctl_keys(namespace)
    if ACTIVE_PROFILE_NAME == "demo":
        keys = [
            key for key in keys
            if not any(
                f".conf.{interface}." in key
                for interface in set(INTERFACE_ALLOWLISTS[namespace]) - existing_links
            )
        ]
    for key in keys:
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

    if namespace in ENDPOINTS and (ACTIVE_PROFILE_NAME != "demo" or "lab0" in existing_links):
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
                blockers.append(f"{SWITCH_NAMESPACE}: bridge link output was not JSON")
        else:
            # ip -j link data below independently proves master membership;
            # retaining this command's failure makes the limitation visible.
            data["bridge_link"] = []
            data["bridge_link_error"] = str(bridge_command.get("stderr", "")).strip()

        for port in ("sw-a", "sw-v"):
            if ACTIVE_PROFILE_NAME == "demo" and port not in existing_links:
                continue
            qdisc_command = _run_tc(namespace, ["-j", "qdisc", "show", "dev", port])
            filter_json_command = _run_tc(namespace, ["-j", "filter", "show", "dev", port, "ingress"])
            filter_text_command = _run_tc(namespace, ["filter", "show", "dev", port, "ingress"])
            try:
                qdisc = _json_stdout(qdisc_command)
            except TopologyError as exc:
                blockers.append(f"{SWITCH_NAMESPACE}: {port} qdisc: {exc}")
                qdisc = []
            try:
                filters = _json_stdout(filter_json_command)
            except TopologyError as exc:
                blockers.append(f"{SWITCH_NAMESPACE}: {port} tc JSON filter: {exc}")
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
                blockers.append(f"{SWITCH_NAMESPACE}: {port} tc text filter failed")
            if ACTIVE_PROFILE_NAME == "demo":
                egress = _run_tc(namespace, ["-j", "filter", "show", "dev", port, "egress"])
                try:
                    data["tc"][port]["egress_filters"] = _json_stdout(egress)
                except TopologyError as exc:
                    blockers.append(f"{SWITCH_NAMESPACE}: {port} egress filters: {exc}")

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
        if ACTIVE_PROFILE_NAME == "demo":
            expected_kinds[MONITOR_MANAGEMENT_INTERFACE] = "veth"
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
    elif namespace == MONITOR_NAMESPACE and ACTIVE_PROFILE_NAME == "demo":
        expected_addresses.add((MONITOR_MANAGEMENT_INTERFACE, "inet", MONITOR_MANAGEMENT_ADDRESS, 30))
    checks["exact_addresses"] = address_set == expected_addresses
    checks["no_ipv6_addresses"] = not any(item.get("family") == "inet6" for item in addresses)

    if namespace in ENDPOINTS and "lab0" in link_by_name:
        checks["endpoint_mac"] = _normalise_mac(link_by_name["lab0"].get("address")) == ENDPOINTS[namespace]["mac"]
    else:
        checks["endpoint_mac"] = namespace not in ENDPOINTS

    ipv4_routes = data.get("ipv4", [])
    ipv6_routes = data.get("ipv6", [])
    allowed_devices = {"lab0"} if namespace in ENDPOINTS else set()
    if namespace == MONITOR_NAMESPACE and ACTIVE_PROFILE_NAME == "demo":
        allowed_devices.add(MONITOR_MANAGEMENT_INTERFACE)
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
    elif namespace == MONITOR_NAMESPACE and ACTIVE_PROFILE_NAME == "demo":
        checks["connected_lab_route"] = any(
            isinstance(route, Mapping)
            and str(route.get("dst")) == str(MANAGEMENT_NETWORK)
            and str(route.get("dev")) == MONITOR_MANAGEMENT_INTERFACE
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


def _tc_port_state(port_data: Mapping[str, Any]) -> str:
    """Classify one owned ingress port without treating foreign filters as absent."""

    qdisc = port_data.get("qdisc", [])
    if not isinstance(qdisc, list):
        return "foreign"
    qdisc_kinds = [
        str(item.get("kind"))
        for item in qdisc
        if isinstance(item, Mapping) and item.get("kind") is not None
    ]
    if port_data.get("egress_filters") not in (None, []):
        return "foreign"
    qdisc_kinds = [kind for kind in qdisc_kinds if kind != "noqueue"]
    if not qdisc_kinds:
        qdisc_state = "missing"
    elif qdisc_kinds == ["clsact"]:
        qdisc_state = "ready"
    else:
        return "foreign"

    filters = _tc_filters(port_data.get("filters_json", []))
    text_summary = port_data.get("text_summary", {})
    if not filters:
        if isinstance(text_summary, Mapping) and any(
            int(text_summary.get(key, 0) or 0) > 0
            for key in ("matchall_count", "mirred_count", "target_count")
        ):
            return "foreign"
        return "qdisc_missing" if qdisc_state == "missing" else "filter_missing"

    records = [item for item in filters if item.get("handle") is not None or isinstance(item.get("options"), Mapping)]
    headers = [item for item in filters if item not in records]
    if len(records) != 1 or any(
        str(item.get("kind", "")).lower() != "matchall"
        or item.get("pref") != records[0].get("pref")
        or item.get("chain", 0) != records[0].get("chain", 0)
        for item in headers
    ):
        return "foreign"
    item = records[0]
    if str(item.get("kind", "")).lower() != "matchall":
        return "foreign"
    options = item.get("options")
    actions = _tc_actions(options if isinstance(options, Mapping) else item)
    if len(actions) != 1:
        return "foreign"
    mode, target = _tc_action_details(actions[0])
    if mode != "mirror" or target != MIRROR_OUT:
        return "foreign"
    if not isinstance(text_summary, Mapping) or not (
        text_summary.get("matchall_count") == 1
        and text_summary.get("mirred_count") == 1
        and text_summary.get("target_count") == 1
    ):
        return "foreign"
    return "ready" if qdisc_state == "ready" else "qdisc_missing"


def _partial_safety_problems(namespace: str, data: Mapping[str, Any]) -> list[str]:
    """Reject foreign state while allowing expected pieces to be missing."""

    problems: list[str] = []
    expected_names = set(INTERFACE_ALLOWLISTS[namespace])
    links = data.get("links", [])
    link_by_name = {
        _link_name(item): item
        for item in links
        if isinstance(item, Mapping) and _link_name(item) is not None
    }
    extras = sorted(set(link_by_name) - expected_names)
    if extras:
        problems.append(f"{namespace}: unexpected interface(s): {', '.join(extras)}")
    expected_kinds = {"lo": "loopback"}
    if namespace in ENDPOINTS:
        expected_kinds["lab0"] = "veth"
    elif namespace == SWITCH_NAMESPACE:
        expected_kinds.update({"sw-a": "veth", "sw-v": "veth", BRIDGE_NAME: "bridge", MIRROR_OUT: "veth"})
    else:
        expected_kinds[MONITOR_INTERFACE] = "veth"
    for name, kind in expected_kinds.items():
        if name in link_by_name and _link_kind(link_by_name[name]) != kind:
            problems.append(f"{namespace}: {name} has unexpected link kind")

    addresses = _addr_entries(data.get("addresses"))
    expected_addresses = {
        ("lo", "inet", "127.0.0.1", 8),
    }
    if namespace in ENDPOINTS:
        expected_addresses.add(("lab0", "inet", ENDPOINTS[namespace]["address"], 24))
    elif namespace == MONITOR_NAMESPACE and ACTIVE_PROFILE_NAME == "demo":
        # ``ip -j addr`` reports the monitor-side management address with the
        # interface name in ``dev``.  Keep the comparison in the same
        # normalized (dev, family, local, prefixlen) form used below so the
        # owned host-only veth is accepted during ensure as well as validate.
        expected_addresses.add((MONITOR_MANAGEMENT_INTERFACE, "inet", MONITOR_MANAGEMENT_ADDRESS, 30))
    for item in addresses:
        value = (
            str(item.get("dev")),
            str(item.get("family")),
            str(item.get("local")),
            int(item.get("prefixlen", -1)),
        )
        if value not in expected_addresses:
            problems.append(f"{namespace}: unexpected address: {value}")

    ipv4_routes = data.get("ipv4", [])
    if isinstance(ipv4_routes, list):
        allowed_devices = {"lab0"} if namespace in ENDPOINTS else set()
        if namespace == MONITOR_NAMESPACE and ACTIVE_PROFILE_NAME == "demo":
            allowed_devices.add(MONITOR_MANAGEMENT_INTERFACE)
        for route in ipv4_routes:
            if isinstance(route, Mapping):
                problem = _route_unsafe(route, allowed_devices)
                if problem:
                    problems.append(f"{namespace}: unsafe route: {problem}")
            else:
                problems.append(f"{namespace}: non-object IPv4 route")
    else:
        problems.append(f"{namespace}: IPv4 routes are not a list")
    if data.get("ipv6") not in ([], None):
        problems.append(f"{namespace}: IPv6 routes present")
    problems.extend(f"{namespace}: unsafe rule: {problem}" for problem in _rules_unsafe(data.get("rules", [])))

    if namespace in ENDPOINTS:
        expected = ENDPOINTS[namespace]
        if "lab0" in link_by_name and _normalise_mac(link_by_name["lab0"].get("address")) != expected["mac"]:
            problems.append(f"{namespace}: lab0 has an unexpected MAC address")
        neighbors = data.get("neighbors", [])
        if isinstance(neighbors, list):
            for item in neighbors:
                if not isinstance(item, Mapping):
                    problems.append(f"{namespace}: malformed neighbor")
                    continue
                state = item.get("state", [])
                state_values = (state.upper(),) if isinstance(state, str) else tuple(
                    str(value).upper() for value in state
                ) if isinstance(state, list) else ()
                if (
                    str(item.get("dst")),
                    _normalise_mac(item.get("lladdr")),
                    state_values,
                ) != (expected["peer_address"], expected["peer_mac"], ("PERMANENT",)):
                    problems.append(f"{namespace}: foreign neighbor entry")
        else:
            problems.append(f"{namespace}: neighbors are not a list")

    if namespace == SWITCH_NAMESPACE:
        bridge_index = link_by_name.get(BRIDGE_NAME, {}).get("ifindex")
        masters = {
            name: link_by_name.get(name, {}).get("master")
            for name in ("sw-a", "sw-v", MIRROR_OUT)
        }
        for port in ("sw-a", "sw-v"):
            master = masters[port]
            if master is not None and master != BRIDGE_NAME and str(master) != str(bridge_index):
                problems.append(f"{namespace}: {port} has a foreign bridge master")
        if masters[MIRROR_OUT] is not None:
            problems.append(f"{namespace}: {MIRROR_OUT} is attached to a foreign master")
        tc_data = data.get("tc", {})
        for port in ("sw-a", "sw-v"):
            port_data = tc_data.get(port, {}) if isinstance(tc_data, Mapping) else {}
            if _tc_port_state(port_data) == "foreign":
                problems.append(f"{namespace}: {port} has a foreign qdisc/filter configuration")
    return problems


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


def _link_packet_stats(namespace: str, interface: str) -> dict[str, Any]:
    """Read kernel link counters for a real mirror probe."""

    command = _run_ip(namespace, ["-j", "-s", "link", "show", "dev", interface])
    value = _json_stdout(command)
    link = value[0] if isinstance(value, list) and value else value
    if not isinstance(link, Mapping):
        raise TopologyError(f"{namespace}/{interface} link stats were not an object")
    stats = link.get("stats64") or link.get("stats")
    if not isinstance(stats, Mapping):
        raise TopologyError(f"{namespace}/{interface} link stats were unavailable")
    packets: dict[str, int] = {}
    for direction in ("rx", "tx"):
        counters = stats.get(direction)
        if isinstance(counters, Mapping) and counters.get("packets") is not None:
            try:
                packets[direction] = int(counters["packets"])
            except (TypeError, ValueError) as exc:
                raise TopologyError(
                    f"{namespace}/{interface} {direction} packet counter was invalid"
                ) from exc
    if "rx" not in packets or "tx" not in packets:
        raise TopologyError(f"{namespace}/{interface} link packet counters were incomplete")
    return {"interface": interface, "packets": packets, "raw": link}


def _host_management_check() -> dict[str, Any]:
    """Verify the demo's host-only control link without inspecting physical NICs."""

    if ACTIVE_PROFILE_NAME != "demo":
        return {"enabled": False, "ok": True}
    link_command = _run(["ip", "-j", "-d", "link", "show", "dev", HOST_MANAGEMENT_INTERFACE])
    address_command = _run(["ip", "-j", "-4", "addr", "show", "dev", HOST_MANAGEMENT_INTERFACE])
    if not _command_succeeded(link_command) or not _command_succeeded(address_command):
        return {
            "enabled": True,
            "ok": False,
            "error": str(link_command.get("stderr") or address_command.get("stderr") or "host management link missing").strip(),
        }
    links = _json_stdout(link_command)
    addresses = _json_stdout(address_command)
    link = links[0] if isinstance(links, list) and links else {}
    alias = str(link.get("ifalias") or "")
    kind = _link_kind(link)
    address_set = {
        (str(item.get("local")), int(item.get("prefixlen", -1)))
        for entry in addresses if isinstance(entry, Mapping)
        for item in entry.get("addr_info", []) if isinstance(item, Mapping)
    }
    ok = (
        kind == "veth"
        and _link_is_up(link)
        and alias == f"intriqo-demo-host:{HOST_MANAGEMENT_INTERFACE}"
        and (HOST_MANAGEMENT_ADDRESS, 30) in address_set
        and all(address == (HOST_MANAGEMENT_ADDRESS, 30) for address in address_set)
    )
    return {
        "enabled": True,
        "ok": ok,
        "interface": HOST_MANAGEMENT_INTERFACE,
        "kind": kind,
        "alias": alias,
        "addresses": sorted(address_set),
    }


_PING_CAPTURE_SCRIPT = r"""
import json, socket, struct, sys, time
from pathlib import Path

interface, source, destination, identifier, ready_path = sys.argv[1:]
counts = {"request": 0, "reply": 0}
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((interface, 0))
Path(ready_path).write_text("ready\n", encoding="ascii")
sock.settimeout(0.10)
source_bytes = socket.inet_aton(source)
destination_bytes = socket.inet_aton(destination)
deadline = time.monotonic() + 4.0
while time.monotonic() < deadline and not all(counts.values()):
    try:
        frame = sock.recv(65535)
    except socket.timeout:
        continue
    if len(frame) < 14 + 20 + 8 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
        continue
    ip_offset = 14
    ihl = (frame[ip_offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < ip_offset + ihl + 8 or frame[ip_offset + 9] != 1:
        continue
    source_seen = frame[ip_offset + 12:ip_offset + 16]
    destination_seen = frame[ip_offset + 16:ip_offset + 20]
    icmp_type = frame[ip_offset + ihl]
    identifier_seen, sequence_seen = struct.unpack("!HH", frame[ip_offset + ihl + 4:ip_offset + ihl + 8])
    if identifier_seen != int(identifier) or sequence_seen != 1:
        continue
    if source_seen == source_bytes and destination_seen == destination_bytes and icmp_type == 8:
        counts["request"] += 1
    elif source_seen == destination_bytes and destination_seen == source_bytes and icmp_type == 0:
        counts["reply"] += 1
sock.close()
print(json.dumps(counts, sort_keys=True), flush=True)
"""


def _capture_fixed_ping() -> dict[str, Any]:
    """Capture the fixed ICMP request/reply pair while issuing one real ping."""

    descriptor, ready_path = tempfile.mkstemp(prefix=".intriqo-ping-ready-")
    os.close(descriptor)
    os.unlink(ready_path)
    identifier = 1 + int.from_bytes(os.urandom(2), "big") % 65535
    command = [
        "ip",
        "netns",
        "exec",
        MONITOR_NAMESPACE,
        sys.executable,
        "-c",
        _PING_CAPTURE_SCRIPT,
        MONITOR_INTERFACE,
        ENDPOINTS[ATTACKER_NAMESPACE]["address"],
        ENDPOINTS[ATTACKER_NAMESPACE]["peer_address"],
        str(identifier),
        ready_path,
    ]
    process: subprocess.Popen[str] | None = None
    try:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=_utc_environment(),
            )
        except (OSError, ValueError) as exc:
            raise TopologyError(f"cannot start monitor packet probe: {exc}") from exc

        deadline = time.monotonic() + 2.0
        while not os.path.exists(ready_path) and time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout is not None else ""
                raise TopologyError(f"monitor packet probe exited before readiness: {output.strip()}")
            time.sleep(0.01)
        if not os.path.exists(ready_path):
            raise TopologyError("monitor packet probe readiness timeout")

        probe = _run_namespace(
            ATTACKER_NAMESPACE,
            ["ping", "-I", "lab0", "-e", str(identifier), "-c", "1", "-W", "1", ENDPOINTS[ATTACKER_NAMESPACE]["peer_address"]],
        )
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGTERM)
            process.wait(timeout=2.0)
        output = process.stdout.read() if process.stdout is not None else ""
        lines = [line for line in output.splitlines() if line.strip()]
        capture: dict[str, Any] = {}
        if lines:
            try:
                value = json.loads(lines[-1])
                if isinstance(value, dict):
                    capture = value
            except json.JSONDecodeError:
                pass
        capture["probe"] = probe
        capture["command"] = command
        capture["capture_returncode"] = process.returncode
        capture["icmp_identifier"] = identifier
        capture["raw_output"] = output
        return capture
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        if process is not None and process.stdout is not None:
            process.stdout.close()
        try:
            os.unlink(ready_path)
        except FileNotFoundError:
            pass


def validate_connectivity(profile: str | None = None) -> dict[str, Any]:
    """Verify topology, then send one fixed-address probe through the mirror.

    Static ``verify`` deliberately remains probe-free for controlled-v2
    compatibility.  This operation is the stronger demo gate: it requires the
    exact topology first, pings only the fixed lab peer, and checks that the
    monitor veth saw both fixed ICMP directions on the capture interface.
    """

    if profile is not None:
        _select_profile(profile)
    evidence = _collect_evidence(require_ownership=True)
    evidence["operation"] = "validate_connectivity"
    connectivity: dict[str, Any] = {
        "source_namespace": ATTACKER_NAMESPACE,
        "source_address": ENDPOINTS[ATTACKER_NAMESPACE]["address"],
        "destination_address": ENDPOINTS[ATTACKER_NAMESPACE]["peer_address"],
        "monitor_namespace": MONITOR_NAMESPACE,
        "monitor_interface": MONITOR_INTERFACE,
        "checks": {},
        "errors": [],
    }
    evidence["connectivity"] = connectivity
    errors: list[str] = evidence["errors"]
    if evidence.get("status") != "PASS":
        connectivity["checks"] = {
            "topology_verified": False,
            "attacker_to_victim": False,
            "monitor_received_probe": False,
            "tap_saw_request": False,
            "tap_saw_reply": False,
        }
        return evidence

    try:
        _require_commands(("ping",))
        before = _link_packet_stats(MONITOR_NAMESPACE, MONITOR_INTERFACE)
        capture = _capture_fixed_ping()
        after = _link_packet_stats(MONITOR_NAMESPACE, MONITOR_INTERFACE)
        before_packets = int(before["packets"]["rx"])
        after_packets = int(after["packets"]["rx"])
        mirror_delta = after_packets - before_packets
        probe = capture.get("probe", {})
        request_count = int(capture.get("request", 0) or 0) if capture.get("capture_returncode") == 0 else 0
        reply_count = int(capture.get("reply", 0) or 0) if capture.get("capture_returncode") == 0 else 0
        connectivity.update(
            {
                "probe": probe,
                "tap_capture": capture,
                "monitor_before": before,
                "monitor_after": after,
                "monitor_rx_packet_delta": mirror_delta,
            }
        )
        connectivity["checks"] = {
            "topology_verified": True,
            "attacker_to_victim": _command_succeeded(probe),
            "monitor_received_probe": request_count > 0 and reply_count > 0,
            "tap_saw_request": request_count > 0,
            "tap_saw_reply": reply_count > 0,
            "tc_ingress_mirror_exactly_once": all(
                evidence.get("checks", {}).get(namespace, {}).get(
                    "tc_ingress_mirror_exactly_once", False
                )
                for namespace in NAMESPACE_NAMES
            ),
        }
        if not connectivity["checks"]["attacker_to_victim"]:
            errors.append("fixed attacker-to-victim ping failed")
        if not connectivity["checks"]["tap_saw_request"]:
            errors.append("tap-intriqo received no fixed ICMP echo request")
        if not connectivity["checks"]["tap_saw_reply"]:
            errors.append("tap-intriqo received no fixed ICMP echo reply")
    except (TopologyError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        connectivity["errors"].append(str(exc))
        errors.append(str(exc))

    evidence["status"] = "PASS" if not errors else "BLOCKED"
    return evidence


validate = validate_connectivity


def _collect_evidence(*, require_ownership: bool) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "operation": "verify",
        "topology": ACTIVE_PROFILE_NAME,
        "status": "BLOCKED",
        "host_network": {
            "modified": ACTIVE_PROFILE_NAME == "demo",
            "physical_interfaces_modified": False,
            "link_operations_are_namespace_scoped": ACTIVE_PROFILE_NAME != "demo",
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
    if ACTIVE_PROFILE_NAME == "demo":
        evidence["host_management"] = _host_management_check()
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
    if ACTIVE_PROFILE_NAME == "demo" and not evidence.get("host_management", {}).get("ok", False):
        errors.append("host-only sensor management link is missing, foreign, or unsafe")
        evidence["status"] = "BLOCKED"
    return evidence


def _validate_owned_marker(state: Mapping[str, Any]) -> Mapping[str, Any]:
    if state.get("version") != TOPOLOGY_VERSION or state.get("topology") != ACTIVE_PROFILE_NAME:
        raise TopologyError("ownership marker has an unexpected topology or version")
    if tuple(state.get("namespaces", ())) != NAMESPACE_NAMES:
        raise TopologyError("ownership marker has an unexpected namespace set")
    recorded = state.get("namespace_inodes")
    if not isinstance(recorded, Mapping):
        raise TopologyError("ownership marker has no namespace identities")
    for namespace in NAMESPACE_NAMES:
        if namespace not in recorded:
            raise TopologyError(f"ownership marker has no identity for {namespace}")
    return recorded


def _observe_owned_namespaces(
    recorded: Mapping[str, Any], *, allow_missing: bool
) -> tuple[set[str], dict[str, Mapping[str, Any]], dict[str, dict[str, Any]]]:
    names = _namespace_names()
    missing = [namespace for namespace in NAMESPACE_NAMES if namespace not in names]
    if missing and not allow_missing:
        raise TopologyError(f"owned namespace(s) are missing: {', '.join(missing)}")
    probes: dict[str, Mapping[str, Any]] = {}
    observations: dict[str, dict[str, Any]] = {}
    for namespace in NAMESPACE_NAMES:
        if namespace not in names:
            continue
        probe = _namespace_probe(namespace)
        try:
            owned_inode = int(recorded[namespace])
            actual_inode = int(probe["net_namespace_inode"])
        except (KeyError, TypeError, ValueError) as exc:
            raise TopologyError(f"cannot establish ownership for {namespace}") from exc
        if owned_inode != actual_inode:
            raise TopologyError(f"namespace identity was replaced: {namespace}")
        probes[namespace] = probe
        observations[namespace], blockers = _parse_namespace_data(namespace)
        if blockers:
            raise TopologyError("; ".join(blockers))
        for link in observations[namespace].get("links", []):
            if not isinstance(link, Mapping) or link.get("ifname") == "lo":
                continue
            interface = str(link.get("ifname"))
            if link.get("ifalias") not in (None, _demo_alias(namespace, interface, owned_inode)):
                raise TopologyError(f"{namespace}/{interface}: foreign link alias")
    for left_ns, left_if, right_ns, right_if in (
        (ATTACKER_NAMESPACE, "lab0", SWITCH_NAMESPACE, "sw-a"),
        (VICTIM_NAMESPACE, "lab0", SWITCH_NAMESPACE, "sw-v"),
        (MONITOR_NAMESPACE, MONITOR_INTERFACE, SWITCH_NAMESPACE, MIRROR_OUT),
    ):
        left = next((link for link in observations.get(left_ns, {}).get("links", []) if link.get("ifname") == left_if), None)
        right = next((link for link in observations.get(right_ns, {}).get("links", []) if link.get("ifname") == right_if), None)
        if left is None or right is None:
            remaining = left or right
            if remaining is not None and remaining.get("link_index") is not None:
                raise TopologyError(f"foreign veth peer for {left_ns}/{left_if}")
        elif (
            left.get("link_index") != right.get("ifindex")
            or right.get("link_index") != left.get("ifindex")
            or left.get("link_index") is None
        ):
            raise TopologyError(f"foreign veth peer for {left_ns}/{left_if}")
    return names, probes, observations


def _ensure_owned_links(observations: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Repair only absent/down pieces of an owned demo topology."""

    changed: list[str] = []
    if ACTIVE_PROFILE_NAME == "demo":
        host_check = _host_management_check()
        if host_check.get("ok") is not True:
            host_link = _run(["ip", "-j", "-d", "link", "show", "dev", HOST_MANAGEMENT_INTERFACE])
            if _command_succeeded(host_link):
                raise TopologyError("host-only sensor management interface exists but is foreign or unsafe")
            if MONITOR_MANAGEMENT_INTERFACE in {
                _link_name(item)
                for item in observations.get(MONITOR_NAMESPACE, {}).get("links", [])
                if isinstance(item, Mapping)
            }:
                raise TopologyError("sensor management peer exists without its owned host peer")
            _create_host_management_link()
            changed.append("recreated-host-management-link")
    links = {
        namespace: {
            _link_name(item): item
            for item in data.get("links", [])
            if isinstance(item, Mapping) and _link_name(item) is not None
        }
        for namespace, data in observations.items()
    }

    def replace_pair(endpoint: str, switch_port: str, peer_name: str) -> None:
        endpoint_links = links.get(endpoint, {})
        switch_links = links.get(SWITCH_NAMESPACE, {})
        if "lab0" in endpoint_links:
            _must_ip(endpoint, ["link", "del", "dev", "lab0"], f"remove incomplete {endpoint}/lab0")
        if switch_port in switch_links:
            _must_ip(SWITCH_NAMESPACE, ["link", "del", "dev", switch_port], f"remove incomplete {switch_port}")
        _create_pair(endpoint, "lab0", SWITCH_NAMESPACE, peer_name)
        _must_ip(SWITCH_NAMESPACE, ["link", "set", "dev", peer_name, "name", switch_port], f"rename {switch_port}")
        _must_ip(endpoint, ["link", "set", "dev", "lab0", "address", ENDPOINTS[endpoint]["mac"]], "restore endpoint MAC")
        _tag_demo_link(endpoint, "lab0")
        _tag_demo_link(SWITCH_NAMESPACE, switch_port)
        changed.append(f"recreated-{endpoint}-link")

    endpoint_pairs = (
        (ATTACKER_NAMESPACE, "sw-a", "a-peer"),
        (VICTIM_NAMESPACE, "sw-v", "v-peer"),
    )
    for endpoint, switch_port, peer_name in endpoint_pairs:
        if "lab0" not in links.get(endpoint, {}) or switch_port not in links.get(SWITCH_NAMESPACE, {}):
            replace_pair(endpoint, switch_port, peer_name)

    monitor_links = links.get(MONITOR_NAMESPACE, {})
    switch_links = links.get(SWITCH_NAMESPACE, {})
    if MONITOR_INTERFACE not in monitor_links or MIRROR_OUT not in switch_links:
        if MONITOR_INTERFACE in monitor_links:
            _must_ip(MONITOR_NAMESPACE, ["link", "del", "dev", MONITOR_INTERFACE], "remove incomplete monitor link")
        if MIRROR_OUT in switch_links:
            _must_ip(SWITCH_NAMESPACE, ["link", "del", "dev", MIRROR_OUT], "remove incomplete mirror link")
        _create_pair(SWITCH_NAMESPACE, MIRROR_OUT, MONITOR_NAMESPACE, "m-peer")
        _must_ip(MONITOR_NAMESPACE, ["link", "set", "dev", "m-peer", "name", MONITOR_INTERFACE], "rename monitor link")
        _tag_demo_link(SWITCH_NAMESPACE, MIRROR_OUT)
        _tag_demo_link(MONITOR_NAMESPACE, MONITOR_INTERFACE)
        changed.append("recreated-monitor-link")

    switch_links = links.get(SWITCH_NAMESPACE, {})
    if BRIDGE_NAME not in switch_links:
        _must_ip(SWITCH_NAMESPACE, ["link", "add", "name", BRIDGE_NAME, "type", "bridge"], "recreate bridge")
        _tag_demo_link(SWITCH_NAMESPACE, BRIDGE_NAME)
        changed.append("recreated-bridge")

    for namespace in NAMESPACE_NAMES:
        _configure_sysctls(namespace)

    for namespace in NAMESPACE_NAMES:
        if "lo" in links.get(namespace, {}):
            _must_ip(namespace, ["link", "set", "dev", "lo", "up"], f"bring up {namespace}/lo")
            if not _link_is_up(links[namespace]["lo"]):
                changed.append(f"brought-up-{namespace}-lo")
    for namespace, interface in (
        (SWITCH_NAMESPACE, BRIDGE_NAME),
        (SWITCH_NAMESPACE, "sw-a"),
        (SWITCH_NAMESPACE, "sw-v"),
        (SWITCH_NAMESPACE, MIRROR_OUT),
        (MONITOR_NAMESPACE, MONITOR_INTERFACE),
        (ATTACKER_NAMESPACE, "lab0"),
        (VICTIM_NAMESPACE, "lab0"),
    ):
        current = links.get(namespace, {}).get(interface)
        if current is None or not _link_is_up(current):
            _must_ip(namespace, ["link", "set", "dev", interface, "up"], f"bring up {namespace}/{interface}")
            changed.append(f"brought-up-{namespace}-{interface}")

    # Bridge membership is repaired only when a port is currently unattached;
    # a foreign master was rejected by _partial_safety_problems first.
    for port in ("sw-a", "sw-v"):
        current = links.get(SWITCH_NAMESPACE, {}).get(port, {})
        if current.get("master") is None:
            _must_ip(SWITCH_NAMESPACE, ["link", "set", "dev", port, "master", BRIDGE_NAME], f"attach {port}")
            changed.append(f"attached-{port}")
    return changed


def _ensure_owned_addresses_and_mirror(
    observations: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    changed: list[str] = []
    for namespace, endpoint in ENDPOINTS.items():
        data = observations[namespace]
        addresses = {
            (str(item.get("dev")), str(item.get("family")), str(item.get("local")), int(item.get("prefixlen", -1)))
            for item in _addr_entries(data.get("addresses"))
            if item.get("local") is not None
        }
        expected = ("lab0", "inet", endpoint["address"], 24)
        if expected not in addresses:
            _must_ip(namespace, ["address", "add", f"{endpoint['address']}/24", "dev", "lab0"], f"restore {namespace} address")
            changed.append(f"restored-{namespace}-address")
        neighbors = data.get("neighbors", [])
        expected_neighbor = (endpoint["peer_address"], endpoint["peer_mac"], ("PERMANENT",))
        observed_neighbors = []
        if isinstance(neighbors, list):
            for item in neighbors:
                if isinstance(item, Mapping):
                    state = item.get("state", [])
                    values = (state.upper(),) if isinstance(state, str) else tuple(str(value).upper() for value in state) if isinstance(state, list) else ()
                    observed_neighbors.append((str(item.get("dst")), _normalise_mac(item.get("lladdr")), values))
        if not observed_neighbors:
            _must_ip(
                namespace,
                ["neigh", "replace", endpoint["peer_address"], "lladdr", endpoint["peer_mac"], "nud", "permanent", "dev", "lab0"],
                f"restore {namespace} neighbor",
            )
            changed.append(f"restored-{namespace}-neighbor")
        elif observed_neighbors != [expected_neighbor]:
            raise TopologyError(f"{namespace}: foreign neighbor state")
        _configure_sysctls(namespace)

    _configure_sysctls(SWITCH_NAMESPACE)
    _configure_sysctls(MONITOR_NAMESPACE)
    tc_data = observations.get(SWITCH_NAMESPACE, {}).get("tc", {})
    for port, preference in (("sw-a", "100"), ("sw-v", "101")):
        port_data = tc_data.get(port, {}) if isinstance(tc_data, Mapping) else {}
        state = _tc_port_state(port_data)
        if state == "foreign":
            raise TopologyError(f"{SWITCH_NAMESPACE}: {port} has a foreign qdisc/filter configuration")
        if state in {"missing", "qdisc_missing"}:
            _must_tc(SWITCH_NAMESPACE, ["qdisc", "add", "dev", port, "clsact"], f"restore clsact on {port}")
            changed.append(f"restored-{port}-qdisc")
        if state in {"missing", "filter_missing", "qdisc_missing"}:
            _must_tc(
                SWITCH_NAMESPACE,
                ["filter", "add", "dev", port, "ingress", "pref", preference, "matchall", "action", "mirred", "egress", "mirror", "dev", MIRROR_OUT],
                f"restore ingress mirror on {port}",
            )
            changed.append(f"restored-{port}-mirror")
    return changed


def ensure(profile: str | None = None) -> dict[str, Any]:
    """Idempotently ensure an owned demo topology without recreating healthy state."""

    if profile is not None:
        _select_profile(profile)
    if ACTIVE_PROFILE_NAME != "demo":
        return {"operation": "ensure", "topology": ACTIVE_PROFILE_NAME, "status": "BLOCKED", "errors": ["ensure is demo-only"]}
    result: dict[str, Any] = {"operation": "ensure", "topology": "demo", "status": "BLOCKED", "changed": [], "errors": []}
    try:
        _require_root()
        _require_commands(("ip", "tc"))
        state = _load_state()
        if state is None:
            created = _setup_create("demo")
            created["operation"] = "ensure"
            return created
        recorded = _validate_owned_marker(state)
        _names, _probes, observations = _observe_owned_namespaces(recorded, allow_missing=False)
        for namespace, data in observations.items():
            problems = _partial_safety_problems(namespace, data)
            if problems:
                raise TopologyError("; ".join(problems))
        # A fully healthy owned topology returns without touching links.
        if _collect_evidence(require_ownership=True).get("status") == "PASS":
            result["status"] = "PASS"
            result["ownership"] = {"marker": _state_file(), "owned": True, "namespace_inodes": dict(recorded)}
            return result
        result["changed"].extend(_ensure_owned_links(observations))
        # Re-observe after link repair so address/mirror decisions use current kernel state.
        _names, _probes, observations = _observe_owned_namespaces(recorded, allow_missing=False)
        for namespace, data in observations.items():
            problems = _partial_safety_problems(namespace, data)
            if problems:
                raise TopologyError("; ".join(problems))
        result["changed"].extend(_ensure_owned_addresses_and_mirror(observations))
        verification = _collect_evidence(require_ownership=True)
        result["verification"] = verification
        if verification.get("status") != "PASS":
            raise TopologyError("repaired topology did not pass verification")
        result["status"] = "PASS"
        result["ownership"] = {"marker": _state_file(), "owned": True, "namespace_inodes": dict(recorded)}
        return result
    except (TopologyError, OSError, ValueError, KeyError) as exc:
        result["errors"].append(str(exc))
        return result


up = ensure


def _cleanup_demo() -> dict[str, Any]:
    result: dict[str, Any] = {
        "operation": "cleanup",
        "topology": "demo",
        "status": "BLOCKED",
        "errors": [],
        "partial": False,
    }
    try:
        _require_root()
        _require_commands(("ip", "tc"))
        state = _load_state()
        if state is None:
            names = _namespace_names()
            foreign = sorted(set(NAMESPACE_NAMES).intersection(names))
            if foreign:
                raise TopologyError(
                    "refusing cleanup; demo namespace(s) exist without an ownership marker: "
                    + ", ".join(foreign)
                )
            if ACTIVE_PROFILE_NAME == "demo" and _command_succeeded(
                _run(["ip", "-j", "-d", "link", "show", "dev", HOST_MANAGEMENT_INTERFACE])
            ):
                raise TopologyError(
                    "refusing cleanup; host-only sensor management interface exists without an ownership marker"
                )
            result["status"] = "PASS"
            result["partial"] = True
            result["already_absent"] = True
            return result
        recorded = _validate_owned_marker(state)
        names, probes, observations = _observe_owned_namespaces(recorded, allow_missing=True)
        present = [namespace for namespace in NAMESPACE_NAMES if namespace in names]
        result["partial"] = len(present) != len(NAMESPACE_NAMES)
        host_check = _host_management_check()
        if host_check.get("enabled") and not host_check.get("ok"):
            host_link = _run(["ip", "-j", "-d", "link", "show", "dev", HOST_MANAGEMENT_INTERFACE])
            if _command_succeeded(host_link):
                raise TopologyError("refusing cleanup; host-only sensor management interface is foreign or unsafe")
        for namespace, data in observations.items():
            problems = _partial_safety_problems(namespace, data)
            if problems:
                raise TopologyError("; ".join(problems))
            named_pids = _namespace_pids(namespace)
            inode_pids = _processes_for_namespace_inode(recorded[namespace])
            if named_pids or inode_pids:
                all_pids = sorted(set(named_pids) | set(inode_pids))
                raise TopologyError(
                    f"refusing cleanup; nonowned process(es) retain {namespace}: {all_pids}"
                )
        for namespace in set(NAMESPACE_NAMES) - set(present):
            pids = _processes_for_namespace_inode(recorded[namespace])
            if pids:
                raise TopologyError(f"refusing cleanup; process(es) retain missing {namespace}: {pids}")

        deletion = _safe_delete_namespaces(present, recorded, refuse_processes=True)
        result["deletion"] = deletion
        if deletion["refused"] or deletion["errors"]:
            raise TopologyError("one or more owned namespaces could not be safely deleted")
        _delete_host_management_link()
        # A process may race with namespace deletion and retain the inode after
        # the named mount disappears.  Keep the ownership marker until it is
        # demonstrably gone; this prevents a later setup from adopting it.
        lingering = {
            namespace: _processes_for_namespace_inode(recorded[namespace])
            for namespace in NAMESPACE_NAMES
        }
        lingering = {namespace: pids for namespace, pids in lingering.items() if pids}
        if lingering:
            raise TopologyError(f"namespace process(es) remain after cleanup: {lingering}")
        remaining = _namespace_names()
        if any(name in remaining for name in NAMESPACE_NAMES):
            raise TopologyError("one or more owned namespaces remain after cleanup")
        _remove_state()
        result["status"] = "PASS"
        return result
    except (TopologyError, OSError, ValueError, KeyError) as exc:
        result["errors"].append(str(exc))
        return result


def _setup_create(profile: str | None = None) -> dict[str, Any]:
    """Create and verify the selected owned topology profile."""

    if profile is not None:
        _select_profile(profile)

    base: dict[str, Any] = {
        "operation": "setup",
        "topology": ACTIVE_PROFILE_NAME,
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
        if ACTIVE_PROFILE_NAME == "demo":
            try:
                _delete_host_management_link()
            except TopologyError:
                pass
        if created:
            base["rollback"] = _safe_delete_namespaces(created, created_inodes)
        return base


def setup(profile: str | None = None) -> dict[str, Any]:
    """Create controlled-v2, or idempotently ensure the explicit demo profile."""

    if profile is not None:
        _select_profile(profile)
    if ACTIVE_PROFILE_NAME == "demo":
        if os.path.exists(_state_file()):
            return ensure("demo")
        return _setup_create("demo")
    return _setup_create("controlled_v2")


def verify(profile: str | None = None) -> dict[str, Any]:
    """Return parsed isolation evidence, passing only for the owned topology."""

    if profile is not None:
        _select_profile(profile)
    return _collect_evidence(require_ownership=True)


def cleanup(profile: str | None = None) -> dict[str, Any]:
    """Remove only the exact topology recorded by the ownership marker."""

    if profile is not None:
        _select_profile(profile)

    if ACTIVE_PROFILE_NAME == "demo":
        return _cleanup_demo()

    result: dict[str, Any] = {
        "operation": "cleanup",
        "topology": ACTIVE_PROFILE_NAME,
        "status": "BLOCKED",
        "errors": [],
    }
    try:
        _require_root()
        _require_commands(("ip", "tc"))
        state = _load_state()
        if state is None:
            raise TopologyError("ownership marker is missing; refusing cleanup")
        if state.get("version") != TOPOLOGY_VERSION or state.get("topology") != ACTIVE_PROFILE_NAME:
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
    if "--help" in args or "-h" in args:
        print("usage: topology.py [--profile PROFILE] {setup|ensure|up|verify|validate|connectivity|cleanup}")
        print(f"profiles: {', '.join(sorted(PROFILES))}")
        return 0
    profile = "controlled_v2"
    filtered: list[str] = []
    index = 0
    while index < len(args):
        value = args[index]
        if value == "--profile":
            if index + 1 >= len(args):
                filtered.append(value)
                break
            profile = args[index + 1]
            index += 2
            continue
        if value.startswith("--profile="):
            profile = value.split("=", 1)[1]
            index += 1
            continue
        filtered.append(value)
        index += 1

    operations = {
        "setup": setup,
        "ensure": ensure,
        "up": ensure,
        "verify": verify,
        "validate": validate_connectivity,
        "connectivity": validate_connectivity,
        "cleanup": cleanup,
    }
    if len(filtered) != 1 or filtered[0] not in operations or profile not in PROFILES:
        _emit(
            {
                "operation": filtered[0] if filtered else None,
                "topology": profile,
                "status": "BLOCKED",
                "errors": [
                    "usage: topology.py [--profile PROFILE] "
                    "{setup|ensure|up|verify|validate|connectivity|cleanup}"
                ],
            }
        )
        return 2
    _select_profile(profile)
    value = operations[filtered[0]]()
    _emit(value)
    return 0 if value.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
