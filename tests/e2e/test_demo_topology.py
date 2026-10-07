"""Focused fail-closed tests for the isolated demo topology and traffic plan."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
TOPOLOGY_PATH = ROOT / "security-lab" / "controlled_v2" / "topology.py"
TRAFFIC_PATH = ROOT / "security-lab" / "controlled_v2" / "traffic.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _owned_state(topology):
    return {
        "version": topology.TOPOLOGY_VERSION,
        "topology": "demo",
        "namespaces": list(topology.DEMO_PROFILE["namespaces"]),
        "namespace_inodes": {
            name: index + 100 for index, name in enumerate(topology.DEMO_PROFILE["namespaces"])
        },
    }


def test_import_ignores_ambient_demo_profile_and_preserves_default(monkeypatch) -> None:
    monkeypatch.setenv("INTRIQO_LAB_PROFILE", "demo")
    topology = _load(TOPOLOGY_PATH, "demo_topology_default_profile")

    assert topology.ACTIVE_PROFILE_NAME == "controlled_v2"
    assert topology.NAMESPACE_NAMES == topology.CONTROLLED_V2_PROFILE["namespaces"]
    assert topology.MONITOR_INTERFACE == "tap-intriqo-v2"

    topology._select_profile("demo")
    assert topology.NAMESPACE_NAMES == (
        "intriqo-attacker",
        "intriqo-victim",
        "intriqo-switch",
        "intriqo-monitor",
    )
    assert topology.NAMESPACE_NAMES == topology.DEMO_PROFILE["namespaces"]
    assert topology.MONITOR_INTERFACE == "tap-intriqo"


def test_route_policy_fails_closed_for_default_gateway_and_foreign_device() -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_routes")
    assert topology._route_unsafe({"dst": "default", "dev": "lab0"}, {"lab0"})
    assert topology._route_unsafe({"dst": "10.77.0.0/24", "dev": "eth9"}, {"lab0"})
    assert topology._route_unsafe({"dst": "10.77.0.0/24", "dev": "lab0", "via": "10.77.0.1"}, {"lab0"})


def test_mocked_demo_route_observation_rejects_default_and_foreign_routes(monkeypatch) -> None:
    traffic = _load(TRAFFIC_PATH, "demo_traffic_routes")

    def default_routes(*args):
        if "-6" in args:
            return "[]"
        if "route" in args:
            return '[{"dst":"default","dev":"lab0"}]'
        return "[]"

    monkeypatch.setattr(traffic, "_run_ip", default_routes)
    monkeypatch.setattr(traffic, "_demo_rotation_enabled", lambda: True)
    with pytest.raises(traffic.TrafficError, match="unexpected destination"):
        traffic._verify_demo_routes()

    def foreign_routes(*args):
        if "-6" in args:
            return "[]"
        if "route" in args:
            return '[{"dst":"10.77.0.0/24","dev":"eth9"}]'
        return "[]"

    monkeypatch.setattr(traffic, "_run_ip", foreign_routes)
    with pytest.raises(traffic.TrafficError, match="unexpected interface"):
        traffic._verify_demo_routes()


def test_missing_owned_interface_is_repairable_but_extra_interface_is_not() -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_partial_safety")
    topology._select_profile("demo")
    base = {
        "links": [
            {"ifname": "lo", "link_type": "loopback", "flags": ["UP"]},
        ],
        "addresses": [
            {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
        ],
        "ipv4": [],
        "ipv6": [],
        "rules": [],
        "neighbors": [],
    }
    assert topology._partial_safety_problems("intriqo-attacker", base) == []
    extra = dict(base)
    extra["links"] = base["links"] + [{"ifname": "eth9", "linkinfo": {"info_kind": "dummy"}}]
    assert any("unexpected interface" in item for item in topology._partial_safety_problems("intriqo-attacker", extra))


def _demo_monitor_observation(topology, management_address: str | None = None, *, extra_link: str | None = None):
    management_address = management_address or topology.MONITOR_MANAGEMENT_ADDRESS
    links = [
        {"ifname": "lo", "link_type": "loopback", "flags": ["UP"]},
        {"ifname": topology.MONITOR_INTERFACE, "linkinfo": {"info_kind": "veth"}, "flags": ["UP"]},
        {"ifname": topology.MONITOR_MANAGEMENT_INTERFACE, "linkinfo": {"info_kind": "veth"}, "flags": ["UP"]},
    ]
    if extra_link:
        links.append({"ifname": extra_link, "linkinfo": {"info_kind": "dummy"}, "flags": ["UP"]})
    return {
        "links": links,
        "addresses": [
            {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
            {"ifname": topology.MONITOR_MANAGEMENT_INTERFACE, "addr_info": [{
                "family": "inet", "local": management_address, "prefixlen": 30,
            }]},
        ],
        "ipv4": [{"dst": str(topology.MANAGEMENT_NETWORK), "dev": topology.MONITOR_MANAGEMENT_INTERFACE}],
        "ipv6": [],
        "rules": [],
        "neighbors": [],
    }


def test_demo_management_address_is_normalized_and_fail_closed() -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_management_address")
    topology._select_profile("demo")

    correct = _demo_monitor_observation(topology)
    assert topology._partial_safety_problems("intriqo-monitor", correct) == []
    assert topology._check_namespace_data("intriqo-monitor", correct)["exact_addresses"] is True

    wrong = _demo_monitor_observation(topology, "169.254.77.99")
    assert any("unexpected address" in item for item in topology._partial_safety_problems("intriqo-monitor", wrong))

    foreign = _demo_monitor_observation(topology, extra_link="sensor-foreign")
    assert any("unexpected interface" in item for item in topology._partial_safety_problems("intriqo-monitor", foreign))


def test_demo_ensure_repairs_missing_management_link_and_is_idempotent(monkeypatch) -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_management_ensure")
    topology._select_profile("demo")
    state = _owned_state(topology)
    names = set(topology.DEMO_PROFILE["namespaces"])
    observations = {
        "intriqo-attacker": {"links": [{"ifname": "lo", "link_type": "loopback", "flags": ["UP"]}, {"ifname": "lab0", "linkinfo": {"info_kind": "veth"}, "flags": ["UP"]}], "addresses": [], "ipv4": [], "ipv6": [], "rules": [], "neighbors": []},
        "intriqo-victim": {"links": [{"ifname": "lo", "link_type": "loopback", "flags": ["UP"]}, {"ifname": "lab0", "linkinfo": {"info_kind": "veth"}, "flags": ["UP"]}], "addresses": [], "ipv4": [], "ipv6": [], "rules": [], "neighbors": []},
        "intriqo-switch": {"links": [{"ifname": "lo", "link_type": "loopback", "flags": ["UP"]}, {"ifname": "sw-a", "linkinfo": {"info_kind": "veth"}, "flags": ["UP"], "master": "br-intriqo"}, {"ifname": "sw-v", "linkinfo": {"info_kind": "veth"}, "flags": ["UP"], "master": "br-intriqo"}, {"ifname": "br-intriqo", "linkinfo": {"info_kind": "bridge"}, "flags": ["UP"]}, {"ifname": "mirror-out", "linkinfo": {"info_kind": "veth"}, "flags": ["UP"]}], "addresses": [], "ipv4": [], "ipv6": [], "rules": [], "neighbors": [], "tc": {}},
        "intriqo-monitor": {"links": [{"ifname": "lo", "link_type": "loopback", "flags": ["UP"]}, {"ifname": "tap-intriqo", "linkinfo": {"info_kind": "veth"}, "flags": ["UP"]}], "addresses": [], "ipv4": [], "ipv6": [], "rules": [], "neighbors": []},
    }
    monkeypatch.setattr(topology, "_require_root", lambda: None)
    monkeypatch.setattr(topology, "_require_commands", lambda commands: None)
    monkeypatch.setattr(topology, "_load_state", lambda: state)
    monkeypatch.setattr(topology, "_namespace_names", lambda: names)
    monkeypatch.setattr(topology, "_namespace_probe", lambda namespace: {"net_namespace_inode": state["namespace_inodes"][namespace]})
    probes = {namespace: {"net_namespace_inode": state["namespace_inodes"][namespace]} for namespace in names}
    monkeypatch.setattr(topology, "_observe_owned_namespaces", lambda recorded, allow_missing: (names, probes, observations))
    monkeypatch.setattr(topology, "_partial_safety_problems", lambda namespace, data: [])
    evidence_statuses = iter(("BLOCKED", "PASS", "PASS"))
    monkeypatch.setattr(topology, "_collect_evidence", lambda require_ownership: {"status": next(evidence_statuses)})
    monkeypatch.setattr(topology, "_host_management_check", lambda: {"enabled": True, "ok": False})
    monkeypatch.setattr(topology, "_run", lambda *args, **kwargs: {"returncode": 1, "stdout": "", "stderr": "not found"})
    monkeypatch.setattr(topology, "_must_ip", lambda *args, **kwargs: {})
    recreated = []
    monkeypatch.setattr(topology, "_create_host_management_link", lambda: recreated.append(True))
    monkeypatch.setattr(topology, "_configure_sysctls", lambda namespace: None)
    monkeypatch.setattr(topology, "_ensure_owned_addresses_and_mirror", lambda observations: [])

    first = topology.ensure("demo")
    second = topology.ensure("demo")
    assert first["status"] == "PASS"
    assert second["status"] == "PASS"
    assert recreated == [True]


def test_demo_ensure_reuses_healthy_owned_inodes_without_repair(monkeypatch) -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_ensure_healthy")
    topology._select_profile("demo")
    state = _owned_state(topology)
    names = set(topology.DEMO_PROFILE["namespaces"])
    monkeypatch.setattr(topology, "_require_root", lambda: None)
    monkeypatch.setattr(topology, "_require_commands", lambda commands: None)
    monkeypatch.setattr(topology, "_load_state", lambda: state)
    monkeypatch.setattr(topology, "_namespace_names", lambda: names)
    monkeypatch.setattr(
        topology,
        "_namespace_probe",
        lambda namespace: {"net_namespace_inode": state["namespace_inodes"][namespace]},
    )
    monkeypatch.setattr(topology, "_parse_namespace_data", lambda namespace: ({}, []))
    monkeypatch.setattr(topology, "_partial_safety_problems", lambda namespace, data: [])
    monkeypatch.setattr(topology, "_collect_evidence", lambda require_ownership: {"status": "PASS"})
    repair_called = []
    monkeypatch.setattr(topology, "_ensure_owned_links", lambda observations: repair_called.append("links") or [])
    result = topology.ensure("demo")
    assert result["status"] == "PASS", result
    assert result["changed"] == []
    assert repair_called == []


def test_demo_ensure_repairs_owned_partial_state(monkeypatch) -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_ensure_partial")
    topology._select_profile("demo")
    state = _owned_state(topology)
    names = set(topology.DEMO_PROFILE["namespaces"])
    monkeypatch.setattr(topology, "_require_root", lambda: None)
    monkeypatch.setattr(topology, "_require_commands", lambda commands: None)
    monkeypatch.setattr(topology, "_load_state", lambda: state)
    monkeypatch.setattr(topology, "_namespace_names", lambda: names)
    monkeypatch.setattr(
        topology,
        "_namespace_probe",
        lambda namespace: {"net_namespace_inode": state["namespace_inodes"][namespace]},
    )
    monkeypatch.setattr(topology, "_parse_namespace_data", lambda namespace: ({}, []))
    monkeypatch.setattr(topology, "_partial_safety_problems", lambda namespace, data: [])
    statuses = iter(("BLOCKED", "PASS"))
    monkeypatch.setattr(topology, "_collect_evidence", lambda require_ownership: {"status": next(statuses)})
    monkeypatch.setattr(topology, "_ensure_owned_links", lambda observations: ["restored-link"])
    monkeypatch.setattr(topology, "_ensure_owned_addresses_and_mirror", lambda observations: ["restored-mirror"])
    result = topology.ensure("demo")
    assert result["status"] == "PASS"
    assert result["changed"] == ["restored-link", "restored-mirror"]


def test_demo_cleanup_allows_missing_namespace_but_checks_owned_identity(monkeypatch) -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_cleanup_partial")
    topology._select_profile("demo")
    state = _owned_state(topology)
    all_names = list(topology.DEMO_PROFILE["namespaces"])
    present = set(all_names[:-1])
    namespace_calls = iter((present, set()))
    monkeypatch.setattr(topology, "_require_root", lambda: None)
    monkeypatch.setattr(topology, "_require_commands", lambda commands: None)
    monkeypatch.setattr(topology, "_load_state", lambda: state)
    monkeypatch.setattr(topology, "_namespace_names", lambda: next(namespace_calls))
    monkeypatch.setattr(
        topology,
        "_namespace_probe",
        lambda namespace: {"net_namespace_inode": state["namespace_inodes"][namespace]},
    )
    monkeypatch.setattr(topology, "_parse_namespace_data", lambda namespace: ({}, []))
    monkeypatch.setattr(topology, "_partial_safety_problems", lambda namespace, data: [])
    monkeypatch.setattr(topology, "_host_management_check", lambda: {"enabled": True, "ok": True})
    monkeypatch.setattr(topology, "_delete_host_management_link", lambda: None)
    monkeypatch.setattr(topology, "_namespace_pids", lambda namespace: [])
    monkeypatch.setattr(topology, "_processes_for_namespace_inode", lambda inode: [])
    monkeypatch.setattr(topology, "_safe_delete_namespaces", lambda names, recorded, **kwargs: {"deleted": list(names), "refused": [], "errors": []})
    removed = []
    monkeypatch.setattr(topology, "_remove_state", lambda: removed.append(True))
    result = topology.cleanup("demo")
    assert result["status"] == "PASS"
    assert result["partial"] is True
    assert removed == [True]


def test_demo_cleanup_refuses_replaced_namespace_inode(monkeypatch) -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_cleanup_replaced")
    topology._select_profile("demo")
    state = _owned_state(topology)
    names = set(topology.DEMO_PROFILE["namespaces"])
    monkeypatch.setattr(topology, "_require_root", lambda: None)
    monkeypatch.setattr(topology, "_require_commands", lambda commands: None)
    monkeypatch.setattr(topology, "_load_state", lambda: state)
    monkeypatch.setattr(topology, "_namespace_names", lambda: names)
    monkeypatch.setattr(topology, "_namespace_probe", lambda namespace: {"net_namespace_inode": 999999})
    result = topology.cleanup("demo")
    assert result["status"] == "BLOCKED"
    assert any("replaced" in item or "ownership" in item for item in result["errors"])


def test_connectivity_requires_both_fixed_tap_directions(monkeypatch) -> None:
    topology = _load(TOPOLOGY_PATH, "demo_topology_connectivity")
    topology._select_profile("demo")
    checks = {
        namespace: {"tc_ingress_mirror_exactly_once": True}
        for namespace in topology.NAMESPACE_NAMES
    }
    monkeypatch.setattr(topology, "_collect_evidence", lambda require_ownership: {"status": "PASS", "errors": [], "checks": checks})
    monkeypatch.setattr(topology, "_require_commands", lambda commands: None)
    monkeypatch.setattr(topology, "_link_packet_stats", lambda namespace, interface: {"packets": {"rx": 10, "tx": 0}})
    monkeypatch.setattr(topology, "_capture_fixed_ping", lambda: {"request": 1, "reply": 0, "capture_returncode": 0, "probe": {"returncode": 0}})
    blocked = topology.validate_connectivity("demo")
    assert blocked["status"] == "BLOCKED"
    assert blocked["connectivity"]["checks"]["tap_saw_request"] is True
    assert blocked["connectivity"]["checks"]["tap_saw_reply"] is False

    monkeypatch.setattr(topology, "_capture_fixed_ping", lambda: {"request": 1, "reply": 1, "capture_returncode": 0, "probe": {"returncode": 0}})
    passed = topology.validate_connectivity("demo")
    assert passed["status"] == "PASS"
    assert passed["connectivity"]["checks"]["monitor_received_probe"] is True


def test_unique_syn_plan_is_bounded_and_preserves_default(monkeypatch) -> None:
    traffic = _load(TRAFFIC_PATH, "demo_traffic_plan")
    monkeypatch.setattr(traffic, "_demo_rotation_enabled", lambda: False)
    assert traffic.send_syn_flood.__defaults__ == (traffic.DEFAULT_FLOOD_DESTINATION_PORT,)
    assert traffic.send_syn_flood.__kwdefaults__["source_port"] == 43000
    assert traffic.send_syn_flood.__kwdefaults__["count"] == 120
    assert traffic.send_syn_flood.__kwdefaults__["rate"] == traffic.DEFAULT_RATE
    assert traffic.send_syn_flood.__kwdefaults__["unique_source_ports"] is False
    assert traffic.plan_syn_flood_source_ports(43000, 4, unique_source_ports=True) == [43000, 43001, 43002, 43003]
    assert traffic.plan_syn_flood_source_ports(43000, 4) == [43000, 43000, 43000, 43000]
    with pytest.raises(traffic.TrafficError, match="exhausted|exceeds"):
        traffic.plan_syn_flood_source_ports(65535, 2, unique_source_ports=True)
