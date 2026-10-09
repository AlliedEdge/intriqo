"""Static and contract checks for the reproducible demo-lab entry points.

Privileged namespace creation is intentionally not performed by the ordinary
test suite.  ``scripts/lab/status.sh --verify`` is the live host check; these
tests protect its fail-closed command surface and the fixed traffic contract.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "scripts" / "lab"
TRAFFIC_PATH = ROOT / "security-lab" / "controlled_v2" / "traffic.py"
TOPOLOGY_PATH = ROOT / "security-lab" / "controlled_v2" / "topology.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "script_name",
    [
        "setup.sh",
        "up.sh",
        "down.sh",
        "status.sh",
        "port-scan.sh",
        "udp-port-scan.sh",
        "syn-flood.sh",
        "reset.sh",
        "intriqo-demo.sh",
        "generate-demo-traffic.sh",
    ],
)
def test_demo_scripts_are_executable_and_parse(script_name: str) -> None:
    path = LAB / script_name
    assert path.is_file()
    assert path.stat().st_mode & 0o111
    result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_demo_profile_keeps_fixed_private_topology() -> None:
    topology = _load_module(TOPOLOGY_PATH, "intriqo_demo_topology")
    profile = topology.PROFILES["demo"]
    assert profile["attacker"] == "intriqo-attacker"
    assert profile["victim"] == "intriqo-victim"
    assert profile["monitor_interface"] == "tap-intriqo"
    assert profile["endpoints"][profile["attacker"]]["address"] == "10.77.0.10"
    assert profile["endpoints"][profile["victim"]]["address"] == "10.77.0.20"
    assert profile["state_file"] == "/run/intriqo-demo-topology.json"


def test_traffic_helpers_reject_non_lab_targets() -> None:
    traffic = _load_module(TRAFFIC_PATH, "intriqo_demo_traffic")
    with pytest.raises(traffic.TrafficError, match="fixed to 10.77.0.20"):
        traffic.send_port_scan("10080-10089", target="192.0.2.20")
    with pytest.raises(traffic.TrafficError, match="fixed to 10.77.0.20"):
        traffic.send_syn_flood(target="198.51.100.20")
    with pytest.raises(traffic.TrafficError, match="fixed to 10.77.0.20"):
        traffic.send_udp_port_scan("10080-10089", target="192.0.2.20")


def test_traffic_cli_does_not_expose_target_argument() -> None:
    result = subprocess.run(
        ["python3", str(TRAFFIC_PATH), "port-scan", "--ports", "10080-10089", "--target", "192.0.2.20"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_udp_scan_cli_does_not_expose_target_argument() -> None:
    result = subprocess.run(
        ["python3", str(TRAFFIC_PATH), "udp-port-scan", "--ports", "10080-10089", "--target", "192.0.2.20"],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr


def test_privileged_engine_launch_authenticates_before_detaching(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    trace = tmp_path / "trace.log"
    fake_sudo = fake_bin / "sudo"
    fake_sudo.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'sudo' >> \"$TRACE\"; printf ' %q' \"$@\" >> \"$TRACE\"; printf '\\n' >> \"$TRACE\"\n"
        "while [[ \"${1:-}\" == -n || \"${1:-}\" == -- ]]; do shift; done\n"
        "exec env -i \"PATH=$PATH\" \"TRACE=$TRACE\" \"$@\"\n",
        encoding="utf-8",
    )
    fake_setsid = fake_bin / "setsid"
    fake_setsid.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'setsid' >> \"$TRACE\"; printf ' %q' \"$@\" >> \"$TRACE\"; printf '\\n' >> \"$TRACE\"\n"
        "while [[ \"${1:-}\" == --wait || \"${1:-}\" == -- ]]; do shift; done\n"
        "exec \"$@\"\n",
        encoding="utf-8",
    )
    fake_engine = fake_bin / "fake-engine"
    fake_engine.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'engine' >> \"$TRACE\"; printf ' %q' \"$@\" >> \"$TRACE\"; printf '\\n' >> \"$TRACE\"\n"
        "printf 'engine_token=%s\\n' \"${INTRIQO_CONTROL_PLANE_TOKEN:-MISSING}\" >> \"$TRACE\"\n",
        encoding="utf-8",
    )
    fake_ip = fake_bin / "ip"
    fake_ip.write_text(
        "#!/usr/bin/env bash\n"
        "printf 'ip' >> \"$TRACE\"; printf ' %q' \"$@\" >> \"$TRACE\"; printf '\\n' >> \"$TRACE\"\n"
        "shift 3\n"
        "exec \"$@\"\n",
        encoding="utf-8",
    )
    for executable in (fake_sudo, fake_setsid, fake_ip, fake_engine):
        executable.chmod(0o755)

    pid_dir = tmp_path / "pids"
    pid_dir.mkdir()
    log_file = tmp_path / "engine.log"
    command = ["ip", "netns", "exec", "intriqo-monitor", str(fake_engine), "--interface", "tap-intriqo"]
    result = subprocess.run(
        [
            "bash", "-c",
            "source scripts/intriqo-runtime.sh; "
            "INTRIQO_PID_DIR=\"$1\"; export INTRIQO_PID_DIR; "
            "intriqo_start_privileged_process engine \"$2\" \"${@:3}\"; "
            "pid=$(cat \"$1/engine.pid\"); wait \"$pid\"",
            "bash", str(pid_dir), str(log_file), *command,
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "TRACE": str(trace),
            "INTRIQO_CONTROL_PLANE_TOKEN": "test-engine-bearer-token",
            "INTRIQO_ENGINE_SINK": "http",
        },
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    lines = trace.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("sudo -n -- setsid --wait -- bash -c ")
    assert "test-engine-bearer-token" not in lines[0]
    assert lines[1].startswith("setsid --wait -- bash -c ")
    assert lines[2].startswith("ip netns exec intriqo-monitor")
    assert lines[3].startswith("engine --interface tap-intriqo")
    assert lines[4] == "engine_token=test-engine-bearer-token"


def test_status_health_url_uses_live_control_plane_bind_address(tmp_path: Path) -> None:
    pid_dir = tmp_path / "pids"
    proc_root = tmp_path / "proc"
    pid_dir.mkdir()
    script = r'''source scripts/intriqo-runtime.sh
INTRIQO_PID_DIR=$1
INTRIQO_PROC_ROOT=$2
mkdir -p "$INTRIQO_PROC_ROOT/$BASHPID"
printf '%s\n' "$BASHPID" > "$INTRIQO_PID_DIR/control-plane.pid"
printf '%s\0' python -m uvicorn --host 169.254.77.1 --port 8000 > "$INTRIQO_PROC_ROOT/$BASHPID/cmdline"
intriqo_control_plane_health_url'''
    result = subprocess.run(
        ["bash", "-c", script, "bash", str(pid_dir), str(proc_root)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "http://169.254.77.1:8000/ready"
