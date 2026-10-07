#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
# shellcheck source=scripts/lab/demo-profile.sh
source "$SCRIPT_DIR/demo-profile.sh"

TOPOLOGY_PY="$REPO_ROOT/security-lab/controlled_v2/topology.py"
PYTHON=${INTRIQO_PYTHON:-python3}

usage() {
    cat <<'EOF'
Usage: scripts/lab/intriqo-demo.sh {setup|up|down|status|validate|reset}

The demo owns four Linux namespaces and never accepts a target address.  It
uses the fixed 10.77.0.10 -> 10.77.0.20 lab pair and tap-intriqo mirror.
INTRIQO_DEMO_STATE_FILE may point at a writable ownership marker location.
EOF
}

run_topology() {
    local operation=$1
    if (( EUID == 0 )); then
        INTRIQO_LAB_PROFILE=demo \
        INTRIQO_LAB_STATE_FILE="$INTRIQO_DEMO_STATE_FILE" \
            "$PYTHON" "$TOPOLOGY_PY" --profile demo "$operation"
        return
    fi
    command -v sudo >/dev/null 2>&1 || {
        echo "intriqo-demo: root or sudo is required for Linux namespaces, bridges, tc, and TAP validation" >&2
        return 1
    }
    if ! sudo -n true >/dev/null 2>&1; then
        if [[ -t 0 && -t 1 ]]; then
            sudo -v || {
                echo "intriqo-demo: sudo authorization failed; rerun as root or authorize sudo" >&2
                return 1
            }
        else
            echo "intriqo-demo: root or non-interactive sudo authorization is required; rerun from a terminal with sudo access" >&2
            return 1
        fi
    fi
    sudo env INTRIQO_LAB_PROFILE=demo \
            INTRIQO_LAB_STATE_FILE="$INTRIQO_DEMO_STATE_FILE" \
            "$PYTHON" "$TOPOLOGY_PY" --profile demo "$operation"
}

namespace_exists() {
    local wanted=$1 name
    local -a ip_cmd=(ip)
    if (( EUID != 0 )); then
        command -v sudo >/dev/null 2>&1 || return 1
        ip_cmd=(sudo ip)
    fi
    while read -r name _; do
        [[ "$name" == "$wanted" ]] && return 0
    done < <("${ip_cmd[@]}" netns list)
    return 1
}

print_status() {
    local evidence_file=$1
    "$PYTHON" - "$evidence_file" <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as stream:
        evidence = json.load(stream)
except (OSError, json.JSONDecodeError) as exc:
    print("INTRIQO LAB\nStatus        BLOCKED\nReason        topology command did not return verification JSON (root/sudo or ip/tc may be unavailable)")
    raise SystemExit(1)

checks = evidence.get("checks", {})
namespaces = evidence.get("namespaces", {})
connectivity = evidence.get("connectivity", {})
connectivity_checks = connectivity.get("checks", {})
switch = checks.get("intriqo-switch", {})
attacker = checks.get("intriqo-attacker", {})
victim = checks.get("intriqo-victim", {})
monitor = checks.get("intriqo-monitor", {})

def state(value):
    return "READY" if value else "BLOCKED"

topology_ok = evidence.get("status") == "PASS"
attacker_ok = topology_ok and attacker.get("all_local_checks", False)
victim_ok = topology_ok and victim.get("all_local_checks", False)
bridge_ok = topology_ok and switch.get("all_local_checks", False) and switch.get("bridge_membership", False)
tap_ok = topology_ok and monitor.get("all_local_checks", False)
mirror_ok = topology_ok and switch.get("tc_ingress_mirror_exactly_once", False)
connectivity_ok = connectivity_checks.get("attacker_to_victim", False)
probe_ok = connectivity_checks.get("monitor_received_probe", False)

print("INTRIQO LAB")
print("────────────────────────────────────────")
print(f"Attacker       10.77.0.10   {state(attacker_ok)}")
print(f"Victim         10.77.0.20   {state(victim_ok)}")
print(f"Bridge         br-intriqo  {state(bridge_ok)}")
print(f"tap-intriqo                 {state(tap_ok)}")
print(f"Traffic Mirror              {'ACTIVE' if mirror_ok else 'BLOCKED'}")
print(f"Attacker → Victim            {'CONNECTED' if connectivity_ok else 'BLOCKED'}")
print(f"TAP probe                    {'RECEIVED' if probe_ok else 'BLOCKED'}")
print(f"Overall                      {'READY' if topology_ok and connectivity_ok and mirror_ok and probe_ok else 'BLOCKED'}")

if evidence.get("errors"):
    print("\nReasons:")
    for error in evidence["errors"][:8]:
        print(f"- {error}")

raise SystemExit(0 if topology_ok and connectivity_ok and mirror_ok and probe_ok else 1)
PY
}

setup_demo() {
    # A complete owned topology is already the desired state.  Validation is
    # real (including a fixed ping and mirror counter), so this is safe to
    # repeat and does not manufacture a success receipt.
    if [[ -e "$INTRIQO_DEMO_STATE_FILE" ]]; then
        run_topology up
        return 0
    fi
    run_topology setup
    run_topology validate
}

down_demo() {
    if [[ ! -e "$INTRIQO_DEMO_STATE_FILE" ]]; then
        for namespace in \
            "$INTRIQO_DEMO_ATTACKER_NAMESPACE" \
            "$INTRIQO_DEMO_VICTIM_NAMESPACE" \
            "$INTRIQO_DEMO_SWITCH_NAMESPACE" \
            "$INTRIQO_DEMO_MONITOR_NAMESPACE"; do
            if namespace_exists "$namespace"; then
                echo "intriqo-demo: refusing down; namespace exists without ownership marker: $namespace" >&2
                return 1
            fi
        done
        echo "intriqo-demo: already down"
        return 0
    fi
    run_topology cleanup
}

case "${1:-}" in
    setup|up)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        setup_demo
        ;;
    down)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        down_demo
        ;;
    status)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        evidence_file=$(mktemp)
        set +e
        run_topology validate >"$evidence_file"
        topology_status=$?
        print_status "$evidence_file"
        report_status=$?
        set -e
        rm -f -- "$evidence_file"
        exit $((topology_status == 0 && report_status == 0 ? 0 : 1))
        ;;
    validate)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        run_topology validate
        ;;
    reset)
        [[ $# -eq 1 ]] || { usage >&2; exit 2; }
        down_demo
        setup_demo
        ;;
    -h|--help)
        usage
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac
