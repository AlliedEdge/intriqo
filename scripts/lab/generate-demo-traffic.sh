#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
# shellcheck source=scripts/lab/demo-profile.sh
source "$SCRIPT_DIR/demo-profile.sh"

PYTHON=${INTRIQO_PYTHON:-python3}
TRAFFIC_PY="$REPO_ROOT/security-lab/controlled_v2/traffic.py"

usage() {
    cat <<'EOF'
Usage: scripts/lab/generate-demo-traffic.sh {port-scan|udp-port-scan|syn-flood}

All scenarios are bounded and fixed to 10.77.0.10 -> 10.77.0.20.  The
topology and monitor mirror are validated before any packet is sent.
EOF
}

[[ $# -eq 1 ]] || { usage >&2; exit 2; }
case "$1" in
    port-scan|udp-port-scan|syn-flood) ;;
    -h|--help) usage; exit 0 ;;
    *) echo "intriqo-demo traffic: unknown scenario: $1" >&2; usage >&2; exit 2 ;;
esac

"$SCRIPT_DIR/intriqo-demo.sh" status >/dev/null

run_lab() {
    if (( EUID == 0 )); then
        ip netns exec "$@"
        return
    fi
    command -v sudo >/dev/null 2>&1 || {
        echo "intriqo-demo traffic: root or sudo is required to enter the attacker namespace" >&2
        return 1
    }
    sudo ip netns exec "$@"
}

case "$1" in
    port-scan)
        # Ten unique TCP destination ports and twenty bounded attempts satisfy
        # the existing PortScanDetector defaults without changing them.
        run_lab "$INTRIQO_DEMO_ATTACKER_NAMESPACE" \
            "$PYTHON" "$TRAFFIC_PY" port-scan \
            --ports 10080-10089 \
            --repeats 2 \
            --source-port-start 44000 \
            --rate 20 \
            --duration 1.0
        ;;
    udp-port-scan)
        # Ten bounded UDP datagrams use the production UDP flow parser and detector.
        run_lab "$INTRIQO_DEMO_ATTACKER_NAMESPACE" \
            "$PYTHON" "$TRAFFIC_PY" udp-port-scan \
            --ports 10080-10089 \
            --source-port-start 45000 \
            --rate 20
        ;;
    syn-flood)
        # One hundred unique five-tuples at 75/s span more than one second,
        # leaving the existing SYN detector thresholds untouched.
        run_lab "$INTRIQO_DEMO_ATTACKER_NAMESPACE" \
            "$PYTHON" "$TRAFFIC_PY" syn-flood \
            --destination-port 65535 \
            --source-port 43000 \
            --count 100 \
            --rate 75 \
            --unique-source-ports
        ;;
esac
