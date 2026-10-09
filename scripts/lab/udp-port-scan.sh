#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $# -eq 0 || ( $# -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ) ]] || {
    echo "Usage: scripts/lab/udp-port-scan.sh" >&2
    exit 2
}
if [[ $# -eq 1 ]]; then
    cat <<'EOF'
Usage: scripts/lab/udp-port-scan.sh

Generates ten bounded UDP probes from 10.77.0.10 to 10.77.0.20.
EOF
    exit 0
fi
cat <<'EOF'
[INTRIQO LAB]
Scenario: UDP PORT SCAN
Attacker: 10.77.0.10
Victim: 10.77.0.20
Generating authorized lab traffic...
EOF
"$SCRIPT_DIR/generate-demo-traffic.sh" udp-port-scan
echo "Waiting for detection..."
sleep 2
