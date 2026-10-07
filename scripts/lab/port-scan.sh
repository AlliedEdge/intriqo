#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
[[ $# -eq 0 || ( $# -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ) ]] || {
    echo "Usage: scripts/lab/port-scan.sh" >&2
    exit 2
}
if [[ $# -eq 1 ]]; then
    cat <<'EOF'
Usage: scripts/lab/port-scan.sh

Generates a bounded, fixed port scan from 10.77.0.10 to 10.77.0.20.
EOF
    exit 0
fi
cat <<'EOF'
[INTRIQO LAB]
Scenario: PORT SCAN
Attacker: 10.77.0.10
Victim: 10.77.0.20
Generating authorized lab traffic...
EOF
"$SCRIPT_DIR/generate-demo-traffic.sh" port-scan
echo "Waiting for detection..."
sleep 2
