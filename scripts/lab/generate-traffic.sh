#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

cat <<'EOF'
The legacy target-taking traffic generator has been removed.  Demo traffic is
fixed to the owned Intriqo lab pair and always validates the real topology.
EOF

if [[ $# -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
    echo "Usage: scripts/lab/generate-traffic.sh {port-scan|udp-port-scan|syn-flood}"
    exit 0
fi
if [[ $# -ne 1 ]]; then
    echo "Usage: scripts/lab/generate-traffic.sh {port-scan|udp-port-scan|syn-flood}" >&2
    exit 2
fi

case "$1" in
    port-scan|udp-port-scan|syn-flood)
        exec "$SCRIPT_DIR/generate-demo-traffic.sh" "$1"
        ;;
    *)
        echo "Unknown traffic type: $1" >&2
        echo "Supported: port-scan, udp-port-scan, syn-flood" >&2
        exit 2
        ;;
esac
