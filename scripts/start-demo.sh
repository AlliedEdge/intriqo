#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

usage() {
    cat <<'EOF'
Usage: scripts/start-demo.sh

Verify the fixed isolated lab and start the existing Release Candidate runtime
with the C++ engine attached to tap-intriqo in the monitor namespace.

The lab must already exist; first run scripts/lab/setup.sh, then use
scripts/lab/up.sh for later sessions.  ML remains controlled by the normal
.env settings and is never altered by this command.
EOF
}

case "${1:-}" in
    "") ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

# Entering a named network namespace and opening a raw capture socket are
# deployment operations.  The application processes remain on the host, but
# the demo engine is deliberately launched with the operator's sudo grant.
if (( EUID != 0 )); then
    command -v sudo >/dev/null 2>&1 || {
        echo "start-demo: root or sudo is required for the monitor namespace" >&2
        exit 1
    }
    sudo -v || {
        echo "start-demo: sudo authorization is required to run the lab sensor" >&2
        exit 1
    }
fi

echo "Verifying INTRIQO SECURITY LAB..."
"$SCRIPT_DIR/lab/status.sh" --verify

export INTRIQO_ENGINE_MODE=interface
export INTRIQO_ENGINE_SOURCE=tap-intriqo
export INTRIQO_ENGINE_NAMESPACE=intriqo-monitor
export INTRIQO_ENGINE_USE_SUDO=true
export INTRIQO_ENGINE_SINK=http
export INTRIQO_ENGINE_NO_PROMISCUOUS=true
export INTRIQO_ENGINE_FILTER='net 10.77.0.0/24'
# The monitor namespace has a host-only management veth. Bind the existing
# Control Plane only to that point-to-point host address; this keeps the API
# off physical host interfaces while the browser remains on localhost through
# the Vite proxy.
export INTRIQO_API_HOST=169.254.77.1
export INTRIQO_API_BIND_HOST=169.254.77.1
export INTRIQO_ENGINE_CONTROL_PLANE_URL=http://169.254.77.1:${INTRIQO_API_PORT:-8000}
export INTRIQO_CONTROL_PLANE_URL=http://169.254.77.1:${INTRIQO_API_PORT:-8000}
export INTRIQO_API_PROXY_TARGET=http://169.254.77.1:${INTRIQO_API_PORT:-8000}

echo "Starting the existing Intriqo Release Candidate runtime..."
"$SCRIPT_DIR/start-intriqo.sh"

echo "Verifying Control Plane, agent poller, and engine..."
"$SCRIPT_DIR/status-intriqo.sh"

echo
echo "INTRIQO DEMO READY"
echo "  Dashboard:     http://${INTRIQO_FRONTEND_HOST:-127.0.0.1}:${INTRIQO_FRONTEND_PORT:-5173}/"
echo "  Control Plane: http://${INTRIQO_API_HOST:-127.0.0.1}:${INTRIQO_API_PORT:-8000}"
echo "  Sensor:        INTRIQO-LAB-01"
echo "  Interface:     tap-intriqo (in intriqo-monitor namespace)"
echo "  Network:       10.77.0.0/24"
echo
"$SCRIPT_DIR/lab/status.sh" --verify
