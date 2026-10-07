#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" == "--verify" ]]; then
    shift
fi
[[ $# -eq 0 ]] || { echo "Usage: scripts/lab/status.sh [--verify]" >&2; exit 2; }
exec "$SCRIPT_DIR/status-intriqo-demo.sh"
