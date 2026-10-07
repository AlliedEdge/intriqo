#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    exec "$SCRIPT_DIR/intriqo-demo.sh" --help
fi
[[ $# -eq 0 ]] || { "$SCRIPT_DIR/intriqo-demo.sh" --help >&2; exit 2; }
exec "$SCRIPT_DIR/intriqo-demo.sh" setup "$@"
