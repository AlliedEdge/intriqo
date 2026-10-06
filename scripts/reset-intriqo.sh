#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
STOP_ARGS=()
while (($#)); do
    case "$1" in
        --keep-postgres) STOP_ARGS+=(--keep-postgres); shift ;;
        --env-file)
            (($# >= 2)) || { echo "reset-intriqo: --env-file needs a path" >&2; exit 2; }
            export INTRIQO_ENV_FILE=$2
            STOP_ARGS+=(--env-file "$2")
            shift 2
            ;;
        -h|--help) echo "Usage: scripts/reset-intriqo.sh [--keep-postgres] [--env-file PATH]"; exit 0 ;;
        *) echo "reset-intriqo: unknown option: $1" >&2; exit 2 ;;
    esac
done

"$SCRIPT_DIR/stop-intriqo.sh" "${STOP_ARGS[@]}" >/dev/null

# shellcheck source=scripts/intriqo-runtime.sh
source "$SCRIPT_DIR/intriqo-runtime.sh"
intriqo_load_env_file
intriqo_refresh_paths
[[ ! -L "$INTRIQO_RUNTIME_ROOT" ]] || { intriqo_die "INTRIQO_RUNTIME_DIR must not be a symlink"; exit 1; }
rm -rf -- "$INTRIQO_PID_DIR" "$INTRIQO_LOG_DIR" "$INTRIQO_STATE_DIR"
intriqo_prepare_runtime
echo "Intriqo runtime state and logs reset. PostgreSQL data was preserved."
