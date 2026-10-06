#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
KEEP_POSTGRES=false
while (($#)); do
    case "$1" in
        --keep-postgres) KEEP_POSTGRES=true; shift ;;
        --env-file)
            (($# >= 2)) || { echo "stop-intriqo: --env-file needs a path" >&2; exit 2; }
            export INTRIQO_ENV_FILE=$2
            shift 2
            ;;
        -h|--help) echo "Usage: scripts/stop-intriqo.sh [--keep-postgres] [--env-file PATH]"; exit 0 ;;
        *) echo "stop-intriqo: unknown option: $1" >&2; exit 2 ;;
    esac
done

# shellcheck source=scripts/intriqo-runtime.sh
source "$SCRIPT_DIR/intriqo-runtime.sh"
intriqo_load_env_file
intriqo_refresh_paths
intriqo_prepare_runtime
TIMEOUT=${INTRIQO_SHUTDOWN_TIMEOUT_SECONDS:-15}

# Stop engine before the ML follower so the engine can flush its bounded feature
# sink. The remaining services then receive the same graceful TERM->KILL flow.
for service in engine ml-worker agents frontend control-plane; do
    if intriqo_service_running "$service"; then
        echo "Stopping $service..."
    fi
    intriqo_stop_process "$service" "$TIMEOUT"
done

if [[ "$KEEP_POSTGRES" != true ]]; then
    echo "Stopping PostgreSQL..."
    intriqo_compose stop postgres >/dev/null 2>&1 || intriqo_warn "PostgreSQL was not running"
fi
echo "Intriqo local runtime stopped."
