#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
if [[ "${1:-}" == "--env-file" ]]; then
    (($# >= 2)) || { echo "status-intriqo: --env-file needs a path" >&2; exit 2; }
    export INTRIQO_ENV_FILE=$2
    shift 2
fi
[[ $# -eq 0 ]] || { echo "Usage: scripts/status-intriqo.sh [--env-file PATH]" >&2; exit 2; }

# shellcheck source=scripts/intriqo-runtime.sh
source "$SCRIPT_DIR/intriqo-runtime.sh"
intriqo_load_env_file
intriqo_refresh_paths
INTRIQO_PYTHON=$(intriqo_choose_python)
export INTRIQO_PYTHON

echo "Intriqo local runtime"
if [[ -f "$INTRIQO_STATE_DIR/current-run" ]]; then
    printf 'Run:             %s\n' "$(cat "$INTRIQO_STATE_DIR/current-run")"
fi

status_ok=true
if pg_isready -q -h "${INTRIQO_POSTGRES_HOST:-127.0.0.1}" -p "${INTRIQO_POSTGRES_PORT:-5432}" -U "${POSTGRES_USER:-intriqo}" -d "${POSTGRES_DB:-intriqo}"; then
    echo "PostgreSQL:      HEALTHY"
else
    echo "PostgreSQL:      UNHEALTHY"
    status_ok=false
fi

health_url="http://${INTRIQO_API_HOST:-127.0.0.1}:${INTRIQO_API_PORT:-8000}/ready"
control_plane_ready=false
if intriqo_health_ok "$health_url"; then
    echo "Control Plane:   HEALTHY ($health_url)"
    control_plane_ready=true
else
    echo "Control Plane:   UNHEALTHY ($health_url)"
    status_ok=false
fi

for service in control-plane frontend agents engine ml-worker; do
    if intriqo_service_running "$service"; then
        pid=$(intriqo_pid_for "$service")
        if [[ "$service" == ml-worker ]]; then
            status_file=$(find "$INTRIQO_STATE_DIR/runs" -path '*/ml/status.json' -type f -print 2>/dev/null | sort | tail -n 1 || true)
            ml_state="STARTING"
            if [[ -n "$status_file" ]]; then
                ml_state=$("$INTRIQO_PYTHON" - "$status_file" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        print(json.load(stream).get("state", "STARTING"))
except (OSError, ValueError):
    print("FAILED")
PY
                )
            fi
            if [[ "$ml_state" == READY && "$control_plane_ready" != true ]]; then
                ml_state=DEGRADED
            fi
            printf '%-16s %s (pid %s)\n' "$service:" "$ml_state" "$pid"
            [[ "$ml_state" == READY ]] || status_ok=false
        elif [[ "$service" == frontend ]]; then
            frontend_url="http://${INTRIQO_FRONTEND_HOST:-127.0.0.1}:${INTRIQO_FRONTEND_PORT:-5173}/"
            if curl --fail --silent --show-error --max-time 3 "$frontend_url" >/dev/null 2>&1; then
                printf '%-16s HEALTHY (pid %s)\n' "$service:" "$pid"
            else
                printf '%-16s UNHEALTHY (pid %s; HTTP unavailable)\n' "$service:" "$pid"
                status_ok=false
            fi
        elif [[ "$service" == agents && "$control_plane_ready" != true ]]; then
            printf '%-16s DEGRADED (pid %s; Control Plane unavailable)\n' "$service:" "$pid"
            status_ok=false
        else
            printf '%-16s HEALTHY (pid %s)\n' "$service:" "$pid"
        fi
    elif [[ -f "$INTRIQO_PID_DIR/$service.pid" ]]; then
        if [[ "$service" == ml-worker ]]; then
            status_file=$(find "$INTRIQO_STATE_DIR/runs" -path '*/ml/status.json' -type f -print 2>/dev/null | sort | tail -n 1 || true)
            ml_state="STOPPED"
            if [[ -n "$status_file" ]]; then
                ml_state=$("$INTRIQO_PYTHON" - "$status_file" <<'PY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        print(json.load(stream).get("state", "FAILED"))
except (OSError, ValueError):
    print("FAILED")
PY
                )
            fi
            printf '%-16s %s\n' "$service:" "$ml_state"
            [[ "$ml_state" == FAILED || "$ml_state" == DEGRADED ]] && status_ok=false
        else
            printf '%-16s exited\n' "$service:"
        fi
        if [[ "$service" == agents && -n "${INTRIQO_AGENT_TASK_ID:-}" ]]; then
            : # Explicit one-shot task mode is allowed to complete normally.
        elif [[ "$service" == ml-worker ]]; then
            : # The ML branch above already classified the worker state.
        elif [[ "$service" == engine && "${INTRIQO_ENGINE_MODE:-synthetic}" != interface && -f "$INTRIQO_LOG_DIR/engine.log" ]] && grep -q 'shutdown status=complete' "$INTRIQO_LOG_DIR/engine.log"; then
            : # Synthetic and PCAP modes are finite and can complete normally.
        else
            status_ok=false
        fi
    else
        if [[ "$service" == ml-worker && "${INTRIQO_ML_ENABLED:-false}" != true ]]; then
            printf '%-16s DISABLED\n' "$service:"
        else
            printf '%-16s STOPPED\n' "$service:"
        fi
        if [[ "$service" == control-plane ]] || \
           { [[ "$service" == frontend ]] && intriqo_bool "${INTRIQO_FRONTEND_ENABLED:-true}"; } || \
           { [[ "$service" == engine ]] && intriqo_bool "${INTRIQO_ENGINE_ENABLED:-true}"; } || \
           { [[ "$service" == ml-worker ]] && intriqo_bool "${INTRIQO_ML_ENABLED:-false}"; }; then
            status_ok=false
        fi
    fi
done

echo "Logs:            $INTRIQO_LOG_DIR"
echo "State:           $INTRIQO_STATE_DIR"
[[ "$status_ok" == true ]] && exit 0
exit 1
