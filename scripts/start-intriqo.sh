#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
CHECK_ONLY=false

usage() {
    cat <<'EOF'
Usage: scripts/start-intriqo.sh [--check] [--env-file PATH]

Start PostgreSQL and configured host processes. Redis and Kafka are never
started by this command. --check validates configuration without starting it.
EOF
}

while (($#)); do
    case "$1" in
        --check) CHECK_ONLY=true; shift ;;
        --env-file)
            (($# >= 2)) || { echo "start-intriqo: --env-file needs a path" >&2; exit 2; }
            export INTRIQO_ENV_FILE=$2
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) echo "start-intriqo: unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# shellcheck source=scripts/intriqo-runtime.sh
source "$SCRIPT_DIR/intriqo-runtime.sh"
intriqo_load_env_file
intriqo_refresh_paths
INTRIQO_PYTHON=$(intriqo_choose_python)
export INTRIQO_PYTHON
export PYTHONPATH="$INTRIQO_ROOT_DIR/control-plane/src:$INTRIQO_ROOT_DIR/agents/src:$INTRIQO_ROOT_DIR/ml/src${PYTHONPATH:+:$PYTHONPATH}"
cd "$INTRIQO_ROOT_DIR"
intriqo_prepare_runtime
intriqo_bootstrap_service_tokens
intriqo_validate_config
[[ "$CHECK_ONLY" == true ]] || intriqo_assert_stack_stopped

if [[ "$CHECK_ONLY" == true ]]; then
    echo "Intriqo configuration is valid."
    exit 0
fi

STARTUP_TIMEOUT=${INTRIQO_STARTUP_TIMEOUT_SECONDS:-60}
SHUTDOWN_TIMEOUT=${INTRIQO_SHUTDOWN_TIMEOUT_SECONDS:-15}
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ)-$$
RUN_DIR="$INTRIQO_STATE_DIR/runs/$RUN_ID"
ENGINE_STATE_DIR="$RUN_DIR/engine"
ML_STATE_DIR="$RUN_DIR/ml"
mkdir -p "$ENGINE_STATE_DIR" "$ML_STATE_DIR"
printf '%s\n' "$RUN_ID" > "$INTRIQO_STATE_DIR/current-run"

STARTUP_COMPLETE=false
cleanup_startup() {
    if [[ "$STARTUP_COMPLETE" != true ]]; then
        intriqo_stop_process engine "$SHUTDOWN_TIMEOUT" || true
        intriqo_stop_process ml-worker "$SHUTDOWN_TIMEOUT" || true
        intriqo_stop_process agents "$SHUTDOWN_TIMEOUT" || true
        intriqo_stop_process frontend "$SHUTDOWN_TIMEOUT" || true
        intriqo_stop_process control-plane "$SHUTDOWN_TIMEOUT" || true
        intriqo_compose stop postgres >/dev/null 2>&1 || true
    fi
}
trap cleanup_startup EXIT

echo "Starting PostgreSQL..."
intriqo_compose up -d postgres
intriqo_wait_for_postgres "$STARTUP_TIMEOUT"

echo "Applying Alembic migrations..."
if ! (
    cd "$INTRIQO_ROOT_DIR"
    "$INTRIQO_PYTHON" -m alembic -c control-plane/alembic.ini upgrade head
) > "$INTRIQO_LOG_DIR/migrations.log" 2>&1; then
    intriqo_die "Alembic migrations failed; see $INTRIQO_LOG_DIR/migrations.log"
    exit 1
fi

CONTROL_PLANE_LOG="$INTRIQO_LOG_DIR/control-plane.log"
FRONTEND_LOG="$INTRIQO_LOG_DIR/frontend.log"
AGENTS_LOG="$INTRIQO_LOG_DIR/agents.log"
ENGINE_LOG="$INTRIQO_LOG_DIR/engine.log"
ML_LOG="$INTRIQO_LOG_DIR/ml-worker.log"

echo "Starting Control Plane..."
    CONTROL_CMD=("$INTRIQO_PYTHON" -m uvicorn intriqo.api.app:app --app-dir "$INTRIQO_ROOT_DIR/control-plane/src" --host "${INTRIQO_API_BIND_HOST:-${INTRIQO_API_HOST:-127.0.0.1}}" --port "${INTRIQO_API_PORT:-8000}")
if intriqo_bool "${INTRIQO_API_RELOAD:-false}"; then
    CONTROL_CMD+=(--reload)
fi
intriqo_start_process control-plane "$CONTROL_PLANE_LOG" "${CONTROL_CMD[@]}" >/dev/null
intriqo_wait_for_health "$STARTUP_TIMEOUT" "http://${INTRIQO_API_HOST:-127.0.0.1}:${INTRIQO_API_PORT:-8000}/ready"

ML_INPUT=""
ML_RUNTIME_READY=false
if intriqo_bool "${INTRIQO_ML_ENABLED:-false}"; then
    ML_INPUT="$ENGINE_STATE_DIR/flow_features.v2.jsonl"
    : > "$ML_INPUT"
    ML_OUTPUT="$ML_STATE_DIR/anomalies.jsonl"
    ML_LEDGER="$ML_STATE_DIR/decisions.sqlite"
    ML_STATS="$ML_STATE_DIR/stats.json"
    ML_STATUS="$ML_STATE_DIR/status.json"
    ML_CMD=("$INTRIQO_PYTHON" -m intriqo_ml.ml_worker "$ML_INPUT" --output "$ML_OUTPUT" --ledger "$ML_LEDGER" --stats "$ML_STATS" --status-file "$ML_STATUS" --follow --queue-capacity "${INTRIQO_ML_QUEUE_CAPACITY:-256}")
    echo "Starting optional ML worker..."
    intriqo_start_process ml-worker "$ML_LOG" "${ML_CMD[@]}" >/dev/null
    if intriqo_wait_for_ml_ready "$ML_STATUS" "$STARTUP_TIMEOUT"; then
        ML_RUNTIME_READY=true
    else
        intriqo_warn "ML is unavailable; deterministic IDS continues without feature streaming"
        ML_INPUT=""
    fi
fi

if intriqo_bool "${INTRIQO_AGENTS_ENABLED:-true}"; then
    if [[ -n "${INTRIQO_AGENT_TASK_ID:-}" ]]; then
        echo "Starting one-shot agent task..."
        AGENT_CMD=("$INTRIQO_PYTHON" -m intriqo_agents.orchestrator.main --task-id "$INTRIQO_AGENT_TASK_ID")
    else
        echo "Starting agent poller..."
        AGENT_CMD=("$INTRIQO_PYTHON" -m intriqo_agents.orchestrator.main --poll --poll-interval "${INTRIQO_AGENT_POLL_INTERVAL:-2}")
    fi
    intriqo_start_process agents "$AGENTS_LOG" "${AGENT_CMD[@]}" >/dev/null
fi

if intriqo_bool "${INTRIQO_FRONTEND_ENABLED:-true}"; then
    echo "Starting Vite dashboard..."
    intriqo_start_process frontend "$FRONTEND_LOG" npm --prefix "$INTRIQO_ROOT_DIR/frontend/dashboard" run dev -- --host "${INTRIQO_FRONTEND_HOST:-127.0.0.1}" --port "${INTRIQO_FRONTEND_PORT:-5173}" >/dev/null
    FRONTEND_URL="http://${INTRIQO_FRONTEND_HOST:-127.0.0.1}:${INTRIQO_FRONTEND_PORT:-5173}/"
    elapsed=0
    until curl --fail --silent --show-error --max-time 3 "$FRONTEND_URL" >/dev/null 2>&1; do
        if ! intriqo_service_running frontend; then
            intriqo_die "Vite exited before becoming ready; see $FRONTEND_LOG"
            exit 1
        fi
        (( elapsed >= STARTUP_TIMEOUT )) && { intriqo_die "Vite HTTP readiness failed at $FRONTEND_URL"; exit 1; }
        sleep 1
        elapsed=$((elapsed + 1))
    done
fi

if intriqo_bool "${INTRIQO_ENGINE_ENABLED:-true}"; then
    ENGINE_BIN=$(intriqo_engine_binary "$(intriqo_bool "${INTRIQO_ML_ENABLED:-false}" && echo true || echo false)")
    ENGINE_CMD=("$ENGINE_BIN")
    ENGINE_USE_PRIVILEGED_LAUNCH=false
    case "${INTRIQO_ENGINE_MODE:-synthetic}" in
        synthetic) ENGINE_CMD+=(--synthetic --synthetic-packets "${INTRIQO_ENGINE_SYNTHETIC_PACKETS:-10}") ;;
        pcap) ENGINE_CMD+=(--pcap "$(intriqo_resolve_path "$INTRIQO_ENGINE_SOURCE")") ;;
        interface)
            ENGINE_CMD+=(--interface "$INTRIQO_ENGINE_SOURCE")
            [[ -n "${INTRIQO_ENGINE_FILTER:-}" ]] && ENGINE_CMD+=(--filter "$INTRIQO_ENGINE_FILTER")
            intriqo_bool "${INTRIQO_ENGINE_NO_PROMISCUOUS:-false}" && ENGINE_CMD+=(--no-promiscuous)
            ;;
    esac
    if [[ "${INTRIQO_ENGINE_SINK:-file}" == http ]]; then
        ENGINE_CMD+=(--sink http --control-plane-url "${INTRIQO_ENGINE_CONTROL_PLANE_URL:-${INTRIQO_CONTROL_PLANE_URL:-http://127.0.0.1:8000}}")
    else
        ENGINE_CMD+=(--sink file --output "$ENGINE_STATE_DIR/events.jsonl")
    fi
    ENGINE_QUEUE_CAPACITY=${INTRIQO_ENGINE_EVENT_QUEUE_CAPACITY:-0}
    if [[ "$ENGINE_QUEUE_CAPACITY" != 0 ]]; then
        "$ENGINE_BIN" --help | grep -q -- '--event-queue-capacity' || {
            intriqo_die "selected intriqo-engine does not support --event-queue-capacity"
            exit 1
        }
        ENGINE_CMD+=(--event-queue-capacity "$ENGINE_QUEUE_CAPACITY")
    fi
    ENGINE_CMD+=(--log-level "${INTRIQO_ENGINE_LOG_LEVEL:-info}")

    if [[ "$ML_RUNTIME_READY" == true ]]; then
        ENGINE_CMD+=(--feature-output "$ML_INPUT" --feature-schema flow_features.v2)
    fi
    if [[ -n "${INTRIQO_ENGINE_NAMESPACE:-}" ]]; then
        if intriqo_bool "${INTRIQO_ENGINE_USE_SUDO:-false}"; then
            ENGINE_USE_PRIVILEGED_LAUNCH=true
        fi
        ENGINE_CMD=(ip netns exec "$INTRIQO_ENGINE_NAMESPACE" "${ENGINE_CMD[@]}")
    fi
    printf 'IDS engine launch:'
    if [[ "$ENGINE_USE_PRIVILEGED_LAUNCH" == true ]]; then
        printf ' sudo -n -- setsid --wait --'
    fi
    printf ' %q' "${ENGINE_CMD[@]}"
    printf '\n'
    echo "Starting IDS engine..."
    if [[ "$ENGINE_USE_PRIVILEGED_LAUNCH" == true ]]; then
        ENGINE_PID=$(intriqo_start_privileged_process engine "$ENGINE_LOG" "${ENGINE_CMD[@]}")
    else
        ENGINE_PID=$(intriqo_start_process engine "$ENGINE_LOG" "${ENGINE_CMD[@]}")
    fi
    intriqo_wait_for_engine_ready "$ENGINE_PID" "$ENGINE_LOG" "$STARTUP_TIMEOUT"
fi

STARTUP_COMPLETE=true
echo "Intriqo local runtime started."
echo "  Control Plane: http://${INTRIQO_API_HOST:-127.0.0.1}:${INTRIQO_API_PORT:-8000}"
if intriqo_bool "${INTRIQO_FRONTEND_ENABLED:-true}"; then
    echo "  Dashboard:     http://${INTRIQO_FRONTEND_HOST:-127.0.0.1}:${INTRIQO_FRONTEND_PORT:-5173}"
fi
echo "  Logs:          $INTRIQO_LOG_DIR"
echo "  State:         $RUN_DIR"
