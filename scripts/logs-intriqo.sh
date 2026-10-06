#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
FOLLOW=false
SERVICE=all
while (($#)); do
    case "$1" in
        -f|--follow) FOLLOW=true; shift ;;
        --env-file)
            (($# >= 2)) || { echo "logs-intriqo: --env-file needs a path" >&2; exit 2; }
            export INTRIQO_ENV_FILE=$2
            shift 2
            ;;
        -h|--help)
            echo "Usage: scripts/logs-intriqo.sh [--follow] [--env-file PATH] [all|control-plane|frontend|agents|engine|ml-worker|migrations|postgres]"
            exit 0
            ;;
        all|control-plane|frontend|agents|engine|ml-worker|migrations|postgres) SERVICE=$1; shift ;;
        *) echo "logs-intriqo: unknown service or option: $1" >&2; exit 2 ;;
    esac
done

# shellcheck source=scripts/intriqo-runtime.sh
source "$SCRIPT_DIR/intriqo-runtime.sh"
intriqo_load_env_file
intriqo_refresh_paths
intriqo_prepare_runtime

if [[ "$SERVICE" == postgres ]]; then
    if [[ "$FOLLOW" == true ]]; then
        intriqo_compose logs -f postgres
        exit $?
    fi
    intriqo_compose logs --tail="${INTRIQO_LOG_LINES:-100}" postgres
    exit $?
fi

declare -a files=()
if [[ "$SERVICE" == all ]]; then
    for service in migrations control-plane frontend agents engine ml-worker; do
        files+=("$INTRIQO_LOG_DIR/$service.log")
    done
else
    files+=("$INTRIQO_LOG_DIR/$SERVICE.log")
fi

for file in "${files[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "No log file yet: $file" >&2
        touch "$file"
    fi
done

if [[ "$FOLLOW" == true ]]; then
    exec tail -n "${INTRIQO_LOG_LINES:-100}" -F "${files[@]}"
fi
exec tail -n "${INTRIQO_LOG_LINES:-100}" "${files[@]}"
