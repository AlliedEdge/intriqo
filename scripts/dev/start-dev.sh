#!/usr/bin/env bash
set -euo pipefail

echo "=== Starting Intriqo Local Development Stack ==="
docker compose up -d postgres redis

echo "Starting Control Plane in background..."
if [ -d ".venv" ]; then
    . .venv/bin/activate
fi

# Run control plane using uvicorn
echo "Running uvicorn intriqo.api.app:app on port 8000..."
uvicorn intriqo.api.app:app --app-dir control-plane/src --reload --port 8000 &
CP_PID=$!
echo $CP_PID > .control-plane.pid

echo "Intriqo Control Plane started (PID: $CP_PID)."
echo "Access dashboard or API docs at http://localhost:8000/docs"
