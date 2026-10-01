#!/usr/bin/env bash
set -euo pipefail

echo "=== Stopping Intriqo Local Development Stack ==="

if [ -f ".control-plane.pid" ]; then
    PID=$(cat .control-plane.pid)
    echo "Stopping Control Plane (PID: $PID)..."
    kill "$PID" 2>/dev/null || true
    rm -f .control-plane.pid
fi

echo "Stopping containers..."
docker compose down

echo "Intriqo stack stopped."
