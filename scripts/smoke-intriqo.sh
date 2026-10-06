#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
TIMEOUT=30
while (($#)); do
    case "$1" in
        --timeout)
            (($# >= 2)) || { echo "smoke-intriqo: --timeout needs seconds" >&2; exit 2; }
            [[ "$2" =~ ^[1-9][0-9]*$ ]] || { echo "smoke-intriqo: --timeout must be a positive integer" >&2; exit 2; }
            TIMEOUT=$2
            shift 2
            ;;
        --env-file) (($# >= 2)) || { echo "smoke-intriqo: --env-file needs a path" >&2; exit 2; }; export INTRIQO_ENV_FILE=$2; shift 2 ;;
        -h|--help) echo "Usage: scripts/smoke-intriqo.sh [--timeout SECONDS] [--env-file PATH]"; exit 0 ;;
        *) echo "smoke-intriqo: unknown option: $1" >&2; exit 2 ;;
    esac
done

# shellcheck source=scripts/intriqo-runtime.sh
source "$SCRIPT_DIR/intriqo-runtime.sh"
intriqo_load_env_file
intriqo_refresh_paths
INTRIQO_PYTHON=$(intriqo_choose_python)
export INTRIQO_PYTHON
intriqo_prepare_runtime
intriqo_load_key_value_file "$(intriqo_runtime_secrets_file)"

if ! intriqo_bool "${INTRIQO_ENGINE_ENABLED:-true}"; then
    echo "smoke-intriqo: the IDS engine must be enabled for a fresh detection" >&2
    exit 1
fi

ENGINE_BIN=$(intriqo_engine_binary "$(intriqo_bool "${INTRIQO_ML_ENABLED:-false}" && echo true || echo false)")
[[ -n "$ENGINE_BIN" && -x "$ENGINE_BIN" && ! -L "$ENGINE_BIN" ]] || {
    echo "smoke-intriqo: no executable production IDS engine was selected" >&2
    exit 1
}

# The configured Control Plane URL is also the destination used by the C++
# HTTP sink.  Do not reconstruct it from local host/port settings when an
# operator has supplied a different base URL.
BASE_URL=${INTRIQO_CONTROL_PLANE_URL:-http://${INTRIQO_API_HOST:-127.0.0.1}:${INTRIQO_API_PORT:-8000}}
FRONTEND_URL=${FRONTEND_BASE_URL:-http://${INTRIQO_FRONTEND_HOST:-127.0.0.1}:${INTRIQO_FRONTEND_PORT:-5173}}
export BASE_URL FRONTEND_URL SMOKE_TIMEOUT=$TIMEOUT SMOKE_ENGINE_BIN=$ENGINE_BIN

"$INTRIQO_PYTHON" - <<'PY'
import os
import subprocess
import time
import uuid
from datetime import datetime, timezone

import httpx


base = os.environ["BASE_URL"]
engine_token = os.environ.get("INTRIQO_CONTROL_PLANE_TOKEN", "")
agent_token = os.environ.get("INTRIQO_AGENT_TOKEN", "")
operator_token = os.environ.get("INTRIQO_OPERATOR_TOKEN", "")
if not engine_token or not agent_token or not operator_token:
    raise SystemExit("runtime service identities are missing; start the stack first")

try:
    timeout_seconds = int(os.environ.get("SMOKE_TIMEOUT", "30"))
except ValueError:
    raise SystemExit("smoke timeout is invalid") from None
deadline = time.monotonic() + timeout_seconds

def request(client: httpx.Client, method: str, path: str, **kwargs):
    try:
        response = client.request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        raise SystemExit(f"{method} {path} could not reach the Control Plane: {type(exc).__name__}") from None
    if response.status_code >= 400:
        raise SystemExit(f"{method} {path} returned HTTP {response.status_code}")
    try:
        return response.json()
    except ValueError:
        raise SystemExit(f"{method} {path} returned invalid JSON") from None

def utc_datetime(value):
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise SystemExit("Control Plane returned an invalid event ingestion time") from None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)

def all_events(client, headers):
    items = []
    page = 1
    while True:
        body = request(
            client,
            "GET",
            "/api/v1/events",
            headers=headers,
            params={
                "event_type": "PORT_SCAN",
                "source_address": "192.0.2.10",
                "destination_address": "198.51.100.20",
                "page": page,
                "page_size": 500,
            },
        )
        items.extend(body.get("items", []))
        if not body.get("has_next"):
            return items
        page += 1

with httpx.Client(base_url=base.rstrip("/"), timeout=min(5.0, max(1.0, float(timeout_seconds)))) as client:
    ready = request(client, "GET", "/ready")
    if ready.get("status") != "ready":
        raise SystemExit("Control Plane readiness did not report ready")

    engine_headers = {"Authorization": f"Bearer {engine_token}"}
    operator_headers = {"Authorization": f"Bearer {operator_token}"}
    agent_headers = {"Authorization": f"Bearer {agent_token}"}
    baseline_ids = {item.get("event_id") for item in all_events(client, engine_headers)}
    invocation_started = datetime.now(timezone.utc)

    # Run the selected production C++ engine for this smoke invocation.  The
    # detector settings make the built-in synthetic source emit one fresh
    # PORT_SCAN without introducing a test-only detector or event producer.
    engine_args = [
        os.environ["SMOKE_ENGINE_BIN"],
        "--synthetic",
        "--synthetic-packets", "10",
        "--synthetic-unique-ports", "10",
        "--portscan-unique-port-threshold", "10",
        "--portscan-minimum-attempts", "10",
        "--sink", "http",
        "--control-plane-url", base.rstrip("/"),
        "--log-level", "error",
    ]
    engine_env = os.environ.copy()
    engine_env["INTRIQO_CONTROL_PLANE_URL"] = base.rstrip("/")
    engine_env["INTRIQO_CONTROL_PLANE_TOKEN"] = engine_token
    try:
        engine_run = subprocess.run(
            engine_args,
            env=engine_env,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(1.0, deadline - time.monotonic()),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit(f"production IDS engine failed during smoke: {type(exc).__name__}") from None
    if engine_run.returncode != 0:
        raise SystemExit(f"production IDS engine exited with status {engine_run.returncode}")

    event = None
    while time.monotonic() < deadline:
        candidates = [
            item for item in all_events(client, engine_headers)
            if item.get("event_id") not in baseline_ids
        ]
        for candidate in candidates:
            if candidate.get("event_type") != "PORT_SCAN":
                continue
            if candidate.get("source_address") != "192.0.2.10" or candidate.get("destination_address") != "198.51.100.20":
                continue
            if utc_datetime(candidate.get("ingested_at")) < invocation_started:
                continue
            event = request(client, "GET", f"/api/v1/events/{candidate['event_id']}", headers=engine_headers)
            break
        if event is not None:
            break
        time.sleep(min(0.5, max(0.05, deadline - time.monotonic())))
    if event is None:
        raise SystemExit("production IDS engine produced no fresh authorized PORT_SCAN event")

    event_id = event.get("event_id")
    if not event_id or event_id in baseline_ids:
        raise SystemExit("Control Plane returned a non-fresh SecurityEvent")
    if event.get("event_type") != "PORT_SCAN":
        raise SystemExit("fresh SecurityEvent has the wrong detector type")

    suffix = uuid.uuid4().hex[:10]
    incident = request(client, "POST", "/api/v1/incidents", headers=operator_headers, json={
        "title": f"Local runtime smoke {suffix}",
        "description": "Controlled local vertical-flow smoke test",
        "severity": event["severity"],
        "event_ids": [event_id],
        "incident_metadata": {"source": "scripts/smoke-intriqo.sh"},
    })
    incident_id = incident.get("incident_id")
    if not incident_id or event_id not in incident.get("linked_event_ids", []):
        raise SystemExit("fresh event was not linked to the smoke incident")
    request(client, "GET", f"/api/v1/incidents/{incident_id}", headers=agent_headers)
    idempotency_key = f"intriqo-smoke-{suffix}"
    task = request(client, "POST", "/api/v1/agent-tasks", headers={**operator_headers, "Idempotency-Key": idempotency_key}, json={
        "task_type": "INVESTIGATION",
        "description": "Investigate the controlled local runtime smoke event.",
        "priority": "HIGH",
        "event_id": event_id,
        "incident_id": incident_id,
        "idempotency_key": idempotency_key,
        "context": {"smoke": True, "event_id": event_id},
    })
    task_id = task.get("task_id")
    if not task_id or task.get("event_id") != event_id or task.get("incident_id") != incident_id:
        raise SystemExit("fresh event did not produce a correctly linked task")

    task_after = task
    finding = None
    while time.monotonic() < deadline:
        task_after = request(client, "GET", f"/api/v1/agent-tasks/{task_id}", headers=agent_headers)
        findings = request(
            client,
            "GET",
            "/api/v1/findings",
            headers=agent_headers,
            params={"task_id": task_id, "page": 1, "page_size": 10},
        )
        candidates = [
            item for item in findings.get("items", [])
            if item.get("task_id") == task_id and item.get("event_id") == event_id
        ]
        if task_after.get("status") == "FAILED":
            raise SystemExit("agent task entered FAILED")
        if task_after.get("status") == "COMPLETED" and candidates:
            finding = candidates[0]
            break
        time.sleep(min(0.5, max(0.05, deadline - time.monotonic())))
    if finding is None:
        raise SystemExit(f"agent task did not complete: {task_after.get('status')}")
    if finding.get("status") != "SUCCESS":
        raise SystemExit("agent finding did not report SUCCESS")

    finding = request(client, "GET", f"/api/v1/findings/{finding['finding_id']}", headers=agent_headers)
    if finding.get("task_id") != task_id or finding.get("event_id") != event_id or finding.get("status") != "SUCCESS":
        raise SystemExit("fresh finding retrieval was not linked to the smoke task and event")

    event_audit = request(
        client, "GET", "/api/v1/audit", headers=operator_headers,
        params={"resource_id": event_id, "page": 1, "page_size": 50},
    )
    task_audit = request(
        client, "GET", "/api/v1/audit", headers=operator_headers,
        params={"resource_id": task_id, "page": 1, "page_size": 50},
    )
    finding_audit = request(
        client, "GET", "/api/v1/audit", headers=operator_headers,
        params={"resource_id": finding["finding_id"], "page": 1, "page_size": 10},
    )
    audit_entries = event_audit.get("items", []) + task_audit.get("items", []) + finding_audit.get("items", [])
    if any(entry.get("outcome") != "SUCCESS" for entry in audit_entries):
        raise SystemExit("audit trail contains a failed operation")
    actions = {entry.get("action") for entry in audit_entries}
    required = {"EVENT_INGESTED", "TASK_CREATED", "TASK_STARTED", "TASK_COMPLETED", "FINDING_SUBMITTED"}
    if not required.issubset(actions):
        raise SystemExit(f"audit trail is incomplete: missing {sorted(required - actions)}")

    try:
        frontend_root = httpx.get(os.environ["FRONTEND_URL"].rstrip("/") + "/", timeout=5.0)
        dashboard = httpx.get(
            os.environ["FRONTEND_URL"].rstrip("/") + "/api/v1/events",
            headers=engine_headers,
            timeout=5.0,
        )
    except httpx.HTTPError as exc:
        raise SystemExit(f"frontend could not be reached: {type(exc).__name__}") from None
    if frontend_root.status_code != 200:
        raise SystemExit(f"frontend server returned HTTP {frontend_root.status_code}")
    if dashboard.status_code != 200:
        raise SystemExit(f"frontend API proxy returned HTTP {dashboard.status_code}")

print(f"SMOKE PASS event={event_id} incident={incident_id} task={task_id} finding={finding['finding_id']}")
PY
