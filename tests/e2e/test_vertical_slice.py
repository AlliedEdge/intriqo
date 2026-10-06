"""Real-process vertical slice: C++ -> FastAPI -> PostgreSQL -> SOC records."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import psycopg2
import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane"
DEMO = Path(os.environ.get("INTRIQO_ENGINE_DEMO", str(ROOT / "engine" / "build" / "intriqo_port_scan_demo")))
BASE = "http://127.0.0.1:8765"


def _register(client: httpx.Client, username: str, role: str) -> str:
    response = client.post("/api/v1/auth/register", json={
        "username": username, "email": f"{username}@example.com",
        "password": "phase3-integration-password", "role": role,
    })
    assert response.status_code == 201, response.text
    login = client.post("/api/v1/auth/login", json={
        "username": username, "password": "phase3-integration-password",
    })
    assert login.status_code == 200, login.text
    return login.json()["access_token"]


def test_cpp_to_control_plane_vertical_slice() -> None:
    if not DEMO.exists():
        pytest.fail(f"Build the C++ demo first: {DEMO}")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(CONTROL_PLANE / "src")
    # Keep this isolated real-process test independent of a developer's
    # control-plane/.env verification policy; it uses unique local test users
    # and does not exercise outbound email delivery.
    env["APP_ENV"] = "test"
    env["REQUIRE_EMAIL_VERIFICATION"] = "false"
    env["RESEND_API_KEY"] = ""
    server = subprocess.Popen([
        sys.executable, "-m", "uvicorn",
        "intriqo.api.app:app", "--host", "127.0.0.1", "--port", "8765",
    ], cwd=CONTROL_PLANE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with httpx.Client(base_url=BASE, timeout=10) as client:
            for _ in range(50):
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(0.1)
            else:
                pytest.fail("FastAPI did not become ready")

            suffix = uuid.uuid4().hex[:10]
            engine_token = _register(client, f"ids_engine_{suffix}", "AGENT")
            operator_token = _register(client, f"integration_operator_{suffix}", "ANALYST")

            demo_env = env | {
                "INTRIQO_CONTROL_PLANE_URL": BASE,
                "INTRIQO_CONTROL_PLANE_TOKEN": engine_token,
            }
            run = subprocess.run([str(DEMO)], cwd=ROOT, env=demo_env, text=True, capture_output=True, check=False)
            assert run.returncode == 0, run.stderr
            event = next(json.loads(line) for line in run.stdout.splitlines() if line.startswith("{"))
            event_id = event["event_id"]

            event_response = client.get(f"/api/v1/events/{event_id}", headers={"Authorization": f"Bearer {engine_token}"})
            assert event_response.status_code == 200, event_response.text
            assert event_response.json()["event_id"] == event_id

            duplicate = client.post("/api/v1/events", headers={"Authorization": f"Bearer {engine_token}"}, json=event)
            assert duplicate.status_code == 409, duplicate.text

            unauthorized = subprocess.run([str(DEMO)], cwd=ROOT, env=env | {
                "INTRIQO_CONTROL_PLANE_URL": BASE, "INTRIQO_CONTROL_PLANE_TOKEN": "invalid-token",
            }, text=True, capture_output=True, check=False)
            assert unauthorized.returncode == 2
            assert "HTTP 401" in unauthorized.stderr

            class ServerErrorHandler(BaseHTTPRequestHandler):
                def do_POST(self):
                    _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    self.send_response(500)
                    self.end_headers()
                def log_message(self, *_args):
                    pass

            error_server = ThreadingHTTPServer(("127.0.0.1", 0), ServerErrorHandler)
            error_thread = __import__("threading").Thread(target=error_server.serve_forever, daemon=True)
            error_thread.start()
            try:
                failed_delivery = subprocess.run([str(DEMO)], cwd=ROOT, env=env | {
                    "INTRIQO_CONTROL_PLANE_URL": f"http://127.0.0.1:{error_server.server_port}",
                    "INTRIQO_CONTROL_PLANE_TOKEN": "not-used",
                }, text=True, capture_output=True, check=False)
                assert failed_delivery.returncode == 2
                assert "HTTP 500" in failed_delivery.stderr
            finally:
                error_server.shutdown()
                error_server.server_close()

            analyst_headers = {"Authorization": f"Bearer {operator_token}"}
            incident_response = client.post("/api/v1/incidents", headers=analyst_headers, json={
                "title": "PORT_SCAN integration incident", "description": "Real C++ vertical slice",
                "severity": event["severity"], "event_ids": [event_id],
                "incident_metadata": {"source": "cpp-e2e-test"},
            })
            assert incident_response.status_code == 201, incident_response.text
            incident = incident_response.json()
            # A prior local event with the same deterministic correlation key
            # may already be within the documented window. Manual analyst
            # linking must retain the fresh event without requiring an empty
            # database or discarding the correlated event.
            assert event_id in incident["linked_event_ids"]

            task_response = client.post("/api/v1/agent-tasks", headers=analyst_headers, json={
                "task_type": "INVESTIGATION", "description": "Investigate this security incident.",
                "priority": "HIGH", "event_id": event_id, "incident_id": incident["incident_id"],
                "context": {"demo": True},
            })
            assert task_response.status_code == 201, task_response.text
            task = task_response.json()
            assert task["status"] == "PENDING"

            agent_env = env | {
                "PYTHONPATH": str(ROOT / "agents" / "src"),
                "INTRIQO_CONTROL_PLANE_URL": BASE,
                "INTRIQO_AGENT_TOKEN": engine_token,
            }
            agent_run = subprocess.run(
                [sys.executable, "-m", "intriqo_agents.orchestrator.main", "--task-id", task["task_id"]],
                cwd=ROOT, env=agent_env, text=True, capture_output=True, check=False,
            )
            assert agent_run.returncode == 0, agent_run.stderr
            finding_response = client.get(
                "/api/v1/findings", headers={"Authorization": f"Bearer {engine_token}"},
                params={"task_id": task["task_id"]},
            )
            assert finding_response.status_code == 200, finding_response.text
            finding = finding_response.json()["items"][0]
            assert finding["task_id"] == task["task_id"]

            replay = subprocess.run(
                [sys.executable, "-m", "intriqo_agents.orchestrator.main", "--task-id", task["task_id"]],
                cwd=ROOT, env=agent_env, text=True, capture_output=True, check=False,
            )
            assert replay.returncode == 0, replay.stderr
            assert client.get("/api/v1/findings", headers={"Authorization": f"Bearer {engine_token}"},
                              params={"task_id": task["task_id"]}).json()["total"] == 1

            task_after = client.get(f"/api/v1/agent-tasks/{task['task_id']}", headers={"Authorization": f"Bearer {engine_token}"})
            assert task_after.status_code == 200
            assert task_after.json()["status"] == "COMPLETED"

            with psycopg2.connect("postgresql://intriqo:intriqo_dev@localhost:5432/intriqo") as db, db.cursor() as cur:
                cur.execute("SELECT action, resource_type, resource_id, actor, outcome FROM audit_logs WHERE resource_id IN (%s,%s,%s,%s) ORDER BY created_at", (event_id, incident["incident_id"], task["task_id"], finding["finding_id"]))
                rows = cur.fetchall()
            actions = {row[0] for row in rows}
            assert {"EVENT_INGESTED", "INCIDENT_CREATED", "TASK_CREATED", "TASK_STARTED",
                    "TASK_COMPLETED", "FINDING_SUBMITTED"} <= actions
            assert all(row[4] == "SUCCESS" for row in rows)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
