"""Side-effect-free regression coverage for the runtime smoke validator."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKE = ROOT / "scripts" / "smoke-intriqo.sh"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SmokeState:
    def __init__(self) -> None:
        self.events: list[dict[str, object]] = [
            {
                "event_id": "old-event",
                "event_type": "PORT_SCAN",
                "severity": "HIGH",
                "timestamp": "2023-11-14T22:13:20+00:00",
                "source_address": "192.0.2.10",
                "destination_address": "198.51.100.20",
                "description": "Persisted event from an earlier run",
                "details": {"detector": "port_scan"},
                "ingested_at": (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(),
            }
        ]
        self.tasks: dict[str, dict[str, object]] = {}
        self.findings: dict[str, dict[str, object]] = {}
        self.audit: dict[str, list[dict[str, object]]] = {}
        self.engine_authorizations: list[str] = []
        self.task_idempotency_keys: list[str] = []
        self.complete_tasks = True
        self.lock = threading.Lock()


def _audit(state: SmokeState, resource_id: str, *actions: str) -> None:
    state.audit[resource_id] = [
        {"action": action, "outcome": "SUCCESS", "resource_id": resource_id}
        for action in actions
    ]


class SmokeHandler(BaseHTTPRequestHandler):
    state: SmokeState

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self, token: str) -> bool:
        return self.headers.get("Authorization") == f"Bearer {token}"

    def _require(self, token: str) -> bool:
        if self._authorized(token):
            return True
        self._json(401, {"detail": "unauthorized"})
        return False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        state = self.state

        if path == "/":
            body = b"<!doctype html><title>mock dashboard</title>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/ready":
            self._json(200, {"status": "ready"})
            return
        if path in {"/api/v1/events", "/api/v1/events/"}:
            if not self._require("engine-token"):
                return
            with state.lock:
                events = list(state.events)
            filtered = [
                event for event in events
                if all(event.get(key) == query.get(key, [None])[0] for key in (
                    "event_type", "source_address", "destination_address"
                ) if key in query)
            ]
            self._json(200, {
                "items": filtered,
                "total": len(filtered),
                "page": int(query.get("page", ["1"])[0]),
                "page_size": int(query.get("page_size", ["500"])[0]),
                "has_next": False,
            })
            return
        if path.startswith("/api/v1/events/"):
            if not self._require("engine-token"):
                return
            event_id = path.rsplit("/", 1)[-1]
            with state.lock:
                event = next((item for item in state.events if item["event_id"] == event_id), None)
            self._json(200 if event else 404, event or {"detail": "not found"})
            return
        if path.startswith("/api/v1/incidents/"):
            if not self._require("agent-token"):
                return
            incident_id = path.rsplit("/", 1)[-1]
            event_id = next(iter(state.tasks.values()), {}).get("event_id")
            self._json(200, {
                "incident_id": incident_id,
                "linked_event_ids": [event_id] if event_id else [],
            })
            return
        if path.startswith("/api/v1/agent-tasks/"):
            if not self._require("agent-token"):
                return
            task_id = path.rsplit("/", 1)[-1]
            with state.lock:
                task = state.tasks.get(task_id)
            self._json(200 if task else 404, task or {"detail": "not found"})
            return
        if path in {"/api/v1/findings", "/api/v1/findings/"}:
            if not self._require("agent-token"):
                return
            task_id = query.get("task_id", [None])[0]
            with state.lock:
                findings = [
                    item for item in state.findings.values()
                    if task_id is None or item["task_id"] == task_id
                ]
            self._json(200, {
                "items": findings, "total": len(findings), "page": 1,
                "page_size": 10, "has_next": False,
            })
            return
        if path.startswith("/api/v1/findings/"):
            if not self._require("agent-token"):
                return
            finding_id = path.rsplit("/", 1)[-1]
            with state.lock:
                finding = state.findings.get(finding_id)
            self._json(200 if finding else 404, finding or {"detail": "not found"})
            return
        if path in {"/api/v1/audit", "/api/v1/audit/"}:
            if not self._require("operator-token"):
                return
            resource_id = query.get("resource_id", [""])[0]
            with state.lock:
                items = list(state.audit.get(resource_id, []))
            self._json(200, {"items": items, "total": len(items), "page": 1, "page_size": 50, "has_next": False})
            return
        self._json(404, {"detail": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        state = self.state

        if parsed.path == "/api/v1/events":
            if not self._require("engine-token"):
                return
            state.engine_authorizations.append(self.headers.get("Authorization", ""))
            event = dict(payload)
            event["ingested_at"] = _now()
            with state.lock:
                state.events.append(event)
                _audit(state, str(event["event_id"]), "EVENT_INGESTED")
            self._json(201, event)
            return
        if parsed.path == "/api/v1/incidents":
            if not self._require("operator-token"):
                return
            incident_id = f"incident-{uuid.uuid4().hex[:8]}"
            event_id = payload["event_ids"][0]
            with state.lock:
                _audit(state, incident_id, "INCIDENT_CREATED")
            self._json(201, {
                "incident_id": incident_id,
                "severity": payload["severity"],
                "linked_event_ids": [event_id],
            })
            return
        if parsed.path == "/api/v1/agent-tasks":
            if not self._require("operator-token"):
                return
            task_id = f"task-{uuid.uuid4().hex[:8]}"
            finding_id = f"finding-{uuid.uuid4().hex[:8]}"
            completed = state.complete_tasks
            task = {
                "task_id": task_id,
                "task_type": payload["task_type"],
                "status": "COMPLETED" if completed else "PENDING",
                "event_id": payload["event_id"],
                "incident_id": payload["incident_id"],
            }
            finding = {
                "finding_id": finding_id,
                "task_id": task_id,
                "event_id": payload["event_id"],
                "status": "SUCCESS",
            }
            with state.lock:
                state.tasks[task_id] = task
                if completed:
                    state.findings[finding_id] = finding
                state.task_idempotency_keys.append(self.headers.get("Idempotency-Key", ""))
                _audit(state, task_id, "TASK_CREATED", "TASK_STARTED", *(('TASK_COMPLETED',) if completed else ()))
                if completed:
                    _audit(state, finding_id, "FINDING_SUBMITTED")
            self._json(201, task)
            return
        self._json(404, {"detail": "not found"})

    def log_message(self, *_args: object) -> None:
        pass


@pytest.fixture
def mock_stack(tmp_path: Path):
    state = SmokeState()
    handler = type("BoundSmokeHandler", (SmokeHandler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _write_fake_engine(tmp_path: Path) -> Path:
    engine = tmp_path / "fake-production-engine.py"
    engine.write_text(
        """#!/usr/bin/env python3
import json
import os
import sys
import urllib.request

with open(os.environ['FAKE_ENGINE_ARGS'], 'w', encoding='utf-8') as stream:
    json.dump(sys.argv[1:], stream)
if os.environ.get('FAKE_ENGINE_EMIT') != '1':
    raise SystemExit(0)
payload = {
    'event_id': 'fresh-' + os.urandom(4).hex(),
    'event_type': 'PORT_SCAN',
    'severity': 'HIGH',
    'timestamp': '2023-11-14T22:13:20+00:00',
    'source_address': '192.0.2.10',
    'destination_address': '198.51.100.20',
    'description': 'Synthetic production detector event',
    'details': {'detector': 'port_scan'},
}
endpoint = os.environ['INTRIQO_CONTROL_PLANE_URL'].rstrip('/') + os.environ.get('INTRIQO_CONTROL_PLANE_ENDPOINT', '/api/v1/events')
request = urllib.request.Request(endpoint, data=json.dumps(payload).encode(), method='POST', headers={
    'Authorization': 'Bearer ' + os.environ['INTRIQO_CONTROL_PLANE_TOKEN'],
    'Content-Type': 'application/json',
})
with urllib.request.urlopen(request, timeout=3) as response:
    raise SystemExit(0 if response.status == 201 else 1)
""",
        encoding="utf-8",
    )
    engine.chmod(engine.stat().st_mode | stat.S_IXUSR)
    return engine


def _run_smoke(tmp_path: Path, base_url: str, *, emit: bool) -> subprocess.CompletedProcess[str]:
    engine = _write_fake_engine(tmp_path)
    args_file = tmp_path / "engine-args.json"
    env_file = tmp_path / "smoke.env"
    env_file.write_text(
        "\n".join([
            "APP_ENV=development",
            "INTRIQO_PYTHON=" + sys.executable,
            "INTRIQO_ENGINE_ENABLED=true",
            "INTRIQO_ML_ENABLED=false",
            "INTRIQO_ENGINE_BIN=" + str(engine),
            "INTRIQO_CONTROL_PLANE_URL=" + base_url,
            "INTRIQO_CONTROL_PLANE_ENDPOINT=/api/v1/events",
            "FRONTEND_BASE_URL=" + base_url,
            "INTRIQO_CONTROL_PLANE_TOKEN=engine-token",
            "INTRIQO_AGENT_TOKEN=agent-token",
            "INTRIQO_OPERATOR_TOKEN=operator-token",
            "INTRIQO_RUNTIME_DIR=" + str(tmp_path / "runtime"),
        ]) + "\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.startswith("INTRIQO_"):
            environment.pop(key)
    environment.update({
        "FAKE_ENGINE_ARGS": str(args_file),
        "FAKE_ENGINE_EMIT": "1" if emit else "0",
    })
    return subprocess.run(
        [str(SMOKE), "--env-file", str(env_file), "--timeout", "3"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def test_smoke_requires_a_new_authenticated_engine_event(tmp_path: Path, mock_stack) -> None:
    state, base_url = mock_stack
    result = _run_smoke(tmp_path, base_url, emit=True)

    assert result.returncode == 0, result.stderr
    assert "SMOKE PASS" in result.stdout
    assert state.engine_authorizations == ["Bearer engine-token"]
    assert state.task_idempotency_keys and state.task_idempotency_keys[0].startswith("intriqo-smoke-")
    assert len(state.events) == 2
    args = json.loads((tmp_path / "engine-args.json").read_text(encoding="utf-8"))
    assert {"--synthetic", "--sink", "http", "--control-plane-url"} <= set(args)
    assert args[args.index("--sink") + 1] == "http"
    assert args[args.index("--control-plane-url") + 1] == base_url


def test_smoke_rejects_persisted_event_when_engine_emits_nothing(tmp_path: Path, mock_stack) -> None:
    state, base_url = mock_stack
    result = _run_smoke(tmp_path, base_url, emit=False)

    assert result.returncode != 0
    assert "fresh" in result.stderr
    assert len(state.events) == 1
    assert not state.tasks


def test_smoke_rejects_fresh_event_when_agent_does_not_complete_task(tmp_path: Path, mock_stack) -> None:
    state, base_url = mock_stack
    state.complete_tasks = False
    result = _run_smoke(tmp_path, base_url, emit=True)

    assert result.returncode != 0
    assert "did not complete" in result.stderr
    assert len(state.events) == 2
    assert len(state.tasks) == 1
