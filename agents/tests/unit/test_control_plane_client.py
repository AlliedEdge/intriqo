"""HTTP boundary and remote deterministic investigation tests."""

from datetime import datetime, timezone
import httpx

from intriqo_agents.control_plane.client import ControlPlaneClient, ControlPlaneNotFound
from intriqo_agents.investigation.agent import InvestigationAgent


def test_client_uses_bearer_and_maps_not_found() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret"
        return httpx.Response(404, json={"error": {"code": "EVENT_NOT_FOUND"}})

    with ControlPlaneClient("http://control", "secret", transport=httpx.MockTransport(handler)) as client:
        try:
            client.get_event("missing")
        except ControlPlaneNotFound as exc:
            assert exc.status_code == 404
        else:
            raise AssertionError("expected ControlPlaneNotFound")


def test_remote_port_scan_lifecycle_and_idempotent_replay() -> None:
    task = {"task_id": "task-1", "task_type": "INVESTIGATION", "description": "scan",
            "priority": "HIGH", "status": "PENDING", "event_id": "event-1",
            "incident_id": "incident-1", "context": {},
            "created_at": datetime.now(timezone.utc).isoformat(), "updated_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": None}
    event = {"event_id": "event-1", "event_type": "PORT_SCAN", "severity": "HIGH",
             "timestamp": "2026-10-01T12:00:00Z", "source_address": "10.0.0.1",
             "destination_address": "10.0.0.2", "description": "scan",
             "details": {"targeted_ports": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], "connection_attempts": 10,
                         "scan_threshold": 10, "detector_name": "PortScanDetector"}, "ingested_at": "2026-10-01T12:00:00Z"}
    incident = {"incident_id": "incident-1", "linked_event_ids": ["event-1"]}
    finding = {"finding_id": "finding-1", "task_id": "task-1", "agent_name": "investigation_agent",
               "status": "SUCCESS", "confidence": 0.95,
               "findings": ["PORT_SCAN_ANALYSIS: 10 unique ports"],
               "evidence": [{"type": "port_scan_analysis"}], "summary": "Port scan confirmed",
               "finding_metadata": {}, "error": None, "created_at": "2026-10-01T12:00:00Z"}
    state = {"finding": None, "status": "PENDING"}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/agent-tasks/task-1" and request.method == "GET":
            return httpx.Response(200, json={**task, "status": state["status"]})
        if path == "/api/v1/findings" and request.method == "GET":
            return httpx.Response(200, json={"items": [state["finding"]] if state["finding"] else [], "total": 1 if state["finding"] else 0})
        if path == "/api/v1/agent-tasks/task-1" and request.method == "PATCH":
            state["status"] = request.read().decode() and __import__("json").loads(request.content)["status"]
            return httpx.Response(200, json={**task, "status": state["status"]})
        if path == "/api/v1/incidents/incident-1":
            return httpx.Response(200, json=incident)
        if path == "/api/v1/events/event-1":
            return httpx.Response(200, json=event)
        if path == "/api/v1/findings" and request.method == "POST":
            state["finding"] = finding
            return httpx.Response(201, json=finding)
        raise AssertionError(f"unexpected {request.method} {path}")

    with ControlPlaneClient("http://control", "secret", transport=httpx.MockTransport(handler)) as client:
        result = InvestigationAgent().execute_task("task-1", client)
        assert result.status == "SUCCESS", result.error
        assert state["status"] == "COMPLETED"
        replay = InvestigationAgent().execute_task("task-1", client)
        assert replay.metadata["idempotent_replay"] is True
