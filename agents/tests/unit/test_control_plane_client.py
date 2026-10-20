"""HTTP boundary and remote deterministic investigation tests."""

import json
import threading
import time
from datetime import datetime, timezone

import httpx
import pytest

from intriqo_agents.control_plane.client import ControlPlaneClient, ControlPlaneError, ControlPlaneNotFound
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


def test_client_lists_investigation_tasks() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret"
        assert request.url.params["task_type"] == "INVESTIGATION"
        assert request.url.params["page_size"] == "500"
        return httpx.Response(
            200,
            json={"items": [{"task_id": "task-1", "status": "PENDING"}]},
        )

    with ControlPlaneClient("http://control", "secret", transport=httpx.MockTransport(handler)) as client:
        assert client.list_tasks(task_type="INVESTIGATION") == [
            {"task_id": "task-1", "status": "PENDING"}
        ]


def test_client_claims_task_with_post_and_returns_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/v1/agent-tasks/task-1/claim"
        assert request.headers["authorization"] == "Bearer secret"
        assert "x-claim-token" not in request.headers
        assert request.content == b""
        return httpx.Response(
            200,
            json={"task_id": "task-1", "status": "IN_PROGRESS", "claim_token": "lease"},
        )

    with ControlPlaneClient("http://control", "secret", transport=httpx.MockTransport(handler)) as client:
        assert client.claim_task("task-1") == {
            "task_id": "task-1",
            "status": "IN_PROGRESS",
            "claim_token": "lease",
        }


def test_client_sends_claim_token_on_renewal_status_and_finding() -> None:
    seen: list[tuple[str, str, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.headers["x-claim-token"], request.content))
        if request.method == "POST" and request.url.path.endswith("/claim"):
            return httpx.Response(200, json={"status": "IN_PROGRESS", "claim_token": "lease"})
        if request.method == "PATCH":
            return httpx.Response(200, json={"status": "IN_PROGRESS"})
        return httpx.Response(201, json={"finding_id": "finding-1"})

    with ControlPlaneClient("http://control", "secret", transport=httpx.MockTransport(handler)) as client:
        client.renew_task_lease("task-1", "lease")
        client.update_task_status("task-1", "IN_PROGRESS", "lease")
        client.submit_finding({"task_id": "task-1"}, "lease")

    assert [method for method, _, _ in seen] == ["POST", "PATCH", "POST"]
    assert all(token == "lease" for _, token, _ in seen)


def test_client_requires_token_for_mutating_task_requests() -> None:
    with ControlPlaneClient(
        "http://control", "secret", transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as client:
        with pytest.raises(ValueError):
            client.update_task_status("task-1", "IN_PROGRESS")
        with pytest.raises(ValueError):
            client.submit_finding({"task_id": "task-1"})


def test_investigation_agent_rejects_direct_persisted_execution_without_token() -> None:
    result = InvestigationAgent().execute_task("task-1", object())
    assert result.status == "FAILED"
    assert "claim token" in result.error["message"]


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
            assert request.headers["x-claim-token"] == "lease"
            state["status"] = request.read().decode() and __import__("json").loads(request.content)["status"]
            return httpx.Response(200, json={**task, "status": state["status"]})
        if path == "/api/v1/incidents/incident-1":
            return httpx.Response(200, json=incident)
        if path == "/api/v1/events/event-1":
            return httpx.Response(200, json=event)
        if path == "/api/v1/findings" and request.method == "POST":
            assert request.headers["x-claim-token"] == "lease"
            state["finding"] = finding
            state["status"] = "COMPLETED"
            return httpx.Response(201, json=finding)
        raise AssertionError(f"unexpected {request.method} {path}")

    with ControlPlaneClient("http://control", "secret", transport=httpx.MockTransport(handler)) as client:
        result = InvestigationAgent().execute_task("task-1", client, "lease")
        assert result.status == "SUCCESS", result.error
        assert state["status"] == "COMPLETED"
        replay = InvestigationAgent().execute_task("task-1", client, "lease")
        assert replay.metadata["idempotent_replay"] is True


@pytest.mark.parametrize(
    ("event_type", "details", "expected_evidence"),
    [
        (
            "SYN_FLOOD",
            {
                "detector": "syn_flood", "destination_port": 443,
                "connection_attempts": 120, "incomplete_handshakes": 110,
                "incomplete_ratio": 0.91, "rate_per_second": 60.0,
            },
            "syn_flood_analysis",
        ),
        (
            "ML_ANOMALY",
            {
                "detection_source": "ML", "detector": "isolation_forest_v2",
                "result": {"flow_id": "8", "anomaly_score": 0.7, "threshold": 0.5,
                           "model_sha256": "a" * 64, "feature_schema_version": "flow_features.v2"},
            },
            "ml_anomaly_analysis",
        ),
    ],
)
def test_remote_supported_event_lifecycle(event_type, details, expected_evidence) -> None:
    state = {"status": "PENDING", "finding": None}
    task = {
        "task_id": "task-supported", "task_type": "INVESTIGATION", "description": "review",
        "priority": "HIGH", "status": "PENDING", "event_id": "event-supported",
        "incident_id": "incident-supported", "context": {},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(), "completed_at": None,
    }
    event = {
        "event_id": "event-supported", "event_type": event_type, "severity": "HIGH",
        "timestamp": "2026-10-01T12:00:00Z", "source_address": "10.0.0.1",
        "destination_address": "10.0.0.2", "details": details,
    }
    incident = {"incident_id": "incident-supported", "linked_event_ids": ["event-supported"]}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/api/v1/agent-tasks/task-supported" and request.method == "GET":
            return httpx.Response(200, json={**task, "status": state["status"]})
        if path == "/api/v1/findings" and request.method == "GET":
            items = [state["finding"]] if state["finding"] else []
            return httpx.Response(200, json={"items": items, "total": len(items)})
        if path == "/api/v1/agent-tasks/task-supported" and request.method == "PATCH":
            assert request.headers["x-claim-token"] == "lease"
            state["status"] = json.loads(request.content)["status"]
            return httpx.Response(200, json={**task, "status": state["status"]})
        if path == "/api/v1/incidents/incident-supported":
            return httpx.Response(200, json=incident)
        if path == "/api/v1/events/event-supported":
            return httpx.Response(200, json=event)
        if path == "/api/v1/findings" and request.method == "POST":
            assert request.headers["x-claim-token"] == "lease"
            body = json.loads(request.content)
            state["finding"] = {"finding_id": "finding-supported", **body}
            state["status"] = "COMPLETED"
            return httpx.Response(201, json=state["finding"])
        raise AssertionError(f"unexpected {request.method} {path}")

    with ControlPlaneClient("http://control", "secret", transport=httpx.MockTransport(handler)) as client:
        result = InvestigationAgent().execute_task("task-supported", client, "lease")

    assert result.status == "SUCCESS", result.error
    assert state["status"] == "COMPLETED"
    assert state["finding"]["event_id"] == "event-supported"
    assert state["finding"]["incident_id"] == "incident-supported"
    assert state["finding"]["evidence"][0]["type"] == expected_evidence


class _HeartbeatClient:
    def __init__(self, renewal_error: bool = False, malformed_renewal: bool = False) -> None:
        self.renewal_error = renewal_error
        self.malformed_renewal = malformed_renewal
        self.renewals: list[tuple[str, str]] = []
        self.statuses: list[tuple[str, str]] = []
        self.findings: list[tuple[dict, str]] = []

    def get_task(self, task_id):
        return {
            "task_id": task_id,
            "task_type": "INVESTIGATION",
            "description": "slow investigation",
            "priority": "HIGH",
            "status": "IN_PROGRESS",
            "event_id": "event-heartbeat",
            "incident_id": "incident-heartbeat",
            "context": {},
            "claim_expires_at": "2099-01-01T00:00:00Z",
        }

    def list_findings(self, task_id):
        return []

    def update_task_status(self, task_id, status, claim_token):
        self.statuses.append((status, claim_token))
        return {"task_id": task_id, "status": status}

    def get_incident(self, incident_id):
        return {"incident_id": incident_id, "linked_event_ids": ["event-heartbeat"]}

    def get_event(self, event_id):
        return {
            "event_id": event_id,
            "event_type": "PORT_SCAN",
            "severity": "HIGH",
            "timestamp": "2026-10-01T12:00:00Z",
            "source_address": "10.0.0.1",
            "destination_address": "10.0.0.2",
            "details": {"targeted_ports": [1, 2, 3]},
        }

    def get_related_events(self, event_ids):
        return [self.get_event(event_id) for event_id in event_ids]

    def submit_finding(self, finding, claim_token):
        self.findings.append((finding, claim_token))
        return {"finding_id": "finding-heartbeat", **finding}

    def renew_task_lease(self, task_id, claim_token):
        self.renewals.append((task_id, claim_token))
        if self.renewal_error:
            raise ControlPlaneError("lease ownership changed", status_code=409)
        if self.malformed_renewal:
            return {"task_id": task_id, "status": "IN_PROGRESS"}
        return {"task_id": task_id, "status": "IN_PROGRESS", "claim_token": claim_token}


class _SlowInvestigationAgent(InvestigationAgent):
    def _investigate_control_plane_event(self, task):
        time.sleep(0.06)
        return super()._investigate_control_plane_event(task)


def test_heartbeat_renews_during_long_running_investigation_and_joins() -> None:
    client = _HeartbeatClient()
    agent = _SlowInvestigationAgent(heartbeat_interval=0.01)

    result = agent.execute_task("task-heartbeat", client, "lease-token")

    assert result.status == "SUCCESS", result.error
    assert client.renewals
    assert client.statuses == [("IN_PROGRESS", "lease-token")]
    assert client.findings[0][1] == "lease-token"
    assert not [thread for thread in threading.enumerate() if thread.name == "intriqo-lease-task-heartbeat"]


def test_heartbeat_failure_suppresses_finding_and_failure_completion_write() -> None:
    client = _HeartbeatClient(renewal_error=True)
    agent = _SlowInvestigationAgent(heartbeat_interval=0.01)

    result = agent.execute_task("task-heartbeat-fail", client, "lease-token")

    assert result.status == "FAILED"
    assert result.metadata["lease_unsafe"] is True
    assert "lease_unsafe" not in result.error
    assert client.findings == []
    assert client.statuses == [("IN_PROGRESS", "lease-token")]


def test_malformed_heartbeat_response_is_treated_as_ownership_loss() -> None:
    client = _HeartbeatClient(malformed_renewal=True)
    agent = _SlowInvestigationAgent(heartbeat_interval=0.01)

    result = agent.execute_task("task-heartbeat-malformed", client, "lease-token")

    assert result.status == "FAILED"
    assert result.metadata["lease_unsafe"] is True
    assert "lease_unsafe" not in result.error
    assert client.findings == []
    assert client.statuses == [("IN_PROGRESS", "lease-token")]
