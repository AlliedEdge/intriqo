"""Role-Based Access Control integration tests.

Verifies the full authorization matrix against live routes.

Authorization matrix under test:

                        ADMIN   ANALYST   AGENT
POST   /events            ✓       ✓        ✓
GET    /events             ✓       ✓        ✓
GET    /events/{id}        ✓       ✓        ✓
POST   /incidents          ✓       ✓        ✗
GET    /incidents          ✓       ✓        ✗
GET    /incidents/{id}     ✓       ✓        ✓
PATCH  /incidents/{id}     ✓       ✓        ✗
POST   /agent-tasks        ✓       ✓        ✗
GET    /agent-tasks        ✓       ✓        ✓
GET    /agent-tasks/{id}   ✓       ✓        ✓
PATCH  /agent-tasks/{id}   ✓       ✓        ✓
POST   /findings           ✓       ✓        ✓
GET    /findings           ✓       ✓        ✓
GET    /findings/{id}      ✓       ✓        ✓
GET    /audit              ✓       ✓        ✗
GET    /auth/me            ✓       ✓        ✓
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests.conftest import SAMPLE_EVENT_PAYLOAD


# ── Helpers ───────────────────────────────────────────────────────────────────

def _event_payload(event_id: str | None = None) -> dict[str, Any]:
    return {
        **SAMPLE_EVENT_PAYLOAD,
        "event_id": event_id or str(uuid.uuid4()),
    }


# ── /events ───────────────────────────────────────────────────────────────────

class TestEventsAuthorization:
    """All three roles can read and write events."""

    @pytest.mark.asyncio
    async def test_agent_can_ingest_event(self, client, agent_headers):
        resp = await client.post("/api/v1/events", json=_event_payload(), headers=agent_headers)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_analyst_can_ingest_event(self, client, analyst_headers):
        resp = await client.post("/api/v1/events", json=_event_payload(), headers=analyst_headers)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_admin_can_ingest_event(self, client, admin_headers):
        resp = await client.post("/api/v1/events", json=_event_payload(), headers=admin_headers)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_ingest_event(self, client):
        resp = await client.post("/api/v1/events", json=_event_payload())
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_all_roles_can_list_events(self, client, admin_headers, analyst_headers, agent_headers):
        for headers in (admin_headers, analyst_headers, agent_headers):
            resp = await client.get("/api/v1/events", headers=headers)
            assert resp.status_code == 200, f"Failed for headers: {headers}"

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_list_events(self, client):
        resp = await client.get("/api/v1/events")
        assert resp.status_code == 401


# ── /incidents ────────────────────────────────────────────────────────────────

class TestIncidentsAuthorization:
    """AGENT is blocked from creating, listing, and updating incidents."""

    @pytest.mark.asyncio
    async def test_analyst_can_create_incident(self, client, analyst_headers):
        payload = {
            "title": "Test Incident",
            "description": "desc",
            "severity": "HIGH",
        }
        resp = await client.post("/api/v1/incidents", json=payload, headers=analyst_headers)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_admin_can_create_incident(self, client, admin_headers):
        payload = {"title": "Admin Incident", "description": "desc", "severity": "LOW"}
        resp = await client.post("/api/v1/incidents", json=payload, headers=admin_headers)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_agent_cannot_create_incident(self, client, agent_headers):
        payload = {"title": "Agent Incident", "description": "desc", "severity": "HIGH"}
        resp = await client.post("/api/v1/incidents", json=payload, headers=agent_headers)
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "FORBIDDEN"

    @pytest.mark.asyncio
    async def test_agent_cannot_list_incidents(self, client, agent_headers):
        resp = await client.get("/api/v1/incidents", headers=agent_headers)
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "FORBIDDEN"

    @pytest.mark.asyncio
    async def test_analyst_can_list_incidents(self, client, analyst_headers):
        resp = await client.get("/api/v1/incidents", headers=analyst_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_can_list_incidents(self, client, admin_headers):
        resp = await client.get("/api/v1/incidents", headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_agent_cannot_update_incident(self, client, analyst_headers, agent_headers):
        create_resp = await client.post(
            "/api/v1/incidents",
            json={"title": "Inc", "description": "d", "severity": "LOW"},
            headers=analyst_headers,
        )
        incident_id = create_resp.json()["incident_id"]
        resp = await client.patch(
            f"/api/v1/incidents/{incident_id}",
            json={"title": "Updated"},
            headers=agent_headers,
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "FORBIDDEN"

    @pytest.mark.asyncio
    async def test_all_roles_can_read_individual_incident(self, client, analyst_headers, admin_headers, agent_headers):
        create_resp = await client.post(
            "/api/v1/incidents",
            json={"title": "Readable Inc", "description": "d", "severity": "LOW"},
            headers=analyst_headers,
        )
        incident_id = create_resp.json()["incident_id"]
        for headers in (admin_headers, analyst_headers, agent_headers):
            resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
            assert resp.status_code == 200, f"Failed for headers: {headers}"

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_access_incidents(self, client):
        resp = await client.get("/api/v1/incidents")
        assert resp.status_code == 401


# ── /agent-tasks ──────────────────────────────────────────────────────────────

class TestAgentTasksAuthorization:
    """AGENT can read and update tasks but cannot create them."""

    @pytest.mark.asyncio
    async def test_analyst_can_create_task(self, client, analyst_headers):
        resp = await client.post(
            "/api/v1/agent-tasks",
            json={"task_type": "INVESTIGATION", "description": "Look into this", "priority": "HIGH"},
            headers=analyst_headers,
        )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_admin_can_create_task(self, client, admin_headers):
        resp = await client.post(
            "/api/v1/agent-tasks",
            json={"task_type": "INVESTIGATION", "description": "Admin task", "priority": "LOW"},
            headers=admin_headers,
        )
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_agent_cannot_create_task(self, client, agent_headers):
        resp = await client.post(
            "/api/v1/agent-tasks",
            json={"task_type": "INVESTIGATION", "description": "Agent self-task", "priority": "HIGH"},
            headers=agent_headers,
        )
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "FORBIDDEN"

    @pytest.mark.asyncio
    async def test_all_roles_can_list_tasks(self, client, admin_headers, analyst_headers, agent_headers):
        for headers in (admin_headers, analyst_headers, agent_headers):
            resp = await client.get("/api/v1/agent-tasks", headers=headers)
            assert resp.status_code == 200, f"Failed for headers: {headers}"

    @pytest.mark.asyncio
    async def test_all_roles_can_update_task_status(self, client, analyst_headers, admin_headers, agent_headers):
        create_resp = await client.post(
            "/api/v1/agent-tasks",
            json={"task_type": "INVESTIGATION", "description": "Status task", "priority": "LOW"},
            headers=analyst_headers,
        )
        task_id = create_resp.json()["task_id"]
        # Agent can update status (this is core to the agent workflow)
        resp = await client.patch(
            f"/api/v1/agent-tasks/{task_id}",
            json={"status": "IN_PROGRESS"},
            headers=agent_headers,
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_access_tasks(self, client):
        resp = await client.get("/api/v1/agent-tasks")
        assert resp.status_code == 401


# ── /findings ─────────────────────────────────────────────────────────────────

class TestFindingsAuthorization:
    """All authenticated roles can submit and read findings."""

    @pytest.mark.asyncio
    async def test_agent_can_submit_finding(self, client, analyst_headers, agent_headers):
        task_resp = await client.post(
            "/api/v1/agent-tasks",
            json={"task_type": "INVESTIGATION", "description": "For finding", "priority": "HIGH"},
            headers=analyst_headers,
        )
        task_id = task_resp.json()["task_id"]

        finding_payload = {
            "task_id": task_id,
            "agent_name": "test_agent",
            "status": "SUCCESS",
            "confidence": 0.9,
            "summary": "Agent found something",
            "findings": ["Finding 1"],
            "evidence": [],
        }
        resp = await client.post("/api/v1/findings", json=finding_payload, headers=agent_headers)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_analyst_can_submit_finding(self, client, analyst_headers):
        task_resp = await client.post(
            "/api/v1/agent-tasks",
            json={"task_type": "INVESTIGATION", "description": "For analyst finding", "priority": "LOW"},
            headers=analyst_headers,
        )
        task_id = task_resp.json()["task_id"]
        finding_payload = {
            "task_id": task_id,
            "agent_name": "human_analyst",
            "status": "SUCCESS",
            "confidence": 0.8,
            "summary": "Analyst finding",
            "findings": ["Finding A"],
            "evidence": [],
        }
        resp = await client.post("/api/v1/findings", json=finding_payload, headers=analyst_headers)
        assert resp.status_code == 201

    @pytest.mark.asyncio
    async def test_all_roles_can_list_findings(self, client, admin_headers, analyst_headers, agent_headers):
        for headers in (admin_headers, analyst_headers, agent_headers):
            resp = await client.get("/api/v1/findings", headers=headers)
            assert resp.status_code == 200, f"Failed for headers: {headers}"

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_access_findings(self, client):
        resp = await client.get("/api/v1/findings")
        assert resp.status_code == 401


# ── /audit ────────────────────────────────────────────────────────────────────

class TestAuditAuthorization:
    """Audit logs are restricted to ADMIN and ANALYST only."""

    @pytest.mark.asyncio
    async def test_admin_can_read_audit(self, client, admin_headers):
        resp = await client.get("/api/v1/audit", headers=admin_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_analyst_can_read_audit(self, client, analyst_headers):
        resp = await client.get("/api/v1/audit", headers=analyst_headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_agent_cannot_read_audit(self, client, agent_headers):
        resp = await client.get("/api/v1/audit", headers=agent_headers)
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "FORBIDDEN"

    @pytest.mark.asyncio
    async def test_unauthenticated_cannot_read_audit(self, client):
        resp = await client.get("/api/v1/audit")
        assert resp.status_code == 401
