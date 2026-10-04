"""Integration tests for the read-only audit log API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from intriqo.db.models.audit_log import AuditLog


async def _seed_logs(db):
    base_time = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
    logs = [
        AuditLog(
            id="audit-1",
            actor="analyst",
            action="INCIDENT_CREATED",
            resource_type="incident",
            resource_id="incident-1",
            outcome="SUCCESS",
            detail=None,
            extra={"severity": "HIGH"},
            created_at=base_time,
        ),
        AuditLog(
            id="audit-2",
            actor="agent",
            action="TASK_FAILED",
            resource_type="agent_task",
            resource_id="task-1",
            outcome="FAILURE",
            detail="Investigation failed",
            extra={},
            created_at=base_time + timedelta(minutes=1),
        ),
        AuditLog(
            id="audit-3",
            actor="analyst",
            action="INCIDENT_UPDATED",
            resource_type="incident",
            resource_id="incident-1",
            outcome="SUCCESS",
            detail="Status changed",
            extra={},
            created_at=base_time + timedelta(minutes=2),
        ),
    ]
    db.add_all(logs)
    await db.flush()


@pytest.mark.asyncio
async def test_list_audit_logs_requires_authentication(client):
    resp = await client.get("/api/v1/audit")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_audit_logs_pagination_and_response_shape(client, db, analyst_headers):
    await _seed_logs(db)

    resp = await client.get(
        "/api/v1/audit?page=1&page_size=2",
        headers=analyst_headers,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["has_next"] is True
    assert [item["id"] for item in body["items"]] == ["audit-3", "audit-2"]
    assert body["items"][0]["resource_type"] == "incident"
    assert body["items"][0]["extra"] == {}


@pytest.mark.asyncio
async def test_list_audit_logs_filters(client, db, analyst_headers):
    await _seed_logs(db)

    resp = await client.get(
        "/api/v1/audit?action=INCIDENT_CREATED&resource_type=incident&outcome=SUCCESS",
        headers=analyst_headers,
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == "audit-1"


@pytest.mark.asyncio
async def test_agent_cannot_read_audit_logs(client, db, agent_headers):
    """AGENT role must be denied access to the audit log (ADMIN/ANALYST only)."""
    await _seed_logs(db)
    resp = await client.get("/api/v1/audit", headers=agent_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_admin_can_read_audit_logs(client, db, admin_headers):
    """ADMIN must have full access to the audit log."""
    await _seed_logs(db)
    resp = await client.get("/api/v1/audit", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 3
