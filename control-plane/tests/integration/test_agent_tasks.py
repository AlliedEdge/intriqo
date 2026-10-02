"""Integration tests for AgentTask API."""

from __future__ import annotations

import uuid
import pytest


@pytest.mark.asyncio
async def test_create_task(client, analyst_headers):
    resp = await client.post(
        "/api/v1/agent-tasks",
        json={
            "task_type": "INVESTIGATION",
            "description": "Investigate port scan from 10.0.0.10",
            "priority": "HIGH",
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["task_type"] == "INVESTIGATION"
    assert body["status"] == "PENDING"
    assert body["priority"] == "HIGH"


@pytest.mark.asyncio
async def test_create_task_with_event_and_incident(client, agent_headers, analyst_headers):
    # Ingest an event
    event_id = str(uuid.uuid4())
    await client.post(
        "/api/v1/events",
        json={
            "event_id": event_id,
            "event_type": "PORT_SCAN",
            "severity": "HIGH",
            "timestamp": "2026-10-01T12:00:00Z",
            "source_address": "10.0.0.5",
            "destination_address": "10.0.0.6",
        },
        headers=agent_headers,
    )
    # Create incident
    inc_resp = await client.post(
        "/api/v1/incidents",
        json={"title": "Port scan incident", "event_ids": [event_id]},
        headers=analyst_headers,
    )
    incident_id = inc_resp.json()["incident_id"]

    # Create task linked to both
    resp = await client.post(
        "/api/v1/agent-tasks",
        json={
            "task_type": "INVESTIGATION",
            "description": "Investigate the incident",
            "event_id": event_id,
            "incident_id": incident_id,
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["event_id"] == event_id
    assert body["incident_id"] == incident_id


@pytest.mark.asyncio
async def test_get_task(client, analyst_headers):
    create_resp = await client.post(
        "/api/v1/agent-tasks",
        json={"task_type": "CORRELATION", "description": "Correlate events"},
        headers=analyst_headers,
    )
    task_id = create_resp.json()["task_id"]

    resp = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["task_id"] == task_id


@pytest.mark.asyncio
async def test_get_task_not_found(client, analyst_headers):
    resp = await client.get("/api/v1/agent-tasks/no-such-task", headers=analyst_headers)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "TASK_NOT_FOUND"


@pytest.mark.asyncio
async def test_list_tasks_filter_by_status(client, analyst_headers):
    await client.post(
        "/api/v1/agent-tasks",
        json={"task_type": "INVESTIGATION", "description": "Pending task"},
        headers=analyst_headers,
    )
    resp = await client.get("/api/v1/agent-tasks?status=PENDING", headers=analyst_headers)
    assert resp.status_code == 200
    for task in resp.json()["items"]:
        assert task["status"] == "PENDING"
