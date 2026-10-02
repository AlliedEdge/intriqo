"""Integration tests for Incident API."""

from __future__ import annotations

import uuid
import pytest


@pytest.mark.asyncio
async def test_create_incident(client, analyst_headers):
    resp = await client.post(
        "/api/v1/incidents",
        json={"title": "Suspicious port scan", "severity": "HIGH"},
        headers=analyst_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["title"] == "Suspicious port scan"
    assert body["status"] == "OPEN"
    assert body["severity"] == "HIGH"
    assert "incident_id" in body


@pytest.mark.asyncio
async def test_create_incident_with_linked_event(client, agent_headers, analyst_headers):
    # First ingest an event
    event_payload = {
        "event_id": str(uuid.uuid4()),
        "event_type": "PORT_SCAN",
        "severity": "CRITICAL",
        "timestamp": "2026-10-01T12:00:00Z",
        "source_address": "10.1.1.1",
        "destination_address": "10.1.1.2",
    }
    evt_resp = await client.post("/api/v1/events", json=event_payload, headers=agent_headers)
    assert evt_resp.status_code == 201

    inc_resp = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Critical port scan incident",
            "severity": "CRITICAL",
            "event_ids": [event_payload["event_id"]],
        },
        headers=analyst_headers,
    )
    assert inc_resp.status_code == 201
    body = inc_resp.json()
    assert event_payload["event_id"] in body["linked_event_ids"]


@pytest.mark.asyncio
async def test_get_incident(client, analyst_headers):
    create_resp = await client.post(
        "/api/v1/incidents",
        json={"title": "Test incident"},
        headers=analyst_headers,
    )
    incident_id = create_resp.json()["incident_id"]

    resp = await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["incident_id"] == incident_id


@pytest.mark.asyncio
async def test_get_incident_not_found(client, analyst_headers):
    resp = await client.get("/api/v1/incidents/nonexistent", headers=analyst_headers)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "INCIDENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_update_incident_status(client, analyst_headers):
    create_resp = await client.post(
        "/api/v1/incidents",
        json={"title": "To resolve"},
        headers=analyst_headers,
    )
    incident_id = create_resp.json()["incident_id"]

    resp = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "RESOLVED"},
        headers=analyst_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "RESOLVED"
    assert body["resolved_at"] is not None


@pytest.mark.asyncio
async def test_list_incidents(client, analyst_headers):
    await client.post("/api/v1/incidents", json={"title": "Inc 1"}, headers=analyst_headers)
    await client.post("/api/v1/incidents", json={"title": "Inc 2"}, headers=analyst_headers)

    resp = await client.get("/api/v1/incidents", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 2


@pytest.mark.asyncio
async def test_incident_requires_auth(client):
    resp = await client.post("/api/v1/incidents", json={"title": "No auth"})
    assert resp.status_code == 401
