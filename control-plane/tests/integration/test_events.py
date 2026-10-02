"""Integration tests for SecurityEvent API."""

from __future__ import annotations

import uuid
import pytest

from tests.conftest import SAMPLE_EVENT_PAYLOAD


def fresh_event(overrides: dict | None = None) -> dict:
    """Return a valid event payload with a unique event_id."""
    payload = dict(SAMPLE_EVENT_PAYLOAD)
    payload["event_id"] = str(uuid.uuid4())
    if overrides:
        payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_post_event_success(client, agent_headers):
    payload = fresh_event()
    resp = await client.post("/api/v1/events", json=payload, headers=agent_headers)
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["event_id"] == payload["event_id"]
    assert body["severity"] == "HIGH"
    assert body["event_type"] == "PORT_SCAN"
    assert "ingested_at" in body


@pytest.mark.asyncio
async def test_post_event_duplicate_returns_409(client, agent_headers):
    payload = fresh_event()
    await client.post("/api/v1/events", json=payload, headers=agent_headers)
    resp = await client.post("/api/v1/events", json=payload, headers=agent_headers)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "DUPLICATE_EVENT"


@pytest.mark.asyncio
async def test_post_event_invalid_severity_returns_422(client, agent_headers):
    payload = fresh_event({"severity": "EXTREME"})
    resp = await client.post("/api/v1/events", json=payload, headers=agent_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_post_event_requires_auth(client):
    resp = await client.post("/api/v1/events", json=fresh_event())
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_event_by_id(client, agent_headers):
    payload = fresh_event()
    await client.post("/api/v1/events", json=payload, headers=agent_headers)
    resp = await client.get(f"/api/v1/events/{payload['event_id']}", headers=agent_headers)
    assert resp.status_code == 200
    assert resp.json()["event_id"] == payload["event_id"]


@pytest.mark.asyncio
async def test_get_event_not_found(client, agent_headers):
    resp = await client.get("/api/v1/events/nonexistent-id", headers=agent_headers)
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "EVENT_NOT_FOUND"


@pytest.mark.asyncio
async def test_list_events_pagination(client, agent_headers):
    # Post 3 events
    for _ in range(3):
        await client.post("/api/v1/events", json=fresh_event(), headers=agent_headers)

    resp = await client.get("/api/v1/events?page=1&page_size=2", headers=agent_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert "total" in body
    assert len(body["items"]) <= 2


@pytest.mark.asyncio
async def test_list_events_filter_by_severity(client, agent_headers):
    low_evt = fresh_event({"severity": "LOW"})
    crit_evt = fresh_event({"severity": "CRITICAL"})
    await client.post("/api/v1/events", json=low_evt, headers=agent_headers)
    await client.post("/api/v1/events", json=crit_evt, headers=agent_headers)

    resp = await client.get("/api/v1/events?severity=CRITICAL", headers=agent_headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_list_events_filter_by_source_ip(client, agent_headers):
    target_ip = "192.168.99.99"
    evt = fresh_event({"source_address": target_ip})
    await client.post("/api/v1/events", json=evt, headers=agent_headers)

    resp = await client.get(f"/api/v1/events?source_address={target_ip}", headers=agent_headers)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert item["source_address"] == target_ip
