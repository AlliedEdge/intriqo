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
    assert body["details"]["detection_source"] == "DETERMINISTIC"
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


@pytest.mark.asyncio
async def test_ml_anomaly_authenticated_persistence_readback_and_duplicate(client, agent_headers):
    payload = fresh_event({
        "event_type": "ML_ANOMALY",
        "severity": "MEDIUM",
        "source_address": "192.0.2.10",
        "destination_address": "198.51.100.20",
        "description": "Locked ML detector anomaly",
        "details": {
            "detection_source": "ML",
            "detector": "isolation_forest_v2",
            "result": {
                "detector": "isolation_forest_v2",
                "model_version": "controlled-v2/isolation-forest-v2",
                "engine_instance_id": "engine-test-1",
                "flow_id": "7",
                "anomaly_score": 0.7,
                "threshold": 0.5153855054112947,
                "is_anomaly": True,
                "feature_schema_version": "flow_features.v2",
                "inference_timestamp": "2026-10-01T12:00:00.000Z",
                "model_sha256": "a" * 64,
                "threshold_sha256": "b" * 64,
            },
        },
    })

    created = await client.post("/api/v1/events", json=payload, headers=agent_headers)
    assert created.status_code == 201, created.text
    assert created.json()["event_type"] == "ML_ANOMALY"
    assert created.json()["details"] == payload["details"]

    read_back = await client.get(
        f"/api/v1/events/{payload['event_id']}", headers=agent_headers
    )
    assert read_back.status_code == 200, read_back.text
    assert read_back.json()["details"] == payload["details"]

    duplicate = await client.post("/api/v1/events", json=payload, headers=agent_headers)
    assert duplicate.status_code == 409, duplicate.text
    assert duplicate.json()["error"]["code"] == "DUPLICATE_EVENT"


@pytest.mark.asyncio
async def test_deterministic_and_ml_events_coexist_without_type_or_source_collapse(
    client, agent_headers
):
    deterministic = fresh_event({"event_type": "PORT_SCAN"})
    ml_event = fresh_event({
        "event_type": "ML_ANOMALY",
        "severity": "MEDIUM",
        "details": {
            "detection_source": "ML",
            "detector": "isolation_forest_v2",
            "result": {
                "detector": "isolation_forest_v2",
                "engine_instance_id": "engine-coexistence",
                "flow_id": "9",
                "anomaly_score": 0.7,
                "threshold": 0.5153855054112947,
                "is_anomaly": True,
            },
        },
    })
    for payload in (deterministic, ml_event):
        response = await client.post("/api/v1/events", json=payload, headers=agent_headers)
        assert response.status_code == 201, response.text

    deterministic_list = await client.get(
        "/api/v1/events?event_type=PORT_SCAN", headers=agent_headers
    )
    ml_list = await client.get("/api/v1/events?event_type=ML_ANOMALY", headers=agent_headers)
    assert deterministic_list.status_code == 200
    assert ml_list.status_code == 200
    assert [item["event_id"] for item in deterministic_list.json()["items"]] == [
        deterministic["event_id"]
    ]
    assert [item["event_id"] for item in ml_list.json()["items"]] == [ml_event["event_id"]]
    assert ml_list.json()["items"][0]["details"]["detection_source"] == "ML"
