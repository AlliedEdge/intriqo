"""Focused Control Plane tests for the SOC workflow invariants."""

from __future__ import annotations

import uuid

import pytest


def _event(event_type: str, timestamp: str, *, event_id: str | None = None) -> dict:
    return {
        "event_id": event_id or str(uuid.uuid4()),
        "event_type": event_type,
        "severity": "HIGH",
        "timestamp": timestamp,
        "source_address": "203.0.113.10",
        "destination_address": "198.51.100.20",
        "details": {"detector": event_type.lower()},
    }


@pytest.mark.asyncio
async def test_deterministic_correlation_uses_key_and_window(
    client, agent_headers, analyst_headers
):
    first = _event("PORT_SCAN", "2026-10-01T12:00:00Z")
    second = _event("PORT_SCAN", "2026-10-01T12:04:59Z")
    outside = _event("PORT_SCAN", "2026-10-01T12:10:00Z")
    for payload in (first, second, outside):
        response = await client.post("/api/v1/events", json=payload, headers=agent_headers)
        assert response.status_code == 201, response.text

    response = await client.get("/api/v1/incidents", headers=analyst_headers)
    assert response.status_code == 200, response.text
    incidents = response.json()["items"]
    correlated = [item for item in incidents if first["event_id"] in item["linked_event_ids"]]
    assert len(correlated) == 1
    assert set(correlated[0]["linked_event_ids"]) == {first["event_id"], second["event_id"]}
    related = [
        item for item in incidents
        if first["event_id"] in item["linked_event_ids"]
        or second["event_id"] in item["linked_event_ids"]
        or outside["event_id"] in item["linked_event_ids"]
    ]
    assert len(related) == 2


@pytest.mark.asyncio
async def test_lifecycle_rejects_skips_and_same_state_is_idempotent(
    client, analyst_headers
):
    created = await client.post(
        "/api/v1/incidents", json={"title": "Lifecycle"}, headers=analyst_headers
    )
    incident_id = created.json()["incident_id"]

    skipped = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "CONTAINED"},
        headers=analyst_headers,
    )
    assert skipped.status_code == 409
    assert skipped.json()["error"]["code"] == "INVALID_STATUS_TRANSITION"

    moved = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "INVESTIGATING"},
        headers=analyst_headers,
    )
    assert moved.status_code == 200
    repeated = await client.patch(
        f"/api/v1/incidents/{incident_id}",
        json={"status": "INVESTIGATING"},
        headers=analyst_headers,
    )
    assert repeated.status_code == 200
    assert repeated.json()["status"] == "INVESTIGATING"

    audit = await client.get(
        f"/api/v1/audit?resource_type=incident&resource_id={incident_id}",
        headers=analyst_headers,
    )
    assert audit.status_code == 200
    assert any(item["extra"].get("idempotent") is True for item in audit.json()["items"])


@pytest.mark.asyncio
async def test_duplicate_workflow_outcomes_and_relationships_are_traceable(
    client, agent_headers, analyst_headers
):
    event = _event("SYN_FLOOD", "2026-10-01T12:00:00Z")
    created_event = await client.post("/api/v1/events", json=event, headers=agent_headers)
    assert created_event.status_code == 201
    incident_id = created_event.json()["linked_incident_ids"][0]

    task_payload = {
        "task_type": "INVESTIGATION",
        "description": "Investigate SYN flood",
        "event_id": event["event_id"],
        "incident_id": incident_id,
    }
    first_task = await client.post(
        "/api/v1/agent-tasks", json=task_payload, headers=analyst_headers
    )
    retry_task = await client.post(
        "/api/v1/agent-tasks", json=task_payload, headers=analyst_headers
    )
    assert first_task.status_code == retry_task.status_code == 201
    assert first_task.json()["task_id"] == retry_task.json()["task_id"]
    task_id = first_task.json()["task_id"]

    finding_payload = {
        "task_id": task_id,
        "agent_name": "investigation_agent",
        "status": "SUCCESS",
        "confidence": 0.9,
        "evidence": [{"type": "syn_ratio", "syn_packets": 100, "ack_packets": 2}],
    }
    finding = await client.post(
        "/api/v1/findings", json=finding_payload, headers=agent_headers
    )
    retry_finding = await client.post(
        "/api/v1/findings", json=finding_payload, headers=agent_headers
    )
    assert finding.status_code == retry_finding.status_code == 201
    assert finding.json()["finding_id"] == retry_finding.json()["finding_id"]
    assert finding.json()["event_id"] == event["event_id"]
    assert finding.json()["incident_id"] == incident_id
    assert finding.json()["severity"] == "HIGH"
    assert finding.json()["source"] == "DETERMINISTIC"
    assert finding.json()["provenance"]["event_type"] == "SYN_FLOOD"
    assert finding.json()["evidence"][0]["event_id"] == event["event_id"]

    event_read = await client.get(
        f"/api/v1/events/{event['event_id']}", headers=analyst_headers
    )
    incident_read = await client.get(
        f"/api/v1/incidents/{incident_id}", headers=analyst_headers
    )
    task_read = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert task_id in event_read.json()["linked_task_ids"]
    assert finding.json()["finding_id"] in event_read.json()["linked_finding_ids"]
    assert task_id in incident_read.json()["linked_task_ids"]
    assert finding.json()["finding_id"] in incident_read.json()["linked_finding_ids"]
    assert incident_read.json()["event_count"] == 1
    assert incident_read.json()["task_count"] == 1
    assert incident_read.json()["finding_count"] == 1
    assert incident_read.json()["detection_sources"] == ["DETERMINISTIC"]
    assert finding.json()["finding_id"] in task_read.json()["finding_ids"]
    assert incident_read.json()["status"] == "OPEN"

    duplicate_event = await client.post("/api/v1/events", json=event, headers=agent_headers)
    assert duplicate_event.status_code == 409


@pytest.mark.asyncio
async def test_manual_incident_retry_returns_existing_correlated_incident(
    client, agent_headers, analyst_headers
):
    event = _event("PORT_SCAN", "2026-10-01T12:00:00Z")
    created = await client.post("/api/v1/events", json=event, headers=agent_headers)
    assert created.status_code == 201
    automatic_id = created.json()["linked_incident_ids"][0]

    retry = await client.post(
        "/api/v1/incidents",
        json={"title": "Analyst retry", "event_ids": [event["event_id"]]},
        headers=analyst_headers,
    )
    assert retry.status_code == 201
    assert retry.json()["incident_id"] == automatic_id

    incidents = await client.get("/api/v1/incidents", headers=analyst_headers)
    assert sum(event["event_id"] in item["linked_event_ids"] for item in incidents.json()["items"]) == 1


@pytest.mark.asyncio
async def test_agent_cannot_change_incident_lifecycle(client, agent_headers, analyst_headers):
    created = await client.post(
        "/api/v1/incidents", json={"title": "RBAC lifecycle"}, headers=analyst_headers
    )
    response = await client.patch(
        f"/api/v1/incidents/{created.json()['incident_id']}",
        json={"status": "INVESTIGATING"},
        headers=agent_headers,
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_ml_link_reuses_deterministic_incident_and_keeps_provenance(
    client, agent_headers, analyst_headers
):
    deterministic = _event("PORT_SCAN", "2026-10-01T12:00:00Z")
    ml = _event("ML_ANOMALY", "2026-10-01T12:04:00Z")
    ml["details"] = {
        "detection_source": "ML",
        "detector": "isolation_forest_v2",
        "result": {"flow_id": "8", "anomaly_score": 0.7, "threshold": 0.5},
    }
    first = await client.post("/api/v1/events", json=deterministic, headers=agent_headers)
    second = await client.post("/api/v1/events", json=ml, headers=agent_headers)
    assert first.status_code == second.status_code == 201
    incident_id = first.json()["linked_incident_ids"][0]
    assert second.json()["linked_incident_ids"] == []

    linked = await client.post(
        "/api/v1/incidents",
        json={"title": "Analyst-linked ML anomaly", "event_ids": [ml["event_id"]]},
        headers=analyst_headers,
    )
    assert linked.status_code == 201
    assert linked.json()["incident_id"] == incident_id
    assert set(linked.json()["linked_event_ids"]) == {
        deterministic["event_id"], ml["event_id"]
    }
    assert linked.json()["detection_sources"] == ["DETERMINISTIC", "ML"]

    ml_read = await client.get(f"/api/v1/events/{ml['event_id']}", headers=analyst_headers)
    assert ml_read.json()["details"]["detection_source"] == "ML"
    assert ml_read.json()["details"]["detector"] == "isolation_forest_v2"


@pytest.mark.asyncio
async def test_deterministic_event_reuses_an_earlier_analyst_linked_ml_incident(
    client, agent_headers, analyst_headers
):
    ml = _event("ML_ANOMALY", "2026-10-01T12:00:00Z")
    ml["details"] = {
        "detection_source": "ML",
        "detector": "isolation_forest_v2",
        "result": {"flow_id": "9", "anomaly_score": 0.8, "threshold": 0.5},
    }
    linked = await client.post(
        "/api/v1/events", json=ml, headers=agent_headers
    )
    assert linked.status_code == 201
    incident = await client.post(
        "/api/v1/incidents",
        json={"title": "Analyst ML review", "event_ids": [ml["event_id"]]},
        headers=analyst_headers,
    )
    assert incident.status_code == 201
    incident_id = incident.json()["incident_id"]

    deterministic = _event("PORT_SCAN", "2026-10-01T12:04:00Z")
    created = await client.post(
        "/api/v1/events", json=deterministic, headers=agent_headers
    )
    assert created.status_code == 201
    assert created.json()["linked_incident_ids"] == [incident_id]

    incidents = await client.get("/api/v1/incidents", headers=analyst_headers)
    assert sum(
        deterministic["event_id"] in item["linked_event_ids"]
        for item in incidents.json()["items"]
    ) == 1
