"""Integration tests for Finding API and end-to-end chain."""

from __future__ import annotations

import uuid
import pytest


async def _create_full_chain(client, agent_headers, analyst_headers):
    """Helper: POST event → create incident → create task. Returns (event_id, incident_id, task_id)."""
    event_id = str(uuid.uuid4())
    await client.post(
        "/api/v1/events",
        json={
            "event_id": event_id,
            "event_type": "PORT_SCAN",
            "severity": "CRITICAL",
            "timestamp": "2026-10-01T13:00:00Z",
            "source_address": "10.2.2.2",
            "destination_address": "10.2.2.3",
            "details": {"scanned_ports": 512},
        },
        headers=agent_headers,
    )

    inc_resp = await client.post(
        "/api/v1/incidents",
        json={"title": "Critical scan", "severity": "CRITICAL", "event_ids": [event_id]},
        headers=analyst_headers,
    )
    incident_id = inc_resp.json()["incident_id"]

    task_resp = await client.post(
        "/api/v1/agent-tasks",
        json={
            "task_type": "INVESTIGATION",
            "description": "Investigate critical port scan",
            "priority": "URGENT",
            "event_id": event_id,
            "incident_id": incident_id,
        },
        headers=analyst_headers,
    )
    task_id = task_resp.json()["task_id"]
    return event_id, incident_id, task_id


@pytest.mark.asyncio
async def test_submit_finding(client, agent_headers, analyst_headers):
    _, _, task_id = await _create_full_chain(client, agent_headers, analyst_headers)

    resp = await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": "investigation_agent",
            "status": "SUCCESS",
            "confidence": 0.95,
            "findings": ["Port scan confirmed from 10.2.2.2"],
            "evidence": [{"type": "flow_count", "count": 512}],
            "summary": "Port scan confirmed.",
        },
        headers=agent_headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "SUCCESS"
    assert body["confidence"] == 0.95
    assert body["task_id"] == task_id


@pytest.mark.asyncio
async def test_submit_finding_marks_task_completed(client, agent_headers, analyst_headers):
    _, _, task_id = await _create_full_chain(client, agent_headers, analyst_headers)

    await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": "investigation_agent",
            "status": "SUCCESS",
            "confidence": 0.9,
        },
        headers=agent_headers,
    )

    task_resp = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert task_resp.json()["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_submit_finding_unknown_task(client, agent_headers):
    resp = await client.post(
        "/api/v1/findings",
        json={
            "task_id": "no-such-task-id",
            "agent_name": "agent",
            "status": "FAILED",
            "confidence": 0.0,
        },
        headers=agent_headers,
    )
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "TASK_NOT_FOUND"


@pytest.mark.asyncio
async def test_get_finding(client, agent_headers, analyst_headers):
    _, _, task_id = await _create_full_chain(client, agent_headers, analyst_headers)

    post_resp = await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": "investigation_agent",
            "status": "INCONCLUSIVE",
            "confidence": 0.5,
        },
        headers=agent_headers,
    )
    finding_id = post_resp.json()["finding_id"]

    get_resp = await client.get(f"/api/v1/findings/{finding_id}", headers=analyst_headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["finding_id"] == finding_id


@pytest.mark.asyncio
async def test_end_to_end_chain(client, agent_headers, analyst_headers):
    """
    Prove the full chain works:
    POST event → GET event → create incident → create task → submit finding → verify chain.
    """
    # 1. POST a realistic SecurityEvent
    event_id = str(uuid.uuid4())
    event_payload = {
        "event_id": event_id,
        "event_type": "PORT_SCAN",
        "severity": "HIGH",
        "timestamp": "2026-10-01T14:00:00.000Z",
        "source_address": "192.168.1.100",
        "destination_address": "10.0.0.50",
        "description": "Automated port scan detected",
        "details": {
            "scanned_ports": 1024,
            "scan_rate_pps": 500,
            "detection_threshold": 100,
        },
    }
    post_evt = await client.post("/api/v1/events", json=event_payload, headers=agent_headers)
    assert post_evt.status_code == 201

    # 2. Retrieve the event
    get_evt = await client.get(f"/api/v1/events/{event_id}", headers=analyst_headers)
    assert get_evt.status_code == 200
    assert get_evt.json()["event_id"] == event_id

    # 3. Create an incident referencing that event
    inc_resp = await client.post(
        "/api/v1/incidents",
        json={
            "title": "Port scan from 192.168.1.100",
            "severity": "HIGH",
            "event_ids": [event_id],
        },
        headers=analyst_headers,
    )
    assert inc_resp.status_code == 201
    incident_id = inc_resp.json()["incident_id"]
    assert event_id in inc_resp.json()["linked_event_ids"]

    # 4. Create an AgentTask for investigating the incident
    task_resp = await client.post(
        "/api/v1/agent-tasks",
        json={
            "task_type": "INVESTIGATION",
            "description": f"Investigate port scan incident {incident_id}",
            "priority": "HIGH",
            "event_id": event_id,
            "incident_id": incident_id,
        },
        headers=analyst_headers,
    )
    assert task_resp.status_code == 201
    task_id = task_resp.json()["task_id"]

    # 5. Submit a Finding for that task
    finding_resp = await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": "investigation_agent",
            "status": "SUCCESS",
            "confidence": 0.95,
            "findings": [
                "Port scan confirmed: 192.168.1.100 scanned 1024 ports on 10.0.0.50.",
                "Attacker probed ports: 21, 22, 80, 443, 3306, 5432, 8080...",
            ],
            "evidence": [
                {"type": "port_distribution", "distinct_port_count": 1024},
                {"type": "flow_telemetry", "total_flows": 1024, "total_packets": 1024},
            ],
            "summary": "Port scan confirmed with high confidence.",
            "finding_metadata": {"tool_used": "query_network_flows"},
        },
        headers=agent_headers,
    )
    assert finding_resp.status_code == 201
    finding_id = finding_resp.json()["finding_id"]

    # 6. Verify the complete chain exists and is accessible
    assert await client.get(f"/api/v1/events/{event_id}", headers=analyst_headers)
    assert await client.get(f"/api/v1/incidents/{incident_id}", headers=analyst_headers)
    assert await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert await client.get(f"/api/v1/findings/{finding_id}", headers=analyst_headers)

    # 7. Verify task was auto-completed
    final_task = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert final_task.json()["status"] == "COMPLETED"
