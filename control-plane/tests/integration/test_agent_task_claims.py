"""PostgreSQL integration coverage for atomic task claiming and ownership."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import update

from intriqo.db.models.agent_task import AgentTask


async def _create_task(client, analyst_headers) -> str:
    response = await client.post(
        "/api/v1/agent-tasks",
        json={"task_type": "INVESTIGATION", "description": "Claim me"},
        headers=analyst_headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["task_id"]


async def _finding(client, task_id: str, headers: dict[str, str], *, agent_name: str = "worker"):
    return await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": agent_name,
            "status": "SUCCESS",
            "confidence": 0.8,
        },
        headers=headers,
    )


@pytest.mark.asyncio
async def test_claim_unknown_task_returns_not_found(client, agent_headers):
    response = await client.post(
        "/api/v1/agent-tasks/missing-task/claim", headers=agent_headers
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "TASK_NOT_FOUND"


@pytest.mark.asyncio
async def test_valid_claim_returns_lease_and_is_agent_only(
    client, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)

    analyst_claim = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim", headers=analyst_headers
    )
    assert analyst_claim.status_code == 403

    claim = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)
    assert claim.status_code == 200, claim.text
    assert claim.json()["status"] == "IN_PROGRESS"
    assert claim.json()["claimed_by"] == "agent_service"
    assert claim.json()["claim_expires_at"] is not None

    renewed = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["claimed_by"] == "agent_service"


@pytest.mark.asyncio
async def test_active_claim_conflicts_with_another_agent(
    client, analyst_headers, agent_headers, other_agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    first = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)
    assert first.status_code == 200

    second = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim", headers=other_agent_headers
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "TASK_CLAIM_CONFLICT"


@pytest.mark.asyncio
async def test_expired_claim_can_be_reclaimed(client, db, analyst_headers, agent_headers, other_agent_headers):
    task_id = await _create_task(client, analyst_headers)
    first = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)
    assert first.status_code == 200

    await db.execute(
        update(AgentTask)
        .where(AgentTask.task_id == task_id)
        .values(claim_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db.commit()

    reclaimed = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim", headers=other_agent_headers
    )
    assert reclaimed.status_code == 200, reclaimed.text
    assert reclaimed.json()["claimed_by"] == "other_agent_service"


@pytest.mark.asyncio
async def test_expired_claim_rejects_status_and_finding(
    client, db, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    claimed = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)
    assert claimed.status_code == 200
    await db.execute(
        update(AgentTask)
        .where(AgentTask.task_id == task_id)
        .values(claim_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db.commit()

    status_response = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "COMPLETED"},
        headers=agent_headers,
    )
    assert status_response.status_code == 409
    assert status_response.json()["error"]["code"] == "TASK_CLAIM_EXPIRED"

    finding_response = await _finding(client, task_id, agent_headers)
    assert finding_response.status_code == 409
    assert finding_response.json()["error"]["code"] == "TASK_CLAIM_EXPIRED"


@pytest.mark.asyncio
async def test_terminal_task_is_not_claimable(client, analyst_headers, agent_headers):
    task_id = await _create_task(client, analyst_headers)
    assert (await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)).status_code == 200
    completed = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "COMPLETED"},
        headers=agent_headers,
    )
    assert completed.status_code == 200
    assert completed.json()["claimed_by"] is None
    assert completed.json()["claim_expires_at"] is None

    retry = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)
    assert retry.status_code == 409
    assert retry.json()["error"]["code"] == "TASK_NOT_CLAIMABLE"


@pytest.mark.asyncio
async def test_wrong_agent_cannot_update_status_or_submit_finding(
    client, analyst_headers, agent_headers, other_agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    assert (await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)).status_code == 200

    status_response = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "IN_PROGRESS"},
        headers=other_agent_headers,
    )
    assert status_response.status_code == 409
    assert status_response.json()["error"]["code"] == "TASK_NOT_OWNED"

    finding_response = await _finding(
        client, task_id, other_agent_headers, agent_name="agent_service"
    )
    assert finding_response.status_code == 409
    assert finding_response.json()["error"]["code"] == "TASK_NOT_OWNED"


@pytest.mark.asyncio
async def test_body_agent_name_is_only_a_label_and_authenticated_submitter_is_stored(
    client, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    assert (await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)).status_code == 200

    response = await _finding(client, task_id, agent_headers, agent_name="admin_user")
    assert response.status_code == 201, response.text
    assert response.json()["agent_name"] == "admin_user"
    assert response.json()["submitted_by"] == "agent_service"


@pytest.mark.asyncio
async def test_claimant_finding_is_idempotent_and_failure_clears_lease(
    client, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    assert (await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)).status_code == 200

    response = await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": "worker",
            "status": "FAILED",
            "confidence": 0.0,
            "error": {"message": "retryable tool failure"},
        },
        headers=agent_headers,
    )
    assert response.status_code == 201, response.text
    retry = await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": "worker",
            "status": "FAILED",
            "confidence": 0.0,
            "error": {"message": "retryable tool failure"},
        },
        headers=agent_headers,
    )
    assert retry.status_code == 201
    assert retry.json()["finding_id"] == response.json()["finding_id"]

    task = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert task.json()["status"] == "FAILED"
    assert task.json()["claimed_by"] is None
    assert task.json()["claim_expires_at"] is None


@pytest.mark.asyncio
async def test_human_status_and_finding_overrides_are_explicit_and_auditable(
    client, analyst_headers, admin_headers
):
    status_task_id = await _create_task(client, analyst_headers)
    denied = await client.patch(
        f"/api/v1/agent-tasks/{status_task_id}",
        json={"status": "FAILED"},
        headers=analyst_headers,
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "OVERRIDE_REQUIRED"

    overridden = await client.patch(
        f"/api/v1/agent-tasks/{status_task_id}?override=true",
        json={"status": "FAILED"},
        headers=admin_headers,
    )
    assert overridden.status_code == 200

    finding_task_id = await _create_task(client, analyst_headers)
    finding = await _finding(client, finding_task_id, analyst_headers)
    assert finding.status_code == 403
    finding = await client.post(
        "/api/v1/findings?override=true",
        json={
            "task_id": finding_task_id,
            "agent_name": "human-reviewer",
            "status": "SUCCESS",
            "confidence": 1.0,
        },
        headers=analyst_headers,
    )
    assert finding.status_code == 201, finding.text
    assert finding.json()["submitted_by"] == "analyst_user"

    audit = await client.get(
        f"/api/v1/audit?resource_type=agent_task&resource_id={status_task_id}",
        headers=analyst_headers,
    )
    assert audit.status_code == 200
    assert any(item["extra"].get("override") is True for item in audit.json()["items"])
