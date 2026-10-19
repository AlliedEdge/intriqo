"""PostgreSQL integration coverage for atomic task claiming and ownership."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from intriqo.api.app import create_app
from intriqo.db.models.agent_task import AgentTask
from intriqo.db.models.finding import Finding
from intriqo.db.session import get_db
from intriqo.services import audit_service
from tests.conftest import _ENGINE_KWARGS, TEST_DB_URL


async def _create_task(client, analyst_headers) -> str:
    response = await client.post(
        "/api/v1/agent-tasks",
        json={"task_type": "INVESTIGATION", "description": "Claim me"},
        headers=analyst_headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["task_id"]


async def _claim(client, task_id: str, headers: dict[str, str]) -> str:
    response = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["claim_token"]


async def _finding(client, task_id: str, headers: dict[str, str], *, agent_name: str = "worker"):
    claim_token = headers.get("X-Claim-Token")
    request_headers = dict(headers)
    if claim_token is None:
        request_headers.pop("X-Claim-Token", None)
    return await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": agent_name,
            "status": "SUCCESS",
            "confidence": 0.8,
        },
        headers=request_headers,
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
    assert claim.json()["claim_token"]
    assert "claim_token" not in (
        await client.get(f"/api/v1/agent-tasks/{task_id}", headers=agent_headers)
    ).json()
    listed = await client.get("/api/v1/agent-tasks", headers=agent_headers)
    assert listed.status_code == 200
    assert all("claim_token" not in item for item in listed.json()["items"])

    missing_status_token = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "IN_PROGRESS"},
        headers=agent_headers,
    )
    assert missing_status_token.status_code == 409
    assert missing_status_token.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"
    missing_finding_token = await _finding(client, task_id, agent_headers)
    assert missing_finding_token.status_code == 409
    assert missing_finding_token.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"

    missing_token_renewal = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers
    )
    assert missing_token_renewal.status_code == 409
    assert missing_token_renewal.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"
    renewal_headers = {**agent_headers, "X-Claim-Token": claim.json()["claim_token"]}
    renewed = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim", headers=renewal_headers
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["claimed_by"] == "agent_service"
    assert renewed.json()["claim_token"] == claim.json()["claim_token"]


@pytest.mark.asyncio
async def test_same_identity_renewal_rejects_mismatched_token(
    client, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    token = await _claim(client, task_id, agent_headers)

    response = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim",
        headers={**agent_headers, "X-Claim-Token": f"{token}-wrong"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"


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
async def test_concurrent_agents_race_and_only_one_claim_succeeds(
    client, db, analyst_headers, agent_headers, other_agent_headers
):
    """Two independent PostgreSQL request transactions cannot both claim one task."""
    task_id = await _create_task(client, analyst_headers)
    # The shared fixture session is used to create the task. Commit before the
    # independent request sessions race so both can observe the same row.
    await db.commit()

    engine = create_async_engine(TEST_DB_URL, **_ENGINE_KWARGS)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    app = create_app()

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with (
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as first,
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as second,
        ):
            responses = await asyncio.gather(
                first.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers),
                second.post(
                    f"/api/v1/agent-tasks/{task_id}/claim",
                    headers=other_agent_headers,
                ),
            )
    finally:
        await engine.dispose()

    assert sorted(response.status_code for response in responses) == [200, 409]
    success = next(response for response in responses if response.status_code == 200)
    conflict = next(response for response in responses if response.status_code == 409)
    assert success.json()["claimed_by"] in {"agent_service", "other_agent_service"}
    assert conflict.json()["error"]["code"] == "TASK_CLAIM_CONFLICT"


@pytest.mark.asyncio
async def test_concurrent_same_identity_claims_require_one_token_proof(
    client, db, analyst_headers, agent_headers
):
    """Two workers sharing an identity cannot both acquire an unproven lease."""
    task_id = await _create_task(client, analyst_headers)
    await db.commit()

    engine = create_async_engine(TEST_DB_URL, **_ENGINE_KWARGS)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    app = create_app()

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with (
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as first,
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as second,
        ):
            responses = await asyncio.gather(
                first.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers),
                second.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers),
            )
    finally:
        await engine.dispose()

    assert sorted(response.status_code for response in responses) == [200, 409]
    rejected = next(response for response in responses if response.status_code == 409)
    assert rejected.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"


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
    assert reclaimed.json()["claim_token"] != first.json()["claim_token"]


@pytest.mark.asyncio
async def test_expired_claim_token_cannot_renew_and_fresh_claim_gets_new_token(
    client, db, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    stale_token = await _claim(client, task_id, agent_headers)
    await db.execute(
        update(AgentTask)
        .where(AgentTask.task_id == task_id)
        .values(claim_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db.commit()

    stale_renewal = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim",
        headers={**agent_headers, "X-Claim-Token": stale_token},
    )
    assert stale_renewal.status_code == 409
    assert stale_renewal.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"

    fresh_claim = await client.post(
        f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers
    )
    assert fresh_claim.status_code == 200, fresh_claim.text
    assert fresh_claim.json()["claim_token"] != stale_token


@pytest.mark.asyncio
async def test_same_identity_reclaim_rejects_old_token_and_accepts_new_owner(
    client, db, analyst_headers, agent_headers
):
    """A restarted worker sharing the JWT cannot finish an old lease."""
    task_id = await _create_task(client, analyst_headers)
    token_a = await _claim(client, task_id, agent_headers)

    await db.execute(
        update(AgentTask)
        .where(AgentTask.task_id == task_id)
        .values(claim_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db.commit()

    token_b = await _claim(client, task_id, agent_headers)
    assert token_b != token_a

    stale_status = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "COMPLETED"},
        headers={**agent_headers, "X-Claim-Token": token_a},
    )
    assert stale_status.status_code == 409
    assert stale_status.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"

    stale_finding = await _finding(
        client,
        task_id,
        {**agent_headers, "X-Claim-Token": token_a},
        agent_name="stale-worker",
    )
    assert stale_finding.status_code == 409
    assert stale_finding.json()["error"]["code"] == "TASK_CLAIM_TOKEN_INVALID"

    valid_status = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "IN_PROGRESS"},
        headers={**agent_headers, "X-Claim-Token": token_b},
    )
    assert valid_status.status_code == 200, valid_status.text

    valid_finding = await _finding(
        client,
        task_id,
        {**agent_headers, "X-Claim-Token": token_b},
        agent_name="current-worker",
    )
    assert valid_finding.status_code == 201, valid_finding.text
    assert valid_finding.json()["submitted_by"] == "agent_service"

    final_task = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert final_task.status_code == 200
    assert final_task.json()["status"] == "COMPLETED"
    assert final_task.json()["claimed_by"] is None


@pytest.mark.asyncio
async def test_reclaimed_lease_rejects_stale_status_and_finding_token(
    client, db, analyst_headers, agent_headers, other_agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    stale_token = await _claim(client, task_id, agent_headers)
    await db.execute(
        update(AgentTask)
        .where(AgentTask.task_id == task_id)
        .values(claim_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db.commit()
    await _claim(client, task_id, other_agent_headers)

    status_response = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "COMPLETED"},
        headers={**agent_headers, "X-Claim-Token": stale_token},
    )
    assert status_response.status_code == 409
    assert status_response.json()["error"]["code"] == "TASK_NOT_OWNED"

    finding_response = await _finding(
        client,
        task_id,
        {**agent_headers, "X-Claim-Token": stale_token},
        agent_name="stale-worker",
    )
    assert finding_response.status_code == 409
    assert finding_response.json()["error"]["code"] == "TASK_NOT_OWNED"


@pytest.mark.asyncio
async def test_expired_claim_rejects_status_and_finding(
    client, db, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    claimed_token = await _claim(client, task_id, agent_headers)
    await db.execute(
        update(AgentTask)
        .where(AgentTask.task_id == task_id)
        .values(claim_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db.commit()

    status_response = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "COMPLETED"},
        headers={**agent_headers, "X-Claim-Token": claimed_token},
    )
    assert status_response.status_code == 409
    assert status_response.json()["error"]["code"] == "TASK_CLAIM_EXPIRED"

    finding_response = await _finding(client, task_id, agent_headers)
    assert finding_response.status_code == 409
    assert finding_response.json()["error"]["code"] == "TASK_CLAIM_EXPIRED"


@pytest.mark.asyncio
async def test_terminal_task_is_not_claimable(client, db, analyst_headers, agent_headers):
    task_id = await _create_task(client, analyst_headers)
    claim_token = await _claim(client, task_id, agent_headers)
    completed = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "COMPLETED"},
        headers={**agent_headers, "X-Claim-Token": claim_token},
    )
    assert completed.status_code == 200
    assert completed.json()["claimed_by"] is None
    assert completed.json()["claim_expires_at"] is None
    stored = await db.scalar(select(AgentTask).where(AgentTask.task_id == task_id))
    assert stored is not None
    assert stored.claim_token is None

    retry = await client.post(f"/api/v1/agent-tasks/{task_id}/claim", headers=agent_headers)
    assert retry.status_code == 409
    assert retry.json()["error"]["code"] == "TASK_NOT_CLAIMABLE"


@pytest.mark.asyncio
async def test_wrong_agent_cannot_update_status_or_submit_finding(
    client, analyst_headers, agent_headers, other_agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    await _claim(client, task_id, agent_headers)

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
    claim_token = await _claim(client, task_id, agent_headers)

    response = await _finding(
        client,
        task_id,
        {**agent_headers, "X-Claim-Token": claim_token},
        agent_name="admin_user",
    )
    assert response.status_code == 201, response.text
    assert response.json()["agent_name"] == "admin_user"
    assert response.json()["submitted_by"] == "agent_service"


@pytest.mark.asyncio
async def test_claimant_finding_is_idempotent_and_failure_clears_lease(
    client, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    claim_token = await _claim(client, task_id, agent_headers)

    response = await client.post(
        "/api/v1/findings",
        json={
            "task_id": task_id,
            "agent_name": "worker",
            "status": "FAILED",
            "confidence": 0.0,
            "error": {"message": "retryable tool failure"},
        },
        headers={**agent_headers, "X-Claim-Token": claim_token},
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
async def test_legacy_null_submitter_retry_is_explicit_and_does_not_infer_identity(
    client, db, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    claim_token = await _claim(client, task_id, agent_headers)
    legacy = Finding(
        finding_id="legacy-finding",
        task_id=task_id,
        agent_name="legacy-worker",
        submitted_by=None,
        status="SUCCESS",
        confidence=0.7,
        summary="legacy result",
        severity=None,
        source="AGENT",
        finding_list=[],
        evidence=[],
        finding_metadata={},
        error=None,
        provenance={},
        event_id=None,
        incident_id=None,
        created_at=datetime.now(timezone.utc),
    )
    db.add(legacy)
    await db.commit()

    retry = await _finding(
        client,
        task_id,
        {**agent_headers, "X-Claim-Token": claim_token},
        agent_name="legacy-worker",
    )
    assert retry.status_code == 201
    assert retry.json()["finding_id"] == "legacy-finding"
    stored = await db.scalar(select(Finding).where(Finding.finding_id == "legacy-finding"))
    assert stored is not None
    assert stored.submitted_by is None

    completed = await client.patch(
        f"/api/v1/agent-tasks/{task_id}",
        json={"status": "COMPLETED"},
        headers={**agent_headers, "X-Claim-Token": claim_token},
    )
    assert completed.status_code == 200, completed.text
    terminal_retry = await _finding(
        client, task_id, agent_headers, agent_name="legacy-worker"
    )
    assert terminal_retry.status_code == 201
    assert terminal_retry.json()["finding_id"] == "legacy-finding"


@pytest.mark.asyncio
async def test_same_submitter_different_finding_labels_conflict(
    client, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    claim_token = await _claim(client, task_id, agent_headers)
    first = await _finding(
        client,
        task_id,
        {**agent_headers, "X-Claim-Token": claim_token},
        agent_name="worker-a",
    )
    assert first.status_code == 201
    conflict = await _finding(
        client,
        task_id,
        {**agent_headers, "X-Claim-Token": claim_token},
        agent_name="worker-b",
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "FINDING_CONFLICT"


@pytest.mark.asyncio
async def test_concurrent_findings_different_labels_same_submitter_use_db_boundary(
    client, db, analyst_headers, agent_headers
):
    task_id = await _create_task(client, analyst_headers)
    claim_token = await _claim(client, task_id, agent_headers)
    await db.commit()

    engine = create_async_engine(TEST_DB_URL, **_ENGINE_KWARGS)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    app = create_app()

    async def override_get_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    request_headers = {**agent_headers, "X-Claim-Token": claim_token}
    payload = {
        "task_id": task_id,
        "status": "SUCCESS",
        "confidence": 0.8,
    }
    try:
        async with (
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as first,
            AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as second,
        ):
            responses = await asyncio.gather(
                first.post(
                    "/api/v1/findings",
                    json={**payload, "agent_name": "worker-a"},
                    headers=request_headers,
                ),
                second.post(
                    "/api/v1/findings",
                    json={**payload, "agent_name": "worker-b"},
                    headers=request_headers,
                ),
            )
    finally:
        await engine.dispose()

    assert sorted(response.status_code for response in responses) == [201, 409]
    conflict = next(response for response in responses if response.status_code == 409)
    assert conflict.json()["error"]["code"] == "FINDING_CONFLICT"


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
    repeated = await client.patch(
        f"/api/v1/agent-tasks/{status_task_id}?override=true",
        json={"status": "FAILED"},
        headers=admin_headers,
    )
    assert repeated.status_code == 200

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
    assert any(item["extra"].get("idempotent") is True for item in audit.json()["items"])


@pytest.mark.asyncio
async def test_override_audit_failure_rolls_back_status_mutation(
    client, analyst_headers, admin_headers, monkeypatch
):
    task_id = await _create_task(client, analyst_headers)

    async def fail_required_audit(*args, **kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit_service, "record_required", fail_required_audit)
    response = await client.patch(
        f"/api/v1/agent-tasks/{task_id}?override=true",
        json={"status": "FAILED"},
        headers=admin_headers,
    )
    assert response.status_code == 500

    task = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert task.status_code == 200
    assert task.json()["status"] == "PENDING"


@pytest.mark.asyncio
async def test_override_audit_failure_rolls_back_finding_mutation(
    client, analyst_headers, monkeypatch
):
    task_id = await _create_task(client, analyst_headers)

    async def fail_required_audit(*args, **kwargs):
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(audit_service, "record_required", fail_required_audit)
    response = await client.post(
        "/api/v1/findings?override=true",
        json={
            "task_id": task_id,
            "agent_name": "human-reviewer",
            "status": "SUCCESS",
            "confidence": 1.0,
        },
        headers=analyst_headers,
    )
    assert response.status_code == 500

    findings = await client.get(
        f"/api/v1/findings?task_id={task_id}", headers=analyst_headers
    )
    assert findings.status_code == 200
    assert findings.json()["items"] == []
    task = await client.get(f"/api/v1/agent-tasks/{task_id}", headers=analyst_headers)
    assert task.status_code == 200
    assert task.json()["status"] == "PENDING"
