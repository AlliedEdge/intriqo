"""AgentTask application service."""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.config import get_settings
from intriqo.db.models.agent_task import AgentTask
from intriqo.db.models.finding import Finding
from intriqo.repositories.agent_tasks import AgentTaskRepository
from intriqo.repositories.events import EventRepository
from intriqo.repositories.findings import FindingRepository
from intriqo.schemas.agent_tasks import AgentTaskCreate
from intriqo.schemas.findings import FindingCreate
from intriqo.services import audit_service

logger = logging.getLogger("intriqo.services.agent_task")

VALID_TASK_TYPES = {"INVESTIGATION", "CORRELATION", "THREAT_INTEL", "RESPONSE"}
VALID_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "URGENT"}
VALID_STATUSES   = {"PENDING", "IN_PROGRESS", "COMPLETED", "FAILED", "CANCELLED"}


class AgentTaskNotFoundError(Exception):
    def __init__(self, task_id: str) -> None:
        super().__init__(f"AgentTask '{task_id}' not found")
        self.task_id = task_id


class InvalidTaskTypeError(ValueError):
    pass


class InvalidStatusTransitionError(ValueError):
    pass


class TaskClaimConflictError(Exception):
    """The task is currently leased to another identity."""

    def __init__(self, task_id: str, claimed_by: str | None = None) -> None:
        super().__init__(f"AgentTask '{task_id}' is actively claimed by another agent")
        self.task_id = task_id
        self.claimed_by = claimed_by


class TaskNotClaimableError(Exception):
    """The task is terminal and cannot be claimed."""

    def __init__(self, task_id: str, task_status: str) -> None:
        super().__init__(f"AgentTask '{task_id}' with status {task_status} is not claimable")
        self.task_id = task_id
        self.task_status = task_status


class TaskClaimExpiredError(Exception):
    """The caller's lease is no longer active."""

    def __init__(self, task_id: str) -> None:
        super().__init__(f"The claim for AgentTask '{task_id}' has expired")
        self.task_id = task_id


class TaskClaimTokenError(Exception):
    """The caller did not prove possession of the current lease token."""

    def __init__(self, task_id: str) -> None:
        super().__init__(f"The claim token for AgentTask '{task_id}' is invalid or missing")
        self.task_id = task_id


class TaskNotOwnedError(Exception):
    """The caller does not own the active task claim."""

    def __init__(self, task_id: str) -> None:
        super().__init__(f"AgentTask '{task_id}' is not owned by this agent")
        self.task_id = task_id


class TaskOverrideRequiredError(Exception):
    """A human role must opt into changing an agent-owned task."""

    def __init__(self, action: str) -> None:
        super().__init__(f"An explicit override is required for {action}")
        self.action = action


class FindingConflictError(Exception):
    """A task finding uniqueness constraint was violated."""

    def __init__(self, task_id: str, agent_name: str) -> None:
        super().__init__(
            f"A finding for AgentTask '{task_id}' and agent label '{agent_name}' already exists"
        )
        self.task_id = task_id
        self.agent_name = agent_name


def _require_active_claim(
    task: AgentTask,
    actor: str,
    claim_token: str | None,
) -> None:
    """Require identity, an unexpired lease, and possession of its token."""
    if task.claimed_by != actor:
        raise TaskNotOwnedError(task.task_id)
    if task.claim_expires_at is None or task.claim_expires_at <= datetime.now(timezone.utc):
        raise TaskClaimExpiredError(task.task_id)
    if (
        claim_token is None
        or task.claim_token is None
        or not secrets.compare_digest(task.claim_token, claim_token)
    ):
        raise TaskClaimTokenError(task.task_id)


async def claim_task(
    db: AsyncSession,
    task_id: str,
    identity: str,
    claim_token: str | None = None,
) -> AgentTask:
    """Atomically claim a pending or in-progress task for one lease period."""
    repo = AgentTaskRepository(db)
    task = await repo.claim(
        task_id,
        identity,
        get_settings().agent_task_lease_seconds,
        claim_token,
        secrets.token_urlsafe(32),
    )
    if task is None:
        # The conditional UPDATE intentionally returns no row for all failed
        # cases.  Read once only to translate that result into a stable API
        # error; no lock is held while the caller performs work.
        current = await repo.get_by_id(task_id)
        if current is None:
            raise AgentTaskNotFoundError(task_id)
        if current.status not in {"PENDING", "IN_PROGRESS"}:
            raise TaskNotClaimableError(task_id, current.status)
        if (
            current.claimed_by == identity
            and current.claim_expires_at is not None
            and current.claim_expires_at > datetime.now(timezone.utc)
        ):
            raise TaskClaimTokenError(task_id)
        if (
            claim_token is not None
            and current.claim_expires_at is not None
            and current.claim_expires_at <= datetime.now(timezone.utc)
        ):
            # A token is proof for renewing the current active lease only. An
            # expired worker must make a fresh tokenless claim instead of
            # reviving its old lease credential.
            raise TaskClaimTokenError(task_id)
        if (
            current.claimed_by is not None
            and current.claimed_by != identity
            and current.claim_expires_at is not None
            and current.claim_expires_at > datetime.now(timezone.utc)
        ):
            raise TaskClaimConflictError(task_id, current.claimed_by)
        # A concurrent claimant may have won between the failed UPDATE and
        # this diagnostic read.  Report it as a conflict rather than retrying
        # the claim and accidentally obscuring the race.
        raise TaskClaimConflictError(task_id, current.claimed_by)

    await audit_service.record(
        db,
        actor=identity,
        action=audit_service.ACTION_TASK_CLAIMED,
        resource_type="agent_task",
        resource_id=task_id,
        extra={
            "claimed_by": identity,
            "claim_expires_at": task.claim_expires_at.isoformat()
            if task.claim_expires_at is not None
            else None,
            "status": task.status,
        },
    )
    return task


async def update_task_status(
    db: AsyncSession,
    task_id: str,
    new_status: str,
    actor: str = "system",
    actor_role: str = "AGENT",
    override: bool = False,
    claim_token: str | None = None,
) -> AgentTask:
    """Apply the small, explicit task state machine used by agent runners."""
    if new_status not in VALID_STATUSES:
        raise InvalidStatusTransitionError(f"Invalid task status '{new_status}'")
    repo = AgentTaskRepository(db)
    task = await repo.get_by_id_for_update(task_id)
    if task is None:
        raise AgentTaskNotFoundError(task_id)

    is_override = actor_role in {"ADMIN", "ANALYST"} and override
    if actor_role == "AGENT":
        _require_active_claim(task, actor, claim_token)
    elif not is_override:
        raise TaskOverrideRequiredError("task status updates")

    if is_override:
        # Overrides are security-sensitive mutations.  Keep the state change
        # and its required audit row in one savepoint so an audit failure
        # cannot leave the override applied without evidence.  Repeated
        # same-state overrides are recorded as idempotent audit events.
        async with db.begin_nested():
            if task.status == new_status:
                await audit_service.record_required(
                    db,
                    actor=actor,
                    action=audit_service.ACTION_TASK_STATUS_OVERRIDDEN,
                    resource_type="agent_task",
                    resource_id=task_id,
                    extra={
                        "from_status": task.status,
                        "status": task.status,
                        "override": True,
                        "override_role": actor_role,
                        "idempotent": True,
                    },
                )
                return task
            old_status = task.status
            allowed = {
                "PENDING": {"IN_PROGRESS", "FAILED"},
                "IN_PROGRESS": {"COMPLETED", "FAILED"},
            }
            if new_status not in allowed.get(task.status, set()):
                raise InvalidStatusTransitionError(
                    f"Cannot transition task '{task_id}' from {task.status} to {new_status}"
                )
            now = datetime.now(timezone.utc)
            task.status = new_status
            task.updated_at = now
            if new_status in {"COMPLETED", "FAILED"}:
                task.completed_at = now
                task.claimed_by = None
                task.claim_expires_at = None
                task.claim_token = None
            await repo.update(task)
            await audit_service.record_required(
                db,
                actor=actor,
                action=audit_service.ACTION_TASK_STATUS_OVERRIDDEN,
                resource_type="agent_task",
                resource_id=task_id,
                extra={
                    "from_status": old_status,
                    "status": new_status,
                    "override": True,
                    "override_role": actor_role,
                },
            )
            return task

    if task.status == new_status:
        return task
    old_status = task.status
    allowed = {
        "PENDING": {"IN_PROGRESS", "FAILED"},
        "IN_PROGRESS": {"COMPLETED", "FAILED"},
    }
    if new_status not in allowed.get(task.status, set()):
        raise InvalidStatusTransitionError(
            f"Cannot transition task '{task_id}' from {task.status} to {new_status}"
        )
    now = datetime.now(timezone.utc)
    task.status = new_status
    task.updated_at = now
    if new_status in {"COMPLETED", "FAILED"}:
        task.completed_at = now
        task.claimed_by = None
        task.claim_expires_at = None
        task.claim_token = None
    await repo.update(task)
    action = (
        audit_service.ACTION_TASK_STATUS_OVERRIDDEN
        if is_override
        else {
            "IN_PROGRESS": audit_service.ACTION_TASK_STARTED,
            "COMPLETED": audit_service.ACTION_TASK_COMPLETED,
            "FAILED": audit_service.ACTION_TASK_FAILED,
        }.get(new_status, audit_service.ACTION_TASK_STATUS_UPDATED)
    )
    await audit_service.record(
        db, actor=actor, action=action, resource_type="agent_task", resource_id=task_id,
        extra={
            "from_status": old_status,
            "status": new_status,
            "override": is_override,
            "override_role": actor_role if is_override else None,
        },
    )
    return task


async def create_task(
    db: AsyncSession,
    payload: AgentTaskCreate,
    actor: str = "system",
    idempotency_key: str | None = None,
) -> AgentTask:
    """Create a new agent task."""
    if payload.task_type not in VALID_TASK_TYPES:
        raise InvalidTaskTypeError(
            f"task_type must be one of {sorted(VALID_TASK_TYPES)}, got '{payload.task_type}'"
        )

    repo = AgentTaskRepository(db)
    durable_key = idempotency_key or payload.idempotency_key
    # Tasks tied to a source are naturally one logical outcome per task type;
    # callers without a source can opt into the same guarantee explicitly.
    if durable_key is None and (payload.event_id or payload.incident_id):
        source_id = payload.event_id or payload.incident_id
        source_kind = "event" if payload.event_id else "incident"
        durable_key = f"{payload.task_type}|{source_kind}:{source_id}"
    if payload.task_id:
        existing = await repo.get_by_id(payload.task_id)
        if existing is not None:
            return existing
    if durable_key:
        existing = await repo.get_by_idempotency_key(durable_key)
        if existing is not None:
            return existing
    now = datetime.now(timezone.utc)

    task = AgentTask(
        task_id=payload.task_id or str(uuid.uuid4()),
        idempotency_key=durable_key,
        task_type=payload.task_type,
        description=payload.description,
        priority=payload.priority,
        status="PENDING",
        event_id=payload.event_id,
        incident_id=payload.incident_id,
        context=payload.context,
        created_at=now,
        updated_at=now,
    )
    try:
        async with db.begin_nested():
            task = await repo.create(task)
    except IntegrityError as exc:
        existing = await repo.get_by_id(payload.task_id) if payload.task_id else None
        if existing is None and durable_key:
            existing = await repo.get_by_idempotency_key(durable_key)
        if existing is None:
            raise exc
        return existing

    await audit_service.record(
        db,
        actor=actor,
        action=audit_service.ACTION_TASK_CREATED,
        resource_type="agent_task",
        resource_id=task.task_id,
        extra={
            "task_type": task.task_type,
            "priority": task.priority,
            "event_id": task.event_id,
            "incident_id": task.incident_id,
        },
    )

    logger.info("Created AgentTask task_id=%s type=%s", task.task_id, task.task_type)
    return task


async def _create_finding(
    db: AsyncSession,
    payload: FindingCreate,
    actor: str,
    actor_role: str,
    override: bool,
    task: AgentTask,
    task_repo: AgentTaskRepository,
    finding_repo: FindingRepository,
    *,
    audit_required: bool,
    legacy_retry_allowed: bool,
) -> Finding:
    """Create one finding and apply its lifecycle transition.

    The caller holds the task row lock.  The finding unique constraints remain
    the final concurrency boundary, including when callers do not share that
    lock (for example, independent workers or future write paths).
    """
    now = datetime.now(timezone.utc)

    event = None
    event_id = payload.event_id or task.event_id
    event_repo = EventRepository(db)
    if event_id:
        event = await event_repo.get_by_id(event_id)
    incident_id = payload.incident_id or task.incident_id
    if incident_id is None and event_id:
        linked_incidents, _ = await event_repo.related_ids(event_id)
        incident_id = linked_incidents[0] if linked_incidents else None
    event_type = event.event_type if event is not None else None
    source = payload.source
    if source is None:
        source = "ML" if event_type == "ML_ANOMALY" else (
            "DETERMINISTIC"
            if event_type in {"PORT_SCAN", "UDP_SCAN", "SYN_FLOOD"}
            else "AGENT"
        )
    severity = payload.severity or (event.severity if event is not None else None)
    provenance = dict(payload.provenance)
    provenance.update(
        {
            "schema_version": "finding_provenance.v1",
            "source": source,
            "event_id": event_id,
            "incident_id": incident_id,
            "event_type": event_type,
            "severity": severity,
        }
    )
    if event is not None:
        provenance["event_timestamp"] = event.timestamp.isoformat()
        provenance["source_address"] = event.source_address
        provenance["destination_address"] = event.destination_address
        details = (event.raw_payload or {}).get("details") or {}
        if event_type == "ML_ANOMALY":
            # Preserve the locked detector/model receipt without interpreting
            # or modifying its values in the Control Plane.
            provenance["detector"] = details.get("detector")
            provenance["model"] = details.get("result", details.get("model"))

    structured_evidence = []
    for item in payload.evidence:
        record = dict(item)
        record.setdefault("source", source)
        record.setdefault("severity", severity)
        record.setdefault("event_id", event_id)
        record.setdefault("incident_id", incident_id)
        structured_evidence.append(record)

    finding = Finding(
        finding_id=str(uuid.uuid4()),
        task_id=payload.task_id,
        agent_name=payload.agent_name,
        submitted_by=actor,
        status=payload.status,
        confidence=payload.confidence,
        summary=payload.summary,
        severity=severity,
        source=source,
        finding_list=payload.findings,
        evidence=structured_evidence,
        finding_metadata=payload.finding_metadata,
        error=payload.error,
        provenance=provenance,
        event_id=event_id,
        incident_id=incident_id,
        created_at=now,
    )
    try:
        async with db.begin_nested():
            finding = await finding_repo.create(finding)
    except IntegrityError as exc:
        # Re-read after the savepoint rollback.  A same-label legacy row is a
        # compatibility retry only after the caller already proved its active
        # claim; agent_name itself is never treated as an identity.
        existing = await finding_repo.get_by_task_submitted_by(payload.task_id, actor)
        if existing is not None:
            if existing.agent_name == payload.agent_name:
                return existing
            raise FindingConflictError(payload.task_id, payload.agent_name) from exc
        existing = await finding_repo.get_by_task_agent(payload.task_id, payload.agent_name)
        if (
            existing is not None
            and existing.submitted_by is None
            and legacy_retry_allowed
        ):
            return existing
        if existing is None:
            raise exc
        raise FindingConflictError(payload.task_id, payload.agent_name) from exc

    audit_record = audit_service.record_required if audit_required else audit_service.record

    # A result closes the investigation attempt, but failed evidence remains
    # visibly failed rather than being misreported as a successful task.
    if payload.status in ("SUCCESS", "FAILED", "INCONCLUSIVE"):
        task.status = "FAILED" if payload.status == "FAILED" else "COMPLETED"
        task.completed_at = now
        task.updated_at = now
        task.claimed_by = None
        task.claim_expires_at = None
        task.claim_token = None
        await task_repo.update(task)
        await audit_record(
            db,
            actor=actor,
            action=(
                audit_service.ACTION_TASK_FAILED
                if payload.status == "FAILED"
                else audit_service.ACTION_TASK_COMPLETED
            ),
            resource_type="agent_task",
            resource_id=task.task_id,
            extra={
                "status": task.status,
                "via": "finding_submission",
                "override": actor_role in {"ADMIN", "ANALYST"} and override,
            },
        )

    await audit_record(
        db,
        actor=actor,
        action=(
            audit_service.ACTION_FINDING_SUBMITTED_OVERRIDE
            if actor_role in {"ADMIN", "ANALYST"} and override
            else audit_service.ACTION_FINDING_SUBMITTED
        ),
        resource_type="finding",
        resource_id=finding.finding_id,
        extra={
            "task_id": finding.task_id,
            "agent_name": finding.agent_name,
            "submitted_by": finding.submitted_by,
            "status": finding.status,
            "confidence": finding.confidence,
            "severity": finding.severity,
            "source": finding.source,
            "event_id": finding.event_id,
            "incident_id": finding.incident_id,
            "override": actor_role in {"ADMIN", "ANALYST"} and override,
            "override_role": actor_role
            if actor_role in {"ADMIN", "ANALYST"} and override
            else None,
        },
    )

    logger.info(
        "Finding submitted finding_id=%s task_id=%s agent=%s status=%s",
        finding.finding_id, finding.task_id, finding.agent_name, finding.status,
    )
    return finding


async def submit_finding(
    db: AsyncSession,
    payload: FindingCreate,
    actor: str = "system",
    actor_role: str = "AGENT",
    override: bool = False,
    claim_token: str | None = None,
) -> Finding:
    """Submit an agent result (Finding) for a task.

    Agent writes require the current authenticated claimant's unexpired lease
    token.  The only token-free agent path is a no-op retry of an existing
    finding already submitted by that same authenticated identity after the
    task reached a terminal state; it cannot change any stored value.
    """
    task_repo = AgentTaskRepository(db)
    task = await task_repo.get_by_id_for_update(payload.task_id)
    if task is None:
        raise AgentTaskNotFoundError(payload.task_id)

    finding_repo = FindingRepository(db)
    is_override = actor_role in {"ADMIN", "ANALYST"} and override
    if actor_role == "AGENT":
        existing = await finding_repo.get_by_task_submitted_by(payload.task_id, actor)
        if existing is not None:
            if existing.agent_name != payload.agent_name:
                raise FindingConflictError(payload.task_id, payload.agent_name)
            if task.status in {"PENDING", "IN_PROGRESS"}:
                _require_active_claim(task, actor, claim_token)
            # Idempotent retry compatibility: once terminal, this is a read of
            # the already accepted result, not a new mutation, so no audit row
            # is emitted and no lease is required.
            return existing

        # A legacy row has no authenticated submitter to match.  Preserve the
        # old (task, agent_name) idempotency contract as a read-only retry, but
        # require the current lease while the task is still mutable.  Once the
        # task is terminal there is no lease to prove; returning the already
        # stored legacy row is safe because it performs no mutation and does
        # not treat agent_name as an authorization identity.
        existing_by_agent = await finding_repo.get_by_task_agent(
            payload.task_id, payload.agent_name
        )
        if existing_by_agent is not None:
            if existing_by_agent.submitted_by is None:
                if task.status in {"PENDING", "IN_PROGRESS"}:
                    _require_active_claim(task, actor, claim_token)
                return existing_by_agent
            raise FindingConflictError(payload.task_id, payload.agent_name)

        _require_active_claim(task, actor, claim_token)
    elif actor_role in {"ADMIN", "ANALYST"}:
        if not override:
            raise TaskOverrideRequiredError("finding submissions")
        existing = await finding_repo.get_by_task_submitted_by(payload.task_id, actor)
        if existing is not None:
            if existing.agent_name != payload.agent_name:
                raise FindingConflictError(payload.task_id, payload.agent_name)
            # Repeated overrides are auditable even though they are idempotent.
            async with db.begin_nested():
                await audit_service.record_required(
                    db,
                    actor=actor,
                    action=audit_service.ACTION_FINDING_SUBMITTED_OVERRIDE,
                    resource_type="finding",
                    resource_id=existing.finding_id,
                    extra={
                        "task_id": existing.task_id,
                        "agent_name": existing.agent_name,
                        "override": True,
                        "override_role": actor_role,
                        "idempotent": True,
                    },
                )
            return existing
    else:
        raise TaskOverrideRequiredError("finding submissions")

    # Human overrides may explicitly replay a legacy row.  Agent legacy rows
    # were handled above so their mutable-task path proves an active claim and
    # their terminal-task path is read-only.  The partial unique index leaves
    # NULL-submitter rows out of authenticated uniqueness checks.
    existing_by_agent = await finding_repo.get_by_task_agent(
        payload.task_id, payload.agent_name
    )
    if existing_by_agent is not None:
        if existing_by_agent.submitted_by is None:
            if is_override:
                async with db.begin_nested():
                    await audit_service.record_required(
                        db,
                        actor=actor,
                        action=audit_service.ACTION_FINDING_SUBMITTED_OVERRIDE,
                        resource_type="finding",
                        resource_id=existing_by_agent.finding_id,
                        extra={
                            "task_id": existing_by_agent.task_id,
                            "agent_name": existing_by_agent.agent_name,
                            "override": True,
                            "override_role": actor_role,
                            "idempotent": True,
                            "legacy_submitted_by_null": True,
                        },
                    )
                return existing_by_agent
        raise FindingConflictError(payload.task_id, payload.agent_name)

    if is_override:
        # The savepoint covers finding insertion, terminal task clearing, and
        # both required override audit writes.
        async with db.begin_nested():
            return await _create_finding(
                db,
                payload,
                actor,
                actor_role,
                override,
                task,
                task_repo,
                finding_repo,
                audit_required=True,
                legacy_retry_allowed=False,
            )
    return await _create_finding(
        db,
        payload,
        actor,
        actor_role,
        override,
        task,
        task_repo,
        finding_repo,
        audit_required=False,
        legacy_retry_allowed=actor_role == "AGENT",
    )
