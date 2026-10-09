"""AgentTask application service."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

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


async def update_task_status(
    db: AsyncSession, task_id: str, new_status: str, actor: str = "system"
) -> AgentTask:
    """Apply the small, explicit task state machine used by agent runners."""
    if new_status not in VALID_STATUSES:
        raise InvalidStatusTransitionError(f"Invalid task status '{new_status}'")
    repo = AgentTaskRepository(db)
    task = await repo.get_by_id(task_id)
    if task is None:
        raise AgentTaskNotFoundError(task_id)
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
    await repo.update(task)
    action = {
        "IN_PROGRESS": audit_service.ACTION_TASK_STARTED,
        "COMPLETED": audit_service.ACTION_TASK_COMPLETED,
        "FAILED": audit_service.ACTION_TASK_FAILED,
    }.get(new_status, audit_service.ACTION_TASK_STATUS_UPDATED)
    await audit_service.record(
        db, actor=actor, action=action, resource_type="agent_task", resource_id=task_id,
        extra={"from_status": old_status, "status": new_status},
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


async def submit_finding(
    db: AsyncSession,
    payload: FindingCreate,
    actor: str = "system",
) -> Finding:
    """Submit an agent result (Finding) for a task."""
    # Verify the task exists
    task_repo = AgentTaskRepository(db)
    task = await task_repo.get_by_id(payload.task_id)
    if task is None:
        raise AgentTaskNotFoundError(payload.task_id)

    finding_repo = FindingRepository(db)
    existing = await finding_repo.get_by_task_agent(payload.task_id, payload.agent_name)
    if existing is not None:
        # A task has one result per agent.  Returning it makes retries safe and
        # avoids duplicate findings without requiring a distributed idempotency store.
        return existing
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
            "DETERMINISTIC" if event_type in {"PORT_SCAN", "UDP_SCAN", "SYN_FLOOD"} else "AGENT"
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
        existing = await finding_repo.get_by_task_agent(payload.task_id, payload.agent_name)
        if existing is None:
            raise exc
        return existing

    # A result closes the investigation attempt, but failed evidence remains
    # visibly failed rather than being misreported as a successful task.
    if payload.status in ("SUCCESS", "FAILED", "INCONCLUSIVE"):
        task.status = "FAILED" if payload.status == "FAILED" else "COMPLETED"
        task.completed_at = now
        task.updated_at = now
        await task_repo.update(task)
        await audit_service.record(
            db,
            actor=actor,
            action=(
                audit_service.ACTION_TASK_FAILED
                if payload.status == "FAILED"
                else audit_service.ACTION_TASK_COMPLETED
            ),
            resource_type="agent_task",
            resource_id=task.task_id,
            extra={"status": task.status, "via": "finding_submission"},
        )

    await audit_service.record(
        db,
        actor=actor,
        action=audit_service.ACTION_FINDING_SUBMITTED,
        resource_type="finding",
        resource_id=finding.finding_id,
        extra={
            "task_id": finding.task_id,
            "agent_name": finding.agent_name,
            "status": finding.status,
            "confidence": finding.confidence,
            "severity": finding.severity,
            "source": finding.source,
            "event_id": finding.event_id,
            "incident_id": finding.incident_id,
        },
    )

    logger.info(
        "Finding submitted finding_id=%s task_id=%s agent=%s status=%s",
        finding.finding_id, finding.task_id, finding.agent_name, finding.status,
    )
    return finding
