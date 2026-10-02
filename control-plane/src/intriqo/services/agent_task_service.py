"""AgentTask application service."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.agent_task import AgentTask
from intriqo.db.models.finding import Finding
from intriqo.repositories.agent_tasks import AgentTaskRepository
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


async def create_task(
    db: AsyncSession,
    payload: AgentTaskCreate,
    actor: str = "system",
) -> AgentTask:
    """Create a new agent task."""
    if payload.task_type not in VALID_TASK_TYPES:
        raise InvalidTaskTypeError(
            f"task_type must be one of {sorted(VALID_TASK_TYPES)}, got '{payload.task_type}'"
        )

    repo = AgentTaskRepository(db)
    now = datetime.now(timezone.utc)

    task = AgentTask(
        task_id=str(uuid.uuid4()),
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
    task = await repo.create(task)

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
    now = datetime.now(timezone.utc)

    finding = Finding(
        finding_id=str(uuid.uuid4()),
        task_id=payload.task_id,
        agent_name=payload.agent_name,
        status=payload.status,
        confidence=payload.confidence,
        summary=payload.summary,
        finding_list=payload.findings,
        evidence=payload.evidence,
        finding_metadata=payload.finding_metadata,
        error=payload.error,
        created_at=now,
    )
    finding = await finding_repo.create(finding)

    # Auto-update task status when a result arrives
    if payload.status in ("SUCCESS", "FAILED", "INCONCLUSIVE"):
        task.status = "COMPLETED"
        task.completed_at = now
        task.updated_at = now
        await task_repo.update(task)

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
        },
    )

    logger.info(
        "Finding submitted finding_id=%s task_id=%s agent=%s status=%s",
        finding.finding_id, finding.task_id, finding.agent_name, finding.status,
    )
    return finding
