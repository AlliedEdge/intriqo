"""Audit service — single point for writing audit records.

All important control-plane actions go through this service.
Failures to write audit records are logged but do NOT abort the primary operation.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.audit_log import AuditLog
from intriqo.repositories.audit_logs import AuditLogRepository

logger = logging.getLogger("intriqo.services.audit")

# ── Action constants ──────────────────────────────────────────────────────────
ACTION_EVENT_INGESTED       = "EVENT_INGESTED"
ACTION_INCIDENT_CREATED     = "INCIDENT_CREATED"
ACTION_INCIDENT_UPDATED     = "INCIDENT_UPDATED"
ACTION_TASK_CREATED         = "TASK_CREATED"
ACTION_TASK_STATUS_UPDATED  = "TASK_STATUS_UPDATED"
ACTION_FINDING_SUBMITTED    = "FINDING_SUBMITTED"
ACTION_USER_REGISTERED      = "USER_REGISTERED"
ACTION_USER_LOGIN           = "USER_LOGIN"
ACTION_USER_LOGIN_FAILED    = "USER_LOGIN_FAILED"


async def record(
    db: AsyncSession,
    *,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str = "SUCCESS",
    detail: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Append one audit record. Swallows exceptions so the caller never fails due to audit."""
    try:
        repo = AuditLogRepository(db)
        log = AuditLog(
            id=str(uuid.uuid4()),
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            detail=detail,
            extra=extra or {},
            created_at=datetime.now(timezone.utc),
        )
        await repo.create(log)
    except Exception:
        logger.exception(
            "Failed to write audit record: actor=%s action=%s resource=%s/%s",
            actor, action, resource_type, resource_id,
        )
