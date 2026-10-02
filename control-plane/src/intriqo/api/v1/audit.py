"""Audit log API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth.dependencies import AuthUser
from intriqo.db.session import get_db
from intriqo.repositories.audit_logs import AuditLogRepository
from intriqo.schemas.audit import AuditLogResponse
from intriqo.schemas.common import PaginatedResponse

router = APIRouter(prefix="/audit")


def _to_response(log) -> AuditLogResponse:
    return AuditLogResponse(
        id=log.id,
        actor=log.actor,
        action=log.action,
        resource_type=log.resource_type,
        resource_id=log.resource_id,
        outcome=log.outcome,
        detail=log.detail,
        extra=log.extra or {},
        created_at=log.created_at,
    )


@router.get("", response_model=PaginatedResponse[AuditLogResponse])
async def list_audit_logs(
    user: AuthUser,
    db: AsyncSession = Depends(get_db),
    action: Annotated[str | None, Query()] = None,
    resource_type: Annotated[str | None, Query()] = None,
    resource_id: Annotated[str | None, Query()] = None,
    outcome: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 50,
) -> PaginatedResponse[AuditLogResponse]:
    """List immutable audit records with optional filters and pagination."""
    repo = AuditLogRepository(db)
    logs, total = await repo.list(
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_to_response(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )
