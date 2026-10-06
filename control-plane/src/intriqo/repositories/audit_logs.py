"""AuditLog repository — append-only."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.audit_log import AuditLog


class AuditLogRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(self, log: AuditLog) -> AuditLog:
        """Append an audit record. Never update or delete."""
        self._db.add(log)
        await self._db.flush()
        return log

    async def list(
        self,
        *,
        action: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[AuditLog], int]:
        """Return audit records newest first with optional filters."""
        query = select(AuditLog)

        if action:
            query = query.where(AuditLog.action == action)
        if resource_type:
            query = query.where(AuditLog.resource_type == resource_type)
        if resource_id:
            query = query.where(AuditLog.resource_id == resource_id)
        if outcome:
            query = query.where(AuditLog.outcome == outcome)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        offset = (page - 1) * page_size
        # Timestamp precision is database-dependent; the UUID tie-breaker
        # makes equal-time timeline rows stable for the dashboard.
        query = query.order_by(
            AuditLog.created_at.desc(), AuditLog.id.desc()
        ).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total
