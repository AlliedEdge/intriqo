"""AuditLog repository — append-only."""

from __future__ import annotations

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
