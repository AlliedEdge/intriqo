"""SecurityEvent repository — all SQL for the security_events table."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.agent_task import AgentTask
from intriqo.db.models.incident import IncidentEvent
from intriqo.db.models.security_event import SecurityEvent


class EventRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(self, event: SecurityEvent) -> SecurityEvent:
        """Persist a new event. Returns the event (including ingested_at).

        Raises IntegrityError if event_id already exists (let caller handle).
        """
        self._db.add(event)
        await self._db.flush()
        await self._db.refresh(event)
        return event

    async def get_by_id(self, event_id: str) -> SecurityEvent | None:
        result = await self._db.execute(
            select(SecurityEvent).where(SecurityEvent.event_id == event_id)
        )
        return result.scalar_one_or_none()

    async def exists(self, event_id: str) -> bool:
        result = await self._db.execute(
            select(func.count()).where(SecurityEvent.event_id == event_id)
        )
        return (result.scalar() or 0) > 0

    async def related_ids(self, event_id: str) -> tuple[list[str], list[str]]:
        """Return incident and task IDs linked to an event."""
        incident_result = await self._db.execute(
            select(IncidentEvent.incident_id).where(IncidentEvent.event_id == event_id)
        )
        task_result = await self._db.execute(
            select(AgentTask.task_id).where(AgentTask.event_id == event_id)
        )
        return list(incident_result.scalars()), list(task_result.scalars())

    async def list(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source_address: str | None = None,
        destination_address: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[SecurityEvent], int]:
        """Return (items, total_count) with optional filters."""
        query = select(SecurityEvent)

        if severity:
            query = query.where(SecurityEvent.severity == severity)
        if event_type:
            query = query.where(SecurityEvent.event_type == event_type)
        if source_address:
            query = query.where(SecurityEvent.source_address == source_address)
        if destination_address:
            query = query.where(SecurityEvent.destination_address == destination_address)
        if from_time:
            query = query.where(SecurityEvent.timestamp >= from_time)
        if to_time:
            query = query.where(SecurityEvent.timestamp <= to_time)

        # Total count (without pagination)
        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        # Paginated results, newest first
        offset = (page - 1) * page_size
        query = query.order_by(SecurityEvent.timestamp.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total
