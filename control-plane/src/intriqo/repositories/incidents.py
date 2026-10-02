"""Incident repository."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.incident import Incident, IncidentEvent


class IncidentRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(self, incident: Incident) -> Incident:
        self._db.add(incident)
        await self._db.flush()
        await self._db.refresh(incident)
        return incident

    async def get_by_id(self, incident_id: str) -> Incident | None:
        result = await self._db.execute(
            select(Incident).where(Incident.incident_id == incident_id)
        )
        return result.scalar_one_or_none()

    async def update(self, incident: Incident) -> Incident:
        await self._db.flush()
        await self._db.refresh(incident)
        return incident

    async def list(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Incident], int]:
        query = select(Incident)
        if status:
            query = query.where(Incident.status == status)
        if severity:
            query = query.where(Incident.severity == severity)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        offset = (page - 1) * page_size
        query = query.order_by(Incident.created_at.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total

    async def add_event_link(self, link: IncidentEvent) -> None:
        self._db.add(link)
        await self._db.flush()
