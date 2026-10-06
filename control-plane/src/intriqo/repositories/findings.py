"""Finding repository."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.finding import Finding


class FindingRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(self, finding: Finding) -> Finding:
        self._db.add(finding)
        await self._db.flush()
        await self._db.refresh(finding)
        return finding

    async def get_by_id(self, finding_id: str) -> Finding | None:
        result = await self._db.execute(
            select(Finding).where(Finding.finding_id == finding_id)
        )
        return result.scalar_one_or_none()

    async def get_by_task_agent(self, task_id: str, agent_name: str) -> Finding | None:
        result = await self._db.execute(
            select(Finding).where(
                Finding.task_id == task_id,
                Finding.agent_name == agent_name,
            )
        )
        return result.scalar_one_or_none()

    async def list(
        self,
        *,
        status: str | None = None,
        task_id: str | None = None,
        agent_name: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[Finding], int]:
        query = select(Finding)
        if status:
            query = query.where(Finding.status == status)
        if task_id:
            query = query.where(Finding.task_id == task_id)
        if agent_name:
            query = query.where(Finding.agent_name == agent_name)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        offset = (page - 1) * page_size
        query = query.order_by(Finding.created_at.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total
