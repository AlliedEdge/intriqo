"""AgentTask repository."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.agent_task import AgentTask


class AgentTaskRepository:
    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def create(self, task: AgentTask) -> AgentTask:
        self._db.add(task)
        await self._db.flush()
        await self._db.refresh(task)
        return task

    async def get_by_id(self, task_id: str) -> AgentTask | None:
        result = await self._db.execute(
            select(AgentTask).where(AgentTask.task_id == task_id)
        )
        return result.scalar_one_or_none()

    async def get_by_idempotency_key(self, idempotency_key: str) -> AgentTask | None:
        result = await self._db.execute(
            select(AgentTask).where(AgentTask.idempotency_key == idempotency_key)
        )
        return result.scalar_one_or_none()

    async def update(self, task: AgentTask) -> AgentTask:
        await self._db.flush()
        await self._db.refresh(task)
        return task

    async def list(
        self,
        *,
        status: str | None = None,
        priority: str | None = None,
        task_type: str | None = None,
        event_id: str | None = None,
        incident_id: str | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[AgentTask], int]:
        query = select(AgentTask)
        if status:
            query = query.where(AgentTask.status == status)
        if priority:
            query = query.where(AgentTask.priority == priority)
        if task_type:
            query = query.where(AgentTask.task_type == task_type)
        if event_id:
            query = query.where(AgentTask.event_id == event_id)
        if incident_id:
            query = query.where(AgentTask.incident_id == incident_id)

        count_result = await self._db.execute(
            select(func.count()).select_from(query.subquery())
        )
        total = count_result.scalar() or 0

        offset = (page - 1) * page_size
        query = query.order_by(AgentTask.created_at.desc()).offset(offset).limit(page_size)
        result = await self._db.execute(query)
        return list(result.scalars().all()), total
