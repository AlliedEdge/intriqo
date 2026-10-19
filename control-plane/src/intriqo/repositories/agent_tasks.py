"""AgentTask repository."""

from __future__ import annotations

from sqlalchemy import and_, case, false, func, or_, select, text, update
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
            select(AgentTask)
            .where(AgentTask.task_id == task_id)
            .execution_options(populate_existing=True)
        )
        return result.scalar_one_or_none()

    async def get_by_id_for_update(self, task_id: str) -> AgentTask | None:
        """Load one task while serializing its short control-plane mutation."""
        result = await self._db.execute(
            select(AgentTask)
            .where(AgentTask.task_id == task_id)
            .with_for_update()
            .execution_options(populate_existing=True)
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

    async def claim(
        self,
        task_id: str,
        identity: str,
        lease_seconds: int,
        presented_claim_token: str | None,
        new_claim_token: str,
    ) -> AgentTask | None:
        """Atomically claim an available task and return the updated task.

        The conditional UPDATE is the concurrency boundary: two agents may
        race, but only the winner can update an unclaimed/expired task.  An
        unexpired same-identity renewal additionally needs the current token;
        the transaction is left to the request dependency to commit after
        this short operation, with no agent work performed while it is open.
        """
        lease_interval = text(f"INTERVAL '{lease_seconds} seconds'")
        same_identity_renewal = (
            and_(
                AgentTask.claimed_by == identity,
                AgentTask.claim_expires_at > func.now(),
                AgentTask.claim_token == presented_claim_token,
            )
            if presented_claim_token is not None
            else false()
        )
        available_claim = (
            same_identity_renewal
            if presented_claim_token is not None
            else or_(
                AgentTask.claimed_by.is_(None),
                AgentTask.claim_expires_at <= func.now(),
            )
        )
        statement = (
            update(AgentTask)
            .where(
                AgentTask.task_id == task_id,
                AgentTask.status.in_(("PENDING", "IN_PROGRESS")),
                available_claim,
            )
            .values(
                claimed_by=identity,
                claim_expires_at=func.now() + lease_interval,
                # A renewal extends the same claim and keeps its proof token;
                # an initial claim/reclaim receives the freshly generated one.
                claim_token=case(
                    (same_identity_renewal, AgentTask.claim_token),
                    else_=new_claim_token,
                ),
                status="IN_PROGRESS",
                updated_at=func.now(),
            )
            .returning(AgentTask.task_id)
        )
        result = await self._db.execute(statement)
        claimed_task_id = result.scalar_one_or_none()
        if claimed_task_id is None:
            return None
        return await self.get_by_id(claimed_task_id)

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
