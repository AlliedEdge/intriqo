"""AgentTask API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth.dependencies import AgentUser, AnalystUser
from intriqo.db.session import get_db
from intriqo.repositories.agent_tasks import AgentTaskRepository
from intriqo.schemas.agent_tasks import AgentTaskCreate, AgentTaskResponse, AgentTaskStatusUpdate
from intriqo.schemas.common import PaginatedResponse
from intriqo.services.agent_task_service import (
    AgentTaskNotFoundError,
    InvalidTaskTypeError,
    create_task,
    update_task_status,
    InvalidStatusTransitionError,
)

router = APIRouter(prefix="/agent-tasks")


def _to_response(task) -> AgentTaskResponse:
    return AgentTaskResponse(
        task_id=task.task_id,
        task_type=task.task_type,
        description=task.description,
        priority=task.priority,
        status=task.status,
        event_id=task.event_id,
        incident_id=task.incident_id,
        context=task.context or {},
        created_at=task.created_at,
        updated_at=task.updated_at,
        completed_at=task.completed_at,
    )


@router.post("", response_model=AgentTaskResponse, status_code=201)
async def create(
    payload: AgentTaskCreate,
    user: AnalystUser,
    db: AsyncSession = Depends(get_db),
) -> AgentTaskResponse:
    try:
        task = await create_task(db, payload, actor=user.username)
    except InvalidTaskTypeError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": {"code": "INVALID_TASK_TYPE", "message": str(e)}},
        )
    return _to_response(task)


@router.get("", response_model=PaginatedResponse[AgentTaskResponse])
async def list_tasks(
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    priority: Annotated[str | None, Query()] = None,
    task_type: Annotated[str | None, Query()] = None,
    event_id: Annotated[str | None, Query()] = None,
    incident_id: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 50,
) -> PaginatedResponse[AgentTaskResponse]:
    repo = AgentTaskRepository(db)
    tasks, total = await repo.list(
        status=status_filter,
        priority=priority,
        task_type=task_type,
        event_id=event_id,
        incident_id=incident_id,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_to_response(t) for t in tasks],
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get("/{task_id}", response_model=AgentTaskResponse)
async def get_task(
    task_id: str,
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
) -> AgentTaskResponse:
    repo = AgentTaskRepository(db)
    task = await repo.get_by_id(task_id)
    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "TASK_NOT_FOUND", "message": f"AgentTask '{task_id}' was not found"}},
        )
    return _to_response(task)


@router.patch("/{task_id}", response_model=AgentTaskResponse)
async def update_status(
    task_id: str,
    payload: AgentTaskStatusUpdate,
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
) -> AgentTaskResponse:
    try:
        task = await update_task_status(db, task_id, payload.status, actor=user.username)
    except AgentTaskNotFoundError as e:
        raise HTTPException(status_code=404, detail={"error": {"code": "TASK_NOT_FOUND", "message": str(e)}})
    except InvalidStatusTransitionError as e:
        raise HTTPException(status_code=409, detail={"error": {"code": "INVALID_STATUS_TRANSITION", "message": str(e)}})
    return _to_response(task)
