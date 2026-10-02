"""Finding API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth.dependencies import AgentUser
from intriqo.db.session import get_db
from intriqo.repositories.findings import FindingRepository
from intriqo.schemas.common import PaginatedResponse
from intriqo.schemas.findings import FindingCreate, FindingResponse
from intriqo.services.agent_task_service import AgentTaskNotFoundError, submit_finding

router = APIRouter(prefix="/findings")


def _to_response(finding) -> FindingResponse:
    return FindingResponse(
        finding_id=finding.finding_id,
        task_id=finding.task_id,
        agent_name=finding.agent_name,
        status=finding.status,
        confidence=finding.confidence,
        summary=finding.summary,
        findings=finding.finding_list or [],
        evidence=finding.evidence or [],
        finding_metadata=finding.finding_metadata or {},
        error=finding.error,
        created_at=finding.created_at,
    )


@router.post("", response_model=FindingResponse, status_code=201)
async def submit(
    payload: FindingCreate,
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    """Submit an agent result (Finding) for a task."""
    try:
        finding = await submit_finding(db, payload, actor=user.username)
    except AgentTaskNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "TASK_NOT_FOUND", "message": str(e)}},
        )
    return _to_response(finding)


@router.get("", response_model=PaginatedResponse[FindingResponse])
async def list_findings(
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    task_id: Annotated[str | None, Query()] = None,
    agent_name: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 50,
) -> PaginatedResponse[FindingResponse]:
    repo = FindingRepository(db)
    findings, total = await repo.list(
        status=status_filter,
        task_id=task_id,
        agent_name=agent_name,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_to_response(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
) -> FindingResponse:
    repo = FindingRepository(db)
    finding = await repo.get_by_id(finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "FINDING_NOT_FOUND", "message": f"Finding '{finding_id}' was not found"}},
        )
    return _to_response(finding)
