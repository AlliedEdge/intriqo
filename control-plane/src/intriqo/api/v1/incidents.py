"""Incident API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth.dependencies import AnalystUser
from intriqo.db.session import get_db
from intriqo.repositories.incidents import IncidentRepository
from intriqo.schemas.common import PaginatedResponse
from intriqo.schemas.incidents import IncidentCreate, IncidentResponse, IncidentUpdate
from intriqo.services.incident_service import (
    IncidentNotFoundError,
    create_incident,
    update_incident,
)

router = APIRouter(prefix="/incidents")


def _to_response(incident) -> IncidentResponse:
    return IncidentResponse(
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        status=incident.status,
        severity=incident.severity,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        resolved_at=incident.resolved_at,
        incident_metadata=incident.incident_metadata or {},
        linked_event_ids=[link.event_id for link in (incident.event_links or [])],
    )


@router.post("", response_model=IncidentResponse, status_code=201)
async def create(
    payload: IncidentCreate,
    user: AnalystUser,
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    incident = await create_incident(db, payload, actor=user.username)
    return _to_response(incident)


@router.get("", response_model=PaginatedResponse[IncidentResponse])
async def list_incidents(
    user: AnalystUser,
    db: AsyncSession = Depends(get_db),
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    severity: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 50,
) -> PaginatedResponse[IncidentResponse]:
    repo = IncidentRepository(db)
    incidents, total = await repo.list(
        status=status_filter,
        severity=severity,
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_to_response(i) for i in incidents],
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    user: AnalystUser,
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    repo = IncidentRepository(db)
    incident = await repo.get_by_id(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "INCIDENT_NOT_FOUND", "message": f"Incident '{incident_id}' was not found"}},
        )
    return _to_response(incident)


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update(
    incident_id: str,
    payload: IncidentUpdate,
    user: AnalystUser,
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    try:
        incident = await update_incident(db, incident_id, payload, actor=user.username)
    except IncidentNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": {"code": "INCIDENT_NOT_FOUND", "message": str(e)}},
        )
    return _to_response(incident)
