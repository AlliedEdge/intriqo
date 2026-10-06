"""Incident API routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth.dependencies import AgentUser, AnalystUser
from intriqo.db.models.security_event import SecurityEvent
from intriqo.db.session import get_db
from intriqo.repositories.incidents import IncidentRepository
from intriqo.schemas.common import PaginatedResponse
from intriqo.schemas.incidents import IncidentCreate, IncidentResponse, IncidentUpdate
from intriqo.services.incident_service import (
    IncidentNotFoundError,
    InvalidIncidentStatusTransitionError,
    create_incident,
    update_incident,
)

router = APIRouter(prefix="/incidents")


def _to_response(incident) -> IncidentResponse:
    event_links = incident.event_links or []
    linked_event_ids = [link.event_id for link in event_links]
    linked_task_ids = [task.task_id for task in (incident.agent_tasks or [])]
    linked_finding_ids = list(
        dict.fromkeys(
            [finding.finding_id for finding in (incident.findings or [])]
            + [
                finding.finding_id
                for task in (incident.agent_tasks or [])
                for finding in (task.findings or [])
            ]
        )
    )
    detection_sources: set[str] = set()
    for link in event_links:
        event = link.event
        details = (event.raw_payload or {}).get("details", {}) if event is not None else {}
        source = details.get("detection_source")
        if not isinstance(source, str):
            source = "ML" if event is not None and event.event_type == "ML_ANOMALY" else "DETERMINISTIC"
        detection_sources.add(source)
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
        correlation_key=incident.correlation_key,
        correlation_window_seconds=(
            (incident.incident_metadata or {}).get("correlation", {}).get("window_seconds")
        ),
        linked_event_ids=linked_event_ids,
        linked_task_ids=linked_task_ids,
        linked_finding_ids=linked_finding_ids,
        event_count=len(linked_event_ids),
        task_count=len(linked_task_ids),
        finding_count=len(linked_finding_ids),
        detection_sources=sorted(detection_sources),
    )


async def _hydrate_event_links(db: AsyncSession, incidents) -> None:
    """Load event payloads before synchronous response mapping.

    Association rows created in the current transaction do not necessarily
    have their nested ``event`` relationship populated. Explicitly loading
    them avoids implicit async IO from the response serializer.
    """
    incident_list = incidents if isinstance(incidents, list) else [incidents]
    event_ids = {
        link.event_id
        for incident in incident_list
        for link in (incident.event_links or [])
    }
    if not event_ids:
        return
    result = await db.execute(select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids)))
    events = {event.event_id: event for event in result.scalars().all()}
    for incident in incident_list:
        for link in incident.event_links or []:
            link.event = events.get(link.event_id)


@router.post("", response_model=IncidentResponse, status_code=201)
async def create(
    payload: IncidentCreate,
    user: AnalystUser,
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    incident = await create_incident(db, payload, actor=user.username)
    await _hydrate_event_links(db, incident)
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
    await _hydrate_event_links(db, incidents)
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
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
) -> IncidentResponse:
    repo = IncidentRepository(db)
    incident = await repo.get_by_id(incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": {
                    "code": "INCIDENT_NOT_FOUND",
                    "message": f"Incident '{incident_id}' was not found",
                }
            },
        )
    await _hydrate_event_links(db, incident)
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
    except InvalidIncidentStatusTransitionError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "INVALID_STATUS_TRANSITION", "message": str(e)}},
        )
    await _hydrate_event_links(db, incident)
    return _to_response(incident)
