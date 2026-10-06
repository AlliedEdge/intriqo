"""SecurityEvent API routes.

POST /api/v1/events          — ingest one SecurityEvent from the IDS engine
GET  /api/v1/events          — list events with optional filters
GET  /api/v1/events/{id}     — retrieve one event
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth.dependencies import AgentUser
from intriqo.db.session import get_db
from intriqo.repositories.events import EventRepository
from intriqo.schemas.common import PaginatedResponse
from intriqo.schemas.events import SecurityEventCreate, SecurityEventResponse
from intriqo.services.event_service import DuplicateEventError, ingest_event

router = APIRouter(prefix="/events")


def _to_response(event) -> SecurityEventResponse:
    raw = event.raw_payload or {}
    return SecurityEventResponse(
        event_id=event.event_id,
        event_type=event.event_type,
        severity=event.severity,
        timestamp=event.timestamp,
        source_address=event.source_address,
        destination_address=event.destination_address,
        description=event.description,
        details=raw.get("details", {}),
        ingested_at=event.ingested_at,
        linked_incident_ids=[link.incident_id for link in (event.incident_links or [])],
        linked_task_ids=[task.task_id for task in (event.agent_tasks or [])],
        linked_finding_ids=list(
            dict.fromkeys(
                [finding.finding_id for finding in (event.findings or [])]
                + [
                    finding.finding_id
                    for task in (event.agent_tasks or [])
                    for finding in (task.findings or [])
                ]
            )
        ),
    )


def _parse_dt(s: str | None) -> datetime | None:
    if s is None:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@router.post("", response_model=SecurityEventResponse, status_code=201)
async def create_event(
    payload: SecurityEventCreate,
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
) -> SecurityEventResponse:
    """Ingest a SecurityEvent emitted by the C++ IDS engine."""
    try:
        event = await ingest_event(db, payload, actor=user.username)
    except DuplicateEventError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "DUPLICATE_EVENT", "message": str(e)}},
        )
    stored = await EventRepository(db).get_by_id(event.event_id)
    return _to_response(stored or event)


@router.get("", response_model=PaginatedResponse[SecurityEventResponse])
async def list_events(
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
    severity: Annotated[str | None, Query()] = None,
    event_type: Annotated[str | None, Query()] = None,
    source_address: Annotated[str | None, Query()] = None,
    destination_address: Annotated[str | None, Query()] = None,
    from_time: Annotated[str | None, Query(description="ISO 8601")] = None,
    to_time: Annotated[str | None, Query(description="ISO 8601")] = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=500)] = 50,
) -> PaginatedResponse[SecurityEventResponse]:
    """List SecurityEvents with optional filters and pagination."""
    repo = EventRepository(db)
    events, total = await repo.list(
        severity=severity,
        event_type=event_type,
        source_address=source_address,
        destination_address=destination_address,
        from_time=_parse_dt(from_time),
        to_time=_parse_dt(to_time),
        page=page,
        page_size=page_size,
    )
    return PaginatedResponse(
        items=[_to_response(e) for e in events],
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get("/{event_id}", response_model=SecurityEventResponse)
async def get_event(
    event_id: str,
    user: AgentUser,
    db: AsyncSession = Depends(get_db),
) -> SecurityEventResponse:
    """Retrieve one SecurityEvent by ID."""
    repo = EventRepository(db)
    event = await repo.get_by_id(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": {
                    "code": "EVENT_NOT_FOUND",
                    "message": f"Security event '{event_id}' was not found",
                }
            },
        )
    return _to_response(event)
