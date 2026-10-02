"""Incident application service."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.incident import Incident, IncidentEvent
from intriqo.repositories.incidents import IncidentRepository
from intriqo.schemas.incidents import IncidentCreate, IncidentUpdate
from intriqo.services import audit_service

logger = logging.getLogger("intriqo.services.incident")


class IncidentNotFoundError(Exception):
    def __init__(self, incident_id: str) -> None:
        super().__init__(f"Incident '{incident_id}' not found")
        self.incident_id = incident_id


async def create_incident(
    db: AsyncSession,
    payload: IncidentCreate,
    actor: str = "system",
) -> Incident:
    """Create a new incident and link any provided SecurityEvents."""
    repo = IncidentRepository(db)

    incident = Incident(
        incident_id=str(uuid.uuid4()),
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status="OPEN",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        incident_metadata=payload.incident_metadata,
    )
    incident = await repo.create(incident)

    # Link any provided event IDs
    for event_id in payload.event_ids:
        link = IncidentEvent(
            incident_id=incident.incident_id,
            event_id=event_id,
            linked_at=datetime.now(timezone.utc),
        )
        await repo.add_event_link(link)

    # Refresh to load event_links after they were inserted
    if payload.event_ids:
        await db.refresh(incident, attribute_names=["event_links"])

    await audit_service.record(
        db,
        actor=actor,
        action=audit_service.ACTION_INCIDENT_CREATED,
        resource_type="incident",
        resource_id=incident.incident_id,
        extra={"title": incident.title, "severity": incident.severity},
    )

    logger.info("Created incident incident_id=%s title=%r", incident.incident_id, incident.title)
    return incident


async def update_incident(
    db: AsyncSession,
    incident_id: str,
    payload: IncidentUpdate,
    actor: str = "system",
) -> Incident:
    """Update mutable incident fields."""
    repo = IncidentRepository(db)
    incident = await repo.get_by_id(incident_id)
    if incident is None:
        raise IncidentNotFoundError(incident_id)

    if payload.title is not None:
        incident.title = payload.title
    if payload.description is not None:
        incident.description = payload.description
    if payload.status is not None:
        incident.status = payload.status
        if payload.status in ("RESOLVED", "CLOSED", "FALSE_POSITIVE"):
            incident.resolved_at = datetime.now(timezone.utc)
    if payload.severity is not None:
        incident.severity = payload.severity
    if payload.incident_metadata is not None:
        incident.incident_metadata = payload.incident_metadata

    incident.updated_at = datetime.now(timezone.utc)
    incident = await repo.update(incident)

    await audit_service.record(
        db,
        actor=actor,
        action=audit_service.ACTION_INCIDENT_UPDATED,
        resource_type="incident",
        resource_id=incident.incident_id,
        extra={"status": incident.status},
    )
    return incident
