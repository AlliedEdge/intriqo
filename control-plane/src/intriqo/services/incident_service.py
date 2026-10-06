"""Incident application service."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.incident import Incident, IncidentEvent
from intriqo.db.models.security_event import SecurityEvent
from intriqo.repositories.incidents import IncidentRepository
from intriqo.schemas.incidents import IncidentCreate, IncidentUpdate
from intriqo.services import audit_service
from intriqo.services.correlation_service import (
    CORRELATION_WINDOW,
    DETERMINISTIC_EVENT_TYPES,
    situation_key,
)

logger = logging.getLogger("intriqo.services.incident")


class IncidentNotFoundError(Exception):
    def __init__(self, incident_id: str) -> None:
        super().__init__(f"Incident '{incident_id}' not found")
        self.incident_id = incident_id


class InvalidIncidentStatusTransitionError(ValueError):
    """Raised when an incident update skips a lifecycle state."""


VALID_INCIDENT_STATUSES = {
    "OPEN",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
    "FALSE_POSITIVE",
}

# The first four states are the required SOC lifecycle.  CLOSED and
# FALSE_POSITIVE are retained as terminal compatibility states already exposed
# by the API.
ALLOWED_STATUS_TRANSITIONS = {
    "OPEN": {"INVESTIGATING", "FALSE_POSITIVE"},
    "INVESTIGATING": {"CONTAINED", "FALSE_POSITIVE"},
    "CONTAINED": {"RESOLVED", "FALSE_POSITIVE"},
    "RESOLVED": {"CLOSED"},
    "CLOSED": set(),
    "FALSE_POSITIVE": set(),
}


async def create_incident(
    db: AsyncSession,
    payload: IncidentCreate,
    actor: str = "system",
) -> Incident:
    """Create a new incident and link any provided SecurityEvents."""
    repo = IncidentRepository(db)

    event_ids = list(dict.fromkeys(payload.event_ids))
    # An analyst retrying the create call for an already-correlated event must
    # not fork the same security situation into a second incident.  Preserve
    # the existing 201 response contract while returning the durable record.
    existing_incident: Incident | None = None
    for event_id in event_ids:
        linked = await db.execute(
            select(Incident)
            .join(IncidentEvent, IncidentEvent.incident_id == Incident.incident_id)
            .where(IncidentEvent.event_id == event_id)
            .order_by(Incident.created_at.asc())
            .limit(1)
        )
        existing_incident = linked.scalar_one_or_none()
        if existing_incident is not None:
            break

    if existing_incident is None and event_ids:
        # ML events are deliberately not auto-promoted into incidents.  When
        # an analyst links one, however, co-locate it with an active
        # deterministic incident for the same endpoints and time window.
        event_result = await db.execute(
            select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids))
        )
        supplied_events = list(event_result.scalars().all())
        for event in supplied_events:
            if event.event_type != "ML_ANOMALY":
                continue
            key_prefixes = [
                f"{event_type}|{situation_key(event)}"
                for event_type in sorted(DETERMINISTIC_EVENT_TYPES)
            ]
            lower_bound = event.timestamp - CORRELATION_WINDOW
            upper_bound = event.timestamp + CORRELATION_WINDOW
            candidate = await db.execute(
                select(Incident)
                .where(
                    Incident.correlation_key.in_(key_prefixes),
                    Incident.status.in_(("OPEN", "INVESTIGATING", "CONTAINED")),
                    Incident.correlation_last_event_at >= lower_bound,
                    Incident.correlation_last_event_at <= upper_bound,
                )
                .order_by(Incident.correlation_last_event_at.desc())
                .limit(1)
            )
            existing_incident = candidate.scalar_one_or_none()
            if existing_incident is not None:
                break

    if existing_incident is not None:
        linked_ids = {
            link.event_id for link in (existing_incident.event_links or [])
        }
        for event_id in event_ids:
            if event_id not in linked_ids:
                await repo.add_event_link(
                    IncidentEvent(
                        incident_id=existing_incident.incident_id,
                        event_id=event_id,
                        linked_at=datetime.now(timezone.utc),
                    )
                )
        existing_incident.updated_at = datetime.now(timezone.utc)
        await repo.update(existing_incident)
        await audit_service.record(
            db,
            actor=actor,
            action=audit_service.ACTION_INCIDENT_EVENT_LINKED,
            resource_type="incident",
            resource_id=existing_incident.incident_id,
            extra={"event_ids": event_ids, "idempotent": True},
        )
        await db.refresh(existing_incident, attribute_names=["event_links"])
        return existing_incident

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

    # Link any provided event IDs.  De-duplicate the request before touching
    # the association primary key so retries cannot create a partial failure.
    for event_id in event_ids:
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
        extra={
            "title": incident.title,
            "severity": incident.severity,
            "event_ids": event_ids,
        },
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
    old_status = incident.status
    status_changed = payload.status is not None and payload.status != old_status
    if payload.status is not None:
        if payload.status not in VALID_INCIDENT_STATUSES:
            raise InvalidIncidentStatusTransitionError(
                f"Invalid incident status '{payload.status}'"
            )
        if status_changed and payload.status not in ALLOWED_STATUS_TRANSITIONS.get(
            old_status, set()
        ):
            raise InvalidIncidentStatusTransitionError(
                f"Cannot transition incident '{incident_id}' from {old_status} to {payload.status}"
            )
        if status_changed:
            incident.status = payload.status
            if payload.status in ("RESOLVED", "CLOSED", "FALSE_POSITIVE"):
                incident.resolved_at = datetime.now(timezone.utc)
    if payload.severity is not None:
        incident.severity = payload.severity
    if payload.incident_metadata is not None:
        incident.incident_metadata = payload.incident_metadata

    # A same-state update is a true no-op for the resource itself.  It still
    # receives an audit record so an operator action is traceable.
    if status_changed or any(
        value is not None
        for value in (
            payload.title,
            payload.description,
            payload.severity,
            payload.incident_metadata,
        )
    ):
        incident.updated_at = datetime.now(timezone.utc)
        incident = await repo.update(incident)

    await audit_service.record(
        db,
        actor=actor,
        action=audit_service.ACTION_INCIDENT_UPDATED,
        resource_type="incident",
        resource_id=incident.incident_id,
        extra={
            "from_status": old_status,
            "status": incident.status,
            "idempotent": not status_changed and payload.status is not None,
        },
    )
    return incident
