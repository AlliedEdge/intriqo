"""SecurityEvent application service.

Responsible for:
- Validating the inbound event payload
- Deduplication (reject duplicate event_id with a clear error)
- Constructing the ORM model
- Calling the repository to persist
- Recording an audit entry
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.security_event import SecurityEvent
from intriqo.repositories.events import EventRepository
from intriqo.schemas.events import SecurityEventCreate
from intriqo.services import audit_service

logger = logging.getLogger("intriqo.services.event")


class DuplicateEventError(Exception):
    """Raised when an event_id already exists in the database."""
    def __init__(self, event_id: str) -> None:
        super().__init__(f"Event '{event_id}' already exists")
        self.event_id = event_id


async def ingest_event(
    db: AsyncSession,
    payload: SecurityEventCreate,
    actor: str = "system",
) -> SecurityEvent:
    """Validate, deduplicate, persist, and audit a new SecurityEvent."""
    repo = EventRepository(db)

    if await repo.exists(payload.event_id):
        raise DuplicateEventError(payload.event_id)

    raw = payload.model_dump()
    # Serialise datetime for JSONB storage
    raw["timestamp"] = payload.timestamp.isoformat()

    event = SecurityEvent(
        event_id=payload.event_id,
        event_type=payload.event_type,
        severity=payload.severity,
        timestamp=payload.timestamp,
        source_address=payload.source_address,
        destination_address=payload.destination_address,
        description=payload.description,
        raw_payload=raw,
        ingested_at=datetime.now(timezone.utc),
    )

    event = await repo.create(event)

    await audit_service.record(
        db,
        actor=actor,
        action=audit_service.ACTION_EVENT_INGESTED,
        resource_type="security_event",
        resource_id=event.event_id,
        extra={"event_type": event.event_type, "severity": event.severity},
    )

    logger.info(
        "Ingested SecurityEvent event_id=%s event_type=%s severity=%s",
        event.event_id, event.event_type, event.severity,
    )
    return event
