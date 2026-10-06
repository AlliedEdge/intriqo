"""Deterministic event-to-incident correlation for the Control Plane.

Only deterministic detector events are auto-correlated here.  ML anomaly
events remain analyst-linked so the ML delivery contract cannot create an
incident merely because an anomaly was emitted.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.db.models.incident import Incident, IncidentEvent
from intriqo.db.models.security_event import SecurityEvent
from intriqo.services import audit_service

CORRELATION_WINDOW = timedelta(minutes=5)
CORRELATION_WINDOW_SECONDS = int(CORRELATION_WINDOW.total_seconds())
CORRELATABLE_EVENT_TYPES = frozenset({"PORT_SCAN", "SYN_FLOOD"})
DETERMINISTIC_EVENT_TYPES = CORRELATABLE_EVENT_TYPES
_SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def correlation_key(event: SecurityEvent) -> str:
    """Build the stable directional key used by the correlator.

    Event type and the normalized source/destination address pair are the
    complete key.  Severity is deliberately excluded so one attack does not
    fork into multiple incidents when detector confidence changes.
    """
    return "|".join(
        (
            event.event_type.strip().upper(),
            event.source_address.strip().lower(),
            event.destination_address.strip().lower(),
        )
    )


def situation_key(event: SecurityEvent) -> str:
    """Return the directional endpoint key shared by detector types."""
    return "|".join(
        (event.source_address.strip().lower(), event.destination_address.strip().lower())
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _metadata(incident: Incident, key: str, event: SecurityEvent) -> dict[str, Any]:
    metadata = dict(incident.incident_metadata or {})
    correlation = dict(metadata.get("correlation") or {})
    correlation["key"] = key
    correlation["window_seconds"] = CORRELATION_WINDOW_SECONDS
    existing_count = max(int(correlation.get("event_count", 0)), len(incident.event_links or []))
    correlation["event_count"] = existing_count + 1
    correlation["last_event_id"] = event.event_id
    metadata["correlation"] = correlation
    return metadata


async def correlate_event(
    db: AsyncSession,
    event: SecurityEvent,
    *,
    actor: str = "system",
) -> Incident | None:
    """Link a deterministic event to one incident, creating one if needed.

    PostgreSQL's transaction advisory lock serializes concurrent arrivals for
    the same key.  The candidate is still selected by the explicit five-minute
    event-time window, so stale incidents do not absorb a new episode.
    """
    if event.event_type.strip().upper() not in CORRELATABLE_EVENT_TYPES:
        return None

    key = correlation_key(event)
    event_time = _aware(event.timestamp)
    lower_bound = event_time - CORRELATION_WINDOW
    upper_bound = event_time + CORRELATION_WINDOW

    # hashtextextended is stable within PostgreSQL and gives us a compact
    # advisory-lock key without adding another persistence table.
    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": key},
    )
    result = await db.execute(
        select(Incident)
        .where(
            Incident.correlation_key == key,
            Incident.status.in_(("OPEN", "INVESTIGATING", "CONTAINED")),
            Incident.correlation_last_event_at.is_not(None),
            Incident.correlation_last_event_at >= lower_bound,
            Incident.correlation_last_event_at <= upper_bound,
        )
        .order_by(Incident.correlation_last_event_at.desc())
        .with_for_update()
        .limit(1)
    )
    incident = result.scalar_one_or_none()

    if incident is None:
        # Make the analyst-link path order-independent: if an ML event was
        # promoted first, the next deterministic event joins that incident
        # instead of creating a second record for the same endpoints/window.
        ml_result = await db.execute(
            select(Incident)
            .join(IncidentEvent, IncidentEvent.incident_id == Incident.incident_id)
            .join(SecurityEvent, SecurityEvent.event_id == IncidentEvent.event_id)
            .where(
                SecurityEvent.event_type == "ML_ANOMALY",
                SecurityEvent.source_address == event.source_address,
                SecurityEvent.destination_address == event.destination_address,
                SecurityEvent.timestamp >= lower_bound,
                SecurityEvent.timestamp <= upper_bound,
                Incident.status.in_(('OPEN', 'INVESTIGATING', 'CONTAINED')),
            )
            .order_by(SecurityEvent.timestamp.desc())
            .limit(1)
        )
        incident = ml_result.scalar_one_or_none()

    if incident is None:
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            title=f"{event.event_type} from {event.source_address} to {event.destination_address}",
            description=(event.description or f"Correlated {event.event_type} detector events"),
            status="OPEN",
            severity=event.severity,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            correlation_key=key,
            correlation_last_event_at=event.timestamp,
            incident_metadata={
                "correlation": {
                    "key": key,
                    "window_seconds": CORRELATION_WINDOW_SECONDS,
                    "event_count": 1,
                    "last_event_id": event.event_id,
                    "source": "deterministic",
                }
            },
        )
        db.add(incident)
        await db.flush()
        action = audit_service.ACTION_INCIDENT_CREATED
    else:
        link_time = _aware(incident.correlation_last_event_at or event.timestamp)
        if _SEVERITY_RANK.get(event.severity, 0) > _SEVERITY_RANK.get(incident.severity, 0):
            incident.severity = event.severity
        incident.correlation_key = key
        incident.correlation_last_event_at = max(link_time, event_time)
        incident.updated_at = datetime.now(timezone.utc)
        incident.incident_metadata = _metadata(incident, key, event)
        await db.flush()
        action = audit_service.ACTION_EVENT_CORRELATED

    db.add(
        IncidentEvent(
            incident_id=incident.incident_id,
            event_id=event.event_id,
            linked_at=datetime.now(timezone.utc),
        )
    )
    await db.flush()
    await audit_service.record(
        db,
        actor=actor,
        action=action,
        # Correlation is an incident mutation: keeping the audit resource on
        # the incident makes the complete timeline visible on its detail page.
        resource_type="incident",
        resource_id=incident.incident_id,
        extra={
            "correlation_key": key,
            "window_seconds": CORRELATION_WINDOW_SECONDS,
            "incident_id": incident.incident_id,
            "event_id": event.event_id,
            "trigger_actor": actor,
        },
    )
    return incident
