"""SecurityEvent ORM model.

Design:
- The complete validated event payload is stored as JSONB (`raw_payload`)
  for schema flexibility and forward compatibility.
- Frequently queried fields are also extracted into typed columns and indexed.
- event_id comes from the C++ engine (UUID string) and is the primary key.
  No synthetic surrogate key — the engine-issued ID is canonical.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from intriqo.db.base import Base

if TYPE_CHECKING:
    from intriqo.db.models.agent_task import AgentTask
    from intriqo.db.models.finding import Finding
    from intriqo.db.models.incident import IncidentEvent


class SecurityEvent(Base):
    """Persisted security event emitted by the C++ IDS engine."""

    __tablename__ = "security_events"

    # ── Primary key: engine-issued UUID ──────────────────────────────────────
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)

    # ── Required typed columns (also appear in raw_payload) ──────────────────
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_address: Mapped[str] = mapped_column(String(45), nullable=False)   # IPv4/IPv6
    destination_address: Mapped[str] = mapped_column(String(45), nullable=False)

    # ── Optional typed columns from the contract ──────────────────────────────
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Full JSONB payload — the canonical record ─────────────────────────────
    # Includes details{} and any future contract extensions.
    raw_payload: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # ── Ingestion metadata ────────────────────────────────────────────────────
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    incident_links: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent",
        back_populates="event",
        lazy="selectin",
    )
    agent_tasks: Mapped[list["AgentTask"]] = relationship(
        "AgentTask",
        back_populates="event",
        lazy="selectin",
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        foreign_keys="Finding.event_id",
        back_populates="event",
        lazy="selectin",
    )

    # ── Indexes for common query patterns ────────────────────────────────────
    __table_args__ = (
        Index("ix_security_events_timestamp",          "timestamp"),
        Index("ix_security_events_severity",           "severity"),
        Index("ix_security_events_event_type",         "event_type"),
        Index("ix_security_events_source_address",     "source_address"),
        Index("ix_security_events_destination_address","destination_address"),
        # Composite for the most common dashboard query: recent events by severity
        Index("ix_security_events_severity_timestamp", "severity", "timestamp"),
    )
