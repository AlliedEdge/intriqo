"""Incident ORM model.

An Incident is a grouping of related SecurityEvents that requires SOC investigation.
The IncidentEvent association table links incidents to their source events.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from intriqo.db.base import Base


class Incident(Base):
    """A security incident tracked by the SOC."""

    __tablename__ = "incidents"

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="OPEN", index=True
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="MEDIUM", index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Metadata / tags stored as JSONB for flexibility
    incident_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)

    # ── Relationships ─────────────────────────────────────────────────────────
    event_links: Mapped[list[IncidentEvent]] = relationship(
        "IncidentEvent",
        back_populates="incident",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    agent_tasks: Mapped[list["AgentTask"]] = relationship(
        "AgentTask",
        back_populates="incident",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_created_at",       "created_at"),
    )


class IncidentEvent(Base):
    """Association between an Incident and the SecurityEvents that triggered it."""

    __tablename__ = "incident_events"

    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        primary_key=True,
    )
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("security_events.event_id", ondelete="CASCADE"),
        primary_key=True,
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    incident: Mapped[Incident] = relationship("Incident", back_populates="event_links")
