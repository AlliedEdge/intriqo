"""Finding ORM model.

Represents the structured result submitted by an agent back to the Control Plane.
Based on contracts/agents/agent_result_v1.json.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from intriqo.db.base import Base

if TYPE_CHECKING:
    from intriqo.db.models.agent_task import AgentTask
    from intriqo.db.models.incident import Incident
    from intriqo.db.models.security_event import SecurityEvent


class Finding(Base):
    """Structured investigation result submitted by an agent."""

    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)

    # ── Agent result contract fields ──────────────────────────────────────────
    agent_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # SUCCESS | FAILED | INCONCLUSIVE
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # ── Structured data as JSONB ───────────────────────────────────────────────
    # "findings" and "evidence" match the agent_result_v1.json field names.
    # "finding_metadata" maps to the "metadata" JSON field (avoids SQLAlchemy reserved name).
    finding_list: Mapped[list] = mapped_column("findings", JSONB, nullable=False, default=list)
    evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    finding_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    error: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    provenance: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # ── Foreign key: the task that produced this finding ─────────────────────
    task_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("agent_tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("security_events.event_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    agent_task: Mapped["AgentTask"] = relationship(
        "AgentTask",
        back_populates="findings",
        lazy="selectin",
    )
    event: Mapped["SecurityEvent | None"] = relationship(
        "SecurityEvent", back_populates="findings", lazy="selectin"
    )
    incident: Mapped["Incident | None"] = relationship(
        "Incident", back_populates="findings", lazy="selectin"
    )

    __table_args__ = (
        UniqueConstraint("task_id", "agent_name", name="uq_findings_task_agent"),
        Index("ix_findings_status_confidence", "status", "confidence"),
        Index("ix_findings_created_at",        "created_at"),
    )
