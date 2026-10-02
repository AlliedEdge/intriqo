"""AgentTask ORM model.

Represents a unit of work dispatched by the Control Plane to the Agent Platform.
The task contract is defined in contracts/agents/agent_task_v1.json.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from intriqo.db.base import Base

if TYPE_CHECKING:
    from intriqo.db.models.incident import Incident
    from intriqo.db.models.finding import Finding


class AgentTask(Base):
    """A task dispatched by the Control Plane to the Agent Platform."""

    __tablename__ = "agent_tasks"

    task_id: Mapped[str] = mapped_column(String(36), primary_key=True)

    # ── Contract fields (mirrors agent_task_v1.json) ──────────────────────────
    task_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # INVESTIGATION | CORRELATION | THREAT_INTEL | RESPONSE
    description: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(
        String(16), nullable=False, default="MEDIUM", index=True
    )  # LOW | MEDIUM | HIGH | URGENT
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING", index=True
    )  # PENDING | IN_PROGRESS | COMPLETED | FAILED | CANCELLED

    # ── Foreign keys ──────────────────────────────────────────────────────────
    # The SecurityEvent this task was derived from
    event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("security_events.event_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # The Incident this task belongs to (optional — task can be standalone)
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Context JSONB — arbitrary per-task metadata ───────────────────────────
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # ── Timestamps ────────────────────────────────────────────────────────────
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
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    incident: Mapped["Incident | None"] = relationship(
        "Incident",
        back_populates="agent_tasks",
        lazy="selectin",
    )
    findings: Mapped[list["Finding"]] = relationship(
        "Finding",
        back_populates="agent_task",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_agent_tasks_status_priority",  "status", "priority"),
        Index("ix_agent_tasks_created_at",       "created_at"),
    )
