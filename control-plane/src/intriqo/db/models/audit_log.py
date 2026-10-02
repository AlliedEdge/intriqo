"""AuditLog ORM model.

Provides an append-only audit trail answering:
  WHO performed the action?
  WHAT happened?
  WHEN?
  ON WHICH RESOURCE?
  WHAT was the result?

Audit records are NEVER updated or deleted through normal application code.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from intriqo.db.base import Base


class AuditLog(Base):
    """Immutable audit record for security-sensitive control-plane actions."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)

    # ── WHO ───────────────────────────────────────────────────────────────────
    actor: Mapped[str] = mapped_column(
        String(128), nullable=False
    )  # username, agent name, or "system"

    # ── WHAT ─────────────────────────────────────────────────────────────────
    action: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # e.g. EVENT_INGESTED, INCIDENT_CREATED, TASK_CREATED, FINDING_SUBMITTED

    # ── ON WHICH RESOURCE ─────────────────────────────────────────────────────
    resource_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # e.g. security_event, incident, agent_task, finding
    resource_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # ── WHAT WAS THE RESULT ───────────────────────────────────────────────────
    outcome: Mapped[str] = mapped_column(
        String(16), nullable=False, default="SUCCESS"
    )  # SUCCESS | FAILURE
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Additional structured context (stored as "extra" column, not "metadata") ──
    extra: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # ── WHEN ─────────────────────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    __table_args__ = (
        Index("ix_audit_logs_actor_created_at",    "actor", "created_at"),
        Index("ix_audit_logs_resource",            "resource_type", "resource_id"),
        Index("ix_audit_logs_action_created_at",   "action", "created_at"),
    )
