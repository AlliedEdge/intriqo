"""Add deterministic SOC correlation and durable workflow idempotency.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-06
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("incidents", sa.Column("correlation_key", sa.String(256), nullable=True))
    op.add_column(
        "incidents",
        sa.Column("correlation_last_event_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_incidents_correlation_key", "incidents", ["correlation_key"])

    op.add_column("agent_tasks", sa.Column("idempotency_key", sa.String(256), nullable=True))
    op.create_index(
        "uq_agent_tasks_idempotency_key",
        "agent_tasks",
        ["idempotency_key"],
        unique=True,
        postgresql_where=sa.text("idempotency_key IS NOT NULL"),
    )

    op.add_column("findings", sa.Column("severity", sa.String(16), nullable=True))
    op.add_column("findings", sa.Column("source", sa.String(64), nullable=True))
    op.add_column("findings", sa.Column("event_id", sa.String(36), nullable=True))
    op.add_column("findings", sa.Column("incident_id", sa.String(36), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "provenance",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.execute(sa.text("UPDATE findings SET provenance = '{}'::jsonb WHERE provenance IS NULL"))
    op.alter_column("findings", "provenance", nullable=False)
    op.create_foreign_key(
        "fk_findings_event_id_security_events",
        "findings",
        "security_events",
        ["event_id"],
        ["event_id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_findings_incident_id_incidents",
        "findings",
        "incidents",
        ["incident_id"],
        ["incident_id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_source", "findings", ["source"])
    op.create_index("ix_findings_event_id", "findings", ["event_id"])
    op.create_index("ix_findings_incident_id", "findings", ["incident_id"])
    op.create_unique_constraint("uq_findings_task_agent", "findings", ["task_id", "agent_name"])


def downgrade() -> None:
    op.drop_constraint("uq_findings_task_agent", "findings", type_="unique")
    op.drop_index("ix_findings_incident_id", table_name="findings")
    op.drop_index("ix_findings_event_id", table_name="findings")
    op.drop_index("ix_findings_source", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_constraint("fk_findings_incident_id_incidents", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_event_id_security_events", "findings", type_="foreignkey")
    op.drop_column("findings", "provenance")
    op.drop_column("findings", "incident_id")
    op.drop_column("findings", "event_id")
    op.drop_column("findings", "source")
    op.drop_column("findings", "severity")

    op.drop_index("uq_agent_tasks_idempotency_key", table_name="agent_tasks")
    op.drop_column("agent_tasks", "idempotency_key")

    op.drop_index("ix_incidents_correlation_key", table_name="incidents")
    op.drop_column("incidents", "correlation_last_event_at")
    op.drop_column("incidents", "correlation_key")
