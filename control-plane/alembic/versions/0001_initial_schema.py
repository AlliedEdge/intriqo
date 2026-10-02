"""Initial schema — security_events, incidents, agent_tasks, findings, audit_logs, users.

Revision ID: 0001
Revises:
Create Date: 2026-10-01
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",              sa.String(36),  nullable=False),
        sa.Column("username",        sa.String(128), nullable=False),
        sa.Column("email",           sa.String(256), nullable=False),
        sa.Column("hashed_password", sa.String(256), nullable=False),
        sa.Column("role",            sa.String(16),  nullable=False),
        sa.Column("is_active",       sa.Boolean(),   nullable=False),
        sa.Column("created_at",      sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",      sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email",    "users", ["email"],    unique=True)

    # ── security_events ───────────────────────────────────────────────────────
    op.create_table(
        "security_events",
        sa.Column("event_id",             sa.String(36),  nullable=False),
        sa.Column("event_type",           sa.String(64),  nullable=False),
        sa.Column("severity",             sa.String(16),  nullable=False),
        sa.Column("timestamp",            sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_address",       sa.String(45),  nullable=False),
        sa.Column("destination_address",  sa.String(45),  nullable=False),
        sa.Column("description",          sa.Text(),      nullable=True),
        sa.Column("raw_payload",          postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("ingested_at",          sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index("ix_security_events_timestamp",           "security_events", ["timestamp"])
    op.create_index("ix_security_events_severity",            "security_events", ["severity"])
    op.create_index("ix_security_events_event_type",          "security_events", ["event_type"])
    op.create_index("ix_security_events_source_address",      "security_events", ["source_address"])
    op.create_index("ix_security_events_destination_address", "security_events", ["destination_address"])
    op.create_index("ix_security_events_severity_timestamp",  "security_events", ["severity", "timestamp"])

    # ── incidents ─────────────────────────────────────────────────────────────
    op.create_table(
        "incidents",
        sa.Column("incident_id",  sa.String(36),  nullable=False),
        sa.Column("title",        sa.String(256), nullable=False),
        sa.Column("description",  sa.Text(),      nullable=False),
        sa.Column("status",       sa.String(32),  nullable=False),
        sa.Column("severity",     sa.String(16),  nullable=False),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata",     postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("incident_id"),
    )
    op.create_index("ix_incidents_status_severity", "incidents", ["status", "severity"])
    op.create_index("ix_incidents_created_at",      "incidents", ["created_at"])

    # ── incident_events (association) ─────────────────────────────────────────
    op.create_table(
        "incident_events",
        sa.Column("incident_id", sa.String(36), nullable=False),
        sa.Column("event_id",    sa.String(36), nullable=False),
        sa.Column("linked_at",   sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"],    ["security_events.event_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("incident_id", "event_id"),
    )

    # ── agent_tasks ───────────────────────────────────────────────────────────
    op.create_table(
        "agent_tasks",
        sa.Column("task_id",      sa.String(36),  nullable=False),
        sa.Column("task_type",    sa.String(32),  nullable=False),
        sa.Column("description",  sa.Text(),      nullable=False),
        sa.Column("priority",     sa.String(16),  nullable=False),
        sa.Column("status",       sa.String(32),  nullable=False),
        sa.Column("event_id",     sa.String(36),  nullable=True),
        sa.Column("incident_id",  sa.String(36),  nullable=True),
        sa.Column("context",      postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",   sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["event_id"],    ["security_events.event_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"],   ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("task_id"),
    )
    op.create_index("ix_agent_tasks_status_priority", "agent_tasks", ["status", "priority"])
    op.create_index("ix_agent_tasks_created_at",      "agent_tasks", ["created_at"])
    op.create_index("ix_agent_tasks_event_id",        "agent_tasks", ["event_id"])
    op.create_index("ix_agent_tasks_incident_id",     "agent_tasks", ["incident_id"])

    # ── findings ──────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("finding_id",   sa.String(36),  nullable=False),
        sa.Column("agent_name",   sa.String(128), nullable=False),
        sa.Column("status",       sa.String(32),  nullable=False),
        sa.Column("confidence",   sa.Float(),     nullable=False),
        sa.Column("summary",      sa.Text(),      nullable=True),
        sa.Column("findings",     postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence",     postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("metadata",     postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("error",        postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("task_id",      sa.String(36),  nullable=False),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["agent_tasks.task_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("finding_id"),
    )
    op.create_index("ix_findings_status_confidence", "findings", ["status", "confidence"])
    op.create_index("ix_findings_created_at",        "findings", ["created_at"])
    op.create_index("ix_findings_task_id",           "findings", ["task_id"])
    op.create_index("ix_findings_agent_name",        "findings", ["agent_name"])

    # ── audit_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id",            sa.String(36), nullable=False),
        sa.Column("actor",         sa.String(128), nullable=False),
        sa.Column("action",        sa.String(64),  nullable=False),
        sa.Column("resource_type", sa.String(64),  nullable=False),
        sa.Column("resource_id",   sa.String(36),  nullable=False),
        sa.Column("outcome",       sa.String(16),  nullable=False),
        sa.Column("detail",        sa.Text(),      nullable=True),
        sa.Column("extra",         postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_logs_actor_created_at",  "audit_logs", ["actor", "created_at"])
    op.create_index("ix_audit_logs_resource",          "audit_logs", ["resource_type", "resource_id"])
    op.create_index("ix_audit_logs_action_created_at", "audit_logs", ["action", "created_at"])
    op.create_index("ix_audit_logs_created_at",        "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("findings")
    op.drop_table("agent_tasks")
    op.drop_table("incident_events")
    op.drop_table("incidents")
    op.drop_table("security_events")
    op.drop_table("users")
