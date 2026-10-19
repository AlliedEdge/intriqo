"""Add lease proof tokens and authenticated finding uniqueness.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agent_tasks",
        sa.Column("claim_token", sa.String(256), nullable=True),
    )
    op.create_index(
        "uq_findings_task_submitted_by",
        "findings",
        ["task_id", "submitted_by"],
        unique=True,
        postgresql_where=sa.text("submitted_by IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_findings_task_submitted_by", table_name="findings")
    op.drop_column("agent_tasks", "claim_token")
