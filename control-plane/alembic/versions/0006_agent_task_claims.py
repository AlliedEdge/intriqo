"""Add atomic agent-task leases and authenticated finding submitters.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Both task columns are nullable so existing tasks remain readable.  An
    # old IN_PROGRESS task with no owner is deliberately reclaimable by the
    # first agent to issue the conditional claim UPDATE.
    op.add_column("agent_tasks", sa.Column("claimed_by", sa.String(128), nullable=True))
    op.add_column(
        "agent_tasks",
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_tasks_claimed_by", "agent_tasks", ["claimed_by"])
    op.create_index("ix_agent_tasks_claim_expires_at", "agent_tasks", ["claim_expires_at"])
    op.create_index(
        "ix_agent_tasks_claim_lease",
        "agent_tasks",
        ["claimed_by", "claim_expires_at"],
    )

    # Legacy findings have no authenticated submitter; do not backfill from
    # agent_name because that value is a logical label, not authorization.
    op.add_column("findings", sa.Column("submitted_by", sa.String(128), nullable=True))
    op.create_index("ix_findings_submitted_by", "findings", ["submitted_by"])


def downgrade() -> None:
    op.drop_index("ix_findings_submitted_by", table_name="findings")
    op.drop_column("findings", "submitted_by")

    op.drop_index("ix_agent_tasks_claim_lease", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_claim_expires_at", table_name="agent_tasks")
    op.drop_index("ix_agent_tasks_claimed_by", table_name="agent_tasks")
    op.drop_column("agent_tasks", "claim_expires_at")
    op.drop_column("agent_tasks", "claimed_by")
