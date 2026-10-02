"""Add an optional display name for public account registration.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-02
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.String(256), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "full_name")
