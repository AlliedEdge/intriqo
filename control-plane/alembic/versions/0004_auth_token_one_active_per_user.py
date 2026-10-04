"""Enforce at most one active token per (user, type) with a partial unique index.

Previously the application relied solely on invalidate_active() to maintain
the one-active-token invariant before inserting a new row.  That is correct
under normal operation but leaves a TOCTOU window: if two concurrent requests
both pass the UPDATE before either INSERT commits, two unconsumed rows can
exist for the same (user_id, token_type) pair.  The resulting duplicate rows
cause scalar_one() test queries to raise MultipleResultsFound and would allow
a race-winning attacker to hold a valid token after a legitimate resend.

The partial unique index restricts uniqueness to rows where used_at IS NULL,
so consumed / expired tokens (used_at IS NOT NULL) are excluded and historical
records are preserved intact for audit purposes.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-04
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Before the index can be created the table must already satisfy the
    # constraint.  In a freshly-migrated database there are no rows, so this
    # is a no-op.  On an existing installation invalidate_active() will have
    # kept the table clean under normal usage; the CREATE INDEX … CONCURRENTLY
    # form is not available inside a transaction, so we use a standard CREATE
    # which takes a ShareLock for the duration of the build — acceptable for
    # the table sizes expected in this deployment.
    op.create_index(
        "uq_auth_tokens_one_active_per_user_type",
        "auth_tokens",
        ["user_id", "token_type"],
        unique=True,
        postgresql_where="used_at IS NULL",
    )


def downgrade() -> None:
    op.drop_index(
        "uq_auth_tokens_one_active_per_user_type",
        table_name="auth_tokens",
    )
