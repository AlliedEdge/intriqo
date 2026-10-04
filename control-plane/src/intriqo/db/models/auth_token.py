"""Hashed, single-use tokens used by account email flows."""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from intriqo.db.base import Base


class AuthTokenType(str, enum.Enum):
    """Supported account token purposes."""

    EMAIL_VERIFICATION = "EMAIL_VERIFICATION"
    PASSWORD_RESET = "PASSWORD_RESET"


class AuthToken(Base):
    """A hashed, expiring token that can be consumed only once."""

    __tablename__ = "auth_tokens"
    __table_args__ = (
        Index("ix_auth_tokens_user_type", "user_id", "token_type"),
        Index("ix_auth_tokens_expires_at", "expires_at"),
        # Enforce at most one unconsumed token per (user, type) at the database
        # level.  The WHERE clause restricts the index to rows where used_at IS
        # NULL, so spent tokens do not violate the constraint and historical
        # records are preserved for audit purposes.
        Index(
            "uq_auth_tokens_one_active_per_user_type",
            "user_id",
            "token_type",
            unique=True,
            postgresql_where=text("used_at IS NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    token_type: Mapped[AuthTokenType] = mapped_column(
        Enum(AuthTokenType, name="auth_token_type", native_enum=False, length=32), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
