"""SQLAlchemy declarative base shared by all ORM models."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base for all Intriqo ORM models.

    Subclass this in every model module so Alembic's autogenerate can
    discover the full schema from a single metadata object.
    """
