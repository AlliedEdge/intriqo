"""Async SQLAlchemy engine and session factory.

Usage in FastAPI route handlers:

    from intriqo.db.session import get_db
    from sqlalchemy.ext.asyncio import AsyncSession

    @router.get("/...")
    async def my_route(db: AsyncSession = Depends(get_db)):
        ...
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from intriqo.config import get_settings


def _build_engine(database_url: str) -> AsyncEngine:
    settings = get_settings()
    # Strip any sslmode query param from URL — asyncpg requires ssl via connect_args
    clean_url = database_url.split("?")[0]
    return create_async_engine(
        clean_url,
        echo=settings.debug,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        connect_args={"ssl": False},
    )


def _build_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )


# Module-level engine and session factory — created once at import time.
# Tests may override these by patching or by passing a different URL.
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine  # noqa: PLW0603
    if _engine is None:
        _engine = _build_engine(get_settings().database_url)
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory  # noqa: PLW0603
    if _session_factory is None:
        _session_factory = _build_session_factory(get_engine())
    return _session_factory


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields an async database session per request."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
