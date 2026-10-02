"""Shared test fixtures.

Integration tests use a real PostgreSQL database (same Docker container as dev).
TEST_DATABASE_URL env var overrides the default if needed.

Isolation strategy:
  - A fresh engine + session are created per test (function scope).
  - This avoids asyncpg "operation in progress" and event-loop scope conflicts.
  - After each test, rows are removed via DELETE (not TRUNCATE, which requires
    exclusive locks that may conflict with open connections).
  - ssl=False is passed via connect_args — the Docker Postgres has no TLS cert
    and asyncpg will otherwise try to load certs from ~/.postgresql/ which may
    not exist or may be permission-denied.
"""

from __future__ import annotations

import os
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from intriqo.api.app import create_app
from intriqo.auth.tokens import create_access_token
from intriqo.db.base import Base
from intriqo.db.session import get_db

# ── Database URL ──────────────────────────────────────────────────────────────
TEST_DB_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://intriqo:intriqo_dev@localhost:5432/intriqo",
)

_ENGINE_KWARGS = {
    "echo": False,
    "pool_pre_ping": True,
    "connect_args": {"ssl": False},
}

# DELETE order respects FK constraints (children before parents)
_DELETE_TABLES = [
    "audit_logs",
    "findings",
    "agent_tasks",
    "incident_events",
    "incidents",
    "security_events",
    "users",
]


@pytest_asyncio.fixture
async def db():
    """Per-test async DB session.

    Schema is created if it doesn't exist. After each test, all rows are
    removed via DELETE so the next test starts with a clean slate.
    """
    engine = create_async_engine(TEST_DB_URL, **_ENGINE_KWARGS)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with factory() as session:
        yield session
        # Ensure the session is cleanly closed before we delete rows
        await session.close()

    # Cleanup: delete all rows in dependency order
    async with engine.begin() as conn:
        for table in _DELETE_TABLES:
            await conn.execute(text(f"DELETE FROM {table}"))

    await engine.dispose()


@pytest_asyncio.fixture
async def client(db):
    """HTTP test client wired to the per-test DB session."""
    app = create_app()

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


# ── Pre-made JWT tokens ───────────────────────────────────────────────────────
@pytest.fixture
def analyst_token():
    return create_access_token(
        subject="analyst_user", role="ANALYST", extra={"user_id": "user-analyst-1"}
    )


@pytest.fixture
def agent_token():
    return create_access_token(
        subject="agent_service", role="AGENT", extra={"user_id": "user-agent-1"}
    )


@pytest.fixture
def admin_token():
    return create_access_token(
        subject="admin_user", role="ADMIN", extra={"user_id": "user-admin-1"}
    )


@pytest.fixture
def analyst_headers(analyst_token):
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def agent_headers(agent_token):
    return {"Authorization": f"Bearer {agent_token}"}


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


# ── Canonical sample payload matching contracts/events/security_event_v1.json ─
SAMPLE_EVENT_PAYLOAD = {
    "event_id": "3f4a8b2e-1234-4c5d-9ef0-abcdef012345",
    "event_type": "PORT_SCAN",
    "severity": "HIGH",
    "timestamp": "2026-10-01T12:00:00.000Z",
    "source_address": "10.0.0.10",
    "destination_address": "10.0.0.20",
    "description": "Port scan detected from 10.0.0.10 targeting 10.0.0.20",
    "details": {
        "scanned_ports": 1024,
        "scan_rate_pps": 500,
        "detection_threshold": 100,
    },
}
