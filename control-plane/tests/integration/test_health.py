"""Integration tests for health endpoint."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from intriqo.api.app import create_app


@pytest.mark.asyncio
async def test_health_ok(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "intriqo-control-plane"
    assert "status" in body
    assert "checks" in body


@pytest.mark.asyncio
async def test_readiness_reports_unavailable_database(monkeypatch):
    async def unavailable_database() -> str:
        return "error"

    monkeypatch.setattr("intriqo.api.app._database_status", unavailable_database)
    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        response = await client.get("/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["checks"]["database"] == "error"


@pytest.mark.asyncio
async def test_readiness_reports_ready_database(monkeypatch):
    async def available_database() -> str:
        return "ok"

    monkeypatch.setattr("intriqo.api.app._database_status", available_database)
    async with AsyncClient(
        transport=ASGITransport(app=create_app()), base_url="http://test"
    ) as client:
        response = await client.get("/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["checks"]["database"] == "ok"
