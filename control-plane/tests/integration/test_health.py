"""Integration tests for health endpoint."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_health_ok(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "intriqo-control-plane"
    assert "status" in body
    assert "checks" in body
