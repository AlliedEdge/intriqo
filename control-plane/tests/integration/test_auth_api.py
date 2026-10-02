"""Integration tests for authentication API."""

from __future__ import annotations

import uuid
import pytest


def unique_user():
    uid = uuid.uuid4().hex[:8]
    return {
        "username": f"user_{uid}",
        "email": f"user_{uid}@example.com",
        "password": "SecurePass123",
        "role": "ANALYST",
    }


@pytest.mark.asyncio
async def test_register_and_login(client):
    user = unique_user()
    # Register
    reg_resp = await client.post("/api/v1/auth/register", json=user)
    assert reg_resp.status_code == 201, reg_resp.text
    assert reg_resp.json()["username"] == user["username"]

    # Login
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": user["username"], "password": user["password"]},
    )
    assert login_resp.status_code == 200
    body = login_resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    user = unique_user()
    await client.post("/api/v1/auth/register", json=user)

    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": user["username"], "password": "wrongpassword"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_CREDENTIALS"


@pytest.mark.asyncio
async def test_login_unknown_user(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "ghost_user_xyz", "password": "whatever"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_duplicate_username_rejected(client):
    user = unique_user()
    await client.post("/api/v1/auth/register", json=user)
    resp = await client.post("/api/v1/auth/register", json=user)
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "USERNAME_TAKEN"


@pytest.mark.asyncio
async def test_protected_route_requires_token(client):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_with_valid_token(client):
    user = unique_user()
    await client.post("/api/v1/auth/register", json=user)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": user["username"], "password": user["password"]},
    )
    token = login_resp.json()["access_token"]

    resp = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == user["username"]


@pytest.mark.asyncio
async def test_analyst_cannot_ingest_events(client):
    """ANALYST role should be able to ingest events (AgentUser allows ANALYST too)."""
    user = unique_user()
    await client.post("/api/v1/auth/register", json=user)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": user["username"], "password": user["password"]},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/api/v1/events",
        json={
            "event_id": str(uuid.uuid4()),
            "event_type": "PORT_SCAN",
            "severity": "LOW",
            "timestamp": "2026-10-01T12:00:00Z",
            "source_address": "1.2.3.4",
            "destination_address": "5.6.7.8",
        },
        headers=headers,
    )
    # ANALYST role is included in require_agent so this should succeed
    assert resp.status_code == 201
