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


@pytest.mark.asyncio
async def test_registration_always_creates_analyst(client):
    """Default registration must always produce an ANALYST account."""
    user = unique_user()
    resp = await client.post("/api/v1/auth/register", json=user)
    assert resp.status_code == 201
    assert resp.json()["role"] == "ANALYST"


@pytest.mark.asyncio
async def test_registration_ignores_role_admin_in_body(client):
    """Supplying role=ADMIN in the request body must still produce ANALYST."""
    user = unique_user()
    user["role"] = "ADMIN"
    resp = await client.post("/api/v1/auth/register", json=user)
    assert resp.status_code == 201
    assert resp.json()["role"] == "ANALYST"


@pytest.mark.asyncio
async def test_registration_ignores_role_agent_in_body(client):
    """Supplying role=AGENT in the request body must still produce ANALYST."""
    user = unique_user()
    user["role"] = "AGENT"
    resp = await client.post("/api/v1/auth/register", json=user)
    assert resp.status_code == 201
    assert resp.json()["role"] == "ANALYST"


@pytest.mark.asyncio
async def test_me_returns_correct_role_for_analyst(client):
    """JWT role claim must match the ANALYST role assigned at registration."""
    user = unique_user()
    await client.post("/api/v1/auth/register", json=user)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": user["username"], "password": user["password"]},
    )
    token = login_resp.json()["access_token"]
    me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    body = me_resp.json()
    assert body["role"] == "ANALYST"
    assert body["username"] == user["username"]


@pytest.mark.asyncio
async def test_me_returns_correct_role_from_jwt_fixture(client, admin_headers, agent_headers, analyst_headers):
    """Pre-baked JWT fixtures must reflect their intended roles."""
    admin_me = await client.get("/api/v1/auth/me", headers=admin_headers)
    assert admin_me.status_code == 200
    assert admin_me.json()["role"] == "ADMIN"

    analyst_me = await client.get("/api/v1/auth/me", headers=analyst_headers)
    assert analyst_me.status_code == 200
    assert analyst_me.json()["role"] == "ANALYST"

    agent_me = await client.get("/api/v1/auth/me", headers=agent_headers)
    assert agent_me.status_code == 200
    assert agent_me.json()["role"] == "AGENT"


@pytest.mark.asyncio
async def test_expired_token_is_rejected(client):
    """An expired JWT must return 401 on any protected endpoint."""
    import datetime as _dt
    from jose import jwt
    from intriqo.config import get_settings

    settings = get_settings()
    past = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=1)
    expired = jwt.encode(
        {"sub": "user", "role": "ANALYST", "exp": past, "iat": past},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_invalid_token_is_rejected(client):
    """A garbage Bearer token must return 401."""
    resp = await client.get(
        "/api/v1/auth/me", headers={"Authorization": "Bearer not.a.real.jwt"}
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_missing_token_is_rejected(client):
    """Requests without a Bearer token must return 401."""
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "MISSING_TOKEN"


@pytest.mark.asyncio
async def test_login_invalid_credentials_fail_safely(client):
    """Invalid credentials must return 401 without revealing account existence."""
    user = unique_user()
    await client.post("/api/v1/auth/register", json=user)

    wrong_pass = await client.post(
        "/api/v1/auth/login",
        json={"username": user["username"], "password": "WrongPassword999"},
    )
    nonexistent = await client.post(
        "/api/v1/auth/login",
        json={"username": "nobody_" + uuid.uuid4().hex, "password": "anything"},
    )
    # Both return 401 with the same error code — no enumeration oracle
    assert wrong_pass.status_code == 401
    assert nonexistent.status_code == 401
    assert wrong_pass.json()["error"]["code"] == "INVALID_CREDENTIALS"
    assert nonexistent.json()["error"]["code"] == "INVALID_CREDENTIALS"
