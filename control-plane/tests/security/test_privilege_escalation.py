"""Privilege escalation tests.

These tests explicitly verify that every known escalation vector is blocked
server-side.  Each test documents an attack pattern and asserts the server
rejects it regardless of what the client sends.

Covered attack patterns
─────────────────────────────────────────────────────────────────────────────
REG-1  POST /register with role=ADMIN → must produce ANALYST
REG-2  POST /register with role=AGENT → must produce ANALYST
REG-3  POST /register with role=SUPERADMIN → must produce ANALYST
REG-4  POST /register with role via query parameter → must produce ANALYST

JWT-1  Forged JWT with role=ADMIN (wrong secret) → 401
JWT-2  Forged JWT with role=ADMIN (payload tamper, original sig) → 401
JWT-3  JWT with alg=none → 401
JWT-4  Expired JWT → 401

AUTHZ-1  AGENT calling ADMIN-only endpoint → 403
AUTHZ-2  ANALYST calling ANALYST-only endpoint as AGENT → 403 (already covered, belt-and-suspenders)
AUTHZ-3  AGENT calling analyst-gated incident creation → 403
AUTHZ-4  AGENT calling analyst-gated task creation → 403
AUTHZ-5  AGENT reading audit logs → 403

RESET-1  Password reset must not change the account role
VERIFY-1 Email verification must not change the account role
"""

from __future__ import annotations

import base64
import datetime as _dt
import json
import uuid

import pytest
from jose import jwt

from intriqo.auth import email as email_service
from intriqo.auth.tokens import create_access_token
from intriqo.config import get_settings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _unique_payload(**extra) -> dict:
    uid = uuid.uuid4().hex[:8]
    return {
        "username": f"esctst_{uid}",
        "email": f"esctst_{uid}@example.com",
        "password": "EscalationTest123",
        **extra,
    }


def _forge_jwt_wrong_secret(role: str) -> str:
    """Create a JWT signed with the wrong secret — must be rejected."""
    return jwt.encode(
        {"sub": "attacker", "role": role, "user_id": "fake-id"},
        "WRONG_SECRET",
        algorithm="HS256",
    )


def _forge_jwt_payload_tamper(role: str) -> str:
    """Take a valid JWT and flip the role claim in the payload without re-signing."""
    good_token = create_access_token(subject="innocent", role="ANALYST")
    header_b64, payload_b64, sig = good_token.split(".")
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    original = json.loads(base64.urlsafe_b64decode(padded))
    original["role"] = role
    new_payload = base64.urlsafe_b64encode(
        json.dumps(original).encode()
    ).rstrip(b"=").decode()
    return f"{header_b64}.{new_payload}.{sig}"


def _expired_jwt(role: str) -> str:
    settings = get_settings()
    past = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=1)
    return jwt.encode(
        {"sub": "user", "role": role, "exp": past, "iat": past},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def _none_alg_jwt(role: str) -> str:
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps({"sub": "attacker", "role": role}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload_b64}."


# ══════════════════════════════════════════════════════════════════════════════
# REG — Registration role injection
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_reg1_registration_with_role_admin_produces_analyst(client, monkeypatch):
    """REG-1: Client submitting role=ADMIN must receive ANALYST."""
    monkeypatch.setattr(email_service, "send_email", lambda **kw: True)
    payload = _unique_payload(role="ADMIN")
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "ANALYST", f"Expected ANALYST, got {resp.json().get('role')}"


@pytest.mark.asyncio
async def test_reg2_registration_with_role_agent_produces_analyst(client, monkeypatch):
    """REG-2: Client submitting role=AGENT must receive ANALYST."""
    monkeypatch.setattr(email_service, "send_email", lambda **kw: True)
    payload = _unique_payload(role="AGENT")
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "ANALYST", f"Expected ANALYST, got {resp.json().get('role')}"


@pytest.mark.asyncio
async def test_reg3_registration_with_unknown_role_produces_analyst(client, monkeypatch):
    """REG-3: Any invented role string must also produce ANALYST (extra fields ignored)."""
    monkeypatch.setattr(email_service, "send_email", lambda **kw: True)
    payload = _unique_payload(role="SUPERADMIN")
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "ANALYST"


@pytest.mark.asyncio
async def test_reg4_registration_role_via_query_param_produces_analyst(client, monkeypatch):
    """REG-4: Role in query parameter must be ignored — ANALYST is assigned."""
    monkeypatch.setattr(email_service, "send_email", lambda **kw: True)
    payload = _unique_payload()
    resp = await client.post("/api/v1/auth/register?role=ADMIN", json=payload)
    # Either 201 with ANALYST or 422 (query param not accepted) — both are safe
    if resp.status_code == 201:
        assert resp.json()["role"] == "ANALYST"
    else:
        # Query params on POST /register are not declared — FastAPI ignores them
        assert resp.status_code in (201, 422)


# ══════════════════════════════════════════════════════════════════════════════
# JWT — Token forgery
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_jwt1_forged_admin_token_wrong_secret_rejected(client):
    """JWT-1: A JWT signed with the wrong secret must return 401."""
    token = _forge_jwt_wrong_secret("ADMIN")
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_jwt2_payload_tamper_to_admin_rejected(client):
    """JWT-2: Flipping role=ADMIN in the payload without re-signing must return 401."""
    token = _forge_jwt_payload_tamper("ADMIN")
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_jwt2b_payload_tamper_analyst_to_admin_on_protected_route(client, agent_headers):
    """JWT-2b: A tampered analyst→admin token must not bypass admin authorization."""
    token = _forge_jwt_payload_tamper("ADMIN")
    # Try to access the audit endpoint which requires ANALYST/ADMIN
    resp = await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_jwt3_none_algorithm_token_rejected(client):
    """JWT-3: A token with alg=none must return 401 — algorithm confusion attack."""
    token = _none_alg_jwt("ADMIN")
    resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "INVALID_TOKEN"


@pytest.mark.asyncio
async def test_jwt4_expired_token_rejected(client):
    """JWT-4: An expired JWT must return 401 regardless of the role it encodes."""
    for role in ("ADMIN", "ANALYST", "AGENT"):
        token = _expired_jwt(role)
        resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401, f"Expired {role} token was not rejected"
        assert resp.json()["error"]["code"] == "INVALID_TOKEN"


# ══════════════════════════════════════════════════════════════════════════════
# AUTHZ — Role boundary enforcement on protected routes
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_authz1_agent_cannot_read_audit_logs(client, agent_headers):
    """AUTHZ-1: AGENT must be denied the audit log endpoint (ADMIN/ANALYST only)."""
    resp = await client.get("/api/v1/audit", headers=agent_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_authz2_agent_cannot_create_incident(client, agent_headers):
    """AUTHZ-2: AGENT must be denied incident creation."""
    resp = await client.post(
        "/api/v1/incidents",
        json={"title": "Escalation attempt", "description": "d", "severity": "HIGH"},
        headers=agent_headers,
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_authz3_agent_cannot_list_incidents(client, agent_headers):
    """AUTHZ-3: AGENT must be denied the incident list endpoint."""
    resp = await client.get("/api/v1/incidents", headers=agent_headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_authz4_agent_cannot_create_agent_task(client, agent_headers):
    """AUTHZ-4: AGENT must be denied task creation (ADMIN/ANALYST only)."""
    resp = await client.post(
        "/api/v1/agent-tasks",
        json={"task_type": "INVESTIGATE", "description": "Self-created task", "priority": "HIGH"},
        headers=agent_headers,
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_authz5_analyst_cannot_call_admin_only_if_admin_routes_existed(client, analyst_headers):
    """AUTHZ-5: ANALYST with a forged ADMIN token claim must still be denied admin paths.
    
    This verifies that role is taken from the validated JWT, not from any
    request header or body that claims a different role.
    """
    # Create a real ANALYST JWT then confirm /auth/me reports ANALYST
    resp = await client.get("/api/v1/auth/me", headers=analyst_headers)
    assert resp.status_code == 200
    assert resp.json()["role"] == "ANALYST"
    # The ANALYST cannot gain ADMIN by adding a header that claims it
    forged_headers = {**analyst_headers, "X-Role": "ADMIN", "X-User-Role": "ADMIN"}
    me_resp = await client.get("/api/v1/auth/me", headers=forged_headers)
    assert me_resp.status_code == 200
    assert me_resp.json()["role"] == "ANALYST"  # role comes from JWT, not headers


# ══════════════════════════════════════════════════════════════════════════════
# RESET — Password reset must not change role
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_reset1_password_reset_does_not_change_role(client, monkeypatch):
    """RESET-1: A password reset must leave the account role unchanged."""
    sent: list[dict] = []

    async def fake_send(**kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send)

    import re
    from urllib.parse import unquote

    payload = _unique_payload()
    reg_resp = await client.post("/api/v1/auth/register", json=payload)
    assert reg_resp.status_code == 201
    original_role = reg_resp.json()["role"]
    assert original_role == "ANALYST"
    sent.clear()

    await client.post("/api/v1/auth/forgot-password", json={"email": payload["email"]})
    assert len(sent) == 1
    match = re.search(r"[?&]token=([^\"&]+)", sent[0]["html_body"])
    assert match
    reset_token = unquote(match.group(1))

    reset_resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "password": "NewPassword999"},
    )
    assert reset_resp.status_code == 200

    # Log in with new password and check role is still ANALYST
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": payload["username"], "password": "NewPassword999"},
    )
    assert login_resp.status_code == 200
    new_token = login_resp.json()["access_token"]

    me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["role"] == "ANALYST", (
        f"Role changed after password reset: was {original_role}, now {me_resp.json()['role']}"
    )


@pytest.mark.asyncio
async def test_reset2_password_reset_cannot_inject_admin_role(client, monkeypatch):
    """RESET-2: Passing role=ADMIN alongside a reset token must be ignored."""
    sent: list[dict] = []

    async def fake_send(**kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send)

    import re
    from urllib.parse import unquote

    payload = _unique_payload()
    await client.post("/api/v1/auth/register", json=payload)
    sent.clear()

    await client.post("/api/v1/auth/forgot-password", json={"email": payload["email"]})
    match = re.search(r"[?&]token=([^\"&]+)", sent[0]["html_body"])
    reset_token = unquote(match.group(1))

    # Attempt to inject role in the reset payload — extra fields are forbidden
    reset_resp = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "password": "NewPassword999", "role": "ADMIN"},
    )
    # ResetPasswordRequest uses extra="forbid", so this is a 422 — role injection blocked
    assert reset_resp.status_code in (200, 422)
    if reset_resp.status_code == 200:
        # If somehow accepted, role must not have changed
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={"username": payload["username"], "password": "NewPassword999"},
        )
        new_token = login_resp.json()["access_token"]
        me_resp = await client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"}
        )
        assert me_resp.json()["role"] == "ANALYST"


# ══════════════════════════════════════════════════════════════════════════════
# VERIFY — Email verification must not change role
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_verify1_email_verification_does_not_change_role(client, monkeypatch):
    """VERIFY-1: Consuming an email verification token must not alter the account role."""
    sent: list[dict] = []

    async def fake_send(**kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send)

    import re
    from urllib.parse import unquote

    payload = _unique_payload()
    reg_resp = await client.post("/api/v1/auth/register", json=payload)
    assert reg_resp.status_code == 201
    assert reg_resp.json()["role"] == "ANALYST"
    assert reg_resp.json()["is_email_verified"] is False

    match = re.search(r"[?&]token=([^\"&]+)", sent[0]["html_body"])
    verify_token = unquote(match.group(1))

    verify_resp = await client.post(
        "/api/v1/auth/verify-email", json={"token": verify_token}
    )
    assert verify_resp.status_code == 200

    # Log in and confirm role is still ANALYST
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": payload["username"], "password": payload["password"]},
    )
    assert login_resp.status_code == 200
    new_token = login_resp.json()["access_token"]

    me_resp = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["role"] == "ANALYST"
