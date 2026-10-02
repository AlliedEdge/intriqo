"""Integration coverage for email verification and account recovery."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import pytest
from sqlalchemy import select

from intriqo.auth import email as email_service
from intriqo.db.models.auth_token import AuthToken, AuthTokenType


def _user_payload() -> dict[str, str]:
    suffix = uuid.uuid4().hex[:8]
    return {
        "username": f"recovery_{suffix}",
        "email": f"recovery_{suffix}@example.com",
        "password": "OriginalPass123",
    }


def _token_from_email(html_body: str) -> str:
    match = re.search(r"[?&]token=([^\"&]+)", html_body)
    assert match is not None
    return unquote(match.group(1))


@pytest.mark.asyncio
async def test_registration_defaults_analyst_and_verification_is_single_use(
    client, db, monkeypatch
):
    sent: list[dict[str, str]] = []

    async def fake_send_email(**kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send_email)
    payload = _user_payload()

    registered = await client.post("/api/v1/auth/register", json=payload)
    assert registered.status_code == 201, registered.text
    assert registered.json()["role"] == "ANALYST"
    assert registered.json()["is_email_verified"] is False
    assert len(sent) == 1

    raw_token = _token_from_email(sent[0]["html_body"])
    stored = (
        await db.execute(select(AuthToken).where(AuthToken.token_type == AuthTokenType.EMAIL_VERIFICATION))
    ).scalar_one()
    assert stored.token_hash != raw_token
    assert len(stored.token_hash) == 64
    assert stored.created_at < stored.expires_at
    assert stored.used_at is None

    resent = await client.post(
        "/api/v1/auth/resend-verification", json={"email": payload["email"]}
    )
    unknown_resend = await client.post(
        "/api/v1/auth/resend-verification", json={"email": "nobody@example.com"}
    )
    assert resent.status_code == unknown_resend.status_code == 202
    assert resent.json() == unknown_resend.json()
    raw_token = _token_from_email(sent[-1]["html_body"])

    verified = await client.post("/api/v1/auth/verify-email", json={"token": raw_token})
    assert verified.status_code == 200, verified.text
    assert verified.json()["message"] == "Email verified successfully."

    stored_after = await db.get(AuthToken, stored.id)
    assert stored_after is not None
    assert stored_after.used_at is not None

    reused = await client.post("/api/v1/auth/verify-email", json={"token": raw_token})
    assert reused.status_code == 400
    assert reused.json()["error"]["code"] == "INVALID_OR_EXPIRED_TOKEN"


@pytest.mark.asyncio
async def test_public_registration_ignores_requested_role_and_supports_full_name(client, monkeypatch):
    async def fake_send_email(**kwargs):
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send_email)
    suffix = uuid.uuid4().hex[:8]
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Ada Lovelace",
            "email": f"ada_{suffix}@example.com",
            "password": "OriginalPass123",
            "role": "ADMIN",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["role"] == "ANALYST"
    assert body["full_name"] == "Ada Lovelace"
    assert body["username"].startswith("ada_lovelace")


@pytest.mark.asyncio
async def test_duplicate_email_is_rejected_case_insensitively(client, monkeypatch):
    async def fake_send_email(**kwargs):
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send_email)
    suffix = uuid.uuid4().hex[:8]
    first = {
        "username": f"first_{suffix}",
        "email": f"Case_{suffix}@example.com",
        "password": "OriginalPass123",
    }
    assert (await client.post("/api/v1/auth/register", json=first)).status_code == 201
    duplicate = {
        "username": f"second_{suffix}",
        "email": first["email"].lower(),
        "password": "OriginalPass123",
    }
    response = await client.post("/api/v1/auth/register", json=duplicate)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_TAKEN"


@pytest.mark.asyncio
async def test_expired_verification_token_is_rejected(client, db, monkeypatch):
    sent: list[dict[str, str]] = []

    async def fake_send_email(**kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send_email)
    payload = _user_payload()
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    raw_token = _token_from_email(sent[0]["html_body"])
    stored = (
        await db.execute(select(AuthToken).where(AuthToken.token_type == AuthTokenType.EMAIL_VERIFICATION))
    ).scalar_one()
    stored.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db.flush()

    expired = await client.post("/api/v1/auth/verify-email", json={"token": raw_token})
    assert expired.status_code == 400
    assert expired.json()["error"]["code"] == "INVALID_OR_EXPIRED_TOKEN"


@pytest.mark.asyncio
async def test_forgot_password_is_generic_and_reset_token_is_single_use(client, monkeypatch):
    sent: list[dict[str, str]] = []

    async def fake_send_email(**kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send_email)
    payload = _user_payload()
    registered = await client.post("/api/v1/auth/register", json=payload)
    assert registered.status_code == 201
    sent.clear()

    unknown = await client.post(
        "/api/v1/auth/forgot-password", json={"email": "nobody@example.com"}
    )
    known = await client.post(
        "/api/v1/auth/forgot-password", json={"email": payload["email"]}
    )
    assert unknown.status_code == known.status_code == 202
    assert unknown.json() == known.json()
    assert len(sent) == 1

    reset_token = _token_from_email(sent[0]["html_body"])
    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": "ReplacementPass123"},
    )
    assert reset.status_code == 200, reset.text

    old_login = await client.post(
        "/api/v1/auth/login",
        json={"username": payload["username"], "password": payload["password"]},
    )
    new_login = await client.post(
        "/api/v1/auth/login",
        json={"username": payload["username"], "password": "ReplacementPass123"},
    )
    assert old_login.status_code == 401
    assert new_login.status_code == 200

    reused = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "password": "AnotherPass123"},
    )
    assert reused.status_code == 400
    assert reused.json()["error"]["code"] == "INVALID_OR_EXPIRED_TOKEN"


@pytest.mark.asyncio
async def test_expired_password_reset_token_is_rejected(client, db, monkeypatch):
    sent: list[dict[str, str]] = []

    async def fake_send_email(**kwargs):
        sent.append(kwargs)
        return True

    monkeypatch.setattr(email_service, "send_email", fake_send_email)
    payload = _user_payload()
    registered = await client.post("/api/v1/auth/register", json=payload)
    assert registered.status_code == 201
    sent.clear()
    requested = await client.post("/api/v1/auth/forgot-password", json={"email": payload["email"]})
    assert requested.status_code == 202
    raw_token = _token_from_email(sent[0]["html_body"])
    stored = (
        await db.execute(select(AuthToken).where(AuthToken.token_type == AuthTokenType.PASSWORD_RESET))
    ).scalar_one()
    stored.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await db.flush()

    expired = await client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "password": "ReplacementPass123"},
    )
    assert expired.status_code == 400
    assert expired.json()["error"]["code"] == "INVALID_OR_EXPIRED_TOKEN"
