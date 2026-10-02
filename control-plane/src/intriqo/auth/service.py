"""Authentication application service — registration, login, and recovery."""

from __future__ import annotations

import hashlib
import logging
import re
import secrets
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from fastapi import BackgroundTasks, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth import email as email_service
from intriqo.auth.passwords import hash_password, verify_password
from intriqo.auth.tokens import create_access_token
from intriqo.config import get_settings
from intriqo.db.models.auth_token import AuthToken, AuthTokenType
from intriqo.db.models.user import User
from intriqo.repositories.auth_tokens import AuthTokenRepository
from intriqo.repositories.users import UserRepository
from intriqo.schemas.auth import (
    EmailRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
)
from intriqo.services import audit_service

logger = logging.getLogger("intriqo.auth.service")

GENERIC_VERIFICATION_MESSAGE = "If an account exists, a verification email has been sent."
GENERIC_RESET_MESSAGE = "If an account exists, a password reset email has been sent."


def _token_hash(token: str) -> str:
    """Hash a raw token before it is compared with persisted data."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _verification_required() -> bool:
    """Enable enforcement in configured environments without breaking local tests."""
    settings = get_settings()
    if not settings.require_email_verification:
        return False
    # A key indicates a configured mail flow even in a local environment.  A
    # keyless development/test setup intentionally permits the legacy login
    # flow while still exercising token persistence and endpoint behavior.
    return settings.app_env.lower() not in {"development", "test"} or bool(
        settings.resend_api_key and settings.resend_api_key.get_secret_value()
    )


def _frontend_link(path: str, token: str) -> str:
    base = get_settings().frontend_base_url.rstrip("/")
    return f"{base}/{path.lstrip('/')}?token={quote(token, safe='')}"


def _username_base(full_name: str) -> str:
    """Create a conservative sign-in identifier from a display name."""
    normalized = unicodedata.normalize("NFKD", full_name)
    ascii_name = normalized.encode("ascii", "ignore").decode("ascii").lower()
    return (re.sub(r"[^a-z0-9]+", "_", ascii_name).strip("_") or "operator")[:128]


async def _unique_username(repo: UserRepository, payload: UserCreate) -> str:
    """Respect a supplied legacy username or derive a unique one."""
    if payload.username and payload.username.strip():
        return payload.username.strip()

    base = _username_base(payload.full_name or "operator")
    if await repo.get_by_username(base) is None:
        return base
    for _ in range(5):
        candidate = f"{base[:120]}_{secrets.token_hex(3)}"
        if await repo.get_by_username(candidate) is None:
            return candidate
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"error": {"code": "USERNAME_UNAVAILABLE", "message": "Unable to create a unique username"}},
    )


async def _issue_token(
    db: AsyncSession,
    *,
    user_id: str,
    token_type: AuthTokenType,
    lifetime_minutes: int,
) -> str:
    """Create and persist a random token, storing only its SHA-256 digest."""
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    token_repo = AuthTokenRepository(db)
    await token_repo.invalidate_active(user_id, token_type, now)
    await token_repo.create(
        AuthToken(
            id=str(uuid.uuid4()),
            user_id=user_id,
            token_hash=_token_hash(token),
            token_type=token_type,
            created_at=now,
            expires_at=now + timedelta(minutes=lifetime_minutes),
        )
    )
    return token


async def _deliver_email(*, recipient: str, subject: str, html_body: str) -> None:
    """Attempt delivery without making account operations depend on an email provider."""
    try:
        await email_service.send_email(
            recipient=recipient,
            subject=subject,
            html_body=html_body,
        )
    except Exception:
        # The token remains available for resend and the user operation still
        # completes.  Do not log provider responses, email bodies, or tokens.
        logger.warning("Transactional email delivery failed")


async def _queue_email(
    db: AsyncSession,
    background_tasks: BackgroundTasks | None,
    *,
    recipient: str,
    subject: str,
    html_body: str,
) -> None:
    """Persist the token before handing its link to the email provider.

    HTTP callers run delivery after the generic response, keeping provider
    latency out of the account-existence response timing. Delivery failures
    are recoverable through the resend/request endpoints.
    """
    await db.commit()
    if background_tasks is not None:
        background_tasks.add_task(
            _deliver_email, recipient=recipient, subject=subject, html_body=html_body
        )
    else:
        await _deliver_email(recipient=recipient, subject=subject, html_body=html_body)


async def register_user(
    db: AsyncSession, payload: UserCreate, background_tasks: BackgroundTasks | None = None
) -> UserResponse:
    repo = UserRepository(db)
    email = str(payload.email).strip().lower()
    username = await _unique_username(repo, payload)

    if await repo.get_by_username(username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "USERNAME_TAKEN", "message": "Username already exists"}},
        )
    if await repo.get_by_email(email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "EMAIL_TAKEN", "message": "Email already registered"}},
        )
    now = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()),
        username=username,
        email=email,
        full_name=payload.full_name.strip() if payload.full_name else None,
        hashed_password=hash_password(payload.password),
        role="ANALYST",
        is_active=True,
        created_at=now,
        updated_at=now,
        email_verified_at=None,
    )
    try:
        async with db.begin_nested():
            user = await repo.create(user)
    except IntegrityError:
        # A concurrent registration may win after the availability checks.
        # The savepoint leaves the surrounding transaction usable.
        username_taken = await repo.get_by_username(username)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {
                "code": "USERNAME_TAKEN" if username_taken else "EMAIL_TAKEN",
                "message": "Username already exists" if username_taken else "Email already registered",
            }},
        ) from None

    token = await _issue_token(
        db,
        user_id=user.id,
        token_type=AuthTokenType.EMAIL_VERIFICATION,
        lifetime_minutes=get_settings().email_verification_token_expire_minutes,
    )
    await audit_service.record(
        db,
        actor=user.username,
        action=audit_service.ACTION_USER_REGISTERED,
        resource_type="user",
        resource_id=user.id,
        extra={"role": user.role},
    )
    await _queue_email(
        db,
        background_tasks,
        recipient=user.email,
        subject="Verify your Intriqo email",
        html_body=email_service.verification_email_html(
            user.username,
            _frontend_link("verify-email", token),
            get_settings().email_verification_token_expire_minutes,
        ),
    )
    return UserResponse.model_validate(user)


async def login(db: AsyncSession, payload: LoginRequest) -> TokenResponse:
    repo = UserRepository(db)
    user = await repo.get_by_username(payload.username)

    if (
        user is None
        or len(payload.password.encode("utf-8")) > 72
        or not verify_password(payload.password, user.hashed_password)
    ):
        await audit_service.record(
            db,
            actor=payload.username,
            action=audit_service.ACTION_USER_LOGIN_FAILED,
            resource_type="user",
            resource_id=payload.username,
            outcome="FAILURE",
            detail="Invalid credentials",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid username or password"}},
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": {"code": "ACCOUNT_DISABLED", "message": "Account is disabled"}},
        )

    if _verification_required() and not user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": {
                    "code": "EMAIL_NOT_VERIFIED",
                    "message": "Verify your email address before logging in",
                }
            },
        )

    token = create_access_token(
        subject=user.username,
        role=user.role,
        extra={"user_id": user.id},
    )

    await audit_service.record(
        db,
        actor=user.username,
        action=audit_service.ACTION_USER_LOGIN,
        resource_type="user",
        resource_id=user.id,
    )
    return TokenResponse(access_token=token)


def _invalid_account_token() -> HTTPException:
    """Return the common safe error for unknown, expired, or consumed tokens."""
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error": {
                "code": "INVALID_OR_EXPIRED_TOKEN",
                "message": "The token is invalid or has expired",
            }
        },
    )


async def verify_email(db: AsyncSession, raw_token: str) -> MessageResponse:
    """Consume an email verification token and mark its account verified."""
    now = datetime.now(timezone.utc)
    token_repo = AuthTokenRepository(db)
    token = await token_repo.get_active(
        _token_hash(raw_token), AuthTokenType.EMAIL_VERIFICATION, now
    )
    if token is None or not await token_repo.consume(token.id, now):
        raise _invalid_account_token()

    user = await UserRepository(db).get_by_id(token.user_id)
    if user is None:
        raise _invalid_account_token()
    user.email_verified_at = now
    user.updated_at = now
    await db.flush()
    await audit_service.record(
        db,
        actor=user.username,
        action=audit_service.ACTION_USER_EMAIL_VERIFIED,
        resource_type="user",
        resource_id=user.id,
    )
    return MessageResponse(message="Email verified successfully.")


async def resend_verification(
    db: AsyncSession, payload: EmailRequest, background_tasks: BackgroundTasks | None = None
) -> MessageResponse:
    """Issue a fresh verification email without disclosing account existence."""
    email = str(payload.email).strip().lower()
    user = await UserRepository(db).get_by_email(email)
    if user is not None and user.is_active and not user.is_email_verified:
        token = await _issue_token(
            db,
            user_id=user.id,
            token_type=AuthTokenType.EMAIL_VERIFICATION,
            lifetime_minutes=get_settings().email_verification_token_expire_minutes,
        )
        await audit_service.record(
            db,
            actor=user.username,
            action=audit_service.ACTION_USER_VERIFICATION_RESENT,
            resource_type="user",
            resource_id=user.id,
        )
        await _queue_email(
            db,
            background_tasks,
            recipient=user.email,
            subject="Verify your Intriqo email",
            html_body=email_service.verification_email_html(
                user.username,
                _frontend_link("verify-email", token),
                get_settings().email_verification_token_expire_minutes,
            ),
        )
    return MessageResponse(message=GENERIC_VERIFICATION_MESSAGE)


async def request_password_reset(
    db: AsyncSession, payload: EmailRequest, background_tasks: BackgroundTasks | None = None
) -> MessageResponse:
    """Issue a password-reset email while keeping the response enumeration-safe."""
    email = str(payload.email).strip().lower()
    user = await UserRepository(db).get_by_email(email)
    if user is not None and user.is_active:
        token = await _issue_token(
            db,
            user_id=user.id,
            token_type=AuthTokenType.PASSWORD_RESET,
            lifetime_minutes=get_settings().password_reset_token_expire_minutes,
        )
        await audit_service.record(
            db,
            actor=user.username,
            action=audit_service.ACTION_USER_PASSWORD_RESET_REQUESTED,
            resource_type="user",
            resource_id=user.id,
        )
        await _queue_email(
            db,
            background_tasks,
            recipient=user.email,
            subject="Reset your Intriqo password",
            html_body=email_service.password_reset_email_html(
                user.username,
                _frontend_link("reset-password", token),
                get_settings().password_reset_token_expire_minutes,
            ),
        )
    return MessageResponse(message=GENERIC_RESET_MESSAGE)


async def reset_password(db: AsyncSession, payload: ResetPasswordRequest) -> MessageResponse:
    """Atomically consume a reset token and replace the user's password."""
    now = datetime.now(timezone.utc)
    token_repo = AuthTokenRepository(db)
    token = await token_repo.get_active(_token_hash(payload.token), AuthTokenType.PASSWORD_RESET, now)
    if token is None or not await token_repo.consume(token.id, now):
        raise _invalid_account_token()

    user = await UserRepository(db).get_by_id(token.user_id)
    if user is None or not user.is_active:
        raise _invalid_account_token()
    user.hashed_password = hash_password(payload.replacement_password)
    user.updated_at = now
    await token_repo.invalidate_active(user.id, AuthTokenType.PASSWORD_RESET, now)
    await db.flush()
    await audit_service.record(
        db,
        actor=user.username,
        action=audit_service.ACTION_USER_PASSWORD_RESET,
        resource_type="user",
        resource_id=user.id,
    )
    return MessageResponse(message="Password updated successfully.")
