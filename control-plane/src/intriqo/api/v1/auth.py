"""Authentication routes."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth import rate_limit
from intriqo.auth import service as auth_service
from intriqo.auth.dependencies import AuthUser
from intriqo.db.session import get_db
from intriqo.schemas.auth import (
    EmailRequest,
    LoginRequest,
    MessageResponse,
    ResetPasswordRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
    VerifyEmailRequest,
)

router = APIRouter(prefix="/auth")


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    payload: UserCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> UserResponse:
    """Register a new user."""
    rate_limit.enforce(rate_limit._registration, rate_limit.client_key(request.client.host if request.client else None))
    return await auth_service.register_user(db, payload, background_tasks)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Authenticate and receive a JWT access token."""
    rate_limit.enforce(
        rate_limit._login,
        rate_limit.client_key(request.client.host if request.client else None, payload.username),
    )
    return await auth_service.login(db, payload)


@router.get("/verify-email", response_model=MessageResponse)
async def verify_email_link(
    request: Request,
    token: str = Query(..., min_length=20, max_length=512),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Verify an account from a token in an email link."""
    rate_limit.enforce(rate_limit._token_consumption, rate_limit.client_key(request.client.host if request.client else None))
    return await auth_service.verify_email(db, token)


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email(
    payload: VerifyEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Verify an account with a token supplied in a JSON request."""
    rate_limit.enforce(rate_limit._token_consumption, rate_limit.client_key(request.client.host if request.client else None))
    return await auth_service.verify_email(db, payload.token)


@router.post("/resend-verification", response_model=MessageResponse, status_code=202)
async def resend_verification(
    payload: EmailRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Resend verification without revealing whether an email is registered."""
    rate_limit.enforce(
        rate_limit._email_requests,
        rate_limit.client_key(request.client.host if request.client else None, str(payload.email)),
    )
    return await auth_service.resend_verification(db, payload, background_tasks)


@router.post("/forgot-password", response_model=MessageResponse, status_code=202)
async def forgot_password(
    payload: EmailRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Request a password reset with an enumeration-safe response."""
    rate_limit.enforce(
        rate_limit._email_requests,
        rate_limit.client_key(request.client.host if request.client else None, str(payload.email)),
    )
    return await auth_service.request_password_reset(db, payload, background_tasks)


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Replace a password using a valid, single-use reset token."""
    rate_limit.enforce(rate_limit._token_consumption, rate_limit.client_key(request.client.host if request.client else None))
    return await auth_service.reset_password(db, payload)


@router.get("/me", response_model=dict)
async def me(user: AuthUser) -> dict:
    """Return the authenticated user's identity."""
    return {"user_id": user.user_id, "username": user.username, "role": user.role}
