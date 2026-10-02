"""Authentication application service — registration and login."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth.passwords import hash_password, verify_password
from intriqo.auth.tokens import create_access_token
from intriqo.db.models.user import User
from intriqo.repositories.users import UserRepository
from intriqo.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserResponse
from intriqo.services import audit_service

logger = logging.getLogger("intriqo.auth.service")

VALID_ROLES = {"ADMIN", "ANALYST", "AGENT"}


async def register_user(db: AsyncSession, payload: UserCreate) -> UserResponse:
    repo = UserRepository(db)

    if await repo.get_by_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "USERNAME_TAKEN", "message": "Username already exists"}},
        )
    if await repo.get_by_email(payload.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": {"code": "EMAIL_TAKEN", "message": "Email already registered"}},
        )
    if payload.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": {"code": "INVALID_ROLE", "message": f"Role must be one of {sorted(VALID_ROLES)}"}},
        )

    now = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()),
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    user = await repo.create(user)

    await audit_service.record(
        db,
        actor=user.username,
        action=audit_service.ACTION_USER_REGISTERED,
        resource_type="user",
        resource_id=user.id,
        extra={"role": user.role},
    )
    return UserResponse.model_validate(user)


async def login(db: AsyncSession, payload: LoginRequest) -> TokenResponse:
    repo = UserRepository(db)
    user = await repo.get_by_username(payload.username)

    if user is None or not verify_password(payload.password, user.hashed_password):
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
