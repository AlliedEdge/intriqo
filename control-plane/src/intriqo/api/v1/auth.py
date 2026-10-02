"""Authentication routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from intriqo.auth import service as auth_service
from intriqo.auth.dependencies import AuthUser
from intriqo.db.session import get_db
from intriqo.schemas.auth import LoginRequest, TokenResponse, UserCreate, UserResponse

router = APIRouter(prefix="/auth")


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(payload: UserCreate, db: AsyncSession = Depends(get_db)) -> UserResponse:
    """Register a new user."""
    return await auth_service.register_user(db, payload)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Authenticate and receive a JWT access token."""
    return await auth_service.login(db, payload)


@router.get("/me", response_model=dict)
async def me(user: AuthUser) -> dict:
    """Return the authenticated user's identity."""
    return {"user_id": user.user_id, "username": user.username, "role": user.role}
