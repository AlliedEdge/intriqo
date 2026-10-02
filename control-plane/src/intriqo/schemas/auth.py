"""Pydantic schemas for authentication endpoints."""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr, Field, model_validator


def _bcrypt_password(value: str) -> str:
    if len(value.encode("utf-8")) > 72:
        raise ValueError("Password must not exceed 72 UTF-8 bytes")
    return value


NewPassword = Annotated[str, Field(min_length=8, max_length=72), AfterValidator(_bcrypt_password)]


class UserCreate(BaseModel):
    """Registration input for legacy and current clients.

    Current clients submit a full name and let the service derive a unique
    sign-in username. The legacy username remains accepted for compatibility.
    Unknown legacy fields (including a previously accepted ``role`` field) are
    ignored so public registration cannot assign an elevated role.
    """

    username: str | None = Field(None, min_length=3, max_length=128)
    email: EmailStr
    password: NewPassword
    full_name: str | None = Field(None, min_length=1, max_length=256)

    model_config = {"extra": "ignore"}

    @model_validator(mode="after")
    def require_name_or_username(self) -> UserCreate:
        if not (self.username and self.username.strip()) and not (self.full_name and self.full_name.strip()):
            raise ValueError("username or full_name is required")
        return self


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str | None
    role: str
    is_active: bool
    is_email_verified: bool

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class EmailRequest(BaseModel):
    """Request containing an email address."""

    email: EmailStr

    model_config = {"extra": "forbid"}


class VerifyEmailRequest(BaseModel):
    """Request containing an email-verification token."""

    token: str = Field(..., min_length=20, max_length=512)

    model_config = {"extra": "forbid"}


class ResetPasswordRequest(BaseModel):
    """Request for consuming a password-reset token.

    ``password`` is retained as the concise public API spelling while
    ``new_password`` is accepted for clients that use an explicit name.
    """

    token: str = Field(..., min_length=20, max_length=512)
    password: NewPassword | None = None
    new_password: NewPassword | None = None

    model_config = {"extra": "forbid"}

    @model_validator(mode="after")
    def require_one_password(self) -> ResetPasswordRequest:
        if self.password is None and self.new_password is None:
            raise ValueError("password is required")
        if self.password is not None and self.new_password is not None:
            raise ValueError("provide only one password field")
        return self

    @property
    def replacement_password(self) -> str:
        """Return the supplied replacement password."""
        return self.password or self.new_password or ""


class MessageResponse(BaseModel):
    """Simple response used by account email flows."""

    message: str
