"""Pydantic schemas for the audit log API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditLogResponse(BaseModel):
    """Outbound representation of an immutable audit record."""

    id: str
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    detail: str | None
    extra: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogListParams(BaseModel):
    """Query parameters for GET /api/v1/audit."""

    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: str | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
