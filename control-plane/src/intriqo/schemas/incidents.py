"""Pydantic schemas for Incident API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


VALID_STATUSES  = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field("", description="Optional description")
    severity: str = Field("MEDIUM", description="LOW | MEDIUM | HIGH | CRITICAL")
    # IDs of SecurityEvents to link to this incident
    event_ids: list[str] = Field(default_factory=list)
    incident_metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    incident_metadata: dict[str, Any] | None = None

    model_config = {"extra": "forbid"}


class IncidentEventLink(BaseModel):
    """Represents one security event linked to an incident."""
    event_id: str
    linked_at: datetime

    model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    description: str
    status: str
    severity: str
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None
    incident_metadata: dict[str, Any]
    linked_event_ids: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class IncidentListParams(BaseModel):
    status: str | None = None
    severity: str | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
