"""Pydantic schemas for Incident API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

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

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str) -> str:
        if value not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        return value


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    severity: str | None = None
    incident_metadata: dict[str, Any] | None = None

    model_config = {"extra": "forbid"}

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str | None) -> str | None:
        if value is not None and value not in VALID_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}")
        return value

    @field_validator("severity")
    @classmethod
    def validate_update_severity(cls, value: str | None) -> str | None:
        if value is not None and value not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        return value


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
    correlation_key: str | None = None
    correlation_window_seconds: int | None = None
    linked_event_ids: list[str] = Field(default_factory=list)
    linked_task_ids: list[str] = Field(default_factory=list)
    linked_finding_ids: list[str] = Field(default_factory=list)
    event_count: int = 0
    task_count: int = 0
    finding_count: int = 0
    detection_sources: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class IncidentListParams(BaseModel):
    status: str | None = None
    severity: str | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
