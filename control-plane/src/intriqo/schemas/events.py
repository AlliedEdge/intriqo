"""Pydantic schemas for SecurityEvent API endpoints.

The inbound schema mirrors contracts/events/security_event_v1.json exactly.
The outbound schema adds ingestion metadata.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class SecurityEventCreate(BaseModel):
    """Inbound payload from the C++ IDS engine — mirrors security_event_v1.json."""

    event_id: str = Field(..., min_length=1, description="Engine-issued UUID")
    event_type: str = Field(..., min_length=1, description="Detector event type literal")
    severity: str = Field(..., description="LOW | MEDIUM | HIGH | CRITICAL")
    timestamp: datetime = Field(..., description="ISO 8601 UTC detection time")
    source_address: str = Field(..., min_length=1, description="Source IP address")
    destination_address: str = Field(..., min_length=1, description="Destination IP address")
    description: str | None = Field(None, description="Human-readable description")
    details: dict[str, Any] = Field(default_factory=dict, description="Detector-specific metadata")

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}, got '{v}'")
        return v

    @field_validator("event_id", "event_type", "source_address", "destination_address")
    @classmethod
    def must_not_be_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("field must not be blank")
        return v

    model_config = {"extra": "forbid"}


class SecurityEventResponse(BaseModel):
    """Outbound representation of a persisted SecurityEvent."""

    event_id: str
    event_type: str
    severity: str
    timestamp: datetime
    source_address: str
    destination_address: str
    description: str | None
    details: dict[str, Any]
    ingested_at: datetime
    linked_incident_ids: list[str] = Field(default_factory=list)
    linked_task_ids: list[str] = Field(default_factory=list)
    linked_finding_ids: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class SecurityEventListParams(BaseModel):
    """Query parameters for GET /api/v1/events."""

    severity: str | None = None
    event_type: str | None = None
    source_address: str | None = None
    destination_address: str | None = None
    from_time: datetime | None = None
    to_time: datetime | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
