"""Pydantic schemas for Finding API endpoints.

Mirrors contracts/agents/agent_result_v1.json.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

VALID_STATUSES = {"SUCCESS", "FAILED", "INCONCLUSIVE"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


class FindingCreate(BaseModel):
    """Inbound payload when an agent submits a result."""

    task_id: str = Field(..., min_length=1)
    agent_name: str = Field(..., min_length=1)
    status: str = Field(..., description="SUCCESS | FAILED | INCONCLUSIVE")
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: str | None = None
    source: str | None = Field(None, max_length=64)
    event_id: str | None = None
    incident_id: str | None = None
    findings: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    summary: str | None = None
    error: dict[str, Any] | None = None
    finding_metadata: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        if value not in VALID_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}")
        return value

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, value: str | None) -> str | None:
        if value is not None and value not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        return value


class FindingResponse(BaseModel):
    finding_id: str
    task_id: str
    agent_name: str
    status: str
    confidence: float
    severity: str | None = None
    source: str | None = None
    event_id: str | None = None
    incident_id: str | None = None
    summary: str | None
    findings: list[str]
    evidence: list[dict[str, Any]]
    finding_metadata: dict[str, Any]
    provenance: dict[str, Any] = Field(default_factory=dict)
    error: dict[str, Any] | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingListParams(BaseModel):
    status: str | None = None
    task_id: str | None = None
    agent_name: str | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
