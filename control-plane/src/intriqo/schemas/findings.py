"""Pydantic schemas for Finding API endpoints.

Mirrors contracts/agents/agent_result_v1.json.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


VALID_STATUSES = {"SUCCESS", "FAILED", "INCONCLUSIVE"}


class FindingCreate(BaseModel):
    """Inbound payload when an agent submits a result."""

    task_id: str = Field(..., min_length=1)
    agent_name: str = Field(..., min_length=1)
    status: str = Field(..., description="SUCCESS | FAILED | INCONCLUSIVE")
    confidence: float = Field(..., ge=0.0, le=1.0)
    findings: list[str] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    summary: str | None = None
    error: dict[str, Any] | None = None
    finding_metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class FindingResponse(BaseModel):
    finding_id: str
    task_id: str
    agent_name: str
    status: str
    confidence: float
    summary: str | None
    findings: list[str]
    evidence: list[dict[str, Any]]
    finding_metadata: dict[str, Any]
    error: dict[str, Any] | None
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingListParams(BaseModel):
    status: str | None = None
    task_id: str | None = None
    agent_name: str | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
