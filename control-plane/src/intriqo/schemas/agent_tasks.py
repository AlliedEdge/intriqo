"""Pydantic schemas for AgentTask API endpoints.

Mirrors contracts/agents/agent_task_v1.json field names.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


VALID_TASK_TYPES = {"INVESTIGATION", "CORRELATION", "THREAT_INTEL", "RESPONSE"}
VALID_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "URGENT"}
VALID_STATUSES   = {"PENDING", "IN_PROGRESS", "COMPLETED", "FAILED", "CANCELLED"}


class AgentTaskCreate(BaseModel):
    task_type: str = Field(..., description="INVESTIGATION | CORRELATION | THREAT_INTEL | RESPONSE")
    description: str = Field(..., min_length=1)
    priority: str = Field("MEDIUM", description="LOW | MEDIUM | HIGH | URGENT")
    # The event and/or incident this task is derived from
    event_id: str | None = None
    incident_id: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}


class AgentTaskStatusUpdate(BaseModel):
    status: str = Field(..., description="PENDING | IN_PROGRESS | COMPLETED | FAILED | CANCELLED")

    model_config = {"extra": "forbid"}


class AgentTaskResponse(BaseModel):
    task_id: str
    task_type: str
    description: str
    priority: str
    status: str
    event_id: str | None
    incident_id: str | None
    context: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None

    model_config = {"from_attributes": True}


class AgentTaskListParams(BaseModel):
    status: str | None = None
    priority: str | None = None
    task_type: str | None = None
    event_id: str | None = None
    incident_id: str | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
