"""Domain model representing a task assigned to an agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from intriqo_agents.contracts.security_event import SecurityEvent


VALID_PRIORITIES = frozenset({"LOW", "MEDIUM", "HIGH", "URGENT"})


@dataclass(frozen=True)
class AgentTask:
    """Immutable unit of work assigned to an agent."""

    task_id: str
    task_type: str
    description: str
    security_event: SecurityEvent
    priority: str = "MEDIUM"
    context: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.task_id or not isinstance(self.task_id, str) or not self.task_id.strip():
            raise ValueError("AgentTask.task_id must be a non-empty string")
        if not self.task_type or not isinstance(self.task_type, str) or not self.task_type.strip():
            raise ValueError("AgentTask.task_type must be a non-empty string")
        if not self.description or not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("AgentTask.description must be a non-empty string")
        if not isinstance(self.security_event, SecurityEvent):
            raise TypeError("AgentTask.security_event must be a SecurityEvent instance")
        if self.priority not in VALID_PRIORITIES:
            raise ValueError(
                f"AgentTask.priority must be one of {sorted(VALID_PRIORITIES)}, got '{self.priority}'"
            )
        if not isinstance(self.context, (dict, Mapping)):
            raise TypeError("AgentTask.context must be a dictionary or mapping")
        if not isinstance(self.created_at, datetime):
            raise TypeError("AgentTask.created_at must be a datetime instance")
        object.__setattr__(self, "context", dict(self.context))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "description": self.description,
            "security_event": self.security_event.to_dict(),
            "priority": self.priority,
            "context": dict(self.context),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentTask:
        raw_ts = data.get("created_at")
        if raw_ts is None:
            ts = datetime.now(timezone.utc)
        elif isinstance(raw_ts, str):
            ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        elif isinstance(raw_ts, datetime):
            ts = raw_ts
        else:
            raise TypeError("created_at must be an ISO 8601 string or datetime object")

        return cls(
            task_id=str(data["task_id"]),
            task_type=str(data["task_type"]),
            description=str(data["description"]),
            security_event=SecurityEvent.from_dict(data["security_event"]),
            priority=str(data.get("priority", "MEDIUM")),
            context=dict(data.get("context", {})),
            created_at=ts,
        )
