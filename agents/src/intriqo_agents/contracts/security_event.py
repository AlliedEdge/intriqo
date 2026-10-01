"""Inbound boundary model representing a security event consumed by agents.

This module is the explicit ingestion boundary for security events produced
by the C++ IDS engine and forwarded by the Python control plane.

Cross-boundary events arrive as JSON (via the control plane API or message
bus) and are validated here before any agent sees them.  The control plane
owns persistence and fanout; agents only receive this immutable value object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping


VALID_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})


@dataclass(frozen=True)
class SecurityEvent:
    """Immutable security event emitted by the IDS engine and consumed by agents.

    All fields are validated on construction.  Invalid events are rejected —
    never silently defaulted.
    """

    id: str
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    target: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id or not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("SecurityEvent.id must be a non-empty string")
        if not isinstance(self.timestamp, datetime):
            raise TypeError("SecurityEvent.timestamp must be a datetime instance")
        if not self.event_type or not isinstance(self.event_type, str) or not self.event_type.strip():
            raise ValueError("SecurityEvent.event_type must be a non-empty string")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"SecurityEvent.severity must be one of {sorted(VALID_SEVERITIES)}, got '{self.severity}'"
            )
        if not self.source or not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("SecurityEvent.source must be a non-empty string")
        if not self.target or not isinstance(self.target, str) or not self.target.strip():
            raise ValueError("SecurityEvent.target must be a non-empty string")
        if not isinstance(self.metadata, (dict, Mapping)):
            raise TypeError("SecurityEvent.metadata must be a dictionary or mapping")
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "target": self.target,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityEvent:
        raw_ts = data["timestamp"]
        if isinstance(raw_ts, str):
            ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        elif isinstance(raw_ts, datetime):
            ts = raw_ts
        else:
            raise TypeError("timestamp must be an ISO 8601 string or datetime object")

        return cls(
            id=str(data["id"]),
            timestamp=ts,
            event_type=str(data["event_type"]),
            severity=str(data["severity"]),
            source=str(data["source"]),
            target=str(data["target"]),
            metadata=dict(data.get("metadata", {})),
        )
