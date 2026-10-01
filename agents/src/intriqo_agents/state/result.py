"""Domain model representing a structured result returned by an agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional


VALID_STATUSES = frozenset({"SUCCESS", "FAILED", "INCONCLUSIVE"})


@dataclass(frozen=True)
class AgentResult:
    """Structured, machine-readable result returned by an agent.

    Human-readable summaries may exist as an optional field, but structured
    fields (findings, evidence, confidence) remain the primary data structure.
    """

    task_id: str
    agent_name: str
    status: str
    findings: tuple[str, ...] = field(default_factory=tuple)
    evidence: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    confidence: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    summary: Optional[str] = None
    error: Optional[dict[str, Any]] = None

    def __post_init__(self) -> None:
        if not self.task_id or not isinstance(self.task_id, str) or not self.task_id.strip():
            raise ValueError("AgentResult.task_id must be a non-empty string")
        if not self.agent_name or not isinstance(self.agent_name, str) or not self.agent_name.strip():
            raise ValueError("AgentResult.agent_name must be a non-empty string")
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"AgentResult.status must be one of {sorted(VALID_STATUSES)}, got '{self.status}'"
            )
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= self.confidence <= 1.0):
            raise ValueError("AgentResult.confidence must be a float between 0.0 and 1.0 inclusive")
        if not isinstance(self.created_at, datetime):
            raise TypeError("AgentResult.created_at must be a datetime instance")
        if not isinstance(self.metadata, (dict, Mapping)):
            raise TypeError("AgentResult.metadata must be a dictionary or mapping")
        if self.error is not None and not isinstance(self.error, (dict, Mapping)):
            raise TypeError("AgentResult.error must be None or a dictionary/mapping")

        object.__setattr__(self, "findings", tuple(str(f) for f in self.findings))
        object.__setattr__(self, "evidence", tuple(dict(e) for e in self.evidence))
        object.__setattr__(self, "confidence", float(self.confidence))
        object.__setattr__(self, "metadata", dict(self.metadata))
        if self.error is not None:
            object.__setattr__(self, "error", dict(self.error))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "status": self.status,
            "findings": list(self.findings),
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
            "created_at": self.created_at.isoformat(),
            "summary": self.summary,
            "error": dict(self.error) if self.error is not None else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentResult:
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
            agent_name=str(data["agent_name"]),
            status=str(data["status"]),
            findings=tuple(data.get("findings", ())),
            evidence=tuple(data.get("evidence", ())),
            confidence=float(data.get("confidence", 0.0)),
            metadata=dict(data.get("metadata", {})),
            created_at=ts,
            summary=data.get("summary"),
            error=dict(data["error"]) if data.get("error") is not None else None,
        )

    @classmethod
    def success(
        cls,
        task_id: str,
        agent_name: str,
        findings: list[str] | tuple[str, ...],
        evidence: list[dict[str, Any]] | tuple[dict[str, Any], ...],
        confidence: float,
        summary: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AgentResult:
        return cls(
            task_id=task_id,
            agent_name=agent_name,
            status="SUCCESS",
            findings=tuple(findings),
            evidence=tuple(evidence),
            confidence=confidence,
            summary=summary,
            metadata=metadata or {},
        )

    @classmethod
    def failure(
        cls,
        task_id: str,
        agent_name: str,
        error_message: str,
        error_details: Optional[dict[str, Any]] = None,
        summary: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> AgentResult:
        err = {"message": error_message}
        if error_details:
            err.update(error_details)
        return cls(
            task_id=task_id,
            agent_name=agent_name,
            status="FAILED",
            findings=(),
            evidence=(),
            confidence=0.0,
            summary=summary or f"Agent execution failed: {error_message}",
            error=err,
            metadata=metadata or {},
        )
