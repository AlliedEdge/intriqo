"""Policy engine — evaluates ActionRequests from agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import logging

logger = logging.getLogger("intriqo.control_plane.policy")


class PolicyDecisionType(str, Enum):
    ALLOW          = "ALLOW"
    DENY           = "DENY"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"


@dataclass(frozen=True)
class PolicyDecision:
    decision: PolicyDecisionType
    reason: str
    conditions: dict[str, Any] = field(default_factory=dict)
    requires_approval_from: str | None = None  # role required to approve


@dataclass(frozen=True)
class ActionRequest:
    """A structured action proposed by an agent.

    Agents may ONLY propose actions through this structured interface.
    No agent receives a shell, SQL cursor, or raw HTTP client.
    """
    action_type: str          # e.g. "BLOCK_IP", "ISOLATE_HOST", "CREATE_TICKET"
    target: str               # The resource being acted upon
    parameters: dict[str, Any] = field(default_factory=dict)
    requesting_agent: str = ""
    justification: str = ""
    confidence: float = 0.0


class PolicyEngine:
    """Evaluates ActionRequests and returns a PolicyDecision.

    This implementation is a placeholder that always requires human approval
    for any action with real-world effect.  The production implementation
    will load rules from a policy store and evaluate them deterministically.
    """

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        """Evaluate an ActionRequest and return a PolicyDecision."""
        logger.info(
            "PolicyEngine evaluating action_type='%s' target='%s' agent='%s'",
            request.action_type, request.target, request.requesting_agent,
        )

        # ── Placeholder policy: require human approval for all network actions ──
        # Real implementation: load rules from policy store, evaluate against
        # request context, return ALLOW / DENY / HUMAN_APPROVAL deterministically.
        if request.action_type in ("BLOCK_IP", "ISOLATE_HOST", "QUARANTINE"):
            return PolicyDecision(
                decision=PolicyDecisionType.HUMAN_APPROVAL,
                reason=f"Action '{request.action_type}' requires operator approval.",
                requires_approval_from="soc_analyst",
            )

        if request.action_type in ("CREATE_TICKET", "NOTIFY_ANALYST"):
            return PolicyDecision(
                decision=PolicyDecisionType.ALLOW,
                reason="Informational action — auto-approved.",
            )

        return PolicyDecision(
            decision=PolicyDecisionType.DENY,
            reason=f"Action type '{request.action_type}' is not in the approved action list.",
        )
