"""Minimal Agent abstraction for the Intriqo autonomous agent platform."""

from __future__ import annotations

from abc import ABC, abstractmethod

from intriqo_agents.state.task import AgentTask
from intriqo_agents.state.result import AgentResult


class Agent(ABC):
    """Abstract base class for all specialized cybersecurity agents.

    Contract:
        - Each agent has a unique identifying name.
        - Each agent declares its specific capabilities.
        - Agents execute tasks deterministically without relying on global mutable state.
        - Agents return structured AgentResult instances.
        - Agents NEVER receive unrestricted shell access, filesystem access, arbitrary SQL,
          or arbitrary network access. All side-effects go through explicit Tool instances.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name of this agent instance/role."""

    @property
    @abstractmethod
    def capabilities(self) -> frozenset[str]:
        """Declared capabilities of this agent (e.g. 'investigation', 'correlation')."""

    @abstractmethod
    def execute(self, task: AgentTask) -> AgentResult:
        """Execute a unit of work and return structured findings.

        Must not rely on global mutable state to allow concurrent investigations.
        """
