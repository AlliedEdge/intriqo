"""Agent registry for capability discovery and lifecycle management."""

from __future__ import annotations

import logging
from typing import Optional, Sequence

from intriqo_agents.core.agent import Agent


logger = logging.getLogger("intriqo.agents.orchestrator.registry")


class AgentRegistry:
    """Registry maintaining available agents and their declared capabilities."""

    def __init__(self, agents: Sequence[Agent] | None = None) -> None:
        self._agents_by_name: dict[str, Agent] = {}
        if agents:
            for agent in agents:
                self.register(agent)

    def register(self, agent: Agent) -> None:
        if not isinstance(agent, Agent):
            raise TypeError(f"Expected Agent instance, got {type(agent).__name__}")
        self._agents_by_name[agent.name] = agent
        logger.info(
            "Registered agent '%s' with capabilities: %s",
            agent.name, sorted(agent.capabilities),
        )

    def get_agent(self, name: str) -> Optional[Agent]:
        return self._agents_by_name.get(name)

    def find_agent_by_capability(self, capability: str) -> Optional[Agent]:
        for agent in self._agents_by_name.values():
            if capability in agent.capabilities:
                return agent
        return None

    def list_agents(self) -> list[Agent]:
        return list(self._agents_by_name.values())
