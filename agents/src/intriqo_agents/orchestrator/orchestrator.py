"""Orchestrator — coordinates events, tasks, and specialized agent dispatch.

Execution flow
──────────────
SecurityEvent → create_task() → select_agent() → agent.execute() → AgentResult

The full autonomous lifecycle (observe → plan → investigate → correlate →
respond → verify → repeat) will build on this foundation in future phases.
"""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from intriqo_agents.core.agent import Agent
from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.state.task import AgentTask
from intriqo_agents.state.result import AgentResult
from intriqo_agents.orchestrator.registry import AgentRegistry


logger = logging.getLogger("intriqo.agents.orchestrator")


class AgentOrchestrator:
    """Coordinates event routing, task generation, agent dispatch, and result aggregation."""

    def __init__(self, registry: AgentRegistry) -> None:
        if not isinstance(registry, AgentRegistry):
            raise TypeError(f"Expected AgentRegistry instance, got {type(registry).__name__}")
        self.registry = registry

    def create_task(self, event: SecurityEvent, task_id: Optional[str] = None) -> AgentTask:
        """Derive an AgentTask from a SecurityEvent."""
        if not isinstance(event, SecurityEvent):
            raise TypeError(f"Expected SecurityEvent instance, got {type(event).__name__}")

        tid = task_id or f"task-{uuid.uuid4().hex[:8]}"
        priority_map = {"CRITICAL": "URGENT", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        priority = priority_map.get(event.severity, "MEDIUM")

        return AgentTask(
            task_id=tid,
            task_type="INVESTIGATION",
            description=(
                f"Investigate security incident: {event.event_type} "
                f"from {event.source} targeting {event.target}"
            ),
            security_event=event,
            priority=priority,
            context={"event_metadata": event.metadata},
        )

    def select_agent(self, task: AgentTask) -> Optional[Agent]:
        """Resolve an appropriate agent for the assigned task."""
        if not isinstance(task, AgentTask):
            raise TypeError(f"Expected AgentTask instance, got {type(task).__name__}")
        if task.task_type == "INVESTIGATION":
            return self.registry.find_agent_by_capability("investigation")
        return None

    def process_event(self, event: SecurityEvent) -> AgentResult:
        """Execute end-to-end: SecurityEvent → AgentTask → Agent → AgentResult."""
        if not isinstance(event, SecurityEvent):
            raise TypeError(f"Expected SecurityEvent instance, got {type(event).__name__}")

        logger.info(
            "Orchestrator received event_id='%s' event_type='%s'", event.id, event.event_type
        )
        task = self.create_task(event)
        logger.info("Created task_id='%s' for event_id='%s'", task.task_id, event.id)

        agent = self.select_agent(task)
        if agent is None:
            err_msg = f"No agent available for task_type='{task.task_type}'"
            logger.error("Agent selection failed for task_id='%s': %s", task.task_id, err_msg)
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name="orchestrator",
                error_message=err_msg,
                error_details={"task_type": task.task_type, "event_type": event.event_type},
            )

        logger.info("Dispatching task_id='%s' to agent '%s'", task.task_id, agent.name)
        try:
            result = agent.execute(task)
            logger.info(
                "Task '%s' completed by agent '%s' status='%s'",
                task.task_id, agent.name, result.status,
            )
            return result
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(
                "Agent '%s' crashed on task '%s': %s",
                agent.name, task.task_id, exc, exc_info=True,
            )
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name=agent.name,
                error_message=f"Agent execution crashed: {exc}",
                error_details={"exception": str(exc)},
            )
