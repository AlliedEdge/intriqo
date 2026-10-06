"""Orchestrator — coordinates events, tasks, and specialized agent dispatch.

Execution flow
──────────────
SecurityEvent → create_task() → select_agent() → agent.execute() → AgentResult

The full autonomous lifecycle (observe → plan → investigate → correlate →
respond → verify → repeat) will build on this foundation in future phases.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from typing import cast

from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.control_plane.client import ControlPlaneClient
from intriqo_agents.core.agent import Agent
from intriqo_agents.orchestrator.registry import AgentRegistry
from intriqo_agents.state.result import AgentResult
from intriqo_agents.state.task import AgentTask

logger = logging.getLogger("intriqo.agents.orchestrator")


class AgentOrchestrator:
    """Coordinates event routing, task generation, agent dispatch, and result aggregation."""

    def __init__(self, registry: AgentRegistry, client: ControlPlaneClient | None = None) -> None:
        if not isinstance(registry, AgentRegistry):
            raise TypeError(f"Expected AgentRegistry instance, got {type(registry).__name__}")
        self.registry = registry
        self.client = client

    def execute_task(self, task_id: str) -> AgentResult:
        """Dispatch one persisted Control Plane task to the registered agent."""
        task_payload = self.client.get_task(task_id) if self.client else None
        if task_payload is not None and task_payload.get("task_type") != "INVESTIGATION":
            return AgentResult.failure(task_id, "orchestrator", "Unsupported task type", {"task_type": task_payload.get("task_type")})
        agent = self.registry.find_agent_by_capability("investigation")
        execute_task = getattr(agent, "execute_task", None) if agent is not None else None
        if not callable(execute_task):
            return AgentResult.failure(task_id, "orchestrator", "No remote investigation agent available")
        runner = cast(Callable[[str, ControlPlaneClient | None], AgentResult], execute_task)
        return runner(task_id, self.client)

    def create_task(self, event: SecurityEvent, task_id: str | None = None) -> AgentTask:
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

    def select_agent(self, task: AgentTask) -> Agent | None:
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
        except Exception as exc:
            logger.exception("Agent '%s' crashed on task '%s'", agent.name, task.task_id)
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name=agent.name,
                error_message=f"Agent execution crashed: {exc}",
                error_details={"exception": str(exc)},
            )
