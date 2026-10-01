"""Unit tests for AgentRegistry and AgentOrchestrator."""

from datetime import datetime, timezone
import unittest

from intriqo_agents.investigation.agent import InvestigationAgent
from intriqo_agents.core.agent import Agent
from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.state.task import AgentTask
from intriqo_agents.state.result import AgentResult
from intriqo_agents.orchestrator.registry import AgentRegistry
from intriqo_agents.orchestrator.orchestrator import AgentOrchestrator
from tests.unit.fixtures import MOCK_PORT_SCAN_EVENT


class TestAgentRegistry(unittest.TestCase):

    def setUp(self) -> None:
        self.registry = AgentRegistry()
        self.agent = InvestigationAgent()

    def test_register_and_get_by_name(self) -> None:
        self.registry.register(self.agent)
        self.assertIs(self.registry.get_agent("investigation_agent"), self.agent)

    def test_find_by_capability(self) -> None:
        self.registry.register(self.agent)
        self.assertIs(self.registry.find_agent_by_capability("investigation"), self.agent)
        self.assertIsNone(self.registry.find_agent_by_capability("threat_intelligence"))

    def test_register_invalid_type(self) -> None:
        with self.assertRaises(TypeError):
            self.registry.register("not_an_agent")  # type: ignore


class TestAgentOrchestrator(unittest.TestCase):

    def setUp(self) -> None:
        self.agent = InvestigationAgent()
        self.registry = AgentRegistry([self.agent])
        self.orchestrator = AgentOrchestrator(self.registry)

    def test_create_task_severity_mapping(self) -> None:
        event = SecurityEvent(
            id="evt-crit", timestamp=datetime.now(timezone.utc),
            event_type="PORT_SCAN_DETECTED", severity="CRITICAL",
            source="10.0.0.1", target="10.0.0.2",
        )
        task = self.orchestrator.create_task(event)
        self.assertEqual(task.priority, "URGENT")
        self.assertEqual(task.task_type, "INVESTIGATION")

    def test_end_to_end_event_processing(self) -> None:
        result = self.orchestrator.process_event(MOCK_PORT_SCAN_EVENT)
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.agent_name, "investigation_agent")
        self.assertGreaterEqual(result.confidence, 0.90)
        self.assertIn("Port scan confirmed", result.summary or "")

    def test_no_agent_available_returns_failure(self) -> None:
        result = AgentOrchestrator(AgentRegistry()).process_event(MOCK_PORT_SCAN_EVENT)
        self.assertEqual(result.status, "FAILED")
        self.assertIn("No agent available", result.error["message"])

    def test_crashing_agent_handled_gracefully(self) -> None:
        class CrashingAgent(Agent):
            @property
            def name(self) -> str:
                return "crashing_agent"
            @property
            def capabilities(self) -> frozenset[str]:
                return frozenset({"investigation"})
            def execute(self, task: AgentTask) -> AgentResult:
                raise RuntimeError("Unexpected agent panic")

        result = AgentOrchestrator(AgentRegistry([CrashingAgent()])).process_event(MOCK_PORT_SCAN_EVENT)
        self.assertEqual(result.status, "FAILED")
        self.assertIn("crashed", result.error["message"])

    def test_invalid_event_input_raises(self) -> None:
        with self.assertRaises(TypeError):
            self.orchestrator.process_event({"not": "a SecurityEvent"})  # type: ignore


if __name__ == "__main__":
    unittest.main()
