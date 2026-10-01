"""Unit tests for InvestigationAgent end-to-end execution."""

from datetime import datetime, timezone
import unittest

from intriqo_agents.investigation.agent import InvestigationAgent
from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.state.task import AgentTask
from intriqo_agents.tools.base import Tool, ToolResult
from intriqo_agents.tools.mock_tools import NetworkFlowQueryTool
from tests.unit.fixtures import MOCK_PORT_SCAN_EVENT


class TestInvestigationAgent(unittest.TestCase):

    def setUp(self) -> None:
        self.agent = InvestigationAgent()
        self.port_scan_task = AgentTask(
            task_id="task-test-001", task_type="INVESTIGATION",
            description="Investigate port scan",
            security_event=MOCK_PORT_SCAN_EVENT, priority="HIGH",
        )

    def test_agent_properties(self) -> None:
        self.assertEqual(self.agent.name, "investigation_agent")
        self.assertIn("investigation", self.agent.capabilities)
        self.assertIn("network_investigation", self.agent.capabilities)

    def test_successful_port_scan_investigation(self) -> None:
        result = self.agent.execute(self.port_scan_task)
        self.assertEqual(result.status, "SUCCESS")
        self.assertGreaterEqual(result.confidence, 0.90)
        self.assertGreater(len(result.findings), 0)
        port_evidence = next(e for e in result.evidence if e.get("type") == "port_distribution")
        self.assertEqual(port_evidence["distinct_port_count"], 10)

    def test_investigation_inconclusive_when_no_flows(self) -> None:
        agent = InvestigationAgent(tools=[NetworkFlowQueryTool(flows=[])])
        result = agent.execute(self.port_scan_task)
        self.assertEqual(result.status, "INCONCLUSIVE")
        self.assertEqual(result.confidence, 0.5)

    def test_missing_required_tool_returns_failure(self) -> None:
        result = InvestigationAgent(tools={}).execute(self.port_scan_task)
        self.assertEqual(result.status, "FAILED")
        self.assertIn("not available", result.error["message"])

    def test_tool_failure_returns_structured_failure(self) -> None:
        class BrokenFlowTool(Tool):
            @property
            def name(self) -> str: return "query_network_flows"
            @property
            def description(self) -> str: return "Fails"
            @property
            def input_schema(self) -> dict: return {"type": "object", "required": ["source_ip"]}
            def _run(self, input_data: dict) -> ToolResult:
                return ToolResult.fail("Network sensor timeout", metadata={"sensor_id": "s1"})

        result = InvestigationAgent(tools=[BrokenFlowTool()]).execute(self.port_scan_task)
        self.assertEqual(result.status, "FAILED")
        self.assertIn("Network sensor timeout", result.error["message"])

    def test_unsupported_event_type(self) -> None:
        event = SecurityEvent(
            id="evt-unknown", timestamp=datetime.now(timezone.utc),
            event_type="UNRECOGNIZED_THREAT", severity="LOW",
            source="1.2.3.4", target="5.6.7.8",
        )
        task = AgentTask(task_id="t2", task_type="INVESTIGATION",
                         description="Unknown threat", security_event=event)
        result = self.agent.execute(task)
        self.assertEqual(result.status, "FAILED")
        self.assertIn("not supported", result.error["message"])

    def test_invalid_task_type_raises(self) -> None:
        with self.assertRaises(TypeError):
            self.agent.execute("not_a_task")  # type: ignore


if __name__ == "__main__":
    unittest.main()
