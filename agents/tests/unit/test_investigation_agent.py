"""Unit tests for InvestigationAgent end-to-end execution."""

import unittest
from datetime import datetime, timezone

from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.investigation.agent import InvestigationAgent
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

    def test_syn_flood_investigation_preserves_detector_evidence(self) -> None:
        event = SecurityEvent(
            id="evt-syn", timestamp=datetime.now(timezone.utc), event_type="SYN_FLOOD",
            severity="CRITICAL", source="10.0.0.1", target="10.0.0.2",
            metadata={
                "detector": "syn_flood", "destination_port": 443,
                "connection_attempts": 120, "incomplete_handshakes": 110,
                "incomplete_ratio": 0.916, "rate_per_second": 60.0,
                "window_seconds": 10.0,
            },
        )
        task = AgentTask(
            task_id="task-syn", task_type="INVESTIGATION", description="Investigate SYN flood",
            security_event=event,
        )

        result = self.agent.execute(task)

        self.assertEqual(result.status, "SUCCESS")
        evidence = result.evidence[0]
        self.assertEqual(evidence["type"], "syn_flood_analysis")
        self.assertEqual(evidence["detector_name"], "syn_flood")
        self.assertEqual(evidence["incomplete_handshake_count"], 110)

    def test_udp_scan_control_plane_event_produces_port_scan_finding(self) -> None:
        event = SecurityEvent(
            id="evt-udp-scan", timestamp=datetime.now(timezone.utc), event_type="UDP_SCAN",
            severity="HIGH", source="10.77.0.10", target="10.77.0.20",
            metadata={"transport_protocol": "UDP", "unique_destination_ports": 10,
                      "connection_attempts": 10, "detector_name": "udp_port_scan"},
        )
        task = AgentTask(
            task_id="task-udp-scan", task_type="INVESTIGATION", description="Investigate UDP scan",
            security_event=event,
        )

        result = self.agent._investigate_control_plane_event(task)

        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.metadata["finding_type"], "PORT_SCAN_ANALYSIS")
        self.assertIn("10 unique ports", result.findings[0])

    def test_ml_anomaly_investigation_preserves_locked_receipt_without_labels(self) -> None:
        event = SecurityEvent(
            id="evt-ml", timestamp=datetime.now(timezone.utc), event_type="ML_ANOMALY",
            severity="MEDIUM", source="10.0.0.1", target="10.0.0.2",
            metadata={
                "detection_source": "ML", "detector": "isolation_forest_v2",
                "result": {
                    "flow_id": "8", "anomaly_score": 0.7, "threshold": 0.5,
                    "model_sha256": "a" * 64, "threshold_sha256": "b" * 64,
                    "feature_schema_version": "flow_features.v2", "detector": "isolation_forest_v2",
                    "labels": ["must-not-be-forwarded"],
                },
            },
        )
        task = AgentTask(
            task_id="task-ml", task_type="INVESTIGATION", description="Review ML anomaly",
            security_event=event,
        )

        result = self.agent.execute(task)

        self.assertEqual(result.status, "SUCCESS")
        evidence = result.evidence[0]
        self.assertEqual(evidence["detection_source"], "ML")
        self.assertEqual(evidence["detector"], "isolation_forest_v2")
        self.assertNotIn("labels", evidence)

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
