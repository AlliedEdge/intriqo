"""Unit tests for domain models (SecurityEvent, AgentTask, AgentResult)."""

import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.state.result import AgentResult
from intriqo_agents.state.task import AgentTask


class TestSecurityEventModel(unittest.TestCase):

    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.event = SecurityEvent(
            id="evt-100",
            timestamp=self.now,
            event_type="PORT_SCAN_DETECTED",
            severity="HIGH",
            source="10.0.0.1",
            target="10.0.0.2",
            metadata={"port_count": 12},
        )

    def test_valid_instantiation(self) -> None:
        self.assertEqual(self.event.id, "evt-100")
        self.assertEqual(self.event.severity, "HIGH")
        self.assertEqual(self.event.metadata, {"port_count": 12})

    def test_immutability(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.event.severity = "LOW"  # type: ignore

    def test_validation_empty_id(self) -> None:
        with self.assertRaises(ValueError):
            SecurityEvent(id="", timestamp=self.now, event_type="PORT_SCAN",
                          severity="HIGH", source="10.0.0.1", target="10.0.0.2")

    def test_validation_invalid_severity(self) -> None:
        with self.assertRaises(ValueError):
            SecurityEvent(id="evt-1", timestamp=self.now, event_type="PORT_SCAN",
                          severity="EXTREME", source="10.0.0.1", target="10.0.0.2")

    def test_validation_invalid_timestamp_type(self) -> None:
        with self.assertRaises(TypeError):
            SecurityEvent(id="evt-1", timestamp="2026-09-12T10:00:00Z",  # type: ignore
                          event_type="PORT_SCAN", severity="HIGH",
                          source="10.0.0.1", target="10.0.0.2")

    def test_serialization_roundtrip(self) -> None:
        d = self.event.to_dict()
        restored = SecurityEvent.from_dict(d)
        self.assertEqual(self.event.id, restored.id)
        self.assertEqual(self.event.event_type, restored.event_type)
        self.assertEqual(self.event.severity, restored.severity)
        self.assertEqual(self.event.metadata, restored.metadata)

    def test_detection_source_defaults_for_native_events(self) -> None:
        self.assertEqual(self.event.detection_source, "DETERMINISTIC")

    def test_detection_source_is_preserved_for_ml_events(self) -> None:
        event = SecurityEvent(
            id="evt-ml", timestamp=self.now, event_type="ML_ANOMALY", severity="MEDIUM",
            source="10.0.0.1", target="10.0.0.2", metadata={"detection_source": "ML"},
        )
        self.assertEqual(event.detection_source, "ML")


class TestAgentTaskModel(unittest.TestCase):

    def setUp(self) -> None:
        self.event = SecurityEvent(
            id="evt-200", timestamp=datetime.now(timezone.utc),
            event_type="PORT_SCAN_DETECTED", severity="MEDIUM",
            source="192.168.1.5", target="192.168.1.10",
        )
        self.task = AgentTask(
            task_id="task-001", task_type="INVESTIGATION",
            description="Investigate suspicious connection burst",
            security_event=self.event, priority="HIGH",
            context={"analyst": "sec-team"},
        )

    def test_valid_instantiation(self) -> None:
        self.assertEqual(self.task.task_id, "task-001")
        self.assertEqual(self.task.priority, "HIGH")
        self.assertEqual(self.task.security_event, self.event)

    def test_immutability(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.task.priority = "LOW"  # type: ignore

    def test_validation_invalid_event_type(self) -> None:
        with self.assertRaises(TypeError):
            AgentTask(task_id="t2", task_type="INVESTIGATION", description="d",
                      security_event={"not": "an event"})  # type: ignore

    def test_validation_invalid_priority(self) -> None:
        with self.assertRaises(ValueError):
            AgentTask(task_id="t3", task_type="INVESTIGATION", description="d",
                      security_event=self.event, priority="SUPER_URGENT")

    def test_serialization_roundtrip(self) -> None:
        d = self.task.to_dict()
        restored = AgentTask.from_dict(d)
        self.assertEqual(self.task.task_id, restored.task_id)
        self.assertEqual(self.task.priority, restored.priority)
        self.assertEqual(self.task.security_event.id, restored.security_event.id)


class TestAgentResultModel(unittest.TestCase):

    def test_success_factory(self) -> None:
        result = AgentResult.success(
            task_id="task-100", agent_name="investigation_agent",
            findings=["Port scan confirmed on 10 ports."],
            evidence=[{"ports": [80, 443]}], confidence=0.95,
            summary="Port scan detected with high confidence.",
        )
        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.confidence, 0.95)
        self.assertIsNone(result.error)

    def test_failure_factory(self) -> None:
        result = AgentResult.failure(
            task_id="task-101", agent_name="investigation_agent",
            error_message="Tool connection timed out",
            error_details={"code": "TIMEOUT"},
        )
        self.assertEqual(result.status, "FAILED")
        self.assertEqual(result.confidence, 0.0)
        self.assertEqual(result.error["message"], "Tool connection timed out")
        self.assertEqual(result.error["code"], "TIMEOUT")

    def test_confidence_out_of_range(self) -> None:
        with self.assertRaises(ValueError):
            AgentResult(task_id="t", agent_name="a", status="SUCCESS", confidence=1.5)
        with self.assertRaises(ValueError):
            AgentResult(task_id="t", agent_name="a", status="SUCCESS", confidence=-0.1)

    def test_invalid_status(self) -> None:
        with self.assertRaises(ValueError):
            AgentResult(task_id="t", agent_name="a", status="MAYBE", confidence=0.5)

    def test_serialization_roundtrip(self) -> None:
        original = AgentResult.success(
            task_id="task-105", agent_name="agent_test",
            findings=["Finding 1", "Finding 2"], evidence=[{"item": 1}],
            confidence=0.85, summary="Summary", metadata={"source": "unit_test"},
        )
        restored = AgentResult.from_dict(original.to_dict())
        self.assertEqual(original.task_id, restored.task_id)
        self.assertEqual(original.findings, restored.findings)
        self.assertEqual(original.confidence, restored.confidence)


if __name__ == "__main__":
    unittest.main()
