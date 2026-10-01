"""Contract tests for representative mock security events."""

import json
import unittest

from tests.unit.fixtures import MOCK_PORT_SCAN_EVENT, MOCK_BRUTE_FORCE_EVENT
from intriqo_agents.contracts.security_event import SecurityEvent


class TestSecurityEventContracts(unittest.TestCase):

    def test_port_scan_event_contract(self) -> None:
        event = MOCK_PORT_SCAN_EVENT
        self.assertEqual(event.event_type, "PORT_SCAN_DETECTED")
        self.assertEqual(event.source, "10.0.0.10")
        self.assertEqual(event.severity, "HIGH")

        payload = json.loads(json.dumps(event.to_dict()))
        for field in ("id", "timestamp", "event_type", "severity", "source", "target", "metadata"):
            self.assertIn(field, payload)
        self.assertEqual(payload["metadata"]["detector"], "PortScanDetector")

        restored = SecurityEvent.from_dict(payload)
        self.assertEqual(event.id, restored.id)
        self.assertEqual(event.event_type, restored.event_type)

    def test_brute_force_event_contract(self) -> None:
        event = MOCK_BRUTE_FORCE_EVENT
        self.assertEqual(event.event_type, "BRUTE_FORCE_DETECTED")
        self.assertEqual(event.metadata["service"], "ssh")

        restored = SecurityEvent.from_dict(json.loads(json.dumps(event.to_dict())))
        self.assertEqual(event.id, restored.id)


if __name__ == "__main__":
    unittest.main()
