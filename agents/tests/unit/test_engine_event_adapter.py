"""Unit tests for the engine → Python SecurityEvent adapter.

Migrated from test_java_event_adapter.py.  The adapter logic is identical;
only the import paths and error class name have been updated to reflect
the new architecture (C++ IDS engine instead of Java).
"""

import json
import unittest
from datetime import datetime, timezone

from intriqo_agents.tools.engine_event_adapter import (
    EngineEventAdapterError,
    adapt_from_dict,
    adapt_from_json,
    EVENT_TYPE_MAP,
)
from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.orchestrator.orchestrator import AgentOrchestrator
from intriqo_agents.orchestrator.registry import AgentRegistry


def _valid_contract(**overrides) -> dict:
    """Return a minimal valid engine SecurityEvent contract dict."""
    base = {
        "event_id":            "evt-engine-001",
        "event_type":          "PORT_SCAN",
        "severity":            "MEDIUM",
        "timestamp":           "2026-09-12T10:00:00.000Z",
        "source_address":      "192.168.1.50",
        "destination_address": "192.168.1.20",
        "description":         "Port scan detected from 192.168.1.50: 6 distinct ports",
        "details": {
            "distinctPortCount": 6,
            "threshold": 5,
            "timeWindowSeconds": 300,
            "targetedHosts": 1,
            "sourceAddress": "192.168.1.50",
        },
    }
    base.update(overrides)
    return base


class TestAdaptFromJson(unittest.TestCase):

    def test_valid_json_produces_security_event(self) -> None:
        event = adapt_from_json(json.dumps(_valid_contract()))
        self.assertIsInstance(event, SecurityEvent)

    def test_non_string_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            adapt_from_json({"not": "a string"})  # type: ignore

    def test_empty_string_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_json("")

    def test_blank_string_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_json("   ")

    def test_malformed_json_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError) as ctx:
            adapt_from_json("{invalid json}")
        self.assertIn("malformed", str(ctx.exception).lower())

    def test_json_array_raises(self) -> None:
        with self.assertRaises((EngineEventAdapterError, TypeError)):
            adapt_from_json("[1, 2, 3]")


class TestAdaptFromDict(unittest.TestCase):

    # ── Successful adaptation ────────────────────────────────────────────────

    def test_valid_contract_maps_all_fields(self) -> None:
        event = adapt_from_dict(_valid_contract())
        self.assertIsInstance(event, SecurityEvent)
        self.assertEqual(event.id, "evt-engine-001")
        self.assertEqual(event.event_type, "PORT_SCAN_DETECTED")   # mapped
        self.assertEqual(event.severity, "MEDIUM")
        self.assertEqual(event.source, "192.168.1.50")
        self.assertEqual(event.target, "192.168.1.20")
        self.assertIsInstance(event.timestamp, datetime)
        self.assertIsNotNone(event.timestamp.tzinfo)

    def test_event_type_port_scan_mapped(self) -> None:
        event = adapt_from_dict(_valid_contract(event_type="PORT_SCAN"))
        self.assertEqual(event.event_type, "PORT_SCAN_DETECTED")

    def test_all_severity_values_accepted(self) -> None:
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            with self.subTest(severity=sev):
                event = adapt_from_dict(_valid_contract(severity=sev))
                self.assertEqual(event.severity, sev)

    def test_description_stored_in_metadata(self) -> None:
        event = adapt_from_dict(_valid_contract())
        self.assertIn("description", event.metadata)
        self.assertIn("Port scan", event.metadata["description"])

    def test_details_merged_into_metadata(self) -> None:
        event = adapt_from_dict(_valid_contract())
        self.assertIn("distinctPortCount", event.metadata)
        self.assertEqual(event.metadata["distinctPortCount"], 6)

    def test_absent_details_no_error(self) -> None:
        c = _valid_contract()
        del c["details"]
        event = adapt_from_dict(c)
        self.assertNotIn("distinctPortCount", event.metadata)

    def test_absent_description_no_error(self) -> None:
        c = _valid_contract()
        del c["description"]
        self.assertIsInstance(adapt_from_dict(c), SecurityEvent)

    # ── Timestamp parsing ────────────────────────────────────────────────────

    def test_timestamp_z_suffix(self) -> None:
        event = adapt_from_dict(_valid_contract(timestamp="2026-09-12T10:00:00.000Z"))
        self.assertEqual(event.timestamp, datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc))

    def test_timestamp_plus_offset(self) -> None:
        event = adapt_from_dict(_valid_contract(timestamp="2026-09-12T10:00:00+00:00"))
        self.assertEqual(event.timestamp.year, 2026)
        self.assertIsNotNone(event.timestamp.tzinfo)

    def test_timestamp_without_millis(self) -> None:
        event = adapt_from_dict(_valid_contract(timestamp="2026-09-12T10:00:00Z"))
        self.assertIsNotNone(event.timestamp)

    # ── Missing required fields ──────────────────────────────────────────────

    def test_missing_event_id(self) -> None:
        c = _valid_contract(); del c["event_id"]
        with self.assertRaises(EngineEventAdapterError) as ctx:
            adapt_from_dict(c)
        self.assertIn("event_id", str(ctx.exception))

    def test_missing_source_address(self) -> None:
        c = _valid_contract(); del c["source_address"]
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(c)

    def test_missing_destination_address(self) -> None:
        c = _valid_contract(); del c["destination_address"]
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(c)

    # ── Null required values ─────────────────────────────────────────────────

    def test_null_event_id_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError) as ctx:
            adapt_from_dict(_valid_contract(event_id=None))
        self.assertIn("null", str(ctx.exception).lower())

    def test_null_timestamp_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(timestamp=None))

    # ── Invalid enum values ──────────────────────────────────────────────────

    def test_invalid_severity_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError) as ctx:
            adapt_from_dict(_valid_contract(severity="FATAL"))
        self.assertIn("FATAL", str(ctx.exception))

    def test_lowercase_severity_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(severity="medium"))

    # ── Invalid types ────────────────────────────────────────────────────────

    def test_integer_event_id_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(event_id=12345))

    def test_integer_timestamp_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(timestamp=1726134000))

    def test_invalid_timestamp_format_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(timestamp="not-a-date"))

    def test_list_as_details_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(details=["invalid"]))

    def test_empty_event_id_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(event_id=""))

    def test_whitespace_source_raises(self) -> None:
        with self.assertRaises(EngineEventAdapterError):
            adapt_from_dict(_valid_contract(source_address="   "))

    def test_non_dict_input_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            adapt_from_dict("this is not a dict")  # type: ignore

    # ── Orchestrator integration ─────────────────────────────────────────────

    def test_adapter_output_accepted_by_orchestrator(self) -> None:
        event = adapt_from_dict(_valid_contract())
        orchestrator = AgentOrchestrator(AgentRegistry())
        task = orchestrator.create_task(event)
        self.assertEqual(event, task.security_event)
        self.assertEqual(task.priority, "MEDIUM")

    # ── EVENT_TYPE_MAP integrity ─────────────────────────────────────────────

    def test_port_scan_in_map(self) -> None:
        self.assertIn("PORT_SCAN", EVENT_TYPE_MAP)
        self.assertEqual(EVENT_TYPE_MAP["PORT_SCAN"], "PORT_SCAN_DETECTED")

    def test_unknown_event_type_passes_through(self) -> None:
        event = adapt_from_dict(_valid_contract(event_type="FUTURE_DETECTOR_TYPE"))
        self.assertEqual(event.event_type, "FUTURE_DETECTOR_TYPE")


if __name__ == "__main__":
    unittest.main()
