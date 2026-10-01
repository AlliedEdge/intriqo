"""Unit tests for the tool abstraction and deterministic mock tools."""

import unittest

from intriqo_agents.tools.base import ToolResult
from intriqo_agents.tools.mock_tools import (
    NetworkFlowQueryTool,
    HistoricalAlertsQueryTool,
    HostActivityQueryTool,
    FailingMockTool,
)


class TestToolResult(unittest.TestCase):

    def test_ok(self) -> None:
        res = ToolResult.ok(data={"count": 5}, metadata={"latency_ms": 12})
        self.assertTrue(res.success)
        self.assertEqual(res.data, {"count": 5})
        self.assertIsNone(res.error)

    def test_fail(self) -> None:
        res = ToolResult.fail("Connection refused", metadata={"code": 503})
        self.assertFalse(res.success)
        self.assertEqual(res.error, "Connection refused")
        self.assertEqual(res.data, {})

    def test_success_type_validation(self) -> None:
        with self.assertRaises(TypeError):
            ToolResult(success="yes")  # type: ignore


class TestMockTools(unittest.TestCase):

    def setUp(self) -> None:
        self.flow_tool  = NetworkFlowQueryTool()
        self.alert_tool = HistoricalAlertsQueryTool()
        self.host_tool  = HostActivityQueryTool()

    def test_network_flow_query_success(self) -> None:
        res = self.flow_tool.execute({"source_ip": "10.0.0.10", "target_ip": "10.0.0.20"})
        self.assertTrue(res.success)
        self.assertEqual(res.data["count"], 10)
        self.assertEqual(res.data["flows"][0]["dst_port"], 21)

    def test_network_flow_query_limit(self) -> None:
        res = self.flow_tool.execute({"source_ip": "10.0.0.10", "limit": 3})
        self.assertEqual(res.data["count"], 3)

    def test_network_flow_missing_required(self) -> None:
        res = self.flow_tool.execute({})
        self.assertFalse(res.success)
        self.assertIn("missing required input field: 'source_ip'", res.error or "")

    def test_network_flow_empty_string(self) -> None:
        res = self.flow_tool.execute({"source_ip": "   "})
        self.assertFalse(res.success)
        self.assertIn("cannot be empty", res.error or "")

    def test_historical_alerts_found(self) -> None:
        res = self.alert_tool.execute({"ip_address": "10.0.0.10"})
        self.assertTrue(res.success)
        self.assertEqual(res.data["alert_count"], 1)

    def test_historical_alerts_not_found(self) -> None:
        res = self.alert_tool.execute({"ip_address": "192.168.99.99"})
        self.assertEqual(res.data["alert_count"], 0)

    def test_host_activity_found(self) -> None:
        res = self.host_tool.execute({"host_ip": "10.0.0.20"})
        self.assertTrue(res.data["found"])
        self.assertEqual(res.data["telemetry"]["hostname"], "srv-prod-web01")

    def test_host_activity_not_found(self) -> None:
        res = self.host_tool.execute({"host_ip": "10.0.0.99"})
        self.assertFalse(res.data["found"])

    def test_failing_tool_graceful(self) -> None:
        res = FailingMockTool(should_raise=False, error_message="DB offline").execute({})
        self.assertFalse(res.success)
        self.assertEqual(res.error, "DB offline")

    def test_failing_tool_exception_wrapped(self) -> None:
        res = FailingMockTool(should_raise=True, error_message="Fatal panic").execute({})
        self.assertFalse(res.success)
        self.assertIn("Fatal panic", res.error or "")


if __name__ == "__main__":
    unittest.main()
