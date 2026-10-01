"""Deterministic mock tools for cybersecurity investigation testing.

These tools exist to support unit and integration tests without requiring
real network infrastructure.  They return deterministic, reproducible
results and are never wired to live data sources.
"""

from __future__ import annotations

from typing import Any

from intriqo_agents.tools.base import Tool, ToolResult


# ── Deterministic mock network flows ──────────────────────────────────────────
_DEFAULT_MOCK_FLOWS = [
    {"flow_id": "flow-001", "timestamp": "2026-09-12T10:00:00Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49152, "dst_port": 21,    "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-002", "timestamp": "2026-09-12T10:00:01Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49153, "dst_port": 22,    "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-003", "timestamp": "2026-09-12T10:00:02Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49154, "dst_port": 23,    "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-004", "timestamp": "2026-09-12T10:00:03Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49155, "dst_port": 80,    "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-005", "timestamp": "2026-09-12T10:00:04Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49156, "dst_port": 443,   "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-006", "timestamp": "2026-09-12T10:00:05Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49157, "dst_port": 8080,  "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-007", "timestamp": "2026-09-12T10:00:06Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49158, "dst_port": 8443,  "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-008", "timestamp": "2026-09-12T10:00:07Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49159, "dst_port": 3306,  "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-009", "timestamp": "2026-09-12T10:00:08Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49160, "dst_port": 5432,  "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
    {"flow_id": "flow-010", "timestamp": "2026-09-12T10:00:09Z", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20", "src_port": 49161, "dst_port": 27017, "protocol": "TCP", "flags": "SYN", "packet_count": 1, "byte_count": 64},
]


class NetworkFlowQueryTool(Tool):
    """Queries deterministic mock network flow telemetry (for testing)."""

    def __init__(self, flows: list[dict[str, Any]] | None = None) -> None:
        self._flows = list(flows) if flows is not None else list(_DEFAULT_MOCK_FLOWS)

    @property
    def name(self) -> str:
        return "query_network_flows"

    @property
    def description(self) -> str:
        return "Queries network flow telemetry for communication between source and target hosts."

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["source_ip"],
            "properties": {
                "source_ip": {"type": "string"},
                "target_ip": {"type": "string"},
                "limit":     {"type": "integer"},
            },
        }

    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        source_ip = input_data["source_ip"]
        target_ip = input_data.get("target_ip")
        limit = input_data.get("limit", 100)

        matched = [
            f for f in self._flows
            if f.get("src_ip") == source_ip
            and (target_ip is None or f.get("dst_ip") == target_ip)
        ]
        if isinstance(limit, int) and limit > 0:
            matched = matched[:limit]

        return ToolResult.ok(
            data={"count": len(matched), "flows": matched},
            metadata={"query_source": source_ip, "query_target": target_ip},
        )


class HistoricalAlertsQueryTool(Tool):
    """Queries historical alerts associated with an IP address."""

    def __init__(self, alerts_map: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self._alerts_map = alerts_map or {
            "10.0.0.10": [
                {
                    "alert_id": "hist-alert-901",
                    "timestamp": "2026-09-11T18:30:00Z",
                    "type": "RECON_PROBE",
                    "severity": "LOW",
                    "description": "Suspicious ICMP sweep observed from 10.0.0.10",
                }
            ]
        }

    @property
    def name(self) -> str:
        return "query_historical_alerts"

    @property
    def description(self) -> str:
        return "Queries prior security alerts for a given IP address."

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["ip_address"],
            "properties": {"ip_address": {"type": "string"}},
        }

    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        ip = input_data["ip_address"]
        alerts = self._alerts_map.get(ip, [])
        return ToolResult.ok(
            data={"ip_address": ip, "alert_count": len(alerts), "alerts": list(alerts)},
            metadata={"source": "mock_historical_store"},
        )


class HostActivityQueryTool(Tool):
    """Queries endpoint/host telemetry records."""

    def __init__(self, host_map: dict[str, dict[str, Any]] | None = None) -> None:
        self._host_map = host_map or {
            "10.0.0.20": {
                "hostname": "srv-prod-web01",
                "os": "Linux 6.6",
                "active_services": ["nginx", "sshd", "postgresql"],
                "open_ports": [22, 80, 443, 5432],
            }
        }

    @property
    def name(self) -> str:
        return "query_host_activity"

    @property
    def description(self) -> str:
        return "Queries host endpoint telemetry, running services, and open listener ports."

    @property
    def input_schema(self) -> dict[str, Any]:
        return {
            "type": "object",
            "required": ["host_ip"],
            "properties": {"host_ip": {"type": "string"}},
        }

    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        host_ip = input_data["host_ip"]
        info = self._host_map.get(host_ip)
        if not info:
            return ToolResult.ok(
                data={"host_ip": host_ip, "found": False, "telemetry": {}},
                metadata={"status": "not_found"},
            )
        return ToolResult.ok(
            data={"host_ip": host_ip, "found": True, "telemetry": info},
            metadata={"status": "found"},
        )


class FailingMockTool(Tool):
    """Unconditionally fails — used for resilience and error-handling tests."""

    def __init__(self, should_raise: bool = False, error_message: str = "Simulated tool failure") -> None:
        self._should_raise = should_raise
        self._error_message = error_message

    @property
    def name(self) -> str:
        return "failing_mock_tool"

    @property
    def description(self) -> str:
        return "Deterministic failure tool for testing agent error handling."

    @property
    def input_schema(self) -> dict[str, Any]:
        return {"type": "object", "required": []}

    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        if self._should_raise:
            raise RuntimeError(self._error_message)
        return ToolResult.fail(error=self._error_message)
