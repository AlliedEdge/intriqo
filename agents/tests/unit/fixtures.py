"""Shared test fixtures for the intriqo_agents test suite."""

from __future__ import annotations

from datetime import datetime, timezone

from intriqo_agents.contracts.security_event import SecurityEvent


MOCK_PORT_SCAN_EVENT = SecurityEvent(
    id="evt-portscan-001",
    timestamp=datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc),
    event_type="PORT_SCAN_DETECTED",
    severity="HIGH",
    source="10.0.0.10",
    target="10.0.0.20",
    metadata={
        "distinct_ports": 10,
        "detector": "PortScanDetector",
        "window_seconds": 300,
    },
)

MOCK_BRUTE_FORCE_EVENT = SecurityEvent(
    id="evt-bruteforce-002",
    timestamp=datetime(2026, 9, 12, 10, 5, 0, tzinfo=timezone.utc),
    event_type="BRUTE_FORCE_DETECTED",
    severity="HIGH",
    source="192.168.1.100",
    target="10.0.0.20",
    metadata={"failed_attempts": 25, "service": "ssh", "target_port": 22},
)


def create_sample_port_scan_event(
    event_id: str = "evt-portscan-custom",
    source: str = "10.0.0.10",
    target: str = "10.0.0.20",
    severity: str = "HIGH",
) -> SecurityEvent:
    return SecurityEvent(
        id=event_id,
        timestamp=datetime.now(timezone.utc),
        event_type="PORT_SCAN_DETECTED",
        severity=severity,
        source=source,
        target=target,
        metadata={"generated_for": "testing"},
    )
