"""Standalone demo entrypoint for the Intriqo autonomous agent platform."""

from __future__ import annotations

import json
import logging
import sys
import argparse

from intriqo_agents.investigation.agent import InvestigationAgent
from intriqo_agents.orchestrator.registry import AgentRegistry
from intriqo_agents.orchestrator.orchestrator import AgentOrchestrator
from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.control_plane.client import ControlPlaneClient
from datetime import datetime, timezone


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def run_demo() -> int:
    setup_logging()
    print("\n========================================================")
    print("  INTRIQO AUTONOMOUS AGENT PLATFORM — DEMO")
    print("========================================================\n")

    # Sample event (mirrors the fixture used in tests)
    event = SecurityEvent(
        id="evt-demo-001",
        timestamp=datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc),
        event_type="PORT_SCAN_DETECTED",
        severity="HIGH",
        source="10.0.0.10",
        target="10.0.0.20",
        metadata={"distinct_ports": 10, "detector": "PortScanDetector", "window_seconds": 300},
    )

    registry = AgentRegistry()
    registry.register(InvestigationAgent())
    orchestrator = AgentOrchestrator(registry)

    print(f"[*] Processing SecurityEvent: {event.id} ({event.event_type})")
    print(f"    Source: {event.source} → Target: {event.target}")
    print(f"    Severity: {event.severity}\n")

    result = orchestrator.process_event(event)

    print("\n--------------------------------------------------------")
    print("  AGENT RESULT")
    print("--------------------------------------------------------")
    print(json.dumps(result.to_dict(), indent=2))
    print("--------------------------------------------------------\n")

    if result.status == "SUCCESS":
        print("[+] Investigation completed successfully.")
        return 0
    print(f"[-] Investigation status: {result.status}")
    return 1


def run_task(task_id: str) -> int:
    """Execute one persisted task; credentials are read from the environment."""
    setup_logging()
    with ControlPlaneClient() as client:
        registry = AgentRegistry([InvestigationAgent()])
        result = AgentOrchestrator(registry, client).execute_task(task_id)
    print(json.dumps(result.to_dict(), indent=2))
    return 0 if result.status in {"SUCCESS", "INCONCLUSIVE"} else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Intriqo deterministic investigation agent")
    parser.add_argument("--task-id", help="Persisted Control Plane AgentTask to execute")
    args = parser.parse_args()
    sys.exit(run_task(args.task_id) if args.task_id else run_demo())
