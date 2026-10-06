"""Standalone demo entrypoint for the Intriqo autonomous agent platform."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.control_plane.client import ControlPlaneClient
from intriqo_agents.investigation.agent import InvestigationAgent
from intriqo_agents.orchestrator.orchestrator import AgentOrchestrator
from intriqo_agents.orchestrator.registry import AgentRegistry

RECOVERABLE_TASK_STATUSES = frozenset({"PENDING", "IN_PROGRESS"})


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


def poll_once(client: ControlPlaneClient, orchestrator: AgentOrchestrator) -> int:
    """Process each recoverable persisted investigation task once."""
    logger = logging.getLogger("intriqo.agents.poller")
    processed = 0
    tasks = client.list_tasks(task_type="INVESTIGATION")
    for task in tasks:
        if (
            task.get("task_type") != "INVESTIGATION"
            or task.get("status") not in RECOVERABLE_TASK_STATUSES
        ):
            continue
        task_id = task.get("task_id")
        if not task_id:
            logger.warning(
                "Skipping persisted investigation task without task_id"
            )
            continue
        try:
            result = orchestrator.execute_task(task_id)
        except Exception as exc:  # noqa: BLE001 - one malformed task must not starve the queue
            logger.error("Task execution failed for task_id='%s': %s", task_id, exc)
            continue
        processed += 1
        logger.info("Processed task_id='%s' status='%s'", task_id, result.status)
    return processed


def run_polling(
    poll_interval: float = 5.0,
    *,
    client_factory: Callable[[], ControlPlaneClient] | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Continuously process recoverable Control Plane tasks until signalled."""
    if poll_interval < 0:
        raise ValueError("poll_interval must be non-negative")

    setup_logging()
    stop = stop_event if stop_event is not None else threading.Event()
    logger = logging.getLogger("intriqo.agents.poller")
    previous_handlers: dict[int, Any] = {}

    def request_stop(signum: int, _frame: Any) -> None:
        logger.info("Received %s; stopping agent poller", signal.Signals(signum).name)
        stop.set()

    try:
        for registered_signal in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[registered_signal] = signal.signal(registered_signal, request_stop)

        factory = client_factory or ControlPlaneClient
        with factory() as client:
            registry = AgentRegistry([InvestigationAgent()])
            orchestrator = AgentOrchestrator(registry, client)
            while not stop.is_set():
                try:
                    poll_once(client, orchestrator)
                except Exception as exc:  # noqa: BLE001 - keep polling after transient failures
                    logger.error("Agent poll failed: %s", exc)
                stop.wait(poll_interval)
    finally:
        for signal_number, previous in previous_handlers.items():
            signal.signal(signal_number, previous)
    return 0


def _non_negative_float(value: str) -> float:
    interval = float(value)
    if interval < 0:
        raise argparse.ArgumentTypeError("poll interval must be non-negative")
    return interval


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Intriqo deterministic investigation agent")
    parser.add_argument("--task-id", help="Persisted Control Plane AgentTask to execute")
    parser.add_argument(
        "--poll", "--poll-tasks", dest="poll", action="store_true",
        help="Poll the Control Plane for persisted investigation tasks",
    )
    parser.add_argument(
        "--poll-interval", type=_non_negative_float, default=5.0,
        help="Seconds between Control Plane polls (default: 5)",
    )
    args = parser.parse_args(argv)
    if args.poll and args.task_id:
        parser.error("--poll cannot be combined with --task-id")
    if args.poll:
        return run_polling(args.poll_interval)
    return run_task(args.task_id) if args.task_id else run_demo()


if __name__ == "__main__":
    sys.exit(main())
