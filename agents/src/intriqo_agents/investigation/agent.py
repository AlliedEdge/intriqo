"""Investigation agent — specialized for incident investigation and evidence collection."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Mapping, Sequence

from intriqo_agents.core.agent import Agent
from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.state.task import AgentTask
from intriqo_agents.state.result import AgentResult
from intriqo_agents.tools.base import Tool, ToolResult
from intriqo_agents.tools.mock_tools import (
    NetworkFlowQueryTool,
    HistoricalAlertsQueryTool,
    HostActivityQueryTool,
)
from intriqo_agents.control_plane.client import ControlPlaneClient, ControlPlaneError
from intriqo_agents.tools.control_plane import (
    GetEventTool, GetIncidentTool, GetRelatedEventsTool, GetTaskTool, SubmitFindingTool, UpdateTaskTool,
)


logger = logging.getLogger("intriqo.agents.investigation")


class InvestigationAgent(Agent):
    """Specialized cybersecurity agent focused on incident investigation and evidence collection.

    Investigation flow
    ──────────────────
    SecurityEvent → AgentTask → route by event_type → tool invocations → AgentResult

    All tool calls go through the Tool abstraction.  No direct database access,
    no shell execution, no unrestricted network calls.
    """

    def __init__(self, tools: Sequence[Tool] | Mapping[str, Tool] | None = None) -> None:
        if tools is None:
            default_tools: list[Tool] = [
                NetworkFlowQueryTool(),
                HistoricalAlertsQueryTool(),
                HostActivityQueryTool(),
            ]
            self._tools: dict[str, Tool] = {t.name: t for t in default_tools}
        elif isinstance(tools, Mapping):
            self._tools = dict(tools)
        else:
            self._tools = {t.name: t for t in tools}

    def execute_task(self, task_id: str, client: ControlPlaneClient | None = None) -> AgentResult:
        """Run one persisted task through the Control Plane, safely and idempotently."""
        owned_client = client is None
        cp = client or ControlPlaneClient()
        try:
            task_data = GetTaskTool(cp).execute({"task_id": task_id})
            if not task_data.success:
                raise ControlPlaneError(task_data.error or "task retrieval failed")
            task_payload = task_data.data["task"]
            existing = cp.list_findings(task_id)
            if existing:
                return AgentResult.from_dict({
                    **existing[0], "metadata": {"idempotent_replay": True},
                })
            await_status = UpdateTaskTool(cp).execute({"task_id": task_id, "status": "IN_PROGRESS"})
            if not await_status.success:
                raise ControlPlaneError(await_status.error or "task start failed")

            event_id = task_payload.get("event_id")
            incident_id = task_payload.get("incident_id")
            if not event_id or not incident_id:
                raise ControlPlaneError("Investigation task must reference an event and incident")
            incident_result = GetIncidentTool(cp).execute({"incident_id": incident_id})
            if not incident_result.success:
                raise ControlPlaneError(incident_result.error or "incident retrieval failed")
            event_result = GetEventTool(cp).execute({"event_id": event_id})
            if not event_result.success:
                raise ControlPlaneError(event_result.error or "event retrieval failed")
            event = event_result.data["event"]
            related_ids = incident_result.data["incident"].get("linked_event_ids", [])
            related_result = GetRelatedEventsTool(cp).execute({"event_ids": related_ids})
            if not related_result.success:
                raise ControlPlaneError(related_result.error or "related event retrieval failed")
            local_event = SecurityEvent(
                id=event["event_id"], timestamp=datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")),
                event_type="PORT_SCAN_DETECTED" if event["event_type"] == "PORT_SCAN" else event["event_type"],
                severity=event["severity"], source=event["source_address"], target=event["destination_address"],
                metadata={**event.get("details", {}), "incident_id": incident_id,
                          "related_event_ids": related_ids,
                          "related_event_count": len(related_result.data["events"])},
            )
            local_task = AgentTask.from_dict({**task_payload, "security_event": local_event.to_dict()})
            result = self._investigate_control_plane_event(local_task)
            finding = {"task_id": task_id, "agent_name": self.name, "status": result.status,
                       "confidence": result.confidence, "findings": list(result.findings),
                       "evidence": list(result.evidence), "summary": result.summary,
                       "error": result.error, "finding_metadata": result.metadata}
            submitted = SubmitFindingTool(cp).execute({"finding": finding})
            if not submitted.success:
                raise ControlPlaneError(submitted.error or "finding submission failed")
            UpdateTaskTool(cp).execute({"task_id": task_id, "status": "COMPLETED"})
            return result
        except Exception as exc:  # failure is persisted, never silently swallowed
            try:
                UpdateTaskTool(cp).execute({"task_id": task_id, "status": "FAILED"})
            except Exception:
                logger.exception("Could not mark task %s FAILED", task_id)
            return AgentResult.failure(task_id, self.name, str(exc), {"exception_type": type(exc).__name__})
        finally:
            if owned_client:
                cp.close()

    def _investigate_control_plane_event(self, task: AgentTask) -> AgentResult:
        """Deterministically analyze detector details returned by the Control Plane."""
        event = task.security_event
        if event.event_type != "PORT_SCAN_DETECTED":
            return self.execute(task)
        details = event.metadata
        ports = details.get("targeted_ports") or details.get("ports") or []
        if isinstance(ports, int):
            ports = list(range(1, ports + 1))
        attempts = details.get("connection_attempts", details.get("attempts", len(ports)))
        threshold = details.get("scan_threshold", details.get("threshold", 10))
        count = len(set(ports)) if ports else details.get("unique_destination_ports", attempts)
        evidence = [{"type": "port_scan_analysis", "source_ip": event.source,
                     "destination_ip": event.target, "targeted_ports": list(ports),
                     "unique_port_count": count, "connection_attempts": attempts,
                     "scan_threshold": threshold, "severity": event.severity,
                     "timestamp": event.timestamp.isoformat(),
                     "detector_name": details.get("detector_name", details.get("detector", "PortScanDetector"))}]
        return AgentResult.success(
            task_id=task.task_id, agent_name=self.name,
            findings=[f"PORT_SCAN_ANALYSIS: {event.source} targeted {count} unique ports on {event.target}.",
                      f"Observed {attempts} connection attempts (threshold {threshold})."],
            evidence=evidence, confidence=0.95,
            summary=f"Port scan confirmed from {event.source} to {event.target}.",
            metadata={"finding_type": "PORT_SCAN_ANALYSIS", "recommendation": "Investigate source host and apply response policy."},
        )

    @property
    def name(self) -> str:
        return "investigation_agent"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"investigation", "network_investigation"})

    def execute(self, task: AgentTask) -> AgentResult:
        """Investigate a security event specified in the AgentTask."""
        if not isinstance(task, AgentTask):
            raise TypeError(
                f"InvestigationAgent expects an AgentTask, received {type(task).__name__}"
            )

        event = task.security_event
        logger.info(
            "Agent '%s' beginning investigation task_id='%s' event_type='%s' source='%s' target='%s'",
            self.name, task.task_id, event.event_type, event.source, event.target,
        )

        try:
            if event.event_type == "PORT_SCAN_DETECTED":
                return self._investigate_port_scan(task)

            logger.warning("Event type '%s' not yet handled by %s", event.event_type, self.name)
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name=self.name,
                error_message=f"Event type '{event.event_type}' is not supported by {self.name}",
                error_details={"unsupported_event_type": event.event_type},
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(
                "Unhandled error in agent '%s' on task '%s': %s",
                self.name, task.task_id, exc, exc_info=True,
            )
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name=self.name,
                error_message=f"Investigation execution failed: {exc}",
                error_details={"exception_type": type(exc).__name__, "details": str(exc)},
            )

    def _investigate_port_scan(self, task: AgentTask) -> AgentResult:
        """Execute a port-scan investigation using network telemetry tools."""
        event = task.security_event
        tool_name = "query_network_flows"
        tool = self._tools.get(tool_name)

        if tool is None:
            logger.error("Required tool '%s' not registered with %s", tool_name, self.name)
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name=self.name,
                error_message=f"Required tool '{tool_name}' is not available",
                error_details={"missing_tool": tool_name},
            )

        tool_result: ToolResult = tool.execute({
            "source_ip": event.source,
            "target_ip": event.target,
            "limit": 100,
        })

        if not tool_result.success:
            logger.warning("Tool '%s' returned failure: %s", tool_name, tool_result.error)
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name=self.name,
                error_message=f"Tool execution failed for '{tool_name}': {tool_result.error}",
                error_details={
                    "tool": tool_name,
                    "error": tool_result.error,
                    "metadata": tool_result.metadata,
                },
            )

        flows = tool_result.data.get("flows", [])
        if not flows:
            logger.info("No network flows found between %s and %s", event.source, event.target)
            return AgentResult(
                task_id=task.task_id,
                agent_name=self.name,
                status="INCONCLUSIVE",
                findings=(
                    f"No matching network flows found for source {event.source} "
                    f"targeting {event.target}",
                ),
                evidence=(),
                confidence=0.5,
                summary=(
                    f"Investigation inconclusive: No network flow evidence found between "
                    f"{event.source} and {event.target}."
                ),
                metadata={"queried_flows": 0},
            )

        ports = sorted(set(f["dst_port"] for f in flows if "dst_port" in f))
        total_packets = sum(f.get("packet_count", 0) for f in flows)
        total_bytes   = sum(f.get("byte_count", 0) for f in flows)

        findings = [
            f"Observed {len(flows)} suspicious connection attempts from {event.source} to {event.target}.",
            f"Attacker probed {len(ports)} distinct destination ports: "
            f"{ports[:10]}{'...' if len(ports) > 10 else ''}.",
        ]
        evidence = [
            {"type": "port_distribution", "distinct_port_count": len(ports), "ports": ports},
            {
                "type": "flow_telemetry_aggregate",
                "total_flows": len(flows),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "sample_flow_ids": [f.get("flow_id") for f in flows[:5]],
            },
        ]
        confidence = 0.95 if len(ports) >= 5 else 0.70

        return AgentResult.success(
            task_id=task.task_id,
            agent_name=self.name,
            findings=findings,
            evidence=evidence,
            confidence=confidence,
            summary=(
                f"Port scan confirmed: source {event.source} scanned "
                f"{len(ports)} ports on {event.target}."
            ),
            metadata={
                "tool_used": tool_name,
                "flow_count": len(flows),
                "scanned_ports_count": len(ports),
            },
        )
