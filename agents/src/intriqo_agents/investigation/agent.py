"""Investigation agent — specialized for incident investigation and evidence collection."""

from __future__ import annotations

import logging
import math
import os
import threading
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from intriqo_agents.contracts.security_event import SecurityEvent
from intriqo_agents.control_plane.client import ControlPlaneClient, ControlPlaneError
from intriqo_agents.core.agent import Agent
from intriqo_agents.state.result import AgentResult
from intriqo_agents.state.task import AgentTask
from intriqo_agents.tools.base import Tool, ToolResult
from intriqo_agents.tools.control_plane import (
    GetEventTool,
    GetIncidentTool,
    GetRelatedEventsTool,
    GetTaskTool,
    SubmitFindingTool,
    UpdateTaskTool,
)
from intriqo_agents.tools.mock_tools import (
    HistoricalAlertsQueryTool,
    HostActivityQueryTool,
    NetworkFlowQueryTool,
)

logger = logging.getLogger("intriqo.agents.investigation")


DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 5.0


class _LeaseHeartbeat:
    """Bounded lease-renewal worker for one remote task execution."""

    def __init__(
        self,
        client: ControlPlaneClient,
        task_id: str,
        claim_token: str,
        interval_seconds: float,
    ) -> None:
        self._client = client
        self._task_id = task_id
        self._claim_token = claim_token
        self._interval_seconds = max(interval_seconds, 0.01)
        self._stop = threading.Event()
        self._unsafe = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"intriqo-lease-{task_id}",
            daemon=True,
        )

    @property
    def unsafe(self) -> bool:
        return self._unsafe.is_set()

    def start(self) -> None:
        self._thread.start()

    def stop_and_join(self) -> None:
        self._stop.set()
        self._thread.join()

    def _run(self) -> None:
        while not self._stop.wait(self._interval_seconds):
            try:
                renew = getattr(self._client, "renew_task_lease", None)
                if not callable(renew):
                    renew = getattr(self._client, "renew_task", None)
                if not callable(renew):
                    raise RuntimeError("Control Plane client has no lease renewal method")
                renewal = renew(self._task_id, self._claim_token)
                if not isinstance(renewal, Mapping):
                    raise RuntimeError("Control Plane returned a malformed lease renewal")
                returned_token = renewal.get("claim_token")
                if returned_token != self._claim_token:
                    raise RuntimeError("Control Plane did not return the current lease token")
                if renewal.get("status") != "IN_PROGRESS":
                    raise RuntimeError("Control Plane did not keep the task in progress")
            except Exception as exc:  # noqa: BLE001 - ownership loss is fail-closed
                self._unsafe.set()
                # Never include request headers or token-bearing exception data
                # in logs.  The task ID is safe operational context.
                logger.error(
                    "Lease renewal failed for task_id='%s' (%s)",
                    self._task_id,
                    type(exc).__name__,
                )
                return


class _LeaseOwnershipLost(RuntimeError):
    """The worker can no longer prove ownership of the persisted task."""

    def __init__(self) -> None:
        super().__init__("Task lease renewal failed; execution is unsafe")


class InvestigationAgent(Agent):
    """Specialized cybersecurity agent focused on incident investigation and evidence collection.

    Investigation flow
    ──────────────────
    SecurityEvent → AgentTask → route by event_type → tool invocations → AgentResult

    All tool calls go through the Tool abstraction.  No direct database access,
    no shell execution, no unrestricted network calls.
    """

    def __init__(
        self,
        tools: Sequence[Tool] | Mapping[str, Tool] | None = None,
        *,
        heartbeat_interval: float | None = None,
    ) -> None:
        self._heartbeat_interval = heartbeat_interval
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

    def execute_task(
        self,
        task_id: str,
        client: ControlPlaneClient | None = None,
        claim_token: str | None = None,
        heartbeat_interval: float | None = None,
    ) -> AgentResult:
        """Run one claimed persisted task through the Control Plane.

        A claim token is mandatory even when a caller supplies a client.  This
        keeps direct persisted-task execution on the same lease-enforced path
        as the poller and one-shot runner.
        """
        if not isinstance(claim_token, str) or not claim_token.strip():
            return AgentResult.failure(
                task_id,
                self.name,
                "A valid claim token is required for persisted task execution",
            )

        owned_client = client is None
        cp = client or ControlPlaneClient()
        heartbeat: _LeaseHeartbeat | None = None
        lease_unsafe = False
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

            interval = self._resolve_heartbeat_interval(task_payload, heartbeat_interval)
            heartbeat = _LeaseHeartbeat(cp, task_id, claim_token, interval)
            heartbeat.start()

            await_status = UpdateTaskTool(cp, claim_token).execute(
                {"task_id": task_id, "status": "IN_PROGRESS"}
            )
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
            if heartbeat.unsafe:
                raise _LeaseOwnershipLost()
            # The heartbeat protects the long-running investigation.  Stop it
            # before the terminal write so a renewal racing with completion
            # cannot turn a finished task into an unsafe replay.
            heartbeat.stop_and_join()
            if heartbeat.unsafe:
                raise _LeaseOwnershipLost()
            finding = {"task_id": task_id, "agent_name": self.name, "status": result.status,
                       "confidence": result.confidence, "findings": list(result.findings),
                       "evidence": list(result.evidence), "summary": result.summary,
                       "error": result.error, "finding_metadata": result.metadata,
                       "event_id": event["event_id"], "incident_id": incident_id,
                       "severity": event["severity"],
                       "source": "ML" if event["event_type"] == "ML_ANOMALY" else "DETERMINISTIC",
                       "provenance": {
                           "event_type": event["event_type"],
                           "detection_source": (
                               event.get("details", {}).get("detection_source")
                               or ("ML" if event["event_type"] == "ML_ANOMALY" else "DETERMINISTIC")
                           ),
                           "detector": event.get("details", {}).get("detector"),
                       }}
            submitted = SubmitFindingTool(cp, claim_token).execute({"finding": finding})
            if not submitted.success:
                raise ControlPlaneError(submitted.error or "finding submission failed")
            # The Control Plane finalizes the task transactionally with finding
            # submission.  No second completion write can be made safely after
            # that endpoint clears the claim token.
            return result
        except _LeaseOwnershipLost as exc:
            return AgentResult.failure(
                task_id,
                self.name,
                str(exc),
                metadata={"lease_unsafe": True},
            )
        except Exception as exc:  # noqa: BLE001 - failure is persisted, never silently swallowed
            lease_unsafe = heartbeat.unsafe if heartbeat is not None else False
            try:
                if not lease_unsafe:
                    UpdateTaskTool(cp, claim_token).execute(
                        {"task_id": task_id, "status": "FAILED"}
                    )
            except Exception:
                logger.exception("Could not mark task %s FAILED", task_id)
            details: dict[str, Any] = {"exception_type": type(exc).__name__}
            metadata: dict[str, Any] = {}
            if lease_unsafe:
                metadata["lease_unsafe"] = True
            return AgentResult.failure(
                task_id,
                self.name,
                str(exc),
                details,
                metadata=metadata,
            )
        finally:
            if heartbeat is not None:
                heartbeat.stop_and_join()
            if owned_client:
                cp.close()

    def _resolve_heartbeat_interval(
        self,
        task_payload: Mapping[str, Any],
        requested_interval: float | None,
    ) -> float:
        configured = requested_interval
        if configured is None:
            configured = self._heartbeat_interval
        if configured is None:
            raw_configured = os.environ.get("INTRIQO_AGENT_HEARTBEAT_SECONDS")
            if raw_configured:
                try:
                    configured = float(raw_configured)
                except ValueError:
                    configured = None
        remaining: float | None = None
        raw_expiry = task_payload.get("claim_expires_at")
        if isinstance(raw_expiry, str):
            try:
                expiry = datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
            except ValueError:
                remaining = None
        if configured is not None and math.isfinite(configured) and configured > 0:
            if remaining is not None and remaining > 0:
                return max(min(configured, remaining / 3.0), 0.01)
            return configured
        if remaining is not None and remaining > 0:
            return max(min(remaining / 3.0, DEFAULT_HEARTBEAT_INTERVAL_SECONDS), 0.01)
        return DEFAULT_HEARTBEAT_INTERVAL_SECONDS

    def _investigate_control_plane_event(self, task: AgentTask) -> AgentResult:
        """Deterministically analyze detector details returned by the Control Plane."""
        event = task.security_event
        if event.event_type in {"PORT_SCAN", "PORT_SCAN_DETECTED", "UDP_SCAN"}:
            return self._investigate_port_scan_details(task)
        if event.event_type == "SYN_FLOOD":
            return self._investigate_syn_flood(task)
        if event.event_type == "ML_ANOMALY":
            return self._investigate_ml_anomaly(task)
        return self.execute(task)

    def _investigate_port_scan_details(self, task: AgentTask) -> AgentResult:
        """Build port-scan evidence directly from the persisted event receipt."""
        event = task.security_event
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

    def _investigate_syn_flood(self, task: AgentTask) -> AgentResult:
        """Build bounded SYN-flood evidence from detector metadata only."""
        event = task.security_event
        details = event.metadata
        destination_port = details.get("destination_port")
        attempts = details.get("initial_syn_attempts", details.get("connection_attempts", 0))
        incomplete = details.get("incomplete_handshakes", 0)
        rate = details.get("rate_per_second", details.get("observed_rate", 0.0))
        ratio = details.get("incomplete_ratio")
        evidence = [{
            "type": "syn_flood_analysis",
            "source_ip": event.source,
            "destination_ip": event.target,
            "destination_port": destination_port,
            "syn_count": attempts,
            "incomplete_handshake_count": incomplete,
            "observed_rate_per_second": rate,
            "incomplete_ratio": ratio,
            "window_seconds": details.get("window_seconds"),
            "detector_name": details.get("detector", "syn_flood"),
            "severity": event.severity,
            "timestamp": event.timestamp.isoformat(),
        }]
        return AgentResult.success(
            task_id=task.task_id,
            agent_name=self.name,
            findings=[
                f"SYN flood indicators observed from {event.source} to {event.target}.",
                f"Observed {incomplete} incomplete handshakes over {destination_port or 'the reported'} destination port.",
            ],
            evidence=evidence,
            confidence=0.95,
            summary=f"SYN flood indicators confirmed from {event.source} to {event.target}.",
            metadata={"finding_type": "SYN_FLOOD_ANALYSIS"},
        )

    def _investigate_ml_anomaly(self, task: AgentTask) -> AgentResult:
        """Preserve the ML detector receipt as structured, payload-free evidence."""
        event = task.security_event
        details = event.metadata
        raw_result = details.get("result")
        result = raw_result if isinstance(raw_result, dict) else details
        allowed = (
            "flow_id", "anomaly_score", "threshold", "model_version", "model_sha256",
            "threshold_sha256", "feature_schema_version", "detector", "engine_instance_id",
        )
        evidence = [{
            "type": "ml_anomaly_analysis",
            "event_type": "ML_ANOMALY",
            **{key: result[key] for key in allowed if key in result},
            "detection_source": "ML",
            "severity": event.severity,
            "source_ip": event.source,
            "destination_ip": event.target,
            "timestamp": event.timestamp.isoformat(),
        }]
        score = result.get("anomaly_score")
        threshold = result.get("threshold")
        return AgentResult.success(
            task_id=task.task_id,
            agent_name=self.name,
            findings=[f"ML anomaly receipt reviewed for flow {result.get('flow_id', 'unknown')} with score {score!r} against threshold {threshold!r}."],
            evidence=evidence,
            confidence=0.75,
            summary="ML anomaly receipt reviewed without changing the locked detector decision.",
            metadata={"finding_type": "ML_ANOMALY_REVIEW", "experimental": True},
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
            if event.event_type in {"PORT_SCAN", "PORT_SCAN_DETECTED", "UDP_SCAN"}:
                return self._investigate_port_scan(task)
            if event.event_type == "SYN_FLOOD":
                return self._investigate_syn_flood(task)
            if event.event_type == "ML_ANOMALY":
                return self._investigate_ml_anomaly(task)

            logger.warning("Event type '%s' not yet handled by %s", event.event_type, self.name)
            return AgentResult.failure(
                task_id=task.task_id,
                agent_name=self.name,
                error_message=f"Event type '{event.event_type}' is not supported by {self.name}",
                error_details={"unsupported_event_type": event.event_type},
            )
        except Exception as exc:
            logger.exception(
                "Unhandled error in agent '%s' on task '%s'",
                self.name, task.task_id,
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
                    (
                        f"No matching network flows found for source {event.source} "
                        f"targeting {event.target}"
                    ),
                ),
                evidence=(),
                confidence=0.5,
                summary=(
                    f"Investigation inconclusive: No network flow evidence found between "
                    f"{event.source} and {event.target}."
                ),
                metadata={"queried_flows": 0},
            )

        ports = sorted({f["dst_port"] for f in flows if "dst_port" in f})
        total_packets = sum(f.get("packet_count", 0) for f in flows)
        total_bytes   = sum(f.get("byte_count", 0) for f in flows)

        findings = [
            f"Observed {len(flows)} suspicious connection attempts from {event.source} to {event.target}.",
            (
                f"Attacker probed {len(ports)} distinct destination ports: "
                f"{ports[:10]}{'...' if len(ports) > 10 else ''}."
            ),
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
