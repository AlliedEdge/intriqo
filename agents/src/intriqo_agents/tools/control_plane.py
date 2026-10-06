"""Narrow tools backed by ControlPlaneClient."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from intriqo_agents.control_plane.client import ControlPlaneClient, ControlPlaneError
from intriqo_agents.tools.base import Tool, ToolResult


class _ControlPlaneTool(Tool):
    def __init__(self, client: ControlPlaneClient) -> None:
        self.client = client

    def _safe(
        self,
        operation: str,
        callback: Callable[[str], dict[str, Any]],
        value: str,
    ) -> ToolResult:
        try:
            return ToolResult.ok({operation: callback(value)})
        except ControlPlaneError as exc:
            return ToolResult.fail(str(exc), {"operation": operation, "status_code": exc.status_code})


class GetEventTool(_ControlPlaneTool):
    @property
    def name(self) -> str: return "get_event"
    @property
    def description(self) -> str: return "Read one assigned SecurityEvent from the Control Plane"
    @property
    def input_schema(self) -> dict[str, Any]: return {"type": "object", "required": ["event_id"]}
    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        return self._safe("event", self.client.get_event, input_data["event_id"])


class GetIncidentTool(_ControlPlaneTool):
    @property
    def name(self) -> str: return "get_incident"
    @property
    def description(self) -> str: return "Read one assigned incident from the Control Plane"
    @property
    def input_schema(self) -> dict[str, Any]: return {"type": "object", "required": ["incident_id"]}
    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        return self._safe("incident", self.client.get_incident, input_data["incident_id"])


class GetTaskTool(_ControlPlaneTool):
    @property
    def name(self) -> str: return "get_task"
    @property
    def description(self) -> str: return "Read one assigned AgentTask from the Control Plane"
    @property
    def input_schema(self) -> dict[str, Any]: return {"type": "object", "required": ["task_id"]}
    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        return self._safe("task", self.client.get_task, input_data["task_id"])


class GetRelatedEventsTool(_ControlPlaneTool):
    @property
    def name(self) -> str: return "get_related_events"
    @property
    def description(self) -> str: return "Read event records linked to the assigned incident"
    @property
    def input_schema(self) -> dict[str, Any]: return {"type": "object", "required": ["event_ids"]}
    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        try:
            return ToolResult.ok({"events": self.client.get_related_events(input_data["event_ids"])})
        except ControlPlaneError as exc:
            return ToolResult.fail(str(exc), {"operation": self.name, "status_code": exc.status_code})


class SubmitFindingTool(_ControlPlaneTool):
    @property
    def name(self) -> str: return "submit_finding"
    @property
    def description(self) -> str: return "Submit a structured finding to the Control Plane"
    @property
    def input_schema(self) -> dict[str, Any]: return {"type": "object", "required": ["finding"]}
    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        try:
            return ToolResult.ok({"finding": self.client.submit_finding(input_data["finding"])})
        except ControlPlaneError as exc:
            return ToolResult.fail(str(exc), {"operation": self.name, "status_code": exc.status_code})


class UpdateTaskTool(_ControlPlaneTool):
    @property
    def name(self) -> str: return "update_task"
    @property
    def description(self) -> str: return "Update the assigned task lifecycle status"
    @property
    def input_schema(self) -> dict[str, Any]: return {"type": "object", "required": ["task_id", "status"]}
    def _run(self, input_data: dict[str, Any]) -> ToolResult:
        try:
            return ToolResult.ok({"task": self.client.update_task_status(input_data["task_id"], input_data["status"])})
        except ControlPlaneError as exc:
            return ToolResult.fail(str(exc), {"operation": self.name, "status_code": exc.status_code})
