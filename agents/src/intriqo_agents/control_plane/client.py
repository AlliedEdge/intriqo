"""Small HTTP client for the agent-facing Control Plane API.

This module deliberately exposes only evidence reads, task status updates, and
finding submission.  It never opens a database connection or executes commands.
"""

from __future__ import annotations

import os
from typing import Any, Mapping

import httpx


class ControlPlaneError(RuntimeError):
    """A Control Plane request failed."""

    def __init__(self, message: str, *, status_code: int | None = None, body: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class ControlPlaneNotFound(ControlPlaneError):
    """A requested task, incident, event, or finding does not exist."""


class ControlPlaneClient:
    """Synchronous, authenticated client used by the deterministic agent runner."""

    def __init__(self, base_url: str | None = None, token: str | None = None,
                 *, timeout: float = 10.0, transport: httpx.BaseTransport | None = None) -> None:
        self.base_url = (base_url or os.environ.get("INTRIQO_CONTROL_PLANE_URL", "http://127.0.0.1:8000")).rstrip("/")
        self.token = token or os.environ.get("INTRIQO_AGENT_TOKEN") or os.environ.get("INTRIQO_CONTROL_PLANE_TOKEN")
        if not self.token:
            raise ValueError("INTRIQO_AGENT_TOKEN is required")
        self._client = httpx.Client(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ControlPlaneClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise ControlPlaneError(f"Control Plane unavailable: {exc}") from exc
        if response.status_code == 404:
            raise ControlPlaneNotFound(f"Control Plane resource not found: {path}", status_code=404, body=response.text)
        if response.status_code >= 400:
            try:
                body: Any = response.json()
            except ValueError:
                body = response.text
            raise ControlPlaneError(
                f"Control Plane HTTP {response.status_code} for {path}",
                status_code=response.status_code,
                body=body,
            )
        return response.json()

    def get_event(self, event_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/events/{event_id}")

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/incidents/{incident_id}")

    def get_task(self, task_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/agent-tasks/{task_id}")

    def get_related_events(self, event_ids: list[str]) -> list[dict[str, Any]]:
        """Read only the event IDs supplied by the assigned incident."""
        return [self.get_event(event_id) for event_id in event_ids]

    def submit_finding(self, finding: Mapping[str, Any]) -> dict[str, Any]:
        """Submit an agent_result_v1-compatible finding through FastAPI."""
        return self._request("POST", "/api/v1/findings", json=dict(finding))

    def list_findings(self, task_id: str) -> list[dict[str, Any]]:
        body = self._request("GET", "/api/v1/findings", params={"task_id": task_id, "page_size": 1})
        return list(body.get("items", []))

    def update_task_status(self, task_id: str, status: str) -> dict[str, Any]:
        return self._request("PATCH", f"/api/v1/agent-tasks/{task_id}", json={"status": status})
