"""Small, authenticated Control Plane transport for ML anomaly events.

The transport intentionally exposes only payload-free status to callers.  In
particular, request URLs, bearer tokens, response bodies, and exception text
are never included in failure messages or worker statistics.
"""

from __future__ import annotations

import json
import math
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import quote, urlsplit

import httpx


class DeliveryStatus(str, Enum):
    """Outcome of one bounded delivery attempt sequence."""

    DELIVERED = "delivered"
    DUPLICATE = "duplicate"
    FAILED = "failed"


@dataclass(frozen=True)
class TransportConfig:
    """Environment-backed transport settings.

    ``max_attempts`` is deliberately small and defaults to one.  A caller may
    opt into a bounded number of transient-error attempts, but the decision
    ledger still prevents a restart from replaying old ML decisions.
    """

    base_url: str = field(repr=False)
    endpoint: str = field(default="/api/v1/events", repr=False)
    token: str = field(default="", repr=False)
    timeout_seconds: float = 5.0
    max_attempts: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url.strip():
            raise ValueError("control-plane URL is required")
        if not isinstance(self.token, str) or not self.token:
            raise ValueError("control-plane token is required")
        _validate_base_url(self.base_url)
        if (
            not isinstance(self.endpoint, str)
            or not self.endpoint.startswith("/")
            or self.endpoint.startswith("//")
            or "?" in self.endpoint
            or "#" in self.endpoint
        ):
            raise ValueError("control-plane endpoint must be an absolute path")
        if not isinstance(self.max_attempts, int) or isinstance(self.max_attempts, bool):
            raise ValueError(  # noqa: TRY004
                "control-plane maximum attempts must be an integer from 1 to 5"
            )
        if not 1 <= self.max_attempts <= 5:
            raise ValueError("control-plane maximum attempts must be from 1 to 5")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("transport timeout must be a positive finite number")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> TransportConfig:
        env = os.environ if environ is None else environ
        base_url = env.get("INTRIQO_CONTROL_PLANE_URL", "").strip()
        token = env.get("INTRIQO_CONTROL_PLANE_TOKEN", "")
        endpoint = env.get("INTRIQO_CONTROL_PLANE_ENDPOINT", "/api/v1/events").strip()
        if not base_url:
            raise ValueError("control-plane URL is required")
        if not token:
            raise ValueError("control-plane token is required")
        timeout_seconds = _positive_float(env.get("INTRIQO_ML_TRANSPORT_TIMEOUT_SECONDS", "5"))
        max_attempts = _positive_int(env.get("INTRIQO_ML_TRANSPORT_MAX_ATTEMPTS", "1"))
        return cls(base_url, endpoint, token, timeout_seconds, max_attempts)

    @property
    def url(self) -> str:
        return self.base_url.rstrip("/") + "/" + self.endpoint.lstrip("/")


@dataclass(frozen=True)
class DeliveryResult:
    """Payload-free result returned by :meth:`ControlPlaneTransport.send`."""

    status: DeliveryStatus
    event_id: str
    http_status: int | None = None
    failure_code: str | None = None


def _validate_base_url(value: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("control-plane URL must use HTTP or HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("control-plane URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("control-plane URL must not contain a query or fragment")


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        raise ValueError("transport timeout must be a positive finite number") from None
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError("transport timeout must be a positive finite number")
    return parsed


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError("transport maximum attempts must be a positive integer") from None
    if parsed <= 0:
        raise ValueError("transport maximum attempts must be a positive integer")
    return parsed


MAX_RESPONSE_BYTES = 64 * 1024


@dataclass(frozen=True)
class _ResponseSnapshot:
    status_code: int
    is_redirect: bool
    has_history: bool
    body: bytes | None


def _response_snapshot(response: httpx.Response) -> _ResponseSnapshot:
    body = bytearray()
    try:
        for chunk in response.iter_bytes(chunk_size=8192):
            remaining = MAX_RESPONSE_BYTES - len(body)
            if len(chunk) > remaining:
                return _ResponseSnapshot(
                    response.status_code, response.is_redirect, bool(response.history), None
                )
            body.extend(chunk)
    except httpx.HTTPError:
        return _ResponseSnapshot(response.status_code, response.is_redirect, bool(response.history), None)
    return _ResponseSnapshot(
        response.status_code, response.is_redirect, bool(response.history), bytes(body)
    )


def _json_object(body: bytes | None) -> dict[str, Any] | None:
    if body is None:
        return None
    try:
        value = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


class ControlPlaneTransport:
    """Authenticated, no-redirect HTTP sender for one event payload."""

    _RETRYABLE = frozenset({408, 425, 429}) | frozenset(range(500, 600))

    def __init__(self, config: TransportConfig, client: httpx.Client | None = None) -> None:
        self.config = config
        self._owns_client = client is None
        self._headers = {"Authorization": f"Bearer {config.token}"}
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(config.timeout_seconds),
            follow_redirects=False,
            headers=self._headers,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> ControlPlaneTransport:  # noqa: PYI034
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def send(self, payload: Mapping[str, Any]) -> DeliveryResult:
        """POST one payload and verify the response before acknowledging it.

        A 409 is success only when its error code is exactly
        ``DUPLICATE_EVENT`` and an authenticated GET verifies the same event
        ID and details.  Every other status, including an arbitrary 409, is a
        failure.
        """

        event_id = payload.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            return DeliveryResult(DeliveryStatus.FAILED, "", failure_code="invalid_event_id")
        for attempt in range(self.config.max_attempts):
            try:
                with self._client.stream(
                    "POST",
                    self.config.url,
                    json=dict(payload),
                    headers=self._headers,
                    timeout=self.config.timeout_seconds,
                    follow_redirects=False,
                ) as response:
                    snapshot = _response_snapshot(response)
            except httpx.RequestError:
                if attempt + 1 < self.config.max_attempts:
                    continue
                return DeliveryResult(DeliveryStatus.FAILED, event_id, failure_code="request_error")
            if snapshot.body is None:
                return DeliveryResult(
                    DeliveryStatus.FAILED,
                    event_id,
                    snapshot.status_code,
                    "response_too_large_or_unreadable",
                )
            if snapshot.status_code == 201:
                if self._matches(snapshot.body, payload):
                    return DeliveryResult(DeliveryStatus.DELIVERED, event_id, 201)
                return DeliveryResult(
                    DeliveryStatus.FAILED, event_id, 201, "response_mismatch"
                )
            if snapshot.status_code == 409:
                return self._verify_duplicate(snapshot, payload)
            if snapshot.is_redirect or snapshot.has_history:
                return DeliveryResult(DeliveryStatus.FAILED, event_id, snapshot.status_code, "redirect")
            if snapshot.status_code in self._RETRYABLE and attempt + 1 < self.config.max_attempts:
                continue
            return DeliveryResult(
                DeliveryStatus.FAILED,
                event_id,
                snapshot.status_code,
                "http_error",
            )
        # The loop always returns; retaining a defensive result keeps static
        # analysers and future changes from widening the API.
        return DeliveryResult(DeliveryStatus.FAILED, event_id, failure_code="attempt_limit")

    def _verify_duplicate(
        self, response: _ResponseSnapshot, payload: Mapping[str, Any]
    ) -> DeliveryResult:
        event_id = str(payload["event_id"])
        body = _json_object(response.body)
        error = body.get("error") if body is not None else None
        code = error.get("code") if isinstance(error, dict) else None
        if code != "DUPLICATE_EVENT":
            return DeliveryResult(DeliveryStatus.FAILED, event_id, 409, "http_error")
        try:
            with self._client.stream(
                "GET",
                f"{self.config.url.rstrip('/')}/{quote(event_id, safe='')}",
                headers=self._headers,
                timeout=self.config.timeout_seconds,
                follow_redirects=False,
            ) as verified_response:
                verified = _response_snapshot(verified_response)
        except httpx.RequestError:
            return DeliveryResult(DeliveryStatus.FAILED, event_id, 409, "duplicate_verify_error")
        if (
            verified.body is None
            or verified.status_code != 200
            or verified.is_redirect
            or verified.has_history
            or not self._matches(verified.body, payload)
        ):
            return DeliveryResult(
                DeliveryStatus.FAILED,
                event_id,
                verified.status_code,
                "duplicate_verify_failed",
            )
        return DeliveryResult(DeliveryStatus.DUPLICATE, event_id, 409)

    @staticmethod
    def _matches(body_bytes: bytes | None, payload: Mapping[str, Any]) -> bool:
        body = _json_object(body_bytes)
        if body is None:
            return False
        for field_name in (
            "event_id",
            "event_type",
            "severity",
            "source_address",
            "destination_address",
            "details",
        ):
            if body.get(field_name) != payload.get(field_name):
                return False
        observed_timestamp = body.get("timestamp")
        expected_timestamp = payload.get("timestamp")
        if not isinstance(observed_timestamp, str) or not isinstance(expected_timestamp, str):
            return False
        try:
            observed = _parse_timestamp(observed_timestamp)
            expected = _parse_timestamp(expected_timestamp)
        except ValueError:
            return False
        return observed == expected


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed


__all__ = [
    "ControlPlaneTransport",
    "DeliveryResult",
    "DeliveryStatus",
    "TransportConfig",
]
