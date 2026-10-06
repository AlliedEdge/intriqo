"""Focused HTTP status, authentication, and duplicate verification checks."""

from __future__ import annotations

import json
import math

import httpx
import pytest
from intriqo_ml.ml_transport import (
    ControlPlaneTransport,
    DeliveryStatus,
    TransportConfig,
)


def _payload() -> dict[str, object]:
    return {
        "event_id": "event-1",
        "event_type": "ML_ANOMALY",
        "severity": "MEDIUM",
        "timestamp": "2026-01-01T00:00:00Z",
        "source_address": "192.0.2.1",
        "destination_address": "198.51.100.2",
        "details": {"detector": "isolation_forest_v2", "detection_source": "ML", "result": {}},
    }


def _config(attempts: int = 1) -> TransportConfig:
    return TransportConfig("https://control.example", "/api/v1/events", "secret", 1.0, attempts)


def test_201_requires_matching_event_id_and_details_and_sends_bearer() -> None:
    payload = _payload()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with ControlPlaneTransport(_config(), client) as transport:
        result = transport.send(payload)
    assert result.status is DeliveryStatus.DELIVERED
    assert seen[0].headers["authorization"] == "Bearer secret"
    assert json.loads(seen[0].content) == payload


def test_409_is_success_only_after_authenticated_matching_get() -> None:
    payload = _payload()
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "POST":
            return httpx.Response(409, json={"error": {"code": "DUPLICATE_EVENT"}})
        return httpx.Response(200, json=payload)

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    with ControlPlaneTransport(_config(), client) as transport:
        result = transport.send(payload)
    assert result.status is DeliveryStatus.DUPLICATE
    assert calls == ["POST", "GET"]


def test_arbitrary_409_and_mismatched_201_fail() -> None:
    payload = _payload()

    def wrong_409(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": {"error": {"code": "OTHER"}}})

    with ControlPlaneTransport(
        _config(), httpx.Client(transport=httpx.MockTransport(wrong_409))
    ) as transport:
        assert transport.send(payload).status is DeliveryStatus.FAILED

    def wrong_201(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={**payload, "event_id": "different"})

    with ControlPlaneTransport(
        _config(), httpx.Client(transport=httpx.MockTransport(wrong_201))
    ) as transport:
        assert transport.send(payload).failure_code == "response_mismatch"


def test_request_error_has_bounded_attempts_without_payload_status() -> None:
    calls = 0

    def failing(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("secret URL should not be reported", request=_request)

    with ControlPlaneTransport(
        _config(2), httpx.Client(transport=httpx.MockTransport(failing))
    ) as transport:
        result = transport.send(_payload())
    assert result.status is DeliveryStatus.FAILED
    assert result.failure_code == "request_error"
    assert calls == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_url": "https://user:pass@control.example"},
        {"base_url": "https://control.example", "timeout_seconds": math.nan},
        {"base_url": "https://control.example", "timeout_seconds": math.inf},
        {"base_url": "https://control.example", "max_attempts": 0},
        {"base_url": "https://control.example", "max_attempts": 6},
        {"base_url": "https://control.example", "endpoint": "events"},
    ],
)
def test_direct_transport_config_is_finite_bounded_and_secret_safe(
    kwargs: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "base_url": "https://control.example",
        "endpoint": "/api/v1/events",
        "token": "secret",
        "timeout_seconds": 1.0,
        "max_attempts": 1,
    }
    values.update(kwargs)
    with pytest.raises(ValueError):
        TransportConfig(**values)  # type: ignore[arg-type]
    rendered = repr(TransportConfig("https://private.example", token="secret"))
    assert "private.example" not in rendered
    assert "secret" not in rendered


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failures_are_not_acknowledged(status: int) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda _request: httpx.Response(status)),
        follow_redirects=True,
    )
    with ControlPlaneTransport(_config(), client) as transport:
        result = transport.send(_payload())
    assert result.status is DeliveryStatus.FAILED
    assert result.http_status == status


def test_server_error_retries_only_within_configured_bound() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500, content=b"backend details must not leak")

    with ControlPlaneTransport(
        _config(2), httpx.Client(transport=httpx.MockTransport(handler))
    ) as transport:
        result = transport.send(_payload())
    assert result.status is DeliveryStatus.FAILED
    assert result.http_status == 500
    assert calls == 2


def test_redirect_is_not_followed_and_timeout_is_set_per_request() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(307, headers={"location": "https://elsewhere.example/events"})

    client = httpx.Client(
        transport=httpx.MockTransport(handler),
        follow_redirects=True,
        timeout=None,
    )
    with ControlPlaneTransport(_config(), client) as transport:
        result = transport.send(_payload())
    assert result.failure_code == "redirect"
    assert len(seen) == 1
    assert seen[0].extensions["timeout"]["connect"] == 1.0


def test_large_response_body_is_bounded() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, content=b"x" * (64 * 1024 + 1))

    with ControlPlaneTransport(
        _config(), httpx.Client(transport=httpx.MockTransport(handler))
    ) as transport:
        result = transport.send(_payload())
    assert result.failure_code == "response_too_large_or_unreadable"


def test_201_must_match_all_relevant_event_fields() -> None:
    payload = _payload()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201,
            json={**payload, "event_type": "OTHER", "timestamp": "2026-01-01T00:00:00+00:00"},
        )

    with ControlPlaneTransport(
        _config(), httpx.Client(transport=httpx.MockTransport(handler))
    ) as transport:
        result = transport.send(payload)
    assert result.failure_code == "response_mismatch"
