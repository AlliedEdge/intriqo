"""Engine event adapter — translates raw engine JSON into control-plane domain models.

This is the entry point for all SecurityEvents arriving from the C++ IDS engine.
It validates the JSON contract, rejects malformed events, and forwards valid
events to the internal domain boundary.

The adapter is deliberately structurally identical to the agent-side
engine_event_adapter — both consume the same JSON contract defined in
contracts/events/security_event.json.  They are separate modules because:

  - The control plane owns persistence, routing, and API exposure.
  - The agent platform owns investigation reasoning and tool invocation.
  - Neither should depend on the other's internal models.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("intriqo.control_plane.engine_client")


class EngineEventError(ValueError):
    """Raised when an engine SecurityEvent contract cannot be safely parsed."""


def parse_engine_event(payload: str | dict[str, Any]) -> dict[str, Any]:
    """Parse and validate an engine SecurityEvent contract.

    Accepts either a JSON string or a pre-parsed dict.
    Returns a normalised dict ready for domain model construction.

    Raises:
        EngineEventError: on any validation failure.
        TypeError: if payload is neither str nor dict.
    """
    if isinstance(payload, str):
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise EngineEventError(f"Malformed engine event JSON: {exc}") from exc
    elif isinstance(payload, dict):
        data = payload
    else:
        raise TypeError(f"Expected str or dict, got {type(payload).__name__}")

    required = {"event_id", "event_type", "severity", "timestamp",
                "source_address", "destination_address"}
    missing = required - data.keys()
    if missing:
        raise EngineEventError(f"Engine event missing required fields: {sorted(missing)}")

    # Normalise timestamp
    raw_ts = data["timestamp"]
    if not isinstance(raw_ts, str) or not raw_ts.strip():
        raise EngineEventError("Engine event 'timestamp' must be a non-empty ISO 8601 string")
    try:
        ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise EngineEventError(f"Invalid timestamp '{raw_ts}': {exc}") from exc

    return {
        "event_id":            data["event_id"],
        "event_type":          data["event_type"],
        "severity":            data["severity"],
        "timestamp":           ts,
        "source_address":      data["source_address"],
        "destination_address": data["destination_address"],
        "description":         data.get("description", ""),
        "details":             data.get("details", {}),
    }
