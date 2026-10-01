"""Adapter translating the IDS engine SecurityEvent JSON contract into the Python SecurityEvent model.

This module is the explicit engine → agent integration boundary.

History
───────
This adapter was originally written to consume events from the Java-based
detection engine.  It has been renamed and updated to serve as the generic
engine event adapter for the C++ IDS engine (and any future engine that
produces the same JSON contract).  All logic and validation are preserved;
only Java-specific names in comments and identifiers have been updated.

Responsibilities
────────────────
1. Accept the engine SecurityEvent JSON contract (as a string or dict).
2. Validate all required fields and their types.
3. Map engine field names to Python agent field names.
4. Map engine event type literals to Python agent event type literals.
5. Convert ISO 8601 timestamp strings to timezone-aware datetime objects.
6. Reject malformed or incomplete events with clear, actionable error messages.
7. Return a fully-validated Python SecurityEvent.

Field Mapping Table
───────────────────
Engine contract field   Python SecurityEvent field  Notes
─────────────────────   ──────────────────────────  ──────────────────────
event_id                id                          UUID string, required, non-empty
event_type              event_type                  via EVENT_TYPE_MAP translation
severity                severity                    validated against VALID_SEVERITIES
timestamp               timestamp                   ISO 8601 → timezone-aware datetime
source_address          source                      required, non-empty
destination_address     target                      required, non-empty
description             metadata["description"]     not a top-level Python field
details                 metadata                    merged with description entry

Event Type Mapping
──────────────────
Engine event_type   Python event_type
─────────────────   ─────────────────
PORT_SCAN           PORT_SCAN_DETECTED

Architectural constraints
─────────────────────────
- This adapter does NOT modify SecurityEvent, AgentOrchestrator, or any agent.
- This adapter does NOT give agents direct access to engine internals or memory.
- This adapter does NOT execute shell commands.
- All validation errors surface as EngineEventAdapterError or TypeError.
- Invalid events are REJECTED — never silently converted to dangerous defaults.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from intriqo_agents.contracts.security_event import SecurityEvent, VALID_SEVERITIES


logger = logging.getLogger("intriqo.agents.tools.engine_event_adapter")

# ── Event type mapping: engine literal → Python agent literal ──────────────
# When the engine adds a new detector, add its event type mapping here.
EVENT_TYPE_MAP: dict[str, str] = {
    "PORT_SCAN": "PORT_SCAN_DETECTED",
}

_REQUIRED_FIELDS: frozenset[str] = frozenset({
    "event_id",
    "event_type",
    "severity",
    "timestamp",
    "source_address",
    "destination_address",
})


class EngineEventAdapterError(ValueError):
    """Raised when the engine SecurityEvent contract cannot be safely adapted.

    Subclass of ValueError so callers can catch it with a broad ``except ValueError``
    if they choose not to import this class directly.
    """


def adapt_from_json(json_str: str) -> SecurityEvent:
    """Parse an engine SecurityEvent contract JSON string and return a Python SecurityEvent.

    :param json_str: JSON string conforming to the engine SecurityEvent contract.
    :returns: Validated Python :class:`~intriqo_agents.contracts.security_event.SecurityEvent`.
    :raises EngineEventAdapterError: If the JSON is malformed or fails validation.
    :raises TypeError: If ``json_str`` is not a string.
    """
    if not isinstance(json_str, str):
        raise TypeError(f"adapt_from_json expects a str, got {type(json_str).__name__}")
    if not json_str.strip():
        raise EngineEventAdapterError("Cannot adapt empty or blank JSON string")
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise EngineEventAdapterError(
            f"Engine SecurityEvent contract JSON is malformed: {exc}"
        ) from exc
    return adapt_from_dict(data)


def adapt_from_dict(data: dict[str, Any]) -> SecurityEvent:
    """Adapt a parsed engine SecurityEvent contract dictionary into a Python SecurityEvent.

    :param data: Dictionary parsed from the engine SecurityEvent contract JSON.
    :returns: Validated Python :class:`~intriqo_agents.contracts.security_event.SecurityEvent`.
    :raises EngineEventAdapterError: On validation failure.
    :raises TypeError: If ``data`` is not a dict.
    """
    if not isinstance(data, dict):
        raise TypeError(f"adapt_from_dict expects a dict, got {type(data).__name__}")

    missing = _REQUIRED_FIELDS - data.keys()
    if missing:
        raise EngineEventAdapterError(
            f"Engine SecurityEvent contract is missing required field(s): {sorted(missing)}"
        )

    event_id   = _require_non_empty_string(data, "event_id")
    event_type = _map_event_type(_require_non_empty_string(data, "event_type"))
    severity   = _validate_severity(_require_non_empty_string(data, "severity"))
    timestamp  = _parse_timestamp(data["timestamp"])
    source     = _require_non_empty_string(data, "source_address")
    target     = _require_non_empty_string(data, "destination_address")

    description: str | None = data.get("description")
    if description is not None and not isinstance(description, str):
        raise EngineEventAdapterError(
            f"'description' must be a string or absent, got {type(description).__name__}"
        )

    raw_details = data.get("details", {})
    if not isinstance(raw_details, dict):
        raise EngineEventAdapterError(
            f"'details' must be a dict or absent, got {type(raw_details).__name__}"
        )
    metadata = _sanitize_metadata(raw_details)
    if description:
        metadata["description"] = description

    logger.debug(
        "Adapted engine SecurityEvent: event_id=%s event_type=%s source=%s target=%s",
        event_id, event_type, source, target,
    )

    return SecurityEvent(
        id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        severity=severity,
        source=source,
        target=target,
        metadata=metadata,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _require_non_empty_string(data: dict[str, Any], field: str) -> str:
    value = data[field]
    if value is None:
        raise EngineEventAdapterError(
            f"Required field '{field}' is null — cannot adapt SecurityEvent safely"
        )
    if not isinstance(value, str):
        raise EngineEventAdapterError(
            f"Field '{field}' must be a string, got {type(value).__name__} (value: {value!r})"
        )
    if not value.strip():
        raise EngineEventAdapterError(f"Required field '{field}' is empty or blank")
    return value


def _map_event_type(engine_event_type: str) -> str:
    """Translate an engine event type literal to a Python agent event type literal.

    Unknown types are passed through with a warning — forward-compatible ingestion.
    """
    if engine_event_type in EVENT_TYPE_MAP:
        return EVENT_TYPE_MAP[engine_event_type]
    logger.warning(
        "No event_type mapping for engine event type '%s'. "
        "Passing through unchanged. Add an entry to EVENT_TYPE_MAP.",
        engine_event_type,
    )
    return engine_event_type


def _validate_severity(raw: str) -> str:
    if raw not in VALID_SEVERITIES:
        raise EngineEventAdapterError(
            f"Invalid severity '{raw}'. Must be one of {sorted(VALID_SEVERITIES)}"
        )
    return raw


def _parse_timestamp(raw: Any) -> datetime:
    if raw is None:
        raise EngineEventAdapterError("Required field 'timestamp' is null")
    if not isinstance(raw, str):
        raise EngineEventAdapterError(
            f"Field 'timestamp' must be an ISO 8601 string, got {type(raw).__name__} (value: {raw!r})"
        )
    if not raw.strip():
        raise EngineEventAdapterError("Field 'timestamp' is empty or blank")
    normalized = raw.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EngineEventAdapterError(
            f"Field 'timestamp' is not a valid ISO 8601 datetime: {raw!r} — {exc}"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _sanitize_metadata(raw: dict[str, Any]) -> dict[str, Any]:
    """Produce a clean metadata dict; coerce unexpected value types to str."""
    clean: dict[str, Any] = {}
    for k, v in raw.items():
        if not isinstance(k, str):
            logger.warning("Skipping non-string metadata key: %r", k)
            continue
        if isinstance(v, (str, int, float, bool, type(None), list, dict)):
            clean[k] = v
        else:
            logger.warning(
                "Metadata value for key '%s' has unexpected type %s; coercing to str",
                k, type(v).__name__,
            )
            clean[k] = str(v)
    return clean
