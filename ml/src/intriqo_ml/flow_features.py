"""Immutable v1 wire models and bounded, strict JSON parsing.

Measurements are accepted as emitted: this module never recalculates features.
"""

from __future__ import annotations

import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

SCHEMA_VERSION = "flow_features.v1"
MAX_RECORD_BYTES = 8192
MAX_JSON_DEPTH = 16
UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
TIMESTAMP_PATTERN = (
    r"^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{9}Z$"
)
IPV4_OCTET_PATTERN = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])"
IPV4_PATTERN = rf"^{IPV4_OCTET_PATTERN}(\.{IPV4_OCTET_PATTERN}){{3}}$"


def _decimal_uint64_pattern() -> str:
    """Encode the string bound in the schema, rather than only in Python."""
    maximum = str(UINT64_MAX)
    alternatives = [r"[1-9][0-9]{0,18}"]
    for index, digit in enumerate(maximum):
        low = 1 if index == 0 else 0
        high = int(digit) - 1
        if high < low:
            continue
        choice = str(low) if low == high else f"[{low}-{high}]"
        remaining = len(maximum) - index - 1
        tail = f"[0-9]{{{remaining}}}" if remaining else ""
        alternatives.append(maximum[:index] + choice + tail)
    alternatives.append(maximum)
    return "^(" + "|".join(alternatives) + ")$"


FLOW_ID_PATTERN = _decimal_uint64_pattern()


def _calendar_timestamp(value: str) -> str:
    # The string remains authoritative; datetime validates the calendar only.
    datetime.fromisoformat(value[:19])
    return value


def _json_number(value: object) -> int | float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    raise ValueError("expected a JSON number")


UInt64 = Annotated[int, Field(ge=0, le=UINT64_MAX)]
UInt32 = Annotated[int, Field(ge=0, le=UINT32_MAX)]
UInt16 = Annotated[int, Field(ge=0, le=65535)]
NonnegativeFloat64 = Annotated[
    float,
    Field(ge=0, le=sys.float_info.max, allow_inf_nan=False),
    BeforeValidator(_json_number),
]
CanonicalUUID = Annotated[
    str, Field(pattern=UUID_PATTERN, min_length=36, max_length=36)
]
FlowId = Annotated[
    str,
    Field(
        pattern=FLOW_ID_PATTERN, min_length=1, max_length=20,
        json_schema_extra={"not": {"pattern": "[^0-9]"}},
    ),
]
Timestamp = Annotated[
    str,
    Field(
        pattern=TIMESTAMP_PATTERN, min_length=30, max_length=30,
        json_schema_extra={"format": "date-time"},
    ),
    AfterValidator(_calendar_timestamp),
]
IPv4String = Annotated[
    str,
    Field(
        pattern=IPV4_PATTERN, min_length=7, max_length=15,
        json_schema_extra={"format": "ipv4", "not": {"pattern": "[^0-9.]"}},
    ),
]
ExportReason = Literal["idle_expired", "capacity_evicted", "shutdown_flush"]
NetworkProtocol = Literal["TCP", "UDP", "ICMP", "OTHER"]


@dataclass(frozen=True)
class NanosecondTimestamp:
    """A UTC whole second plus nanoseconds, retaining the original wire string.

    ``utc_second`` deliberately contains no fraction. ``as_datetime`` rejects a
    conversion that would silently discard submicrosecond precision.
    """

    canonical: str
    utc_second: datetime
    nanosecond: int

    @classmethod
    def from_canonical(cls, value: str) -> NanosecondTimestamp:
        return cls(
            canonical=value,
            utc_second=datetime.fromisoformat(value[:19]).replace(tzinfo=timezone.utc),
            nanosecond=int(value[20:29]),
        )

    def as_datetime(self) -> datetime:
        if self.nanosecond % 1000:
            raise ValueError("timestamp cannot be represented exactly by datetime")
        return self.utc_second.replace(microsecond=self.nanosecond // 1000)


class _WireModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        extra="forbid",
        frozen=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


class FlowNetwork(_WireModel):
    src_ip: IPv4String
    dst_ip: IPv4String
    src_port: UInt16
    dst_port: UInt16
    protocol: NetworkProtocol

    @property
    def src_address(self) -> IPv4Address:
        return IPv4Address(self.src_ip)

    @property
    def dst_address(self) -> IPv4Address:
        return IPv4Address(self.dst_ip)


class FlowMetadata(_WireModel):
    engine_instance_id: CanonicalUUID
    flow_id: FlowId
    first_seen: Timestamp
    timestamp: Timestamp
    export_reason: ExportReason
    network: FlowNetwork

    @model_validator(mode="after")
    def _chronological(self) -> FlowMetadata:
        if self.timestamp < self.first_seen:
            raise ValueError("last packet timestamp precedes first_seen")
        return self

    @property
    def engine_uuid(self) -> UUID:
        return UUID(self.engine_instance_id)

    @property
    def flow_id_number(self) -> int:
        return int(self.flow_id)

    @property
    def first_seen_time(self) -> NanosecondTimestamp:
        return NanosecondTimestamp.from_canonical(self.first_seen)

    @property
    def timestamp_time(self) -> NanosecondTimestamp:
        return NanosecondTimestamp.from_canonical(self.timestamp)


TCP_COUNT_FIELDS = (
    "syn_count", "fin_count", "rst_count",
    "initial_syn_count", "syn_ack_count", "ack_count",
)


class FlowFeatures(_WireModel):
    packet_count: UInt64
    byte_count: UInt64
    duration_seconds: NonnegativeFloat64
    bytes_per_packet: NonnegativeFloat64
    packets_per_second: NonnegativeFloat64
    bytes_per_second: NonnegativeFloat64
    fwd_packet_count: UInt64
    rev_packet_count: UInt64
    fwd_byte_count: UInt64
    rev_byte_count: UInt64
    syn_count: UInt32
    fin_count: UInt32
    rst_count: UInt32
    initial_syn_count: UInt32
    syn_ack_count: UInt32
    ack_count: UInt32
    tcp_handshake_started: bool
    tcp_syn_ack_seen: bool
    tcp_handshake_completed: bool

    @model_validator(mode="after")
    def _consistent(self) -> FlowFeatures:
        if self.fwd_packet_count + self.rev_packet_count != self.packet_count:
            raise ValueError("directional packet totals disagree")
        if self.fwd_byte_count + self.rev_byte_count != self.byte_count:
            raise ValueError("directional byte totals disagree")
        if (self.fwd_packet_count == 0 and self.fwd_byte_count != 0) or (
            self.rev_packet_count == 0 and self.rev_byte_count != 0
        ):
            raise ValueError("empty direction cannot contain bytes")
        if any(getattr(self, field) > self.packet_count for field in TCP_COUNT_FIELDS):
            raise ValueError("TCP flag count exceeds packet count")
        if self.initial_syn_count + self.syn_ack_count > self.syn_count:
            raise ValueError("TCP SYN subsets exceed SYN count")
        # ACK-only packets cannot also contribute to a SYN count.
        if self.syn_count + self.ack_count > self.packet_count:
            raise ValueError("disjoint TCP flag counts exceed packet count")
        if self.tcp_handshake_started and (
            self.initial_syn_count == 0 or self.fwd_packet_count == 0
        ):
            raise ValueError("handshake start lacks forward initial SYN evidence")
        if self.tcp_syn_ack_seen and (
            not self.tcp_handshake_started
            or self.syn_ack_count == 0
            or self.rev_packet_count == 0
        ):
            raise ValueError("SYN ACK evidence lacks handshake start or reverse packet")
        if self.tcp_handshake_completed and (
            not self.tcp_syn_ack_seen
            or self.ack_count == 0
            or self.fwd_packet_count < 2
        ):
            raise ValueError("handshake completion lacks ordered evidence")
        return self


class FlowFeatureRecord(_WireModel):
    schema_version: Literal["flow_features.v1"]
    metadata: FlowMetadata
    features: FlowFeatures

    @model_validator(mode="after")
    def _protocol_evidence(self) -> FlowFeatureRecord:
        if self.metadata.network.protocol != "TCP" and (
            any(getattr(self.features, field) != 0 for field in TCP_COUNT_FIELDS)
            or self.features.tcp_handshake_started
            or self.features.tcp_syn_ack_seen
            or self.features.tcp_handshake_completed
        ):
            raise ValueError("non-TCP flow contains TCP evidence")
        return self


def flow_feature_json_schema() -> dict[str, object]:
    """Generate the checked-in draft-07 schema from the exact wire models.

    Draft-07 cannot express directional sums, chronology or ordered handshake
    evidence. Its integer type also cannot enforce integer *token* spelling.
    These parser-only rules are explicitly documented in the schema comment.
    """
    schema = FlowFeatureRecord.model_json_schema(ref_template="#/definitions/{model}")
    schema["definitions"] = schema.pop("$defs")
    schema["$schema"] = "http://json-schema.org/draft-07/schema#"
    schema["$id"] = "https://intriqo.dev/contracts/features/flow_features_v1.json"
    schema["description"] = (
        "Immutable flow measurements emitted on retirement; all fields required, "
        "no ML execution or feature recalculation. Generated by "
        "intriqo_ml.flow_features.flow_feature_json_schema."
    )
    schema["$comment"] = (
        "The Python parser additionally enforces: at most 8192 UTF-8 bytes excluding "
        "a single LF/CRLF; at most 16 nested JSON containers; no duplicate keys; no "
        "NaN/Infinity, including numeric overflow; integer fields require integer JSON "
        "tokens (not 1.0); real calendar dates (year 0001..9999, no leap seconds); "
        "timestamp >= first_seen; directional packet/byte sums equal totals; "
        "empty packet direction has zero bytes; each TCP "
        "flag count <= packet_count; initial_syn_count + syn_ack_count <= syn_count; "
        "syn_count + ack_count <= packet_count; started implies forward initial SYN "
        "evidence; syn_ack_seen implies started and reverse SYN ACK evidence; "
        "completed "
        "implies syn_ack_seen, ACK evidence and at least two forward packets; non-TCP "
        "records have zero TCP counts and false handshake booleans. Draft-07 cannot "
        "express these cross-field/token/transport rules. Enable format assertions "
        "for date-time/ipv4 checks; use the Python parser for complete validation. "
        "Timestamp strings preserve all nine fractional digits, and no rates are "
        "recomputed or normalized."
    )
    return schema


ErrorCode = Literal[
    "invalid_input", "record_too_large", "invalid_encoding", "invalid_json",
    "duplicate_key", "nonfinite_number", "nesting_too_deep", "invalid_record",
    "unsupported_schema_version",
]
_ERROR_MESSAGES: dict[ErrorCode, str] = {
    "invalid_input": "record must be JSON text or bytes",
    "record_too_large": "record exceeds 8192 bytes",
    "invalid_encoding": "record is not valid UTF-8",
    "invalid_json": "record is not valid JSON",
    "duplicate_key": "record contains duplicate JSON keys",
    "nonfinite_number": "record contains a nonfinite number",
    "nesting_too_deep": "record exceeds JSON nesting limit",
    "invalid_record": "record violates flow_features.v1 contract",
    "unsupported_schema_version": "unsupported flow feature schema version",
}


class FlowFeatureError(ValueError):
    """Payload-free domain error; callers may log ``code`` and ``str(error)``."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(_ERROR_MESSAGES[code])


class UnsupportedSchemaVersionError(FlowFeatureError):
    def __init__(self) -> None:
        super().__init__("unsupported_schema_version")


def _check_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise FlowFeatureError("nesting_too_deep")
        elif char in "}]":
            depth -= 1


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FlowFeatureError("duplicate_key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise FlowFeatureError("nonfinite_number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise FlowFeatureError("nonfinite_number")
    return number


def parse_flow_feature_record(raw: str | bytes) -> FlowFeatureRecord:
    """Parse one UTF-8 JSON record (at most 8192 bytes, excluding LF/CRLF).

    Duplicate keys, nonfinite numbers and nesting beyond 16 containers are
    rejected before model validation. Errors never contain input values.
    """
    if not isinstance(raw, (str, bytes)):
        raise FlowFeatureError("invalid_input")
    # Bound any UTF-8 allocation first; LF/CRLF can add at most two characters.
    if len(raw) > MAX_RECORD_BYTES + 2:
        raise FlowFeatureError("record_too_large")
    try:
        encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
        # At most one line terminator is excluded from the record size.
        if encoded.endswith(b"\n"):
            encoded = encoded[:-1]
            if encoded.endswith(b"\r"):
                encoded = encoded[:-1]
        if len(encoded) > MAX_RECORD_BYTES:
            raise FlowFeatureError("record_too_large")
        text = encoded.decode("utf-8")
    except UnicodeError:
        raise FlowFeatureError("invalid_encoding") from None
    _check_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except FlowFeatureError:
        raise
    except (ValueError, RecursionError, OverflowError):
        raise FlowFeatureError("invalid_json") from None
    if (
        isinstance(value, dict)
        and isinstance(value.get("schema_version"), str)
        and value["schema_version"] != SCHEMA_VERSION
    ):
        raise UnsupportedSchemaVersionError()
    try:
        return FlowFeatureRecord.model_validate(value)
    except (ValidationError, ValueError, OverflowError):
        raise FlowFeatureError("invalid_record") from None
