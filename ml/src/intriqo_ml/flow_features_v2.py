"""Explicit native v2 contract; the frozen v1 parser remains v1-only."""

from __future__ import annotations

import json
import math
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Annotated, BinaryIO, Literal

from pydantic import Field, ValidationError, model_validator

from .flow_features import (
    MAX_RECORD_BYTES,
    FlowFeatureError,
    FlowFeatureRecord,
    FlowFeatures,
    FlowMetadata,
    NonnegativeFloat64,
    UInt64,
    UnsupportedSchemaVersionError,
    _check_depth,
    _finite_float,
    _reject_constant,
    _unique_object,
    _WireModel,
)

SCHEMA_VERSION_V2 = "flow_features.v2"
IAT_POLICY = "capture_order_nondecreasing_population.v1"
FEATURES_V2 = (
    "duration_seconds", "packet_count", "packets_per_second",
    "minor_direction_packet_fraction", "mean_ipv4_packet_bytes",
    "ipv4_direction_byte_imbalance", "syn_packet_fraction", "fin_packet_fraction",
    "flow_iat_std_seconds",
)
Fraction = Annotated[NonnegativeFloat64, Field(le=1.0)]
MinorFraction = Annotated[NonnegativeFloat64, Field(le=0.5)]


class FlowFeaturesV2(_WireModel):
    duration_seconds: NonnegativeFloat64
    packet_count: UInt64
    packets_per_second: NonnegativeFloat64
    minor_direction_packet_fraction: MinorFraction
    mean_ipv4_packet_bytes: NonnegativeFloat64
    ipv4_direction_byte_imbalance: Fraction
    syn_packet_fraction: Fraction
    fin_packet_fraction: Fraction
    flow_iat_std_seconds: NonnegativeFloat64


class FlowTimingV2(_WireModel):
    policy: Literal["capture_order_nondecreasing_population.v1"]
    gap_count: UInt64


class FlowFeatureRecordV2(_WireModel):
    schema_version: Literal["flow_features.v2"]
    metadata: FlowMetadata
    measurements: FlowFeatures
    timing: FlowTimingV2
    features: FlowFeaturesV2

    @model_validator(mode="after")
    def _native_consistency(self) -> FlowFeatureRecordV2:
        # Reuse native counter, transport and handshake invariants without
        # changing or version-dispatching the v1 wire parser.
        FlowFeatureRecord(
            schema_version="flow_features.v1",
            metadata=self.metadata,
            features=self.measurements,
        )
        m, f = self.measurements, self.features
        if f.packet_count != m.packet_count:
            raise ValueError("v2 packet totals disagree")
        if self.timing.gap_count != max(m.packet_count - 1, 0):
            raise ValueError("v2 gap count disagrees with native packet count")
        first, last = self.metadata.first_seen_time, self.metadata.timestamp_time
        elapsed = last.utc_second - first.utc_second
        ns = ((elapsed.days * 86400 + elapsed.seconds) * 1_000_000_000
              + last.nanosecond - first.nanosecond)
        duration = ns / 1_000_000_000
        packets = m.packet_count
        expected = {
            "duration_seconds": duration,
            "packets_per_second": packets / duration if duration else 0.0,
            "minor_direction_packet_fraction": min(m.fwd_packet_count, m.rev_packet_count) / packets if packets else 0.0,
            "mean_ipv4_packet_bytes": m.byte_count / packets if packets else 0.0,
            "ipv4_direction_byte_imbalance": abs(m.fwd_byte_count - m.rev_byte_count) / m.byte_count if m.byte_count else 0.0,
            "syn_packet_fraction": m.syn_count / packets if packets else 0.0,
            "fin_packet_fraction": m.fin_count / packets if packets else 0.0,
        }
        for name, value in expected.items():
            if not math.isclose(getattr(f, name), value, rel_tol=1e-12, abs_tol=1e-15):
                raise ValueError("v2 projection disagrees with native measurements")
        for observed, value in (
            (m.duration_seconds, duration),
            (m.packets_per_second, expected["packets_per_second"]),
            (m.bytes_per_packet, expected["mean_ipv4_packet_bytes"]),
            (m.bytes_per_second, m.byte_count / duration if duration else 0.0),
        ):
            if not math.isclose(observed, value, rel_tol=1e-12, abs_tol=1e-15):
                raise ValueError("native v2 rates or size mean disagree")
        if (self.timing.gap_count < 2 and f.flow_iat_std_seconds != 0.0) or (
            f.flow_iat_std_seconds > duration
        ):
            raise ValueError("v2 timing statistic outside native lifespan")
        return self


def flow_feature_json_schema_v2() -> dict[str, object]:
    """Return the draft-07 schema for the explicit v2 wire contract."""
    schema = FlowFeatureRecordV2.model_json_schema(ref_template="#/definitions/{model}")
    schema["definitions"] = schema.pop("$defs")
    schema["$schema"] = "http://json-schema.org/draft-07/schema#"
    schema["$id"] = "https://intriqo.dev/contracts/features/flow_features_v2.json"
    schema["description"] = (
        "Native v2 retirement measurements and nine feature inputs. IPv4 total bytes "
        "exclude Ethernet headers. IAT uses nondecreasing capture/file order and "
        "population standard deviation in seconds; invalid timing is never exported."
    )
    schema["$comment"] = (
        "Use parse_flow_feature_record_v2 for full validation: 8192-byte bound, "
        "16-container depth, unique keys, finite numbers, strict integer tokens, "
        "calendar timestamps, native sums/transport/handshake evidence, projection "
        "formulas, duration/rates and gap_count=max(packet_count-1,0). "
        "Empty or one-gap population std is zero. No model execution or "
        "recalculation/normalization of accepted feature values occurs. "
        "Roundoff checks use rtol=1e-12, atol=1e-15."
    )
    return schema


# Retain the name used by the initial v2 implementation while making the
# versioned public name unambiguous beside flow_feature_json_schema (v1).
flow_feature_v2_json_schema = flow_feature_json_schema_v2


def parse_flow_feature_record_v2(raw: str | bytes) -> FlowFeatureRecordV2:
    """Bounded v2-only parsing; reuse v1 transport guards, never normalize v1."""
    if not isinstance(raw, (str, bytes)):
        raise FlowFeatureError("invalid_input")
    if len(raw) > MAX_RECORD_BYTES + 2:
        raise FlowFeatureError("record_too_large")
    try:
        encoded = raw.encode("utf-8") if isinstance(raw, str) else raw
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
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant, parse_float=_finite_float)
    except FlowFeatureError:
        raise
    except (ValueError, RecursionError, OverflowError):
        raise FlowFeatureError("invalid_json") from None
    if (isinstance(value, dict) and isinstance(value.get("schema_version"), str)
            and value["schema_version"] != SCHEMA_VERSION_V2):
        raise UnsupportedSchemaVersionError()
    try:
        return FlowFeatureRecordV2.model_validate(value)
    except (ValidationError, ValueError, OverflowError):
        error = FlowFeatureError("invalid_record")
        # The shared domain error stays payload-free, but must name v2 accurately.
        error.args = ("record violates flow_features.v2 contract",)
        raise error from None


@dataclass(frozen=True)
class FlowFeatureLineV2:
    """One v2 JSONL line and its payload-free validation result."""

    line_number: int
    record: FlowFeatureRecordV2 | None
    error: FlowFeatureError | None


def read_line_v2(stream: BinaryIO) -> bytes | None:
    """Read one bounded v2 JSONL line without buffering oversized input."""
    chunk = stream.readline(MAX_RECORD_BYTES + 3)
    if not chunk:
        return None
    if chunk.endswith(b"\n"):
        terminator_size = 2 if chunk.endswith(b"\r\n") else 1
        if len(chunk) - terminator_size > MAX_RECORD_BYTES:
            raise FlowFeatureError("record_too_large")
        return chunk
    if len(chunk) <= MAX_RECORD_BYTES:
        return chunk
    while chunk and not chunk.endswith(b"\n"):
        chunk = stream.readline(MAX_RECORD_BYTES + 3)
    raise FlowFeatureError("record_too_large")


def iter_flow_feature_records_v2(stream: BinaryIO) -> Iterator[FlowFeatureLineV2]:
    """Yield a typed result for every physical v2 JSONL line; continue on errors."""
    line_number = 0
    while True:
        try:
            raw = read_line_v2(stream)
        except FlowFeatureError as error:
            line_number += 1
            yield FlowFeatureLineV2(line_number, None, error)
            continue
        if raw is None:
            return
        line_number += 1
        try:
            record = parse_flow_feature_record_v2(raw)
        except FlowFeatureError as error:
            yield FlowFeatureLineV2(line_number, None, error)
        else:
            yield FlowFeatureLineV2(line_number, record, None)


def project_flow_features_v2(record: FlowFeatureRecordV2) -> tuple[float, ...]:
    """Only the nine model dimensions; no metadata or measurement evidence."""
    if record.features.packet_count > 1 << 53:
        raise ValueError("v2 packet count cannot be represented exactly in float64")
    return tuple(float(getattr(record.features, name)) for name in FEATURES_V2)
