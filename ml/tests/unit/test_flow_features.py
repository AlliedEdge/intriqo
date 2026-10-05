"""Unit checks for the frozen flow_features.v1 boundary and its JSONL reader."""

from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
from datetime import timezone
from pathlib import Path
from typing import Any

import pytest
from intriqo_ml import (
    MAX_RECORD_BYTES,
    FlowFeatureError,
    FlowFeatureRecord,
    UnsupportedSchemaVersionError,
    flow_feature_json_schema,
    parse_flow_feature_record,
)
from intriqo_ml.consumer import (
    ConsumptionCounts,
    consume_flow_feature_records,
    iter_flow_feature_records,
    main,
    read_line,
)
from intriqo_ml.flow_features import MAX_JSON_DEPTH, UINT32_MAX, UINT64_MAX
from pydantic import ValidationError


def valid_record() -> dict[str, Any]:
    return {
        "schema_version": "flow_features.v1",
        "metadata": {
            "engine_instance_id": "123e4567-e89b-42d3-a456-426614174000",
            "flow_id": "1",
            "first_seen": "2026-10-05T12:00:00.123456789Z",
            "timestamp": "2026-10-05T12:00:01.123456790Z",
            "export_reason": "idle_expired",
            "network": {
                "src_ip": "192.0.2.1",
                "dst_ip": "198.51.100.2",
                "src_port": 49152,
                "dst_port": 443,
                "protocol": "TCP",
            },
        },
        "features": {
            "packet_count": 3,
            "byte_count": 120,
            "duration_seconds": 1.000000001,
            "bytes_per_packet": 40.0,
            "packets_per_second": 2.999999997,
            "bytes_per_second": 119.99999988,
            "fwd_packet_count": 2,
            "rev_packet_count": 1,
            "fwd_byte_count": 80,
            "rev_byte_count": 40,
            "syn_count": 2,
            "fin_count": 0,
            "rst_count": 0,
            "initial_syn_count": 1,
            "syn_ack_count": 1,
            "ack_count": 1,
            "tcp_handshake_started": True,
            "tcp_syn_ack_seen": True,
            "tcp_handshake_completed": True,
        },
    }


def encoded(record: dict[str, Any]) -> str:
    return json.dumps(record, separators=(",", ":"))


def group(record: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    for key in path:
        record = record[key]
    return record


GROUP_PATHS = [(), ("metadata",), ("metadata", "network"), ("features",)]
REQUIRED_FIELDS = [
    (path, field) for path in GROUP_PATHS for field in group(valid_record(), path)
]
FLOAT_FIELDS = [
    "duration_seconds", "bytes_per_packet", "packets_per_second", "bytes_per_second"
]
BOOL_FIELDS = ["tcp_handshake_started", "tcp_syn_ack_seen", "tcp_handshake_completed"]
UINT64_FIELDS = [
    "packet_count", "byte_count", "fwd_packet_count", "rev_packet_count",
    "fwd_byte_count", "rev_byte_count",
]
UINT32_FIELDS = [
    "syn_count", "fin_count", "rst_count",
    "initial_syn_count", "syn_ack_count", "ack_count",
]


@pytest.mark.parametrize("binary", [False, True])
@pytest.mark.parametrize("terminator", ["", "\n", "\r\n"])
def test_valid_record_retains_nanoseconds(binary: bool, terminator: str) -> None:
    original = valid_record()
    raw = encoded(original) + terminator
    record = parse_flow_feature_record(raw.encode() if binary else raw)
    assert isinstance(record, FlowFeatureRecord)
    assert record.model_dump() == original
    timestamp = record.metadata.timestamp_time
    assert timestamp.canonical == original["metadata"]["timestamp"]
    assert timestamp.nanosecond == 123456790
    assert timestamp.utc_second.microsecond == 0
    assert timestamp.utc_second.tzinfo == timezone.utc
    with pytest.raises(ValueError, match="represented exactly"):
        timestamp.as_datetime()
    assert record.metadata.first_seen_time.nanosecond == 123456789
    assert str(record.metadata.engine_uuid) == (
        original["metadata"]["engine_instance_id"]
    )
    assert record.metadata.flow_id_number == 1
    assert str(record.metadata.network.src_address) == "192.0.2.1"
    assert str(record.metadata.network.dst_address) == "198.51.100.2"


def test_exact_datetime_conversion_and_frozen_models() -> None:
    original = valid_record()
    original["metadata"]["first_seen"] = "2026-10-05T12:00:00.123456000Z"
    record = parse_flow_feature_record(encoded(original))
    assert record.metadata.first_seen_time.as_datetime().microsecond == 123456
    for obj, field, value in [
        (record, "schema_version", "flow_features.v2"),
        (record.metadata, "flow_id", "2"),
        (record.metadata.network, "src_port", 1),
        (record.features, "packet_count", 4),
    ]:
        with pytest.raises(ValidationError, match="frozen"):
            setattr(obj, field, value)


@pytest.mark.parametrize("path,field", REQUIRED_FIELDS)
def test_every_field_is_required(path: tuple[str, ...], field: str) -> None:
    record = valid_record()
    del group(record, path)[field]
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("path,field", REQUIRED_FIELDS)
def test_every_field_rejects_null(path: tuple[str, ...], field: str) -> None:
    record = valid_record()
    group(record, path)[field] = None
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("path", GROUP_PATHS)
@pytest.mark.parametrize("field", ["label", "score", "connection_attempts", "optional"])
def test_unknown_fields_rejected_at_every_level(
    path: tuple[str, ...], field: str
) -> None:
    record = valid_record()
    group(record, path)[field] = None
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("field", UINT64_FIELDS + UINT32_FIELDS)
@pytest.mark.parametrize("wrong", ["1", True, False, 1.0, [], {}])
def test_integer_fields_do_not_coerce(field: str, wrong: object) -> None:
    record = valid_record()
    record["features"][field] = wrong
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("field", ["src_port", "dst_port"])
@pytest.mark.parametrize("wrong", ["443", True, 443.0, -1, 65536])
def test_port_types_and_range(field: str, wrong: object) -> None:
    record = valid_record()
    record["metadata"]["network"][field] = wrong
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("field", FLOAT_FIELDS)
@pytest.mark.parametrize("wrong", ["1.0", True, False, [], {}, -0.1])
def test_float_fields_reject_coercion_and_negatives(field: str, wrong: object) -> None:
    record = valid_record()
    record["features"][field] = wrong
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("field", FLOAT_FIELDS)
@pytest.mark.parametrize("value", [0, 1, 1.7976931348623157e308])
def test_float_fields_accept_integer_numbers_and_keep_measurements(
    field: str, value: float
) -> None:
    record = valid_record()
    record["features"][field] = value
    parsed = parse_flow_feature_record(encoded(record))
    assert getattr(parsed.features, field) == float(value)
    # The parser is intentionally not deriving rates or enforcing rounded rates.
    for other in FLOAT_FIELDS:
        if other != field:
            assert getattr(parsed.features, other) == record["features"][other]


@pytest.mark.parametrize("field", BOOL_FIELDS)
@pytest.mark.parametrize("wrong", [0, 1, "true", "false", [], {}])
def test_boolean_fields_do_not_coerce(field: str, wrong: object) -> None:
    record = valid_record()
    record["features"][field] = wrong
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize(
    "field,bound",
    [(field, UINT64_MAX) for field in UINT64_FIELDS]
    + [(field, UINT32_MAX) for field in UINT32_FIELDS],
)
@pytest.mark.parametrize("overflow", [False, True])
def test_integer_range(field: str, bound: int, overflow: bool) -> None:
    record = valid_record()
    record["features"][field] = bound + 1 if overflow else -1
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


def test_uint64_and_uint32_upper_bounds_are_valid() -> None:
    record = valid_record()
    record["metadata"]["flow_id"] = str(UINT64_MAX)
    features = record["features"]
    features.update(
        packet_count=UINT64_MAX,
        fwd_packet_count=UINT64_MAX - 1,
        rev_packet_count=1,
        byte_count=UINT64_MAX,
        fwd_byte_count=UINT64_MAX - 40,
        rev_byte_count=40,
        syn_count=UINT32_MAX,
    )
    parsed = parse_flow_feature_record(encoded(record))
    assert parsed.metadata.flow_id_number == UINT64_MAX
    assert parsed.features.packet_count == UINT64_MAX
    assert parsed.features.syn_count == UINT32_MAX


@pytest.mark.parametrize("field", FLOAT_FIELDS)
@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e309", "-1e309"])
def test_nonfinite_json_numbers_rejected(field: str, token: str) -> None:
    record = valid_record()
    record["features"][field] = "REPLACE_NUMBER"
    raw = encoded(record).replace('"REPLACE_NUMBER"', token)
    with pytest.raises(FlowFeatureError) as caught:
        parse_flow_feature_record(raw)
    assert caught.value.code == "nonfinite_number"


@pytest.mark.parametrize("version", ["flow_features.v2", "v1", "SECRET_VERSION"])
def test_unsupported_schema_version_is_explicit_and_payload_free(version: str) -> None:
    record = valid_record()
    record["schema_version"] = version
    with pytest.raises(UnsupportedSchemaVersionError) as caught:
        parse_flow_feature_record(encoded(record))
    assert caught.value.code == "unsupported_schema_version"
    assert version not in str(caught.value)


@pytest.mark.parametrize("field,value", [
    ("flow_id", "0"), ("flow_id", "01"), ("flow_id", "+1"), ("flow_id", "-1"),
    ("flow_id", str(UINT64_MAX + 1)), ("flow_id", "1\n"), ("flow_id", 1),
    ("flow_id", "١"), ("engine_instance_id", "123E4567-e89b-42d3-a456-426614174000"),
    ("engine_instance_id", "123e4567e89b42d3a456426614174000"),
    ("engine_instance_id", "{123e4567-e89b-42d3-a456-426614174000}"),
    ("export_reason", "fin_closed"), ("schema_version", 1),
])
def test_metadata_canonical_strings(field: str, value: object) -> None:
    record = valid_record()
    target = record if field == "schema_version" else record["metadata"]
    target[field] = value
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("field", ["first_seen", "timestamp"])
@pytest.mark.parametrize("value", [
    "2026-10-05T12:00:00Z", "2026-10-05T12:00:00.123456Z",
    "2026-10-05T12:00:00.123456789+00:00", "2026-10-05t12:00:00.123456789z",
    "2026-02-30T12:00:00.123456789Z", "0000-10-05T12:00:00.123456789Z",
    "2026-10-05T24:00:00.123456789Z", "2026-10-05T12:00:60.123456789Z",
    "2026-10-05T12:00:00.1234567890Z",
])
def test_timestamps_are_exact_canonical_calendar_strings(
    field: str, value: str
) -> None:
    record = valid_record()
    record["metadata"][field] = value
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


def test_chronology_uses_nanoseconds_not_datetime_rounding() -> None:
    record = valid_record()
    record["metadata"]["timestamp"] = "2026-10-05T12:00:00.123456788Z"
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))
    record["metadata"]["timestamp"] = record["metadata"]["first_seen"]
    parsed = parse_flow_feature_record(encoded(record))
    assert parsed.metadata.timestamp_time.nanosecond == 123456789


@pytest.mark.parametrize("field", ["src_ip", "dst_ip"])
@pytest.mark.parametrize(
    "value", ["256.0.2.1", "192.00.2.1", "192.0.2.1\n", "::1", "127.1", 1]
)
def test_ipv4_canonical_strings(field: str, value: object) -> None:
    record = valid_record()
    record["metadata"]["network"][field] = value
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize(
    "reason", ["idle_expired", "capacity_evicted", "shutdown_flush"]
)
@pytest.mark.parametrize("protocol", ["TCP", "UDP", "ICMP", "OTHER"])
def test_protocols_and_retirement_reasons(reason: str, protocol: str) -> None:
    record = valid_record()
    record["metadata"]["export_reason"] = reason
    record["metadata"]["network"]["protocol"] = protocol
    if protocol != "TCP":
        for field in UINT32_FIELDS:
            record["features"][field] = 0
        for field in BOOL_FIELDS:
            record["features"][field] = False
    parsed = parse_flow_feature_record(encoded(record))
    assert parsed.metadata.network.protocol == protocol


@pytest.mark.parametrize("updates", [
    {"fwd_packet_count": 3}, {"rev_byte_count": 0},
    {"tcp_handshake_started": False}, {"tcp_syn_ack_seen": False},
    {"initial_syn_count": 0}, {"syn_ack_count": 0}, {"ack_count": 0},
    {"fwd_packet_count": 1, "rev_packet_count": 2},
    {"fwd_packet_count": 3, "rev_packet_count": 0},
    {"initial_syn_count": 2}, {"syn_count": 3},
])
def test_inconsistent_totals_and_handshake_evidence(updates: dict[str, Any]) -> None:
    record = valid_record()
    record["features"].update(updates)
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("field", UINT32_FIELDS)
def test_each_tcp_count_cannot_exceed_packets(field: str) -> None:
    record = valid_record()
    record["features"][field] = 4
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("protocol", ["UDP", "ICMP", "OTHER"])
@pytest.mark.parametrize("field", UINT32_FIELDS + BOOL_FIELDS)
def test_non_tcp_rejects_any_tcp_evidence(protocol: str, field: str) -> None:
    record = valid_record()
    record["metadata"]["network"]["protocol"] = protocol
    for count in UINT32_FIELDS:
        record["features"][count] = 0
    for boolean in BOOL_FIELDS:
        record["features"][boolean] = False
    record["features"][field] = True if field in BOOL_FIELDS else 1
    with pytest.raises(FlowFeatureError, match="violates"):
        parse_flow_feature_record(encoded(record))


@pytest.mark.parametrize("original,replacement", [
    (
        '"schema_version":"flow_features.v1"',
        '"schema_version":"flow_features.v1","schema_version":"flow_features.v1"',
    ),
    ('"flow_id":"1"', '"flow_id":"1","flow_id":"1"'),
    ('"src_port":49152', '"src_port":49152,"src_port":49152'),
    ('"packet_count":3', '"packet_count":3,"packet_count":3'),
    ('"flow_id":"1"', '"flow_id":"1","flow_\\u0069d":"1"'),
])
def test_duplicate_keys_rejected_in_all_objects(
    original: str, replacement: str
) -> None:
    raw = encoded(valid_record()).replace(original, replacement)
    with pytest.raises(FlowFeatureError) as caught:
        parse_flow_feature_record(raw)
    assert caught.value.code == "duplicate_key"


@pytest.mark.parametrize(
    "raw", ["", "{", "[]", "null", "true", "1", '{"SECRET_PAYLOAD":']
)
def test_malformed_and_nonobject_json_is_sanitized(raw: str) -> None:
    with pytest.raises(FlowFeatureError) as caught:
        parse_flow_feature_record(raw)
    assert "SECRET_PAYLOAD" not in str(caught.value)


def test_nesting_is_bounded_before_json_decoding() -> None:
    raw = "[" * 3000 + "0" + "]" * 3000
    with pytest.raises(FlowFeatureError) as caught:
        parse_flow_feature_record(raw)
    assert caught.value.code == "nesting_too_deep"
    record = valid_record()
    nested: object = 0
    for _ in range(MAX_JSON_DEPTH):
        nested = [nested]
    record["features"]["extra"] = nested
    with pytest.raises(FlowFeatureError, match="nesting"):
        parse_flow_feature_record(encoded(record))
    record["features"]["extra"] = '"\\' + "[" * 100
    with pytest.raises(FlowFeatureError) as caught:
        parse_flow_feature_record(encoded(record))
    # Brackets inside strings are not nesting depth.
    assert caught.value.code == "invalid_record"


@pytest.mark.parametrize("terminator", [b"", b"\n", b"\r\n"])
def test_record_size_boundary_excludes_only_line_terminator(terminator: bytes) -> None:
    raw = encoded(valid_record()).encode()
    boundary = raw + b" " * (MAX_RECORD_BYTES - len(raw))
    assert parse_flow_feature_record(boundary + terminator).metadata.flow_id == "1"
    with pytest.raises(FlowFeatureError) as caught:
        parse_flow_feature_record(boundary + b" " + terminator)
    assert caught.value.code == "record_too_large"


def test_utf8_byte_limit_encoding_and_huge_integers() -> None:
    record = valid_record()
    record["features"]["extra"] = "é" * 4000
    raw = json.dumps(record, ensure_ascii=False)
    assert len(raw) < MAX_RECORD_BYTES < len(raw.encode())
    with pytest.raises(FlowFeatureError, match="8192"):
        parse_flow_feature_record(raw)
    for raw in [b"\xff", "\ud800"]:
        with pytest.raises(FlowFeatureError) as caught:
            parse_flow_feature_record(raw)
        assert caught.value.code == "invalid_encoding"
    with pytest.raises(FlowFeatureError):
        parse_flow_feature_record('{"number":' + "9" * 7000 + "}")


class BoundedStream(io.BytesIO):
    def readline(self, size: int = -1) -> bytes:
        assert 0 < size <= MAX_RECORD_BYTES + 3
        return super().readline(size)


@pytest.mark.parametrize(
    "extra,terminator", [(1, b"\n"), (1, b"\r\n"), (200000, b"\n"), (1, b"")]
)
def test_read_line_drains_oversized_input_in_bounded_chunks(
    extra: int, terminator: bytes
) -> None:
    good = encoded(valid_record()).encode()
    stream = BoundedStream(
        b"x" * (MAX_RECORD_BYTES + extra)
        + terminator
        + (good if terminator else b"")
    )
    with pytest.raises(FlowFeatureError, match="8192"):
        read_line(stream)
    assert read_line(stream) == (good if terminator else None)
    assert read_line(stream) is None


def test_jsonl_continues_after_rejections_and_counts_lines() -> None:
    good = encoded(valid_record()).encode()
    stream = BoundedStream(
        good + b"\r\nSECRET_PAYLOAD\n" + b"x" * 100000 + b"\n\xff\n\n" + good
    )
    results = list(iter_flow_feature_records(stream))
    assert [result.line_number for result in results] == list(range(1, 7))
    assert [result.record is not None for result in results] == [
        True, False, False, False, False, True,
    ]
    assert all(result.error is not None for result in results[1:5])
    errors = io.StringIO()
    counts = consume_flow_feature_records(
        io.BytesIO(good + b"\nSECRET_PAYLOAD\n" + good), error_stream=errors
    )
    assert counts == ConsumptionCounts(validated=2, rejected=1)
    assert "line 2: rejected:" in errors.getvalue()
    assert "SECRET_PAYLOAD" not in errors.getvalue()
    assert consume_flow_feature_records(io.BytesIO()) == ConsumptionCounts(0, 0)


def test_cli_reports_counts_and_nonzero_without_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "records.jsonl"
    source.write_bytes(encoded(valid_record()).encode() + b"\nSECRET_PAYLOAD\n")
    assert main([str(source)]) == 1
    captured = capsys.readouterr()
    assert captured.out == "validated=1 rejected=1\n"
    assert "line 2: rejected:" in captured.err
    assert "SECRET_PAYLOAD" not in captured.err
    source.write_text(encoded(valid_record()), encoding="utf-8")
    assert main([str(source)]) == 0
    assert capsys.readouterr().out == "validated=1 rejected=0\n"
    assert main([str(tmp_path / "missing")]) == 2
    assert capsys.readouterr().err == "cannot read input file\n"


def test_module_cli_does_not_import_ml_libraries(tmp_path: Path) -> None:
    source = tmp_path / "records.jsonl"
    source.write_text(encoded(valid_record()), encoding="utf-8")
    src = Path(__file__).resolve().parents[2] / "src"
    env = {**os.environ, "PYTHONPATH": str(src)}
    result = subprocess.run(
        [sys.executable, "-m", "intriqo_ml.consumer", str(source)],
        capture_output=True, text=True, env=env, check=False,
    )
    assert result.returncode == 0
    assert result.stdout == "validated=1 rejected=0\n"
    assert result.stderr == ""
    probe = subprocess.run(
        [
            sys.executable, "-c",
            (
                "import intriqo_ml.consumer, sys; "
                "assert not {'numpy', 'sklearn', 'pandas'} & sys.modules.keys()"
            ),
        ],
        capture_output=True, text=True, env=env, check=False,
    )
    assert probe.returncode == 0, probe.stderr


def test_checked_in_draft07_schema_exactly_matches_wire_models() -> None:
    root = Path(__file__).resolve().parents[3]
    schema = json.loads((root / "contracts/features/flow_features_v1.json").read_text())
    assert schema == flow_feature_json_schema()
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    for model in [schema, *schema["definitions"].values()]:
        assert model["additionalProperties"] is False
        assert set(model["required"]) == set(model["properties"])
    flow_id = schema["definitions"]["FlowMetadata"]["properties"]["flow_id"]
    for value in [1, 10, 10**19, UINT64_MAX - 1, UINT64_MAX]:
        assert re.fullmatch(flow_id["pattern"], str(value))
    for value in [0, UINT64_MAX + 1, 10**20]:
        assert not re.fullmatch(flow_id["pattern"], str(value))
    for field in FLOAT_FIELDS:
        spec = schema["definitions"]["FlowFeatures"]["properties"][field]
        assert spec["minimum"] == 0
        assert spec["maximum"] == sys.float_info.max


@pytest.mark.parametrize("empty_direction", ["fwd", "rev"])
def test_empty_packet_direction_cannot_contain_bytes(empty_direction: str) -> None:
    value = valid_record()
    value["metadata"]["network"]["protocol"] = "UDP"
    f = value["features"]
    for field in UINT32_FIELDS:
        f[field] = 0
    for field in BOOL_FIELDS:
        f[field] = False
    other = "rev" if empty_direction == "fwd" else "fwd"
    f[f"{empty_direction}_packet_count"] = 0
    f[f"{other}_packet_count"] = f["packet_count"]
    # Byte sums still agree; only the empty-direction invariant rejects this.
    with pytest.raises(FlowFeatureError, match="violates flow_features.v1"):
        parse_flow_feature_record(encoded(value))
