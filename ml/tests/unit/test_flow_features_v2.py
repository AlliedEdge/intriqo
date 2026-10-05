"""Version isolation, honest native projection, and strict v2 transport guards."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from intriqo_ml.flow_features import FlowFeatureError, parse_flow_feature_record
from intriqo_ml.flow_features_v2 import (
    FEATURES_V2,
    flow_feature_v2_json_schema,
    parse_flow_feature_record_v2,
    project_flow_features_v2,
)


def valid_v2():
    return {
        "schema_version": "flow_features.v2",
        "metadata": {
            "engine_instance_id": "123e4567-e89b-42d3-a456-426614174000", "flow_id": "1",
            "first_seen": "2023-11-14T22:13:20.000000001Z",
            "timestamp": "2023-11-14T22:13:23.000000001Z",
            "export_reason": "shutdown_flush",
            "network": {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20",
                        "src_port": 40000, "dst_port": 443, "protocol": "TCP"},
        },
        "measurements": {
            "packet_count": 3, "byte_count": 120, "duration_seconds": 3.0,
            "bytes_per_packet": 40.0, "packets_per_second": 1.0, "bytes_per_second": 40.0,
            "fwd_packet_count": 2, "rev_packet_count": 1, "fwd_byte_count": 80, "rev_byte_count": 40,
            "syn_count": 2, "fin_count": 0, "rst_count": 0, "initial_syn_count": 1,
            "syn_ack_count": 1, "ack_count": 1, "tcp_handshake_started": True,
            "tcp_syn_ack_seen": True, "tcp_handshake_completed": True,
        },
        "timing": {"policy": "capture_order_nondecreasing_population.v1", "gap_count": 2},
        "features": {
            "duration_seconds": 3.0, "packet_count": 3, "packets_per_second": 1.0,
            "minor_direction_packet_fraction": 1/3, "mean_ipv4_packet_bytes": 40.0,
            "ipv4_direction_byte_imbalance": 1/3, "syn_packet_fraction": 2/3,
            "fin_packet_fraction": 0.0, "flow_iat_std_seconds": 0.5,
        },
    }


def test_v2_round_trip_and_metadata_is_not_projected():
    value = valid_v2()
    record = parse_flow_feature_record_v2(json.dumps(value).encode() + b"\r\n")
    assert record.model_dump(mode="json") == value
    assert record.metadata.first_seen_time.nanosecond == 1
    projected = project_flow_features_v2(record)
    assert len(projected) == 9
    assert projected == tuple(float(value["features"][name]) for name in FEATURES_V2)


def test_v1_stays_v1_only_and_v2_stays_v2_only():
    value = valid_v2()
    with pytest.raises(FlowFeatureError, match="unsupported"):
        parse_flow_feature_record(json.dumps(value))
    for version in ("flow_features.v1", "flow_features.v3", "v2"):
        value["schema_version"] = version
        with pytest.raises(FlowFeatureError, match="unsupported"):
            parse_flow_feature_record_v2(json.dumps(value))


@pytest.mark.parametrize("name", FEATURES_V2)
def test_native_projection_cannot_be_fabricated(name):
    value = valid_v2()
    value["features"][name] = 123 if name == "packet_count" else 123.0
    with pytest.raises(FlowFeatureError):
        parse_flow_feature_record_v2(json.dumps(value))


@pytest.mark.parametrize("name", [name for name in FEATURES_V2 if name != "packet_count"])
@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, True, "1.0"])
def test_invalid_numeric_values(name, bad):
    value = valid_v2()
    value["features"][name] = bad
    with pytest.raises(FlowFeatureError):
        parse_flow_feature_record_v2(json.dumps(value))


def test_integer_token_and_iat_policy_are_strict():
    value = valid_v2()
    for key, bad in (("gap_count", 2.0), ("gap_count", 1), ("policy", "sample")):
        value["timing"] = {"gap_count": 2, "policy": "capture_order_nondecreasing_population.v1"}
        value["timing"][key] = bad
        with pytest.raises(FlowFeatureError):
            parse_flow_feature_record_v2(json.dumps(value))


@pytest.mark.parametrize("raw,code", [
    ('{"schema_version":"flow_features.v2","schema_version":"flow_features.v2"}', "duplicate_key"),
    (b"\xff", "invalid_encoding"),
    ("{" + " " * 8192, "record_too_large"),
    ("[" * 17 + "0" + "]" * 17, "nesting_too_deep"),
    ('{"x":1e9999}', "nonfinite_number"),
])
def test_transport_guards(raw, code):
    with pytest.raises(FlowFeatureError) as error:
        parse_flow_feature_record_v2(raw)
    assert error.value.code == code


def test_v2_schema_is_generated_from_exact_model():
    root = Path(__file__).resolve().parents[3]
    assert json.loads((root / "contracts/features/flow_features_v2.json").read_text()) == flow_feature_v2_json_schema()


def test_non_tcp_evidence_and_native_rates_are_checked():
    value = valid_v2()
    value["metadata"]["network"]["protocol"] = "UDP"
    with pytest.raises(FlowFeatureError):
        parse_flow_feature_record_v2(json.dumps(value))
    value = valid_v2()
    value["measurements"]["bytes_per_packet"] = 0.0
    with pytest.raises(FlowFeatureError):
        parse_flow_feature_record_v2(json.dumps(value))
