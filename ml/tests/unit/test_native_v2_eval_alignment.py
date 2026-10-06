"""Conservative controller-to-native alignment tests."""

from __future__ import annotations

import json

from intriqo_ml.flow_features_v2 import parse_flow_feature_record_v2
from intriqo_ml.native_v2_eval.alignment import align_record
from intriqo_ml.native_v2_eval.schema import ExperimentManifest, ExperimentScenario


def native_record(**overrides):
    value = {
        "schema_version": "flow_features.v2",
        "metadata": {
            "engine_instance_id": "123e4567-e89b-42d3-a456-426614174000",
            "flow_id": "1",
            "first_seen": "2023-11-14T22:13:20.000000001Z",
            "timestamp": "2023-11-14T22:13:23.000000001Z",
            "export_reason": "shutdown_flush",
            "network": {"src_ip": "192.0.2.10", "dst_ip": "198.51.100.20", "src_port": 40000, "dst_port": 443, "protocol": "TCP"},
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
            "minor_direction_packet_fraction": 1 / 3, "mean_ipv4_packet_bytes": 40.0,
            "ipv4_direction_byte_imbalance": 1 / 3, "syn_packet_fraction": 2 / 3,
            "fin_packet_fraction": 0.0, "flow_iat_std_seconds": 0.5,
        },
    }
    value["metadata"].update(overrides)
    return parse_flow_feature_record_v2(json.dumps(value))


def scenario(**overrides) -> ExperimentScenario:
    value = {
        "experiment_id": "exp-1", "scenario_id": "scenario-1", "split": "validation",
        "label": "ATTACK", "attack_family": "PORT_SCAN", "attacker_ip": "192.0.2.10",
        "victim_ip": "198.51.100.20", "capture_interface": "tap0", "subnet": "192.0.2.0/24",
        "protocol": "TCP", "source_port": 40000, "destination_port": 443,
        "start_timestamp": "2023-11-14T22:13:20.000000001Z",
        "end_timestamp": "2023-11-14T22:13:23.000000001Z",
        "expected_flow_scope": "single_five_tuple", "source_label_id": "label-1",
    }
    value.update(overrides)
    return ExperimentScenario.model_validate(value)


def manifest(*scenarios: ExperimentScenario) -> ExperimentManifest:
    return ExperimentManifest(
        corpus_id="corpus-1", timezone="UTC", clock_synchronization="recorded",
        experiments=scenarios,
    )


def test_exact_match_is_the_only_eligible_status() -> None:
    row = align_record(
        native_record(), capture_id="capture-1", capture_experiment_id="exp-1",
        manifest=manifest(scenario()), native_line_number=1,
    )
    assert row.match_status == "EXACT"
    assert row.label == "ATTACK" and row.attack_family == "PORT_SCAN"
    assert row.eligible is True


def test_partial_and_unknown_are_not_benign() -> None:
    partial = scenario(end_timestamp="2023-11-14T22:13:24.000000001Z")
    row = align_record(
        native_record(), capture_id="capture-1", capture_experiment_id="exp-1",
        manifest=manifest(partial), native_line_number=1,
    )
    assert row.match_status == "PARTIAL" and row.eligible is False

    unknown = align_record(
        native_record(), capture_id="capture-1", capture_experiment_id="missing",
        manifest=manifest(scenario()), native_line_number=1,
    )
    assert unknown.match_status == "UNKNOWN"
    assert unknown.label is None and unknown.eligible is False


def test_overlapping_controller_rows_are_ambiguous() -> None:
    second = scenario(scenario_id="scenario-2", source_label_id="label-2", label="BENIGN", attack_family=None)
    row = align_record(
        native_record(), capture_id="capture-1", capture_experiment_id="exp-1",
        manifest=manifest(scenario(), second), native_line_number=1,
    )
    assert row.match_status == "AMBIGUOUS"
    assert row.label is None and row.eligible is False
