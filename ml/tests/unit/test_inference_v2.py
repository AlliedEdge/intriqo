"""Focused controls for the locked, read-only controlled-v2 inference API."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from intriqo_ml.flow_features_v2 import (
    FEATURES_V2,
    FlowFeatureRecordV2,
    FlowFeaturesV2,
    parse_flow_feature_record_v2,
    project_flow_features_v2,
)
from intriqo_ml.inference_v2 import (
    DETECTOR_NAME,
    LOCKED_CONTRACT_SHA256,
    LOCKED_MODEL_SHA256,
    LOCKED_THRESHOLD,
    LOCKED_THRESHOLD_SHA256,
    ArtifactLoadError,
    DetectorState,
    LockedArtifactLoader,
    MLConfig,
    MLDetector,
    MLInferenceError,
    MLUnavailableError,
    deterministic_event_id,
)
from intriqo_ml.models.isolation_forest import scores_from_sklearn

ROOT = Path(__file__).resolve().parents[3]
ARTIFACTS = ROOT / "ml/artifacts/models/controlled-v2/isolation-forest-v2"


def _wire_record(flow_id: str = "1") -> dict[str, Any]:
    return {
        "schema_version": "flow_features.v2",
        "metadata": {
            "engine_instance_id": "123e4567-e89b-42d3-a456-426614174000",
            "flow_id": flow_id,
            "first_seen": "2023-11-14T22:13:20.000000001Z",
            "timestamp": "2023-11-14T22:13:23.000000001Z",
            "export_reason": "shutdown_flush",
            "network": {
                "src_ip": "192.0.2.10",
                "dst_ip": "198.51.100.20",
                "src_port": 40000,
                "dst_port": 443,
                "protocol": "TCP",
            },
        },
        "measurements": {
            "packet_count": 3,
            "byte_count": 120,
            "duration_seconds": 3.0,
            "bytes_per_packet": 40.0,
            "packets_per_second": 1.0,
            "bytes_per_second": 40.0,
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
        "timing": {"policy": "capture_order_nondecreasing_population.v1", "gap_count": 2},
        "features": {
            "duration_seconds": 3.0,
            "packet_count": 3,
            "packets_per_second": 1.0,
            "minor_direction_packet_fraction": 1 / 3,
            "mean_ipv4_packet_bytes": 40.0,
            "ipv4_direction_byte_imbalance": 1 / 3,
            "syn_packet_fraction": 2 / 3,
            "fin_packet_fraction": 0.0,
            "flow_iat_std_seconds": 0.5,
        },
    }


def _record(flow_id: str = "1") -> FlowFeatureRecordV2:
    return parse_flow_feature_record_v2(json.dumps(_wire_record(flow_id)))


def _config() -> MLConfig:
    return MLConfig(
        enabled=True,
        model_path=ARTIFACTS / "model.joblib",
        threshold_path=ARTIFACTS / "threshold.json",
        feature_schema_path=ARTIFACTS / "feature_schema.json",
        feature_contract_path=ROOT / "contracts/features/flow_features_v2.json",
    )


def test_locked_hashes_schema_and_model_are_admitted() -> None:
    config = _config()
    loaded = LockedArtifactLoader().load(config)
    assert loaded.model_sha256 == LOCKED_MODEL_SHA256
    assert loaded.threshold_sha256 == LOCKED_THRESHOLD_SHA256
    assert loaded.feature_order == FEATURES_V2
    assert loaded.threshold == LOCKED_THRESHOLD
    assert LOCKED_CONTRACT_SHA256 == "67b96b59fce896ba33fdfd93cb445eeab901a2cee2c5b3347267622e0a140924"


def test_loader_rejects_non_locked_model_hash() -> None:
    config = replace(_config(), expected_model_sha256="0" * 64)
    with pytest.raises(ArtifactLoadError, match="configured model hash"):
        LockedArtifactLoader().load(config)


def test_loader_rejects_non_locked_threshold_hash() -> None:
    config = replace(_config(), expected_threshold_sha256="0" * 64)
    with pytest.raises(ArtifactLoadError, match="configured threshold hash"):
        LockedArtifactLoader().load(config)


def test_loader_rejects_wrong_schema_order_and_contract_hash(tmp_path: Path) -> None:
    schema = json.loads((_config().feature_schema_path or Path()).read_text())
    schema["features"][0], schema["features"][1] = schema["features"][1], schema["features"][0]
    schema_path = tmp_path / "feature_schema.json"
    schema_path.write_text(json.dumps(schema), encoding="utf-8")
    with pytest.raises(ArtifactLoadError, match="feature schema order"):
        LockedArtifactLoader().load(replace(_config(), feature_schema_path=schema_path))

    contract_path = tmp_path / "flow_features_v2.json"
    contract_path.write_bytes((ROOT / "contracts/features/flow_features_v2.json").read_bytes() + b"\n")
    with pytest.raises(ArtifactLoadError, match="feature contract SHA-256"):
        LockedArtifactLoader().load(replace(_config(), feature_contract_path=contract_path))


def test_detector_load_failure_is_failed_and_payload_free() -> None:
    class FailingLoader:
        def load(self, _config: MLConfig) -> object:
            raise RuntimeError("private artifact path")

    detector = MLDetector(_config(), FailingLoader())  # type: ignore[arg-type]
    assert detector.state is DetectorState.FAILED
    assert detector.failure_reason == "artifact_load_failed"


def test_disabled_by_default_and_config_requires_paths() -> None:
    config = MLConfig.from_env({})
    assert config.enabled is False
    detector = MLDetector(config)
    assert detector.state.value == DetectorState.DEGRADED.value
    assert detector.failure_reason == "disabled_by_configuration"
    with pytest.raises(MLUnavailableError):
        detector.detect(_record())

    with pytest.raises(ValueError, match="INTRIQO_ML_MODEL_PATH"):
        MLConfig.from_env({"INTRIQO_ML_ENABLED": "true"})
    failed = MLDetector(MLConfig(enabled=True))
    assert failed.state is DetectorState.FAILED
    assert failed.failure_reason == "artifact_load_failed"


def test_only_revalidated_typed_records_are_accepted() -> None:
    detector = MLDetector(_config())
    assert detector.state is DetectorState.READY

    with pytest.raises(MLInferenceError):
        detector.detect({})  # type: ignore[arg-type]
    assert detector.state.value == DetectorState.DEGRADED.value

    forged_wire = _wire_record()
    forged_wire["features"]["duration_seconds"] = -1.0
    forged = FlowFeatureRecordV2.model_construct(**forged_wire)
    detector = MLDetector(_config())
    with pytest.raises(MLInferenceError):
        detector.detect(forged)
    assert detector.state is DetectorState.DEGRADED

    forged_nested = _record().model_copy(
        update={
            "features": FlowFeaturesV2.model_construct(
                **{**_wire_record()["features"], "duration_seconds": -1.0}
            )
        }
    )
    detector = MLDetector(_config())
    with pytest.raises(MLInferenceError):
        detector.detect(forged_nested)

    forged_extra = _record().model_copy(update={"unexpected": 1})
    detector = MLDetector(_config())
    with pytest.raises(MLInferenceError):
        detector.detect(forged_extra)


def test_score_is_native_negation_on_float32_and_threshold_is_inclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    detector = MLDetector(_config())
    assert detector.artifacts is not None
    seen: list[np.dtype[Any]] = []

    def score(model: object, features: np.ndarray[Any, Any]) -> np.ndarray[Any, Any]:
        del model
        seen.append(features.dtype)
        return np.asarray([-LOCKED_THRESHOLD], dtype=np.float64)

    monkeypatch.setattr("intriqo_ml.inference_v2.scores_from_sklearn", score)
    result = detector.detect(_record())
    assert result.anomaly_score == -LOCKED_THRESHOLD
    assert result.is_anomaly is False
    assert seen == [np.dtype(np.float32)]

    def exact_score(_model: object, _features: Any) -> np.ndarray[Any, Any]:
        return np.asarray([LOCKED_THRESHOLD])

    monkeypatch.setattr("intriqo_ml.inference_v2.scores_from_sklearn", exact_score)
    result = MLDetector(_config()).detect(_record("2"))
    assert result.is_anomaly is True


def test_locked_native_v2_records_match_canonical_score() -> None:
    native_path = ROOT / "ml/artifacts/feature-analysis/controlled-v2/run-complete-20261006/native_features_v2.jsonl"
    records = [
        parse_flow_feature_record_v2(line)
        for line in native_path.read_bytes().splitlines()[:5]
    ]
    detector = MLDetector(_config())
    assert detector.artifacts is not None
    for record in records:
        vector = np.asarray(project_flow_features_v2(record), dtype=np.float32).reshape(1, -1)
        expected = float(scores_from_sklearn(detector.artifacts.model, vector)[0])
        assert detector.detect(record).anomaly_score == expected


def test_inference_failure_degrades_without_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    detector = MLDetector(_config())
    def fail_score(_model: object, _features: Any) -> Any:
        raise RuntimeError("secret payload")

    monkeypatch.setattr("intriqo_ml.inference_v2.scores_from_sklearn", fail_score)
    with pytest.raises(MLInferenceError, match="^inference_failed$"):
        detector.detect(_record())
    assert detector.state is DetectorState.DEGRADED
    assert detector.failure_reason == "inference_failed"


def test_result_serialization_and_event_id_are_stable() -> None:
    detector = MLDetector(_config())
    result = detector.detect(_record())
    payload = result.to_dict()
    assert payload["detector"] == DETECTOR_NAME
    assert payload["model_sha256"] == LOCKED_MODEL_SHA256
    assert payload["threshold_sha256"] == LOCKED_THRESHOLD_SHA256
    assert deterministic_event_id(result) == deterministic_event_id(replace(result, inference_timestamp="later"))
