"""Read-only inference for the locked controlled-v2 model.

The inference boundary is intentionally small.  It accepts an already parsed
and validated native :class:`FlowFeatureRecordV2`, verifies the immutable
artifacts once, and invokes only ``IsolationForest.score_samples``.  There is
no fitting, feature engineering, threshold selection, or transport coupling
in this module.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Final
from uuid import NAMESPACE_URL, uuid5

import joblib  # type: ignore[import-untyped]
import numpy as np
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
from sklearn.utils.validation import check_is_fitted  # type: ignore[import-untyped]

from .flow_features_v2 import (
    FEATURES_V2,
    FlowFeatureRecordV2,
    parse_flow_feature_record_v2,
    project_flow_features_v2,
)
from .models.isolation_forest import scores_from_sklearn

LOCKED_MODEL_SHA256: Final = "69d7df6a027eebcaa64c227c3ab34d8a9fd44d4a0158264e86c3fb93db960cb5"
LOCKED_THRESHOLD_SHA256: Final = "28ebd68f65e255e9c32aa433b609c4dc969402605d936b8d49c357c5979058b2"
LOCKED_CONTRACT_SHA256: Final = "67b96b59fce896ba33fdfd93cb445eeab901a2cee2c5b3347267622e0a140924"
LOCKED_THRESHOLD: Final = 0.5153855054112947
LOCKED_MODEL_VERSION: Final = "controlled-v2/isolation-forest-v2"
DETECTOR_NAME: Final = "isolation_forest_v2"
DETECTION_SOURCE: Final = "ML"
FEATURE_SCHEMA_VERSION: Final = "flow_features.v2"
SCORE_DEFINITION: Final = "-model.score_samples(features)"
DECISION_RULE: Final = "anomaly_score >= threshold"
FEATURE_SCHEMA_ARTIFACT_VERSION: Final = "controlled_v2_model_feature_schema.v1"
MODEL_METADATA_ARTIFACT_VERSION: Final = "controlled_v2_isolation_forest_model_metadata.v1"
MODEL_FEATURE_SCHEMA_PATH: Final = "contracts/features/flow_features_v2.json"
SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")

# Keep this list complete.  Comparing all estimator parameters (including
# values that happen to be sklearn defaults) prevents a compatible-looking,
# but differently fitted, model from being admitted.
FROZEN_MODEL_PARAMETERS: Final[dict[str, Any]] = {
    "n_estimators": 300,
    "max_samples": "auto",
    "contamination": "auto",
    "random_state": 42,
    "n_jobs": -1,
    "bootstrap": False,
    "max_features": 1.0,
    "warm_start": False,
    "verbose": 0,
}


class DetectorState(str, Enum):
    """Lifecycle state of the optional detector."""

    STARTING = "STARTING"
    READY = "READY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class ArtifactLoadError(RuntimeError):
    """Raised when a locked artifact cannot be admitted for inference."""


class MLUnavailableError(RuntimeError):
    """Raised when inference is requested while ML is not READY."""


class MLInferenceError(ValueError):
    """Payload-free inference failure; the detector is DEGRADED afterwards."""


def sha256_file(path: Path) -> str:
    """Return a file's SHA-256 without deserialising its contents."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except (OSError, UnicodeError) as error:
        raise ArtifactLoadError(f"cannot read artifact {path}: {error}") from None
    return digest.hexdigest()


def _read_hashed_bytes(path: Path) -> tuple[bytes, str]:
    try:
        data = path.read_bytes()
    except (OSError, UnicodeError) as error:
        raise ArtifactLoadError(f"cannot read artifact {path}: {error}") from None
    return data, hashlib.sha256(data).hexdigest()


def _read_json_bytes(data: bytes, name: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArtifactLoadError(f"cannot read JSON artifact {name}: {error}") from None
    if not isinstance(value, dict):
        raise ArtifactLoadError(f"JSON artifact {name} must contain an object")
    return value


def _read_json(path: Path) -> dict[str, Any]:
    data, _ = _read_hashed_bytes(path)
    return _read_json_bytes(data, str(path))


def _parse_bool(value: str | None) -> bool:
    if value is None or value == "":
        return False
    if value.lower() in {"1", "true", "yes", "on"}:
        return True
    if value.lower() in {"0", "false", "no", "off"}:
        return False
    raise ValueError("INTRIQO_ML_ENABLED must be true/false, 1/0, yes/no, or on/off")


def _path(value: str | None, name: str) -> Path:
    if not value:
        raise ValueError(f"{name} is required when INTRIQO_ML_ENABLED=true")
    return Path(value).expanduser()


def _expected_hash(value: str | None, name: str, default: str) -> str:
    result = value or default
    if not SHA256_PATTERN.fullmatch(result):
        raise ValueError(f"{name} must be a lowercase SHA-256 hash")
    return result


@dataclass(frozen=True)
class MLConfig:
    """Environment-backed configuration for the optional detector."""

    enabled: bool = False
    model_path: Path | None = None
    threshold_path: Path | None = None
    feature_schema_path: Path | None = None
    feature_contract_path: Path | None = None
    expected_model_sha256: str = LOCKED_MODEL_SHA256
    expected_threshold_sha256: str = LOCKED_THRESHOLD_SHA256
    model_metadata_path: Path | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> MLConfig:
        env = os.environ if environ is None else environ
        enabled = _parse_bool(env.get("INTRIQO_ML_ENABLED"))
        if not enabled:
            return cls()
        contract_default = Path(__file__).resolve().parents[3] / "contracts/features/flow_features_v2.json"
        metadata_value = env.get("INTRIQO_ML_MODEL_METADATA_PATH")
        return cls(
            enabled=True,
            model_path=_path(env.get("INTRIQO_ML_MODEL_PATH"), "INTRIQO_ML_MODEL_PATH"),
            threshold_path=_path(env.get("INTRIQO_ML_THRESHOLD_PATH"), "INTRIQO_ML_THRESHOLD_PATH"),
            feature_schema_path=_path(
                env.get("INTRIQO_ML_FEATURE_SCHEMA_PATH"), "INTRIQO_ML_FEATURE_SCHEMA_PATH"
            ),
            feature_contract_path=Path(
                env.get("INTRIQO_ML_FEATURE_CONTRACT_PATH", str(contract_default))
            ).expanduser(),
            model_metadata_path=Path(metadata_value).expanduser() if metadata_value else None,
            expected_model_sha256=_expected_hash(
                env.get("INTRIQO_ML_EXPECTED_MODEL_SHA256"),
                "INTRIQO_ML_EXPECTED_MODEL_SHA256",
                LOCKED_MODEL_SHA256,
            ),
            expected_threshold_sha256=_expected_hash(
                env.get("INTRIQO_ML_EXPECTED_THRESHOLD_SHA256"),
                "INTRIQO_ML_EXPECTED_THRESHOLD_SHA256",
                LOCKED_THRESHOLD_SHA256,
            ),
        )


@dataclass(frozen=True)
class LoadedArtifacts:
    """Verified artifacts held by a READY detector."""

    model: IsolationForest
    threshold: float
    model_sha256: str
    threshold_sha256: str
    feature_schema_version: str
    feature_order: tuple[str, ...]
    loaded_dtype: str
    model_input_dtype: str
    load_seconds: float


class LockedArtifactLoader:
    """Admit locked artifacts only after every boundary check succeeds."""

    def load(self, config: MLConfig) -> LoadedArtifacts:
        if not config.enabled or config.model_path is None or config.threshold_path is None:
            raise ArtifactLoadError("ML is disabled")
        if config.feature_schema_path is None or config.feature_contract_path is None:
            raise ArtifactLoadError("feature schema paths are incomplete")

        started = time.perf_counter()
        if config.expected_model_sha256 != LOCKED_MODEL_SHA256:
            raise ArtifactLoadError("configured model hash is not the locked v2 hash")
        if config.expected_threshold_sha256 != LOCKED_THRESHOLD_SHA256:
            raise ArtifactLoadError("configured threshold hash is not the locked v2 hash")

        # Read and hash the exact bytes that will later be passed to joblib.
        # Both artifact hashes are established before any model deserialisation.
        model_bytes, model_sha256 = _read_hashed_bytes(config.model_path)
        threshold_bytes, threshold_sha256 = _read_hashed_bytes(config.threshold_path)
        if model_sha256 != config.expected_model_sha256:
            raise ArtifactLoadError("model SHA-256 verification failed")
        if threshold_sha256 != config.expected_threshold_sha256:
            raise ArtifactLoadError("threshold SHA-256 verification failed")

        threshold_artifact = _read_json_bytes(threshold_bytes, str(config.threshold_path))
        self._verify_threshold(threshold_artifact, model_sha256)
        schema_artifact = _read_json(config.feature_schema_path)
        self._verify_feature_schema(schema_artifact, config.feature_contract_path)

        metadata_path = config.model_metadata_path or config.model_path.with_name("model_metadata.json")
        metadata_artifact = _read_json(metadata_path)
        self._verify_model_metadata(metadata_artifact, model_sha256)

        try:
            model = joblib.load(io.BytesIO(model_bytes))
        except Exception as error:  # noqa: BLE001 - deserialisation errors are backend-specific
            raise ArtifactLoadError(f"model loading failed: {type(error).__name__}") from None
        self._verify_fitted_model(model)

        return LoadedArtifacts(
            model=model,
            threshold=LOCKED_THRESHOLD,
            model_sha256=model_sha256,
            threshold_sha256=threshold_sha256,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_order=tuple(FEATURES_V2),
            loaded_dtype="float64",
            model_input_dtype="float32",
            load_seconds=time.perf_counter() - started,
        )

    @staticmethod
    def _verify_threshold(value: dict[str, Any], model_sha256: str) -> None:
        if value.get("threshold") != LOCKED_THRESHOLD:
            raise ArtifactLoadError("threshold value is not the locked validation threshold")
        if value.get("model_sha256") != model_sha256:
            raise ArtifactLoadError("threshold is not bound to the verified model")
        if value.get("comparison_operator") != ">=" or value.get("decision_rule") != DECISION_RULE:
            raise ArtifactLoadError("threshold decision rule is not locked")
        if value.get("score_definition") != SCORE_DEFINITION:
            raise ArtifactLoadError("threshold score convention is not locked")

    @staticmethod
    def _verify_feature_schema(value: dict[str, Any], contract_path: Path) -> None:
        if value.get("schema_version") != FEATURE_SCHEMA_ARTIFACT_VERSION:
            raise ArtifactLoadError("feature schema artifact version is not locked")
        if value.get("feature_schema") != FEATURE_SCHEMA_VERSION:
            raise ArtifactLoadError("feature schema version is not flow_features.v2")
        if value.get("feature_count") != len(FEATURES_V2):
            raise ArtifactLoadError("feature schema count is not nine")
        if value.get("features") != list(FEATURES_V2):
            raise ArtifactLoadError("feature schema order is not the frozen order")
        if value.get("loaded_dtype") != "float64" or value.get("model_input_dtype") != "float32":
            raise ArtifactLoadError("feature dtypes do not match the locked artifact")
        if value.get("preprocessing") != "NONE":
            raise ArtifactLoadError("preprocessing is not permitted for the locked model")
        if value.get("contract_path") != MODEL_FEATURE_SCHEMA_PATH:
            raise ArtifactLoadError("feature contract path is not locked")
        if value.get("contract_sha256") != LOCKED_CONTRACT_SHA256:
            raise ArtifactLoadError("feature contract SHA-256 is not the frozen contract")
        if sha256_file(contract_path) != LOCKED_CONTRACT_SHA256:
            raise ArtifactLoadError("feature contract SHA-256 verification failed")

    @staticmethod
    def _verify_model_metadata(value: dict[str, Any], model_sha256: str) -> None:
        if value.get("schema_version") != MODEL_METADATA_ARTIFACT_VERSION:
            raise ArtifactLoadError("model metadata artifact version is not locked")
        if value.get("model_class") != "sklearn.ensemble.IsolationForest":
            raise ArtifactLoadError("model metadata class is not IsolationForest")
        if value.get("model_sha256") != model_sha256:
            raise ArtifactLoadError("model metadata is not bound to the verified model")
        if value.get("feature_schema") != MODEL_FEATURE_SCHEMA_PATH:
            raise ArtifactLoadError("model metadata feature schema path is not locked")
        if value.get("feature_contract_sha256") != LOCKED_CONTRACT_SHA256:
            raise ArtifactLoadError("model metadata contract hash is not frozen")
        if value.get("feature_order") != list(FEATURES_V2) or value.get("features") != list(FEATURES_V2):
            raise ArtifactLoadError("model metadata feature order is not the frozen order")
        if value.get("loaded_dtype") != "float64" or value.get("model_input_dtype") != "float32":
            raise ArtifactLoadError("model metadata dtypes do not match the locked artifact")
        if value.get("preprocessing") != "NONE":
            raise ArtifactLoadError("model metadata preprocessing is not permitted")
        if value.get("score_definition") != SCORE_DEFINITION or value.get("decision_rule") != DECISION_RULE:
            raise ArtifactLoadError("model metadata scoring contract is not locked")
        parameters = value.get("parameters")
        metadata_parameters = {
            name: expected for name, expected in FROZEN_MODEL_PARAMETERS.items() if name != "verbose"
        }
        if parameters != metadata_parameters:
            raise ArtifactLoadError("model metadata parameters are not locked")
        if value.get("resolved_parameters") != FROZEN_MODEL_PARAMETERS:
            raise ArtifactLoadError("model metadata resolved parameters are not locked")

    @staticmethod
    def _verify_fitted_model(model: Any) -> None:
        if not isinstance(model, IsolationForest):
            raise ArtifactLoadError("model artifact is not an IsolationForest")
        try:
            check_is_fitted(model)
            parameters = model.get_params(deep=False)
        except Exception as error:  # noqa: BLE001 - sklearn fit checks are backend-specific
            raise ArtifactLoadError(f"loaded model is not fitted: {type(error).__name__}") from None
        for name, expected in FROZEN_MODEL_PARAMETERS.items():
            if parameters.get(name) != expected:
                raise ArtifactLoadError(f"model parameter {name} is not locked")
        if getattr(model, "n_features_in_", None) != len(FEATURES_V2):
            raise ArtifactLoadError("model feature count is not the frozen nine-feature contract")
        estimators = getattr(model, "estimators_", None)
        if not isinstance(estimators, list) or len(estimators) != FROZEN_MODEL_PARAMETERS["n_estimators"]:
            raise ArtifactLoadError("model estimator count is not locked")
        feature_names = getattr(model, "feature_names_in_", None)
        if feature_names is not None and tuple(feature_names) != tuple(FEATURES_V2):
            raise ArtifactLoadError("model feature names are not in the frozen order")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class MLDetectionResult:
    """A label-free, serialisable decision for one native flow record."""

    detector_name: str
    model_version: str
    engine_instance_id: str
    flow_id: str
    anomaly_score: float
    threshold: float
    is_anomaly: bool
    feature_schema_version: str
    inference_timestamp: str
    model_sha256: str
    threshold_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "detector": self.detector_name,
            "model_version": self.model_version,
            "engine_instance_id": self.engine_instance_id,
            "flow_id": self.flow_id,
            "anomaly_score": self.anomaly_score,
            "threshold": self.threshold,
            "is_anomaly": self.is_anomaly,
            "feature_schema_version": self.feature_schema_version,
            "inference_timestamp": self.inference_timestamp,
            "model_sha256": self.model_sha256,
            "threshold_sha256": self.threshold_sha256,
        }


def _revalidate_record(record: FlowFeatureRecordV2) -> FlowFeatureRecordV2:
    """Re-run bounded wire validation, including for forged Pydantic models."""

    if type(record) is not FlowFeatureRecordV2:
        raise ValueError("record is not a flow_features.v2 record")
    try:
        if not _model_shape_is_exact(record):
            raise ValueError("forged model shape")
        payload = record.model_dump(mode="json")
        encoded = json.dumps(payload, allow_nan=False, separators=(",", ":"))
        return parse_flow_feature_record_v2(encoded)
    except Exception:  # noqa: BLE001 - forged Pydantic models may fail in several ways
        raise ValueError("record is not a validated flow_features.v2 record") from None


def _model_shape_is_exact(value: object) -> bool:
    if not isinstance(value, BaseModel):
        return True
    fields = set(type(value).model_fields)
    if set(value.__dict__) != fields or getattr(value, "__pydantic_extra__", None):
        return False
    return all(_model_shape_is_exact(getattr(value, name)) for name in fields)


class MLDetector:
    """Stateful optional scorer with no training or feature recomputation."""

    def __init__(self, config: MLConfig, loader: LockedArtifactLoader | None = None) -> None:
        self.config = config
        self.state = DetectorState.STARTING
        self.failure_reason: str | None = None
        self.artifacts: LoadedArtifacts | None = None
        if not config.enabled:
            self.state = DetectorState.DEGRADED
            self.failure_reason = "disabled_by_configuration"
            return
        try:
            self.artifacts = (loader or LockedArtifactLoader()).load(config)
        except Exception:  # noqa: BLE001 - artifact backends must fail closed
            self.state = DetectorState.FAILED
            self.failure_reason = "artifact_load_failed"
        else:
            self.state = DetectorState.READY

    @property
    def load_seconds(self) -> float:
        return self.artifacts.load_seconds if self.artifacts is not None else 0.0

    def detect(self, record: FlowFeatureRecordV2) -> MLDetectionResult:
        if self.state is not DetectorState.READY or self.artifacts is None:
            raise MLUnavailableError(self.failure_reason or f"ML detector state is {self.state.value}")
        try:
            validated = _revalidate_record(record)
            vector = np.asarray(project_flow_features_v2(validated), dtype=np.float32)
            if vector.shape != (len(FEATURES_V2),) or not np.all(np.isfinite(vector)):
                raise ValueError("native v2 projection is not a finite nine-feature vector")
            score_values = scores_from_sklearn(self.artifacts.model, vector.reshape(1, -1))
            if np.asarray(score_values).shape != (1,):
                raise ValueError("model returned an invalid anomaly score")
            score = float(score_values[0])
            if not math.isfinite(score):
                raise ValueError("model returned a non-finite anomaly score")
        except Exception:  # noqa: BLE001 - isolate every inference backend failure
            self.state = DetectorState.DEGRADED
            self.failure_reason = "inference_failed"
            raise MLInferenceError("inference_failed") from None
        return MLDetectionResult(
            detector_name=DETECTOR_NAME,
            model_version=LOCKED_MODEL_VERSION,
            engine_instance_id=validated.metadata.engine_instance_id,
            flow_id=validated.metadata.flow_id,
            anomaly_score=score,
            threshold=self.artifacts.threshold,
            is_anomaly=score >= self.artifacts.threshold,
            feature_schema_version=self.artifacts.feature_schema_version,
            inference_timestamp=_utc_now(),
            model_sha256=self.artifacts.model_sha256,
            threshold_sha256=self.artifacts.threshold_sha256,
        )


def deterministic_event_id(result: MLDetectionResult) -> str:
    """Return a stable UUID so Control Plane retries are idempotent."""

    key = f"{result.engine_instance_id}|{result.flow_id}|{result.detector_name}|{result.model_sha256}"
    return str(uuid5(NAMESPACE_URL, f"intriqo:ml-anomaly:{key}"))
