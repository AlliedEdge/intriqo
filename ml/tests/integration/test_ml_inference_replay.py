"""Replay enrolled native-v2 captures through deterministic and ML paths.

The inputs and model are immutable enrollment artifacts.  Every replay output
is written below pytest's temporary directory; this module never fits a model,
rewrites a corpus, or writes beside the enrolled records.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, cast

import numpy as np
import pytest

pytest.importorskip("sklearn")
pytest.importorskip("joblib")

from intriqo_ml.flow_features_v2 import (
    FEATURES_V2,
    FlowFeatureRecordV2,
    iter_flow_feature_records_v2,
    parse_flow_feature_record_v2,
    project_flow_features_v2,
)
from intriqo_ml.inference_v2 import (
    DetectorState,
    MLConfig,
    MLDetectionResult,
    MLDetector,
    MLUnavailableError,
)
from intriqo_ml.ml_transport import (
    ControlPlaneTransport,
    TransportConfig,
)
from intriqo_ml.ml_worker import (
    DecisionLedger,
    DetectorLike,
    MLWorker,
    TransportLike,
)
from intriqo_ml.models.isolation_forest import scores_from_sklearn
from intriqo_ml.models.isolation_forest_v2 import _model_input

ROOT = Path(__file__).resolve().parents[3]
ENGINE = Path(
    os.environ.get(
        "INTRIQO_ENGINE_BINARY",
        str(ROOT / "build/runtime-release-ml-integration/engine/intriqo-engine"),
    )
)
ENROLLED_ROOT = ROOT / "ml/artifacts/feature-analysis/controlled-v2"
MODEL_ROOT = ROOT / "ml/artifacts/models/controlled-v2/isolation-forest-v2"
CAPTURE_IDS: Final[dict[str, str]] = {
    "benign": "cap-test-benign-mixed-64af578ae077",
    "scan": "cap-validation-port-scan-946c553a52d3",
    "syn": "cap-validation-syn-flood-febd1fb23294",
}
Mode = Literal["both", "suppressed"]


@dataclass(frozen=True)
class CaptureAsset:
    kind: str
    capture_id: str
    pcap: Path
    enrolled_features: Path


@dataclass(frozen=True)
class Replay:
    asset: CaptureAsset
    records: tuple[FlowFeatureRecordV2, ...]
    events: tuple[dict[str, Any], ...]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _asset(kind: str, capture_id: str) -> CaptureAsset | None:
    manifest_path = ENROLLED_ROOT / "completed_capture_manifest.json"
    if not manifest_path.is_file():
        return None
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entry = next(
        (row for row in manifest.get("captures", []) if row.get("capture_id") == capture_id),
        None,
    )
    if not isinstance(entry, dict) or entry.get("status") != "CAPTURED":
        return None
    pcap = Path(str(entry.get("source_path", "")))
    enrolled = (
        ENROLLED_ROOT
        / "run-complete-20261006"
        / "replay"
        / capture_id
        / "native_features_v2.jsonl"
    )
    if (
        not pcap.is_file()
        or not enrolled.is_file()
        or pcap.stat().st_size != entry.get("byte_size")
        or _sha256(pcap) != entry.get("sha256")
    ):
        return None
    return CaptureAsset(kind, capture_id, pcap, enrolled)


def _assets() -> dict[str, CaptureAsset]:
    if not ENGINE.is_file():
        pytest.skip("controlled-v2 engine is unavailable")
    assets = {
        kind: _asset(kind, capture_id) for kind, capture_id in CAPTURE_IDS.items()
    }
    if any(asset is None for asset in assets.values()):
        pytest.skip("completed capture manifest, raw PCAP, or enrolled replay is unavailable")
    return {kind: asset for kind, asset in assets.items() if asset is not None}


def _engine_detector_args(kind: str, mode: Mode) -> list[str]:
    args = ["--flow-idle-timeout", "1.0", "--max-active-flows", "100000"]
    if kind == "scan":
        if mode == "both":
            args.extend(
                [
                    "--portscan-window",
                    "10",
                    "--portscan-unique-port-threshold",
                    "3",
                    "--portscan-minimum-attempts",
                    "3",
                ]
            )
        else:
            args.extend(
                [
                    "--portscan-window",
                    "10",
                    "--portscan-unique-port-threshold",
                    "65535",
                    "--portscan-minimum-attempts",
                    "65535",
                ]
            )
        args.append("--disable-syn-flood")
    elif kind == "syn":
        args.extend(
            [
                "--portscan-window",
                "10",
                "--portscan-unique-port-threshold",
                "65535",
                "--portscan-minimum-attempts",
                "65535",
            ]
        )
        if mode == "both":
            args.extend(
                [
                    "--synflood-minimum-attempts",
                    "1",
                    "--synflood-minimum-rate",
                    "0",
                    "--synflood-minimum-incomplete",
                    "1",
                    "--synflood-minimum-observation",
                    "0.0001",
                    "--synflood-incomplete-ratio",
                    "0",
                ]
            )
        else:
            args.append("--disable-syn-flood")
    else:
        args.extend(
            [
                "--portscan-window",
                "10",
                "--portscan-unique-port-threshold",
                "65535",
                "--portscan-minimum-attempts",
                "65535",
                "--disable-syn-flood",
            ]
        )
    return args


def _run_replay(asset: CaptureAsset, output_dir: Path, mode: Mode) -> Replay:
    output_dir.mkdir(parents=True)
    feature_path = output_dir / "native_features_v2.jsonl"
    event_path = output_dir / "events.jsonl"
    command = [
        str(ENGINE),
        "--pcap",
        str(asset.pcap),
        "--feature-schema",
        "flow_features.v2",
        "--feature-output",
        str(feature_path),
        "--output",
        str(event_path),
        *_engine_detector_args(asset.kind, mode),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert feature_path.is_file() and event_path.is_file()
    with feature_path.open("rb") as stream:
        records = tuple(
            line.record for line in iter_flow_feature_records_v2(stream) if line.record is not None
        )
    events = tuple(
        json.loads(line)
        for line in event_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    )
    assert records
    return Replay(asset, records, events)


def _event_fingerprint(events: tuple[dict[str, Any], ...]) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (
            str(event["event_type"]),
            str(event["source_address"]),
            str(event["details"]["detector"]),
        )
        for event in events
    )


def _worker(
    records: tuple[FlowFeatureRecordV2, ...],
    output_dir: Path,
    detector: DetectorLike,
    transport: TransportLike | None = None,
    extra_input: bytes = b"",
) -> tuple[list[dict[str, Any]], dict[str, int | str]]:
    output_dir.mkdir(parents=True)
    output = io.StringIO()
    stream = extra_input + b"".join(
        record.model_dump_json().encode("utf-8") + b"\n" for record in records
    )
    with DecisionLedger(output_dir / "decisions.sqlite", max_entries=100) as ledger:
        result = MLWorker(detector, ledger, output, transport=transport).run(io.BytesIO(stream))
    payloads = [
        json.loads(line)
        for line in output.getvalue().splitlines()
        if line.strip()
    ]
    return payloads, cast(dict[str, int | str], result)


class _CrashingDetector:
    state = DetectorState.READY

    def detect(self, _record: FlowFeatureRecordV2) -> MLDetectionResult:
        raise RuntimeError("test detector failure")


class _UnavailableDetector:
    state = DetectorState.DEGRADED

    def detect(self, _record: FlowFeatureRecordV2) -> MLDetectionResult:
        raise MLUnavailableError("test detector unavailable")


def _config() -> MLConfig:
    return MLConfig(
        enabled=True,
        model_path=MODEL_ROOT / "model.joblib",
        threshold_path=MODEL_ROOT / "threshold.json",
        feature_schema_path=MODEL_ROOT / "feature_schema.json",
        feature_contract_path=ROOT / "contracts/features/flow_features_v2.json",
    )


def _load_detector() -> MLDetector:
    for path in (
        MODEL_ROOT / "model.joblib",
        MODEL_ROOT / "threshold.json",
        MODEL_ROOT / "feature_schema.json",
        ROOT / "contracts/features/flow_features_v2.json",
    ):
        if not path.is_file():
            pytest.skip("locked controlled-v2 model artifacts are unavailable")
    detector = MLDetector(_config())
    assert detector.state is DetectorState.READY, detector.failure_reason
    assert detector.artifacts is not None
    return detector


def test_enrolled_replay_preserves_nine_native_values_and_locked_float32_scores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = _assets()
    replays = {
        kind: _run_replay(asset, tmp_path / "replay" / kind, "both")
        for kind, asset in assets.items()
    }
    for replay in replays.values():
        enrolled = [
            parse_flow_feature_record_v2(line)
            for line in replay.asset.enrolled_features.read_bytes().splitlines()
            if line.strip()
        ]
        assert len(replay.records) == len(enrolled)
        for actual, expected in zip(replay.records, enrolled, strict=True):
            assert actual.metadata.engine_instance_id != expected.metadata.engine_instance_id
            assert tuple(getattr(actual.features, name) for name in FEATURES_V2) == tuple(
                getattr(expected.features, name) for name in FEATURES_V2
            )
        assert _sha256(replay.asset.pcap) == next(
            row["sha256"]
            for row in json.loads(
                (ENROLLED_ROOT / "completed_capture_manifest.json").read_text()
            )["captures"]
            if row["capture_id"] == replay.asset.capture_id
        )

    detector = _load_detector()
    scored_records = tuple(
        record
        for replay in replays.values()
        for record in replay.records
    )
    seen_inputs: list[np.ndarray[Any, Any]] = []
    from intriqo_ml import inference_v2

    original_score = scores_from_sklearn

    def score_spy(model: object, features: Any) -> np.ndarray[Any, Any]:
        captured = np.asarray(features).copy()
        seen_inputs.append(captured)
        return original_score(model, features)

    monkeypatch.setattr(inference_v2, "scores_from_sklearn", score_spy)
    observed = [detector.detect(record).anomaly_score for record in scored_records]
    assert len(seen_inputs) == len(scored_records)
    for record, captured in zip(scored_records, seen_inputs, strict=True):
        native = np.asarray(project_flow_features_v2(record), dtype=np.float32).reshape(1, -1)
        assert captured.dtype == np.dtype(np.float32)
        assert np.array_equal(captured, native)

    assert detector.artifacts is not None
    canonical_input = _model_input(
        np.asarray([project_flow_features_v2(record) for record in scored_records], dtype=np.float64)
    )
    canonical_scores = scores_from_sklearn(detector.artifacts.model, canonical_input)
    np.testing.assert_allclose(observed, canonical_scores, rtol=1e-12, atol=1e-12)


def test_a_to_e_ml_deterministic_coexistence_and_failure_independence(tmp_path: Path) -> None:
    assets = _assets()
    detector = _load_detector()
    both = {
        kind: _run_replay(asset, tmp_path / "A-both" / kind, "both")
        for kind, asset in assets.items()
    }
    ml_only = {
        kind: _run_replay(asset, tmp_path / "B-ml-only" / kind, "suppressed")
        for kind, asset in assets.items()
    }
    expected_both = {"benign": (), "scan": ("PORT_SCAN",), "syn": ("SYN_FLOOD",)}
    for kind, replay in both.items():
        assert tuple(event["event_type"] for event in replay.events) == expected_both[kind]
    assert all(not replay.events for replay in ml_only.values())

    # A: both paths observe the same enrolled replay; B: CLI thresholds suppress
    # deterministic output while the locked ML worker remains independent.
    both_payloads: dict[str, list[dict[str, Any]]] = {}
    ml_only_payloads: dict[str, list[dict[str, Any]]] = {}
    for kind, replay in both.items():
        payloads, stats = _worker(replay.records, tmp_path / "A-worker" / kind, detector)
        both_payloads[kind] = payloads
        assert int(stats["anomalies"]) == len(payloads)
        suppressed_payloads, suppressed_stats = _worker(
            ml_only[kind].records, tmp_path / "B-worker" / kind, detector
        )
        ml_only_payloads[kind] = suppressed_payloads
        assert int(suppressed_stats["anomalies"]) == len(suppressed_payloads)
    assert not both_payloads["benign"]
    assert both_payloads["scan"] and both_payloads["syn"]
    assert ml_only_payloads["scan"] and ml_only_payloads["syn"]

    # C: disabling ML leaves deterministic results unchanged.  D/E: a worker
    # crash, unavailable detector, malformed input, or failed CP delivery does
    # not alter the deterministic event stream.
    deterministic_disabled = {
        kind: _run_replay(asset, tmp_path / "C-ml-disabled" / kind, "both")
        for kind, asset in assets.items()
    }
    for kind in assets:
        assert _event_fingerprint(deterministic_disabled[kind].events) == _event_fingerprint(
            both[kind].events
        )

    crash_payloads, crash_stats = _worker(
        both["scan"].records, tmp_path / "D-crash", _CrashingDetector()
    )
    unavailable_payloads, unavailable_stats = _worker(
        both["scan"].records, tmp_path / "D-unavailable", _UnavailableDetector()
    )
    malformed_payloads, malformed_stats = _worker(
        (), tmp_path / "E-malformed", detector, extra_input=b"not-json\n"
    )
    failing_transport = ControlPlaneTransport(
        TransportConfig(base_url="http://127.0.0.1:9", token="test", timeout_seconds=0.1)
    )
    try:
        failed_delivery_payloads, failed_delivery_stats = _worker(
            both["scan"].records, tmp_path / "E-control-plane-failure", detector, failing_transport
        )
    finally:
        failing_transport.close()
    assert not crash_payloads and int(crash_stats["inference_errors"]) == len(both["scan"].records)
    assert not unavailable_payloads
    assert int(unavailable_stats["inference_errors"]) == len(both["scan"].records)
    assert not malformed_payloads and int(malformed_stats["rejected"]) == 1
    assert failed_delivery_payloads
    assert int(failed_delivery_stats["delivery_failures"]) == len(failed_delivery_payloads)
    for kind in assets:
        assert _event_fingerprint(both[kind].events) == _event_fingerprint(
            deterministic_disabled[kind].events
        )
