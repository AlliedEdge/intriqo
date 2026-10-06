"""Locked native-v2 inference through the authenticated worker transport.

This test deliberately consumes an already enrolled native record and a PCAP
already present in ``/tmp/opencode/intriqo-controlled-v2/raw``.  It never
creates a capture or corpus.  The only files written by the C++ replay are in
pytest's temporary directory.
"""

from __future__ import annotations

import asyncio
import importlib
import io
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTROL_PLANE = ROOT / "control-plane"
ML_SRC = ROOT / "ml/src"
AGENTS_SRC = ROOT / "agents/src"
ENGINE = Path(
    os.environ.get(
        "INTRIQO_ENGINE_BINARY", str(ROOT / "build/flow-release/engine/intriqo-engine")
    )
)
RAW_ROOT = Path("/tmp/opencode/intriqo-controlled-v2/raw")
ENROLLED_ROOT = ROOT / "ml/artifacts/feature-analysis/controlled-v2"
MODEL_ROOT = ROOT / "ml/artifacts/models/controlled-v2/isolation-forest-v2"

if str(ML_SRC) not in sys.path:
    sys.path.insert(0, str(ML_SRC))
if str(AGENTS_SRC) not in sys.path:
    sys.path.insert(0, str(AGENTS_SRC))


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _database_url() -> str:
    return os.environ.get(
        "TEST_DATABASE_URL",
        os.environ.get(
            "DATABASE_URL", "postgresql+asyncpg://intriqo:intriqo_dev@localhost:5432/intriqo"
        ),
    )


def _asset_pair() -> tuple[Path, Path] | None:
    """Return the manifest-validated enrolled anomalous capture and PCAP."""
    capture_id = "cap-validation-syn-flood-febd1fb23294"
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
    pcap = Path(str(entry["source_path"]))
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
    return enrolled, pcap


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


async def _select_persisted_event(event_id: str) -> dict[str, Any]:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_database_url().split("?", 1)[0], connect_args={"ssl": False})
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text(
                    "SELECT event_id, event_type, severity, source_address, "
                    "destination_address, raw_payload FROM security_events "
                    "WHERE event_id = :event_id"
                ),
                {"event_id": event_id},
            )
            row = result.mappings().one_or_none()
            assert row is not None
            return dict(row)
    finally:
        await engine.dispose()


async def _cleanup_created_rows(
    event_ids: list[str],
    incident_ids: list[str],
    task_ids: list[str] | None = None,
    finding_ids: list[str] | None = None,
) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_database_url().split("?", 1)[0], connect_args={"ssl": False})
    try:
        async with engine.begin() as connection:
            for finding_id in finding_ids or []:
                await connection.execute(
                    text("DELETE FROM audit_logs WHERE resource_id = :resource_id"),
                    {"resource_id": finding_id},
                )
                await connection.execute(
                    text("DELETE FROM findings WHERE finding_id = :finding_id"),
                    {"finding_id": finding_id},
                )
            for task_id in task_ids or []:
                await connection.execute(
                    text("DELETE FROM audit_logs WHERE resource_id = :resource_id"),
                    {"resource_id": task_id},
                )
                await connection.execute(
                    text("DELETE FROM agent_tasks WHERE task_id = :task_id"),
                    {"task_id": task_id},
                )
            for incident_id in incident_ids:
                await connection.execute(
                    text("DELETE FROM incident_events WHERE incident_id = :incident_id"),
                    {"incident_id": incident_id},
                )
                await connection.execute(
                    text("DELETE FROM audit_logs WHERE resource_id = :resource_id"),
                    {"resource_id": incident_id},
                )
                await connection.execute(
                    text("DELETE FROM incidents WHERE incident_id = :incident_id"),
                    {"incident_id": incident_id},
                )
            for event_id in event_ids:
                await connection.execute(
                    text("DELETE FROM audit_logs WHERE resource_id = :resource_id"),
                    {"resource_id": event_id},
                )
                await connection.execute(
                    text("DELETE FROM security_events WHERE event_id = :event_id"),
                    {"event_id": event_id},
                )
    finally:
        await engine.dispose()


def _replay(engine: Path, pcap: Path, output_dir: Path) -> tuple[Path, Path]:
    features = output_dir / "native_features_v2.jsonl"
    events = output_dir / "events.jsonl"
    output_dir.mkdir()
    run = subprocess.run(
        [
            str(engine),
            "--pcap",
            str(pcap),
            "--feature-schema",
            "flow_features.v2",
            "--feature-output",
            str(features),
            "--output",
            str(events),
            "--flow-idle-timeout",
            "1",
            "--max-active-flows",
            "100000",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert run.returncode == 0, run.stderr
    assert features.is_file() and features.stat().st_size > 0
    return features, events


def test_locked_ml_event_persists_deduplicates_and_links_to_analyst_incident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("sklearn")
    pytest.importorskip("joblib")
    asset_pair = _asset_pair()
    if not ENGINE.is_file() or asset_pair is None:
        pytest.skip("controlled-v2 engine, enrolled record, or raw PCAP is unavailable")

    # Imports stay below the availability checks so this repository's normal
    # control-plane-only test environment does not need the ML stack installed.
    from intriqo_ml.flow_features_v2 import (
        iter_flow_feature_records_v2,
        parse_flow_feature_record_v2,
    )
    from intriqo_ml.inference_v2 import MLConfig, MLDetector
    from intriqo_ml.ml_transport import (
        ControlPlaneTransport,
        DeliveryStatus,
        TransportConfig,
    )
    from intriqo_ml.ml_worker import DecisionLedger, MLWorker

    enrolled_path, pcap = asset_pair
    enrolled_raw = next(line for line in enrolled_path.read_bytes().splitlines() if line.strip())
    enrolled_record = parse_flow_feature_record_v2(enrolled_raw)
    assert enrolled_record.schema_version == "flow_features.v2"

    features_path, events_path = _replay(ENGINE, pcap, tmp_path / "native-replay")
    with features_path.open("rb") as stream:
        records = [line.record for line in iter_flow_feature_records_v2(stream) if line.record is not None]
    assert records
    detector = MLDetector(
        MLConfig(
            enabled=True,
            model_path=MODEL_ROOT / "model.joblib",
            threshold_path=MODEL_ROOT / "threshold.json",
            feature_schema_path=MODEL_ROOT / "feature_schema.json",
            feature_contract_path=ROOT / "contracts/features/flow_features_v2.json",
        )
    )
    assert detector.state.value == "READY", detector.failure_reason
    assert events_path.is_file()

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    jwt_secret = secrets.token_urlsafe(32)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(CONTROL_PLANE / "src"), env.get("PYTHONPATH", "")]
    )
    env["APP_ENV"] = "test"
    env["REQUIRE_EMAIL_VERIFICATION"] = "false"
    env["RESEND_API_KEY"] = ""
    env["JWT_SECRET_KEY"] = jwt_secret
    env["DATABASE_URL"] = _database_url()
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("REQUIRE_EMAIL_VERIFICATION", "false")
    monkeypatch.setenv("RESEND_API_KEY", "")
    monkeypatch.setenv("JWT_SECRET_KEY", jwt_secret)
    monkeypatch.syspath_prepend(str(CONTROL_PLANE / "src"))
    auth_tokens: Any = importlib.import_module("intriqo.auth.tokens")
    config: Any = importlib.import_module("intriqo.config")

    config.get_settings.cache_clear()
    agent_token = cast(
        str,
        auth_tokens.create_access_token(
            "agent_service", "AGENT", extra={"user_id": "user-agent-1"}
        ),
    )
    analyst_token = cast(
        str,
        auth_tokens.create_access_token(
            "analyst_user", "ANALYST", extra={"user_id": "user-analyst-1"}
        ),
    )
    event_ids: list[str] = []
    incident_ids: list[str] = []
    task_ids: list[str] = []
    finding_ids: list[str] = []
    payload: dict[str, Any] | None = None
    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "intriqo.api.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=CONTROL_PLANE,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with httpx.Client(base_url=base_url, timeout=10) as client:
            for _ in range(50):
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    time.sleep(0.1)
            else:
                pytest.skip("PostgreSQL-backed FastAPI test service is unavailable")

            transport = ControlPlaneTransport(
                TransportConfig(base_url=base_url, token=agent_token)
            )
            try:
                output = io.StringIO()
                with DecisionLedger(tmp_path / "ml-decisions.sqlite", max_entries=100) as ledger:
                    worker = MLWorker(detector, ledger, output, transport=transport)
                    stats = worker.run(io.BytesIO(features_path.read_bytes()))
                assert int(stats["anomalies"]) >= 1
                assert int(stats["delivered"]) >= 1
                payload = json.loads(output.getvalue().splitlines()[0])
                assert isinstance(payload, dict)
                event_ids.append(str(payload["event_id"]))
                assert payload["details"]["detection_source"] == "ML"
                assert payload["details"]["detector"] == "isolation_forest_v2"
                assert set(payload["details"]) == {"detection_source", "detector", "result"}
                assert "ports" not in payload["details"] and "labels" not in payload["details"]
                duplicate = transport.send(payload)
                assert duplicate.status is DeliveryStatus.DUPLICATE
            finally:
                transport.close()

            agent_headers = {"Authorization": f"Bearer {agent_token}"}
            analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
            read_back = client.get(
                f"/api/v1/events/{payload['event_id']}", headers=agent_headers
            )
            assert read_back.status_code == 200, read_back.text
            assert read_back.json()["details"] == payload["details"]
            persisted = asyncio.run(_select_persisted_event(str(payload["event_id"])))
            assert persisted["event_id"] == payload["event_id"]
            assert persisted["event_type"] == "ML_ANOMALY"
            assert persisted["severity"] == "MEDIUM"
            persisted_payload = persisted["raw_payload"]
            assert persisted_payload["event_id"] == payload["event_id"]
            assert persisted_payload["event_type"] == payload["event_type"]
            assert persisted_payload["severity"] == payload["severity"]
            assert persisted_payload["source_address"] == payload["source_address"]
            assert persisted_payload["destination_address"] == payload["destination_address"]
            assert persisted_payload["details"] == payload["details"]
            assert persisted_payload["description"] is None
            assert datetime.fromisoformat(persisted_payload["timestamp"]) == datetime.fromisoformat(
                payload["timestamp"].replace("Z", "+00:00")
            )

            duplicate_response = client.post(
                "/api/v1/events", json=payload, headers=agent_headers
            )
            assert duplicate_response.status_code == 409
            assert duplicate_response.json()["error"]["code"] == "DUPLICATE_EVENT"
            denied = client.post(
                "/api/v1/incidents",
                json={"title": "ML anomaly", "severity": "MEDIUM", "event_ids": [payload["event_id"]]},
                headers=agent_headers,
            )
            assert denied.status_code == 403
            linked = client.post(
                "/api/v1/incidents",
                json={"title": "ML anomaly", "severity": "MEDIUM", "event_ids": [payload["event_id"]]},
                headers=analyst_headers,
            )
            assert linked.status_code == 201, linked.text
            incident_ids.append(str(linked.json()["incident_id"]))
            assert linked.json()["linked_event_ids"] == [payload["event_id"]]

            task_response = client.post(
                "/api/v1/agent-tasks",
                json={
                    "task_type": "INVESTIGATION",
                    "description": "Review the controlled ML anomaly.",
                    "priority": "MEDIUM",
                    "event_id": payload["event_id"],
                    "incident_id": linked.json()["incident_id"],
                },
                headers=analyst_headers,
            )
            assert task_response.status_code == 201, task_response.text
            task_id = str(task_response.json()["task_id"])
            task_ids.append(task_id)

            from intriqo_agents.control_plane.client import ControlPlaneClient
            from intriqo_agents.investigation.agent import InvestigationAgent

            with ControlPlaneClient(base_url, agent_token) as agent_client:
                investigation = InvestigationAgent().execute_task(task_id, agent_client)
            assert investigation.status == "SUCCESS", investigation.error

            finding_response = client.get(
                "/api/v1/findings",
                headers=agent_headers,
                params={"task_id": task_id, "page": 1, "page_size": 10},
            )
            assert finding_response.status_code == 200, finding_response.text
            finding = finding_response.json()["items"][0]
            finding_ids.append(str(finding["finding_id"]))
            assert finding["event_id"] == payload["event_id"]
            assert finding["incident_id"] == linked.json()["incident_id"]
            assert finding["source"] == "ML"
            assert finding["evidence"][0]["type"] == "ml_anomaly_analysis"
            assert finding["task_id"] == task_id
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        if event_ids or incident_ids or task_ids or finding_ids:
            asyncio.run(_cleanup_created_rows(event_ids, incident_ids, task_ids, finding_ids))
