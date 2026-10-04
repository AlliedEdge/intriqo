"""Opt-in loopback SYN-flood detector -> HTTP -> FastAPI -> PostgreSQL tests.

Set ``INTRIQO_RUN_LIVE_TEST=1`` after building the engine.  The test creates
only unique rows and never clears PostgreSQL, so it must not be used as a
database-reset fixture while another regression suite is running.  If the
host process cannot open a raw socket, set ``INTRIQO_LIVE_DOCKER_IMAGE`` to
the existing validation image; both the engine and the stdlib-only raw
generator then run in capability-dropped containers with NET_RAW added back.
"""

from __future__ import annotations

import os
import json
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "control-plane"
FIXTURE = ROOT / "engine" / "tests" / "fixtures" / "syn_flood_fixture.py"


def _engine_path() -> Path:
    configured = os.environ.get("INTRIQO_ENGINE_BINARY")
    candidates = [Path(configured)] if configured else [
        ROOT / "build" / "runtime-release" / "engine" / "intriqo-engine",
        ROOT / "build" / "runtime-release" / "intriqo-engine",
        ROOT / "engine" / "build" / "intriqo-engine",
        ROOT / "engine" / "build-syn" / "intriqo-engine",
    ]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    pytest.skip("build the engine or set INTRIQO_ENGINE_BINARY")


def _can_open_raw_socket() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW):
            return True
    except OSError:
        return False


def _reserve_closed_port() -> int:
    # The bind is a local availability check only.  Closing immediately before
    # the raw sender starts leaves this destination deliberately closed.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.2", 0))
        return int(probe.getsockname()[1])


def _register_agent(client: Any, username: str, password: str) -> str:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            "role": "AGENT",
        },
    )
    assert response.status_code == 201, "test identity registration failed"
    # Public registration intentionally creates ANALYST users. Provision ONLY
    # this unique test identity as an engine service account in the authorized
    # local development DB; do not weaken public registration or auth/RBAC.
    import psycopg2
    user_id = response.json()["id"]
    with psycopg2.connect(_database_url()) as database, database.cursor() as cursor:
        cursor.execute(
            "UPDATE users SET role='AGENT', email_verified_at=CURRENT_TIMESTAMP "
            "WHERE id=%s AND username=%s",
            (user_id, username),
        )
        assert cursor.rowcount == 1, "test service identity provisioning failed"
    login = client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )
    assert login.status_code == 200, "test identity login failed"
    token = login.json().get("access_token")
    assert isinstance(token, str) and token
    return token


def _docker_engine_command(engine: Path, args: list[str], name: str, image: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "host",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--user",
        "0",
        "-v",
        f"{engine}:/engine:ro",
        "-v",
        "/usr/lib/x86_64-linux-gnu:/host-lib:ro",
        "-e",
        "INTRIQO_CONTROL_PLANE_URL",
        "-e",
        "INTRIQO_CONTROL_PLANE_TOKEN",
        "-e",
        "INTRIQO_CONTROL_PLANE_ENDPOINT",
        "--entrypoint",
        "/host-lib/ld-linux-x86-64.so.2",
        image,
        "--library-path",
        "/host-lib",
        "/engine",
        *args,
    ]


def _docker_generator_command(port: int, name: str, image: str) -> list[str]:
    # No package manager or checkout is used in the capability-dropped
    # container.  The host's interpreter and stdlib are mounted read-only.
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "host",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_RAW",
        "--user",
        "0",
        "-v",
        f"{FIXTURE.resolve()}:/syn_flood_fixture.py:ro",
        "-v",
        "/usr/bin/python3.14:/usr/bin/python3.14:ro",
        "-v",
        "/usr/lib/python3.14:/usr/lib/python3.14:ro",
        "-v",
        "/usr/lib/x86_64-linux-gnu:/host-lib:ro",
        "--entrypoint",
        "/host-lib/ld-linux-x86-64.so.2",
        image,
        "--library-path",
        "/host-lib",
        "/usr/bin/python3.14",
        "/syn_flood_fixture.py",
        "--raw-syn-burst",
        "--destination-port",
        str(port),
    ]


def _redact(text: str, token: str) -> str:
    return text.replace(token, "<redacted-token>")


def _parse_summary(output: bytes) -> dict[str, str | int | float]:
    for line in output.decode(errors="replace").splitlines():
        if not line.startswith("shutdown "):
            continue
        result: dict[str, str | int | float] = {}
        for field in line.split()[1:]:
            if "=" not in field:
                continue
            key, value = field.split("=", 1)
            try:
                result[key] = float(value) if any(c in value for c in ".eE") else int(value)
            except ValueError:
                result[key] = value
        return result
    raise AssertionError("live engine did not emit a shutdown summary")


def _wait_for_ready(process: subprocess.Popen[bytes]) -> bytes:
    assert process.stdout is not None
    output = b""
    deadline = time.monotonic() + 15
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while b"capture_ready=true" not in output and time.monotonic() < deadline:
            if selector.select(timeout=0.1):
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                output += chunk
    return output


def _database_url() -> str:
    sys.path.insert(0, str(CONTROL / "src"))
    from intriqo.config import Settings

    return (
        Settings(_env_file=CONTROL / ".env").sync_database_url
        .replace("postgresql+psycopg2://", "postgresql://")
        .replace("postgresql+asyncpg://", "postgresql://")
    )


@pytest.mark.skipif(
    os.environ.get("INTRIQO_RUN_LIVE_TEST") != "1",
    reason="opt-in local loopback raw-capture/FastAPI/PostgreSQL validation",
)
@pytest.mark.parametrize("shutdown_signal", [signal.SIGINT, signal.SIGTERM])
def test_live_syn_flood_loopback_to_postgres(shutdown_signal: signal.Signals) -> None:
    assert sys.platform == "linux"
    # Keep the opt-in test harmless during normal collection on engine-only
    # workstations; these are live-test dependencies, not fixture dependencies.
    import httpx
    import psycopg2

    engine_binary = _engine_path()
    assert FIXTURE.is_file()
    image = os.environ.get("INTRIQO_LIVE_DOCKER_IMAGE")
    if image and shutil.which("docker") is None:
        pytest.skip("INTRIQO_LIVE_DOCKER_IMAGE is set but docker is unavailable")
    if not image and not _can_open_raw_socket():
        pytest.skip("host lacks NET_RAW; set INTRIQO_LIVE_DOCKER_IMAGE for validation launcher")

    env = os.environ | {"PYTHONPATH": str(CONTROL / "src"), "APP_ENV": "test",
                       "REQUIRE_EMAIL_VERIFICATION": "false", "RESEND_API_KEY": ""}
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        api_port = int(reservation.getsockname()[1])
    base = f"http://127.0.0.1:{api_port}"
    api = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "intriqo.api.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(api_port),
        ],
        cwd=CONTROL,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    engine: subprocess.Popen[bytes] | None = None
    generator: subprocess.Popen[bytes] | None = None
    engine_container: str | None = None
    generator_container: str | None = None
    token = ""
    username = ""
    event = None
    try:
        with httpx.Client(base_url=base, timeout=10) as client:
            for _ in range(150):
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.1)
            else:
                pytest.fail("local FastAPI did not become ready")

            suffix = uuid.uuid4().hex[:12]
            username = f"syn_flood_live_{suffix}"
            token = _register_agent(client, username, uuid.uuid4().hex)
            port = _reserve_closed_port()
            capture_filter = (
                "tcp and ((src host 127.0.0.1 and dst host 127.0.0.2 "
                f"and dst port {port}) or (src host 127.0.0.2 and dst host 127.0.0.1 "
                f"and src port {port}))"
            )
            # The HTTP sink has no local event-file output.  The engine CLI
            # rejects --output with --sink http, so its only payload sink is
            # the authenticated Control Plane endpoint; stdout remains metrics.
            engine_args = [
                "--interface",
                "lo",
                "--no-promiscuous",
                "--filter",
                capture_filter,
                "--sink",
                "http",
                "--event-queue-capacity",
                "256",
                "--synflood-window",
                "10",
                "--synflood-minimum-attempts",
                "20",
                "--synflood-minimum-rate",
                "10",
                "--synflood-incomplete-ratio",
                "0.9",
                "--synflood-minimum-incomplete",
                "20",
                "--portscan-unique-port-threshold",
                "65535",
                "--portscan-minimum-attempts",
                "65535",
            ]
            engine_env = env | {
                "INTRIQO_CONTROL_PLANE_URL": base,
                "INTRIQO_CONTROL_PLANE_TOKEN": token,
                "INTRIQO_CONTROL_PLANE_ENDPOINT": "/api/v1/events",
            }
            if image:
                engine_container = f"intriqo-syn-engine-{suffix}"
                engine_command = _docker_engine_command(
                    engine_binary, engine_args, engine_container, image
                )
            else:
                engine_command = [str(engine_binary), *engine_args]
            engine = subprocess.Popen(
                engine_command,
                env=engine_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output = _wait_for_ready(engine)
            assert b"capture_ready=true" in output, "live source failed to initialize"

            if image:
                generator_container = f"intriqo-syn-generator-{suffix}"
                generator_command = _docker_generator_command(port, generator_container, image)
            else:
                generator_command = [
                    sys.executable,
                    str(FIXTURE),
                    "--raw-syn-burst",
                    "--destination-port",
                    str(port),
                ]
            generator = subprocess.Popen(
                generator_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            generator_out, generator_err = generator.communicate(timeout=15)
            assert generator.returncode == 0, _redact(
                (generator_out + generator_err).decode(errors="replace"), token
            )
            assert b"raw_syn_sent=120" in generator_out

            event = None
            for _ in range(160):
                response = client.get(
                    "/api/v1/events",
                    headers={"Authorization": f"Bearer {token}"},
                    params={
                        "event_type": "SYN_FLOOD",
                        "source_address": "127.0.0.1",
                        "destination_address": "127.0.0.2",
                        "page_size": 500,
                    },
                )
                assert response.status_code == 200, response.text
                candidates = [
                    item
                    for item in response.json().get("items", [])
                    if item.get("details", {}).get("destination_port") == port
                ]
                if candidates:
                    assert len(candidates) == 1, "live detector emitted an event explosion"
                    event = candidates[0]
                    break
                time.sleep(0.1)
            assert event is not None, "live traffic did not persist one SYN_FLOOD event"
            assert len(event["event_id"]) == 36
            assert str(uuid.UUID(event["event_id"])) == event["event_id"].lower()
            assert event["event_type"] == "SYN_FLOOD"
            assert event["severity"] == "HIGH"
            assert event["source_address"] == "127.0.0.1"
            assert event["destination_address"] == "127.0.0.2"
            details = event["details"]
            assert details["connection_attempts"] >= 20
            assert details["incomplete_handshakes"] >= 20
            assert details["incomplete_ratio"] >= 0.9
            assert details["rate_per_second"] >= 10
            assert client.get(
                f"/api/v1/events/{event['event_id']}",
                headers={"Authorization": f"Bearer {token}"},
            ).status_code == 200

            with psycopg2.connect(_database_url()) as database, database.cursor() as cursor:
                cursor.execute(
                    "SELECT event_type, source_address, destination_address "
                    "FROM security_events WHERE event_id=%s",
                    (event["event_id"],),
                )
                assert cursor.fetchone() == ("SYN_FLOOD", "127.0.0.1", "127.0.0.2")
                cursor.execute(
                    "SELECT count(*) FROM audit_logs "
                    "WHERE resource_id=%s AND action='EVENT_INGESTED' AND outcome='SUCCESS'",
                    (event["event_id"],),
                )
                assert cursor.fetchone()[0] == 1

            if generator_container:
                subprocess.run(
                    ["docker", "stop", "--time", "3", generator_container],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            if engine_container:
                subprocess.run(
                    ["docker", "kill", "--signal", shutdown_signal.name, engine_container],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=True,
                )
            else:
                engine.send_signal(shutdown_signal)
            tail, errors = engine.communicate(timeout=15)
            output += tail
            assert engine.returncode == 0, _redact(errors.decode(errors="replace"), token)
            summary = _parse_summary(output)
            assert summary.get("status") == "interrupted"
            assert summary.get("flows_active") == 0
            assert summary.get("events_emitted") == 1
            assert summary.get("detections_fired") == 1
            assert summary.get("sink_failures") == 0
            assert summary.get("event_sink_failures") == 0
            assert summary.get("queue_depth") == 0
            assert summary.get("queue_overflows") == 0
            assert summary.get("detector_state_sources", 0) <= 1
            assert summary.get("detector_state_observations", 0) <= 120
            assert summary["detector_peak_sources"] <= 2
            assert summary["detector_peak_observations"] <= 240
            assert token.encode() not in output + errors
            result = {"signal": shutdown_signal.name, "offered_syns": 120,
                      "event_type": event["event_type"], "details": event["details"],
                      "api_postgres_audit_verified": True, "summary": summary}
            print("syn_live_measurement=" + json.dumps(result, sort_keys=True))
            result_path = os.environ.get("INTRIQO_SYN_LIVE_RESULTS")
            if result_path:
                path = Path(result_path)
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a") as output_file:
                    output_file.write(json.dumps(result, sort_keys=True) + "\n")
    finally:
        if generator_container:
            subprocess.run(
                ["docker", "stop", "--time", "3", generator_container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        if generator and generator.poll() is None:
            generator.terminate()
            try:
                generator.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                generator.kill()
                generator.communicate()
        if engine_container:
            subprocess.run(
                ["docker", "stop", "--time", "3", engine_container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
        if engine and engine.poll() is None:
            engine.terminate()
            try:
                engine.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                engine.kill()
                engine.communicate()
        api.terminate()
        try:
            api.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api.kill()
            api.wait()
        # Delete only rows owned by this isolated test; never clear the DB or
        # other sessions' identities/events. This prevents account-token rows
        # contaminating the subsequently run account-recovery regression suite.
        if username:
            import psycopg2
            with psycopg2.connect(_database_url()) as database, database.cursor() as cursor:
                if event:
                    cursor.execute("DELETE FROM audit_logs WHERE resource_id=%s", (event["event_id"],))
                    cursor.execute("DELETE FROM security_events WHERE event_id=%s", (event["event_id"],))
                cursor.execute("DELETE FROM audit_logs WHERE actor=%s", (username,))
                cursor.execute("DELETE FROM users WHERE username=%s", (username,))
