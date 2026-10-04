"""Opt-in local-only Linux live capture -> authenticated FastAPI -> PostgreSQL.

Run with INTRIQO_RUN_LIVE_TEST=1 after building. Capture only loopback TCP traffic
between 127.0.0.1 and 127.0.0.2 on ten reserved local listening ports. No raw
packet injection and no external targets. Requires CAP_NET_RAW or the optional
validation-only Docker launcher; it is not deployment infrastructure.
"""
from __future__ import annotations

import os
import selectors
import signal
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import psycopg2
import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTROL = ROOT / "control-plane"
ENGINE = Path(os.environ.get("INTRIQO_ENGINE_BINARY", str(ROOT / "build/runtime-release/engine/intriqo-engine")))


def local_listeners():
    """Reserve ten consecutive local ports, without probing remote hosts."""
    for _ in range(100):
        first = 40000 + int(uuid.uuid4().hex[:4], 16) % 19000
        listeners = []
        try:
            for port in range(first, first + 10):
                listener = socket.socket()
                listeners.append(listener)
                listener.bind(("127.0.0.2", port))
                listener.listen(1)
            return first, listeners
        except OSError:
            for listener in listeners:
                listener.close()
    raise RuntimeError("could not reserve ten local ports")


@pytest.mark.skipif(os.environ.get("INTRIQO_RUN_LIVE_TEST") != "1", reason="opt-in CAP_NET_RAW/local PostgreSQL validation")
@pytest.mark.parametrize("shutdown_signal", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("delivery_queue_capacity", [0, 256])
def test_live_loopback_to_postgres(shutdown_signal, delivery_queue_capacity, capsys):
    assert sys.platform == "linux"
    assert ENGINE.is_file(), "build intriqo-engine first"
    env = os.environ | {"PYTHONPATH": str(CONTROL / "src")}
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        api_port = reservation.getsockname()[1]
    base = f"http://127.0.0.1:{api_port}"
    api = subprocess.Popen([sys.executable, "-m", "uvicorn", "intriqo.api.app:app", "--host", "127.0.0.1",
                            "--port", str(api_port)], cwd=CONTROL, env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    engine = None
    container = None
    listeners = []
    try:
        with httpx.Client(base_url=base, timeout=10) as client:
            for _ in range(100):
                try:
                    if client.get("/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.05)
            else:
                pytest.fail("local FastAPI did not become ready")
            suffix = uuid.uuid4().hex[:12]
            username, password = f"live_ids_{suffix}", uuid.uuid4().hex
            response = client.post("/api/v1/auth/register", json={"username": username,
                "email": f"{username}@example.com", "password": password, "role": "AGENT"})
            assert response.status_code == 201, "test identity registration failed"
            login = client.post("/api/v1/auth/login", json={"username": username, "password": password})
            assert login.status_code == 200, "test identity login failed"
            token = login.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            first, listeners = local_listeners()
            capture_filter = f"tcp and src host 127.0.0.1 and dst host 127.0.0.2 and dst portrange {first}-{first+9}"
            args = ["--interface", "lo", "--no-promiscuous", "--filter", capture_filter, "--sink", "http"]
            if delivery_queue_capacity:
                args += ["--event-queue-capacity", str(delivery_queue_capacity)]
            engine_env = env | {"INTRIQO_CONTROL_PLANE_URL": base, "INTRIQO_CONTROL_PLANE_TOKEN": token,
                                "INTRIQO_CONTROL_PLANE_ENDPOINT": "/api/v1/events"}
            image = os.environ.get("INTRIQO_LIVE_DOCKER_IMAGE")
            if image:
                container = f"intriqo-live-validation-{suffix}"
                # Mount only the executable and public shared libraries, never
                # the checkout/.env or credential files. Pass token by env name.
                command = ["docker", "run", "--rm", "--name", container, "--network", "host",
                    "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--user", "0",
                    "-v", f"{ENGINE.resolve()}:/engine:ro", "-v", "/usr/lib/x86_64-linux-gnu:/host-lib:ro",
                    "-e", "INTRIQO_CONTROL_PLANE_URL", "-e", "INTRIQO_CONTROL_PLANE_TOKEN",
                    "-e", "INTRIQO_CONTROL_PLANE_ENDPOINT", "--entrypoint", "/host-lib/ld-linux-x86-64.so.2",
                    image, "--library-path", "/host-lib", "/engine", *args]
            else:
                command = [str(ENGINE), *args]
            engine = subprocess.Popen(command, env=engine_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert engine.stdout is not None
            # Read bytes without buffering: avoid selector/readline mismatches.
            output = b""
            deadline = time.monotonic() + 15
            with selectors.DefaultSelector() as selector:
                selector.register(engine.stdout, selectors.EVENT_READ)
                while b"capture_ready=true" not in output and time.monotonic() < deadline:
                    if selector.select(timeout=0.1):
                        chunk = os.read(engine.stdout.fileno(), 4096)
                        if not chunk:
                            break
                        output += chunk
            assert b"capture_ready=true" in output, "live source failed to initialize (check libpcap/CAP_NET_RAW)"
            # SecurityEvent v1 serializes milliseconds. A microsecond lower bound
            # can exclude this run's fast loopback event within the same millisecond.
            started = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            for port in range(first, first + 10):
                with socket.socket() as connection:
                    connection.settimeout(2)
                    connection.bind(("127.0.0.1", 0))
                    connection.connect(("127.0.0.2", port))
            event = None
            for _ in range(100):
                response = client.get("/api/v1/events", headers=headers, params={"event_type": "PORT_SCAN",
                    "source_address": "127.0.0.1", "destination_address": "127.0.0.2", "from_time": started})
                assert response.status_code == 200
                if response.json()["items"]:
                    event = response.json()["items"][0]
                    break
                time.sleep(0.05)
            if event is None:
                # Preserve engine counters on failure, without logging test credentials.
                if container:
                    subprocess.run(["docker", "kill", "--signal", "TERM", container],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
                elif engine.poll() is None:
                    engine.send_signal(signal.SIGTERM)
                tail, errors = engine.communicate(timeout=10)
                diagnostic = (output + tail + errors).decode(errors="replace").replace(token, "<redacted>")
                pytest.fail(f"local live traffic did not persist a PORT_SCAN event (from_time={started}); " + diagnostic)
            assert event is not None, "local live traffic did not persist a PORT_SCAN event"
            assert client.get(f"/api/v1/events/{event['event_id']}", headers=headers).status_code == 200
            sys.path.insert(0, str(CONTROL / "src"))
            from intriqo.config import Settings
            database_url = Settings(_env_file=CONTROL / ".env").sync_database_url.replace("postgresql+psycopg2://", "postgresql://")
            with psycopg2.connect(database_url) as db, db.cursor() as cursor:
                cursor.execute("SELECT event_type, source_address, destination_address FROM security_events WHERE event_id=%s", (event["event_id"],))
                assert cursor.fetchone() == ("PORT_SCAN", "127.0.0.1", "127.0.0.2")
                cursor.execute("SELECT outcome FROM audit_logs WHERE resource_id=%s AND action='EVENT_INGESTED'", (event["event_id"],))
                assert cursor.fetchone() == ("SUCCESS",)
            if container:
                subprocess.run(["docker", "kill", "--signal", str(shutdown_signal.value), container],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)
            else:
                engine.send_signal(shutdown_signal)
            tail, errors = engine.communicate(timeout=10)
            output += tail
            assert engine.returncode == 0, "live engine did not exit cleanly"
            assert b"flows_active=0" in output and b"sink_failures=0" in output
            assert b"events_emitted=1" in output and b"queue_depth=0" in output
            assert b"queue_overflows=0" in output
            assert token.encode() not in output + errors
            with capsys.disabled():
                print(f"live validation signal={shutdown_signal.name} queue_capacity={delivery_queue_capacity} API/PostgreSQL/audit=verified")
                print(output.decode().strip())
    finally:
        if container:
            subprocess.run(["docker", "stop", "--time", "3", container], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
        if engine and engine.poll() is None:
            engine.terminate()
            try:
                engine.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                engine.kill()
                engine.communicate()
        for listener in listeners:
            listener.close()
        api.terminate()
        try:
            api.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api.kill()
            api.wait()
