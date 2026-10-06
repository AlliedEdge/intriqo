"""Focused tests for development service-token ownership and refresh."""

from __future__ import annotations

import os
import shlex
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from jose import jwt

ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "scripts" / "intriqo-runtime.sh"
TOKEN_NAMES = (
    "INTRIQO_CONTROL_PLANE_TOKEN",
    "INTRIQO_AGENT_TOKEN",
    "INTRIQO_OPERATOR_TOKEN",
)


def make_token(secret: str, expires_in: int, subject: str = "test") -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "sub": subject,
            "role": "AGENT",
            "iat": datetime.fromtimestamp(now, timezone.utc),
            "exp": datetime.fromtimestamp(now + expires_in, timezone.utc),
        },
        secret,
        algorithm="HS256",
    )


def write_runtime_file(runtime_dir: Path, secret: str, tokens: dict[str, str]) -> Path:
    state = runtime_dir / "state"
    state.mkdir(parents=True)
    path = state / "service-tokens.env"
    lines = [f"JWT_SECRET_KEY={secret}"] + [f"{name}={tokens[name]}" for name in TOKEN_NAMES]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)
    return path


def bootstrap(tmp_path: Path, extra_env: dict[str, str] | None = None, load_env: bool = False) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    for name in ("JWT_SECRET_KEY", *TOKEN_NAMES):
        env.pop(name, None)
    env.update(
        {
            "APP_ENV": "development",
            "INTRIQO_ROOT_DIR": str(ROOT),
            "INTRIQO_RUNTIME_DIR": str(tmp_path / ".intriqo"),
            "INTRIQO_PYTHON": sys.executable,
            "INTRIQO_ENV_FILE": str(tmp_path / "empty.env"),
        }
    )
    if extra_env:
        env.update(extra_env)
    command = [
        "set -euo pipefail",
        f"source {shlex.quote(str(RUNTIME))}",
    ]
    if load_env:
        command.append("intriqo_load_env_file")
    command.extend(
        [
            "intriqo_bootstrap_service_tokens",
            'printf \'CP=%s\\nAGENT=%s\\nOPERATOR=%s\\nSECRET=%s\\n\' "${INTRIQO_CONTROL_PLANE_TOKEN:-}" "${INTRIQO_AGENT_TOKEN:-}" "${INTRIQO_OPERATOR_TOKEN:-}" "$JWT_SECRET_KEY"',
        ]
    )
    return subprocess.run(
        ["bash", "-c", "; ".join(command)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def read_runtime(path: Path) -> dict[str, str]:
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)


def test_expired_and_near_expired_runtime_tokens_are_refreshed(tmp_path: Path) -> None:
    secret = "development-secret-that-is-long-enough-for-tests"
    runtime_dir = tmp_path / ".intriqo"
    old = write_runtime_file(
        runtime_dir,
        secret,
        {
            TOKEN_NAMES[0]: make_token(secret, -60, TOKEN_NAMES[0]),
            TOKEN_NAMES[1]: make_token(secret, 30, TOKEN_NAMES[1]),
            TOKEN_NAMES[2]: make_token("different-signing-secret", 1800, TOKEN_NAMES[2]),
        },
    )
    before = read_runtime(old)

    result = bootstrap(tmp_path)

    assert result.returncode == 0, result.stderr
    refreshed = read_runtime(old)
    assert refreshed["JWT_SECRET_KEY"] == secret
    assert all(refreshed[name] != before[name] for name in TOKEN_NAMES)
    for name in TOKEN_NAMES:
        assert refreshed[name]
        claims = jwt.decode(refreshed[name], secret, algorithms=["HS256"])
        assert claims["exp"] > time.time() + 20 * 60
    assert stat.S_IMODE(old.stat().st_mode) == 0o600


def test_valid_runtime_tokens_are_reused(tmp_path: Path) -> None:
    secret = "development-secret-that-is-long-enough-for-tests"
    path = write_runtime_file(tmp_path / ".intriqo", secret, {name: make_token(secret, 1800, name) for name in TOKEN_NAMES})
    before = path.read_bytes()

    result = bootstrap(tmp_path)

    assert result.returncode == 0, result.stderr
    assert path.read_bytes() == before
    assert "CP=" + read_runtime(path)[TOKEN_NAMES[0]] in result.stdout


def test_explicit_process_and_env_tokens_are_not_overwritten(tmp_path: Path) -> None:
    secret = "development-secret-that-is-long-enough-for-tests"
    runtime_dir = tmp_path / ".intriqo"
    path = write_runtime_file(runtime_dir, secret, {name: make_token(secret, -60, name) for name in TOKEN_NAMES})
    before = read_runtime(path)
    process_token = make_token("process-secret-that-is-also-long-enough", 1800, "process")
    env_token = make_token("env-secret-that-is-also-long-enough", 1800, "env")
    env_file = tmp_path / "explicit.env"
    env_file.write_text(f"JWT_SECRET_KEY={secret}\nINTRIQO_AGENT_TOKEN={env_token}\n")

    result = bootstrap(
        tmp_path,
        {
            "INTRIQO_CONTROL_PLANE_TOKEN": process_token,
            "INTRIQO_ENV_FILE": str(env_file),
        },
        load_env=True,
    )

    assert result.returncode == 0, result.stderr
    assert f"CP={process_token}" in result.stdout
    assert f"AGENT={env_token}" in result.stdout
    refreshed = read_runtime(path)
    assert refreshed["JWT_SECRET_KEY"] == secret
    assert "INTRIQO_CONTROL_PLANE_TOKEN" not in refreshed
    assert "INTRIQO_AGENT_TOKEN" not in refreshed
    assert refreshed["INTRIQO_OPERATOR_TOKEN"] != before["INTRIQO_OPERATOR_TOKEN"]
    assert jwt.decode(refreshed["INTRIQO_OPERATOR_TOKEN"], secret, algorithms=["HS256"])["exp"] > time.time()


def test_production_requires_explicit_credentials_and_does_not_use_runtime_file(tmp_path: Path) -> None:
    secret = "production-secret-that-is-long-enough-for-tests"
    path = write_runtime_file(tmp_path / ".intriqo", secret, {name: make_token(secret, -60, name) for name in TOKEN_NAMES})
    before = path.read_bytes()

    result = bootstrap(tmp_path, {"APP_ENV": "production"})

    assert result.returncode != 0
    assert "production requires" in result.stderr
    assert path.read_bytes() == before

    explicit = bootstrap(
        tmp_path,
        {
            "APP_ENV": "production",
            "JWT_SECRET_KEY": secret,
            "INTRIQO_CONTROL_PLANE_TOKEN": make_token(secret, 1800, "engine"),
            "INTRIQO_AGENT_TOKEN": make_token(secret, 1800, "agent"),
        },
    )
    assert explicit.returncode == 0, explicit.stderr
    assert path.read_bytes() == before
