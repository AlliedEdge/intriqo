"""Opt-in real-process test for the documented local runtime commands.

Run with ``INTRIQO_RUN_RUNTIME_STACK_E2E=1``.  It intentionally stays opt-in
because it owns local ports, Docker PostgreSQL, and host processes.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
START = ROOT / "scripts/start-intriqo.sh"
SMOKE = ROOT / "scripts/smoke-intriqo.sh"
STOP = ROOT / "scripts/stop-intriqo.sh"
ENGINE = ROOT / "build/runtime-integration/engine/intriqo-engine"


@pytest.mark.skipif(
    os.environ.get("INTRIQO_RUN_RUNTIME_STACK_E2E") != "1",
    reason="set INTRIQO_RUN_RUNTIME_STACK_E2E=1 to own the local runtime",
)
def test_documented_runtime_stack_smoke(tmp_path: Path) -> None:
    """Start the documented stack and prove the complete real-process flow."""

    if not ENGINE.is_file():
        pytest.fail(f"Build the production engine first: {ENGINE}")

    env = os.environ.copy()
    env.update(
        {
            "APP_ENV": "development",
            "DEBUG": "false",
            "JWT_SECRET_KEY": "",
            "POSTGRES_USER": "intriqo",
            "POSTGRES_PASSWORD": "intriqo_dev",
            "POSTGRES_DB": "intriqo",
            "DATABASE_URL": "postgresql+asyncpg://intriqo:intriqo_dev@127.0.0.1:5432/intriqo",
            "INTRIQO_POSTGRES_HOST": "127.0.0.1",
            "INTRIQO_POSTGRES_PORT": "5432",
            "INTRIQO_RUNTIME_DIR": str(tmp_path / ".intriqo"),
            "INTRIQO_ENGINE_BIN": str(ENGINE),
            "INTRIQO_ENGINE_SINK": "http",
            "INTRIQO_ENGINE_MODE": "synthetic",
            "INTRIQO_ML_ENABLED": "false",
            "INTRIQO_AGENTS_ENABLED": "true",
            "INTRIQO_FRONTEND_ENABLED": "true",
            "INTRIQO_ENV_FILE": str(tmp_path / "empty.env"),
        }
    )
    (tmp_path / "empty.env").write_text("# runtime e2e overrides are passed in the process environment\n")

    def run(command: list[str]) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        if result.returncode != 0:
            pytest.fail(f"{' '.join(command)} failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}")
        return result

    try:
        run([str(START), "--env-file", str(tmp_path / "empty.env")])
        result = run([str(SMOKE), "--env-file", str(tmp_path / "empty.env"), "--timeout", "30"])
        assert "SMOKE PASS" in result.stdout
    finally:
        subprocess.run(
            [str(STOP), "--env-file", str(tmp_path / "empty.env")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
