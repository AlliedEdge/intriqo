# Intriqo local development

This guide runs the current Intriqo architecture as one local development
stack. It uses the existing C++ engine, FastAPI Control Plane, PostgreSQL,
agent poller, optional locked-model ML worker, and React/Vite dashboard. It is
not a production deployment.

For the analyst-facing event → incident → investigation → finding workflow,
see [SOC Workflow](soc-workflow.md). For the complete isolated live path, see
[Demo Lab](demo-lab.md) and the [Demo Runbook](demo-runbook.md).

## 1. Prerequisites

- Linux for the existing C++ live-capture path; synthetic and authorized PCAP
  replay do not require a live interface.
- Python 3.10+, CMake 3.24+, a C++20 compiler, Node.js 20+, npm, Docker, and
  Docker Compose.
- `libpcap-dev` only for building/enabling live capture and PCAP replay.
- An authorized, isolated lab interface or the repository's synthetic/PCAP
  fixtures. Never point the demo at an external target.

Check the repository's current build and test tooling with:

```bash
cmake --version
python3 --version
node --version
docker compose version
```

## 2. Installation

Install the Python components into the Control Plane virtual environment and
install the frontend dependencies:

```bash
python3 -m venv control-plane/.venv
control-plane/.venv/bin/pip install -e 'control-plane[dev]' -e 'agents[dev]' -e 'ml[dev]'
(cd frontend/dashboard && npm ci)
```

Build the existing production engine (no demo replacement is used):

```bash
cmake -S . -B build/intriqo-runtime-release \
  -DCMAKE_BUILD_TYPE=Release -DINTRIQO_BUILD_TESTS=ON
cmake --build build/intriqo-runtime-release --parallel
```

## 3. Environment configuration

Copy the safe template and edit only local values:

```bash
cp .env.example .env
```

`.env` is ignored by Git. The template separates public/demo settings from
secrets. The existing canonical names are:

| Role | Setting |
|---|---|
| PostgreSQL | `DATABASE_URL`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` |
| Control Plane | `INTRIQO_CONTROL_PLANE_URL`, `INTRIQO_CONTROL_PLANE_ENDPOINT` |
| Engine/ML bearer identity | `INTRIQO_CONTROL_PLANE_TOKEN` |
| Agent bearer identity | `INTRIQO_AGENT_TOKEN` |
| ML switch | `INTRIQO_ML_ENABLED=false` |
| ML model | `INTRIQO_ML_MODEL_PATH` |
| ML threshold | `INTRIQO_ML_THRESHOLD_PATH` |
| ML model schema | `INTRIQO_ML_FEATURE_SCHEMA_PATH` |
| Frozen contract | `INTRIQO_ML_FEATURE_CONTRACT_PATH` |
| Locked hashes | `INTRIQO_ML_EXPECTED_MODEL_SHA256`, `INTRIQO_ML_EXPECTED_THRESHOLD_SHA256` |
| Development token refresh | `INTRIQO_JWT_REFRESH_MARGIN_SECONDS` |

`DATABASE_URL` is the async SQLAlchemy URL. Alembic derives its synchronous
URL from the same setting; do not maintain a second migration database URL.
With the template's empty `JWT_SECRET_KEY` and token values, the launcher
generates a private random signing key plus distinct development-only engine,
agent, and analyst JWTs under `.intriqo/state/service-tokens.env`. They are
never printed. Launcher-owned development tokens are refreshed when invalid or
within the configured refresh margin; explicit process/environment credentials
are never replaced. In production, explicit secrets and service tokens are
required and automatic generation is refused.

## 4. Database initialization

The launcher starts only PostgreSQL from the existing root Compose file, waits
for `pg_isready`, and runs Alembic before starting the API:

```bash
./scripts/start-intriqo.sh --check
./scripts/start-intriqo.sh
```

For a clean database without deleting application runtime state, use the
destructive reset command described in §8. PostgreSQL data is persistent and
is not removed by `stop-intriqo.sh` or `reset-intriqo.sh`.

## 5. Start the stack

```bash
./scripts/start-intriqo.sh
```

Startup order is PostgreSQL → Alembic → Control Plane `/ready` → optional ML
worker and agent poller → Vite → C++ engine. The C++ engine is independent of
ML. The default synthetic engine is finite and emits a deterministic
`PORT_SCAN`; the Control Plane and agent poller remain running.

The default local process endpoints are:

- Control Plane: <http://127.0.0.1:8000>
- API readiness: <http://127.0.0.1:8000/ready>
- Dashboard: <http://127.0.0.1:5173>
- PostgreSQL: `127.0.0.1:5432` (local development only)

The engine can instead use an authorized source by setting
`INTRIQO_ENGINE_MODE=pcap` with `INTRIQO_ENGINE_SOURCE`, or
`INTRIQO_ENGINE_MODE=interface` with an authorized interface. Live capture
requires the privileges and libpcap setup documented in
[the engine runtime guide](engine/ids-engine.md).

## 6. Status and logs

```bash
./scripts/status-intriqo.sh
./scripts/logs-intriqo.sh
./scripts/logs-intriqo.sh control-plane
./scripts/logs-intriqo.sh engine
./scripts/logs-intriqo.sh agents
./scripts/logs-intriqo.sh ml-worker
./scripts/logs-intriqo.sh --follow all
```

Status checks PostgreSQL connectivity and Control Plane readiness, not just
process existence. It reports `ML Worker: DISABLED`, `READY`, or `FAILED`; a
failed ML worker does not make deterministic engine or Control Plane status
healthy/unhealthy by implication. Finite synthetic/PCAP engine completion is
reported as an expected exit; a live engine exit is a failure.

## 7. Stop the stack

```bash
./scripts/stop-intriqo.sh
```

The launcher sends SIGTERM to the engine first so its flow and bounded sinks
flush, then stops ML, agents, frontend, and Control Plane. It stops PostgreSQL
but leaves its persistent Compose volume intact. Use `--keep-postgres` while
iterating on application processes.

## 8. Reset runtime state

```bash
./scripts/reset-intriqo.sh
```

This is destructive for local runtime state: it stops services and removes
`.intriqo/` PIDs, logs, ML outputs, the local signing key, and the SQLite
decision ledger. It does
**not** remove PostgreSQL data. To reinitialize the database from zero, use
the explicit Compose volume removal command only when you intend to lose all
local records:

```bash
docker compose down -v --remove-orphans
```

Then start again; the launcher reruns all Alembic migrations. Do not edit
PostgreSQL tables manually.

## 9. ML enablement

ML remains disabled by default. Deterministic PortScan and SynFlood detection,
Control Plane persistence, agents, and the dashboard do not require it.

To enable the already locked Isolation Forest v2, set these values in a local
environment file (the launcher accepts `--env-file`):

```dotenv
INTRIQO_ML_ENABLED=true
INTRIQO_ML_MODEL_PATH=ml/artifacts/models/controlled-v2/isolation-forest-v2/model.joblib
INTRIQO_ML_THRESHOLD_PATH=ml/artifacts/models/controlled-v2/isolation-forest-v2/threshold.json
INTRIQO_ML_FEATURE_SCHEMA_PATH=ml/artifacts/models/controlled-v2/isolation-forest-v2/feature_schema.json
INTRIQO_ML_FEATURE_CONTRACT_PATH=contracts/features/flow_features_v2.json
INTRIQO_ML_EXPECTED_MODEL_SHA256=69d7df6a027eebcaa64c227c3ab34d8a9fd44d4a0158264e86c3fb93db960cb5
INTRIQO_ML_EXPECTED_THRESHOLD_SHA256=28ebd68f65e255e9c32aa433b609c4dc969402605d936b8d49c357c5979058b2
```

Then run:

```bash
./scripts/start-intriqo.sh --env-file .env.ml
./scripts/status-intriqo.sh --env-file .env.ml
```

The worker publishes `READY` only after model bytes, threshold metadata, model
metadata, frozen feature schema, fitted estimator, and hashes pass validation.
The worker consumes the bounded native `flow_features.v2` JSONL file and sends
separate authenticated `ML_ANOMALY` events. It never runs in the C++ packet
callback and never feeds back into deterministic detection.

If validation fails, status becomes `FAILED`, the launcher logs a warning, and
the deterministic engine still starts without the ML feature stream. The
locked model, threshold, nine-feature schema, and controlled-v2 corpus are
not changed by startup.

## 10. Smoke tests and isolated demonstrations

Run the complete local event → database → incident → task → finding → audit →
frontend-proxy flow after starting the stack:

```bash
./scripts/smoke-intriqo.sh
```

The smoke command runs the selected production C++ engine with a synthetic,
authenticated `PORT_SCAN` sink during that invocation. It rejects persisted
events from earlier runs, creates an incident and investigation task, waits for
the existing agent poller to complete it, checks the finding/audit records, and
reads the resulting event through the Vite API proxy. It does not run an
external target and fails if the agent is stopped or the fresh event is not
persisted.

For the existing isolated lab and authorized PCAP procedures, read
[Controlled Security Lab](lab/security-lab.md) and
`security-lab/TESTING_GUIDE.md`. The small synthetic helper is also available
for local loopback-only experiments:

```bash
./scripts/lab/generate-traffic.sh 127.0.0.1 port-scan
```

Do not use that helper against an address you do not own or have explicit
permission to observe.

## 10. Isolated live demo lab

The persistent lab is separate from the application runtime. Set it up once,
bring it up for each session, and validate it before starting the existing
Release Candidate sensor:

```bash
./scripts/lab/setup.sh
./scripts/lab/up.sh
./scripts/start-demo.sh
```

Run only the fixed authorized scenarios from the second terminal:

```bash
./scripts/lab/port-scan.sh
./scripts/lab/syn-flood.sh
```

The generators accept no target address. They fail if the owned topology,
bidirectional mirror, fixed connectivity, or TAP packet probe is not verified.
The C++ engine is launched against `tap-intriqo` in the monitor namespace; the
SOC analyst does not configure the Linux lab. Use `scripts/stop-intriqo.sh`
and `scripts/lab/down.sh` for clean shutdown. See [Demo Lab](demo-lab.md) for
the topology and [Demo Runbook](demo-runbook.md) for the presentation sequence.

## 11. Frontend authentication smoke

Open <http://127.0.0.1:5173>, register a local account, sign in, and confirm
the protected dashboard routes load real Control Plane data. In development,
email delivery is a no-op when `RESEND_API_KEY` is absent, so the existing
development verification behavior remains usable. Sign out and confirm the
protected route redirects to login. The API still returns 401 for missing or
invalid bearer tokens and 403 for disallowed roles; the frontend does not
contain service secrets.

## 12. Troubleshooting and recovery

- **PostgreSQL not ready:** run `docker compose ps postgres`, inspect
  `./scripts/logs-intriqo.sh postgres`, and retry after the container is
  healthy.
- **Control Plane not ready:** inspect `control-plane.log` and
  `migrations.log`; `/health` reports degraded when `SELECT 1` fails, while
  `/ready` returns HTTP 503.
- **No engine binary:** run the Release CMake build or set
  `INTRIQO_ENGINE_BIN` to an existing production engine binary.
- **ML `FAILED`:** inspect the ML log and status JSON. Check paths and the two
  locked hashes; never replace the artifact or retrain as a recovery step.
- **Agent unavailable:** events remain persisted and tasks remain `PENDING` or
  recoverable `IN_PROGRESS`. Restart the stack; the poller will retry the
  existing task lifecycle.
- **Control Plane restart:** run `scripts/stop-intriqo.sh --keep-postgres`
  followed by `scripts/start-intriqo.sh`; migrations are idempotent and
  PostgreSQL data remains intact. The start command refuses to layer a second
  process over a partially running stack.
- **Ports already in use:** set `INTRIQO_API_PORT` or
  `INTRIQO_FRONTEND_PORT` in a local env file and keep the Vite proxy/API
  settings aligned.

Failure boundaries are intentional: ML, frontend, and agents are not packet
path dependencies. Control Plane delivery remains bounded by the existing C++
sink behavior; no durable broker or unbounded queue is added.

## 13. Checks

Run the component checks from the repository root:

```bash
ctest --test-dir build/intriqo-runtime-release --output-on-failure
control-plane/.venv/bin/pytest ml/tests -c ml/pyproject.toml -q
(cd agents && ../control-plane/.venv/bin/pytest tests -q)
(cd control-plane && .venv/bin/pytest tests -q)
(cd frontend/dashboard && npm run build && npm run test -- --run)
control-plane/.venv/bin/ruff check \
  agents/src agents/tests control-plane/src control-plane/tests ml/src ml/tests
control-plane/.venv/bin/mypy agents/src control-plane/src ml/src
git diff --check
```

The existing C++ ASAN/UBSan configuration and backend E2E suites remain
separate checks. ML-enabled inference throughput is asynchronous and must not
be merged into the existing C++ engine benchmark baseline; use the recorded ML
worker measurements in [ML inference integration](ml-inference-integration.md).

## 14. Security boundaries

- Keep `.env`, `.intriqo/`, service tokens, SQLite ledgers, logs, runtime
  databases, and temporary PCAPs out of Git.
- Use only local loopback, owned lab, or explicitly authorized capture sources.
- Public signup remains an `ANALYST` flow; service JWTs are generated only by
  the local launcher or supplied out-of-band.
- Agents investigate and submit findings through the existing Control Plane;
  no automated blocking, remediation, response automation, Kafka, Redis, or
  Kubernetes was added.
- The experimental Isolation Forest v2 is disabled by default, is trained only
  on the existing controlled corpus, has no external-generalization evidence,
  and is not production-ready.
