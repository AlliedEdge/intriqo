# INTRIQO live demonstration runbook

Target duration: **10–15 minutes**. This runbook is deliberately narrow: one
analyst, one isolated sensor, three deterministic scenarios, one validated ML
path, and one failure-isolation check. Do not open database consoles or create
records manually during the demo.

## Operator setup and quick start

Use a Linux host with Docker Compose, `iproute2` (`ip` and `tc`), `ping`,
Python 3, Node.js/npm, and `sudo`. Namespace creation, traffic mirroring,
traffic generation, and capture initialization require root privileges. The
runtime launcher asks for sudo before startup and starts the engine only after
the host services; the engine's privileged `setsid --wait` launch path must be
preserved so its PID and shutdown handling remain attached to the runtime.

Install the build and runtime prerequisites on a new host:

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libpcap-dev \
  iproute2 iputils-ping docker.io docker-compose-v2 python3 python3-venv \
  nodejs npm
```

The existing engine is built with CMake's `INTRIQO_ENABLE_PCAP=ON` option.
Confirm CMake reports `libpcap found — live capture enabled` and that
`build/intriqo-runtime-release/engine/CMakeFiles/intriqo_engine_lib.dir/flags.make`
contains `-DINTRIQO_HAS_PCAP`. The runtime library may be dynamically or
statically linked; `ldd` alone is not the feature check.

Create the local configuration once, then keep it private:

```bash
cp .env.example .env
```

The default local `.env.example` values configure PostgreSQL on `127.0.0.1:5432`,
the Control Plane on `127.0.0.1:8000`, and Vite on `127.0.0.1:5173`. `start-demo.sh`
overrides the Control Plane bind and engine sink URLs to the lab's host-only
management link (`169.254.77.1`) while the browser continues using localhost.
The engine and agent service tokens are created and stored by the existing
runtime under `.intriqo/`; do not paste them into frontend source or commit
`.env` or `.intriqo/`.

Exact first-run and per-session commands:

```bash
# One-time, owned lab creation and verification
./scripts/lab/setup.sh
./scripts/lab/status.sh --verify

# Each session: bring the lab up before the application runtime
./scripts/lab/up.sh
./scripts/start-demo.sh
INTRIQO_API_HOST=169.254.77.1 ./scripts/status-intriqo.sh
./scripts/logs-intriqo.sh --follow engine
```

Open the dashboard URL printed by `start-demo.sh`, sign in as an `ANALYST`,
and confirm the Overview refresh succeeds. Keep the lab status output and
engine's live-capture readiness log visible. A stored event is historical
until its event timestamp and `ingested_at` are checked against the current
session; use the newest events and the scenario's `10.77.0.10` → `10.77.0.20`
addresses when demonstrating a fresh detection.

## Before the audience arrives

```bash
# One-time host setup
./scripts/lab/setup.sh

# Each session
./scripts/lab/up.sh
./scripts/start-demo.sh
```

Open the dashboard URL printed by `start-demo.sh` and sign in with a verified
`ANALYST` account. A clean known state means the operator has checked the dashboard's current event and
incident lists; it does not mean deleting PostgreSQL rows. Use only the
repository's existing reset procedures if a new clean database is intentionally
required before the demo.

Confirm these actual runtime observations before starting:

```bash
./scripts/lab/status.sh --verify
./scripts/status-intriqo.sh
./scripts/logs-intriqo.sh engine
```

The engine log must show `tap-intriqo`, live capture readiness, and the existing
detector configuration. The Control Plane must report ready. If ML is enabled,
the status file must report `READY`; if it is disabled, say so explicitly.

## 00:00–01:00 — Architecture

Show the lab diagram from [demo-lab.md](demo-lab.md): fixed attacker and
victim namespaces, a private bridge, bidirectional `tc/mirred` copies, and
`tap-intriqo` as the camera. Explain that the sensor is already deployed before
the analyst arrives. The analyst operates the SOC; the analyst does not create
namespaces, bridges, TAPs, or SPAN ports.

## 01:00–02:00 — Analyst login and health

1. Sign in as the demo `ANALYST`.
2. Show the normal Overview page, not an attack-simulation screen.
3. Show the real empty/known-state event and incident views.
4. Show `Agents` and the actual agent task list.
5. If ML is enabled, point to the worker state and the engine feature stream in
   the runtime status/logs. Do not call a disabled worker ready.

## 02:00–03:00 — Sensor health and dashboard provenance

In the second terminal, show:

```bash
./scripts/lab/status.sh --verify
```

Explain that `READY` is backed by a fixed ping and a real monitor-interface
packet-counter delta. In the dashboard, emphasize that event provenance is
returned by the Control Plane: deterministic source, detector name, source and
destination addresses, event time, and persisted relationships.

## 03:00–06:00 — PORT_SCAN

In the second terminal run:

```bash
./scripts/lab/port-scan.sh
```

While the bounded traffic runs:

1. Show the C++ engine log: capture, flow tracking, `port_scan`, and event
   delivery. The exact counters are the engine's real output; do not invent a
   packets-per-second value for this short scenario.
2. Refresh Overview and open the new `PORT_SCAN` event.
3. Show the event detail: `HIGH` severity, `10.77.0.10`, `10.77.0.20`, detector,
   deterministic source, timestamps, threshold, unique ports, attempts, and
   linked incident.
4. Open the incident and select **Create investigation task**. This is the
   existing authenticated analyst API and creates a real `INVESTIGATION`
   AgentTask linked to the event and incident.
5. Move the incident to `INVESTIGATING` with the lifecycle control.

The agent poller will read the persisted task. Refresh until the task is
`COMPLETED` and a finding is attached. No operator should submit a finding by
hand.

## 06:00–08:00 — Finding and audit review

Open the task and finding from the incident page:

1. Review the structured port distribution and flow evidence.
2. Show the finding type, confidence, detector provenance, event/incident
   links, and timestamps.
3. Open the finding and incident audit links.
4. Show the traceable sequence:

   ```text
   SecurityEvent → Incident → AgentTask → Finding → audit records
   ```

5. Move the incident through the permitted states appropriate for the demo
   (`INVESTIGATING` → `CONTAINED` → `RESOLVED`). The API rejects skipped or
   unauthorized transitions; the UI only offers the existing allowed next
   states.

## 08:00–09:00 — UDP_SCAN

Run the bounded UDP reconnaissance scenario:

```bash
./scripts/lab/udp-port-scan.sh
```

Show the distinct `UDP_SCAN` detector event, UDP transport metadata, linked
incident, and audit entry. This is still a port-scan family scenario; it tests
UDP flow parsing and detection separately from the TCP scan.

## 09:00–11:00 — SYN_FLOOD

Run the third authorized scenario:

```bash
./scripts/lab/syn-flood.sh
```

Repeat the same short path: engine log, real `SYN_FLOOD` event, incident,
investigation task, finding evidence, audit trail, and permitted incident
lifecycle. Point out the detector receipt fields for initial SYN attempts,
incomplete handshakes, ratio, rate, destination port, and observation window.

## 11:00–13:00 — ML anomaly

The ML path is an experimental, locked integration rather than a production
accuracy claim. Before this segment, use the existing `.env.ml` configuration
from [ml-inference-integration.md](ml-inference-integration.md) and start the
same demo runtime; do not alter the model, threshold, feature contract, or
controlled corpus.

Use the existing validated native-v2 flow-feature replay/integration procedure
when a deterministic live packet does not correspond to a known locked
evaluation record. The repository's previously recorded ML-enabled runtime
evidence is documented in [runtime-recovery.md](runtime-recovery.md): worker
`READY`, authenticated `ML_ANOMALY`, analyst promotion, agent investigation,
and audit verification.

In the dashboard show:

- `ML_ANOMALY` and `source: ML`;
- detector `isolation_forest_v2`;
- score, locked threshold, model and threshold hashes, model version, and
  `flow_features.v2` provenance when returned;
- the fact that an ML anomaly does not auto-create an incident: the analyst
  promotes it through the existing incident workflow;
- the same task → finding → audit path as deterministic events.

If the worker is not `READY` or the validated replay is unavailable, stop at
the honest failure state and say “ML validation is environment-gated”; do not
manufacture an ML event or claim a live result.

## 13:00–14:00 — ML failure isolation

With deterministic engine and Control Plane still running:

1. Stop only the ML worker using the existing process/runtime controls.
2. Confirm ML is `FAILED`/stopped in runtime status.
3. Run:

   ```bash
   ./scripts/lab/port-scan.sh
   ```

4. Show that a real deterministic `PORT_SCAN` still reaches the Control Plane.

The point is an architectural boundary, not an artificial error: ML failure is
not C++ deterministic detector failure. Restart the normal runtime before
leaving the environment if further testing is needed.

## 14:00–15:00 — RBAC, audit, and close

1. Show Settings with the current user role `ANALYST`.
2. Explain that public registration ignores elevated-role input and defaults
   new accounts to analyst; the agent identity is a separate `AGENT` service
   account.
3. Point out that analysts can view events, create tasks, update permitted
   incidents, and read audit data, while admin-only operations remain protected.
4. Open the audit view filtered to the incident or finding.
5. Close with the deployment boundary: a real network administrator places the
   sensor on a SPAN/TAP; the analyst investigates the persisted telemetry.


```bash
./scripts/stop-intriqo.sh
./scripts/lab/down.sh
```

The stop command preserves PostgreSQL data by default. The lab cleanup is
separate and removes only the owned demo namespaces after verification.

For recovery while retaining the lab, stop and restart only the application
runtime, then verify it again:

```bash
./scripts/stop-intriqo.sh
./scripts/start-demo.sh
INTRIQO_API_HOST=169.254.77.1 ./scripts/status-intriqo.sh
```

PostgreSQL data is persisted in the Compose-managed volume and is retained by
`stop-intriqo.sh`. Do not use `docker compose down -v` as a demo recovery step.

## Troubleshooting

- **Lab says `BLOCKED` or `sudo` is unavailable:** rerun from a terminal with
  working sudo authorization, then run `./scripts/lab/status.sh --verify`.
  The dashboard cannot create namespaces or independently inspect host lab
  interfaces.
- **Engine says live capture is unavailable:** rebuild the existing Release
  configuration with libpcap development headers available:

  ```bash
  cmake -S . -B build/intriqo-runtime-release \
    -DCMAKE_BUILD_TYPE=Release -DINTRIQO_BUILD_TESTS=ON \
    -DINTRIQO_ENABLE_PCAP=ON
  cmake --build build/intriqo-runtime-release --parallel
  ctest --test-dir build/intriqo-runtime-release --output-on-failure
  ```

  Check CMake's libpcap detection and `INTRIQO_HAS_PCAP` compile definition,
  then verify the monitor namespace and interface with `./scripts/lab/status.sh
  --verify` before restarting the runtime.
- **Control Plane or dashboard does not start:** inspect
  `./scripts/logs-intriqo.sh control-plane`, `./scripts/logs-intriqo.sh
  frontend`, and `./scripts/logs-intriqo.sh postgres`; check Docker Compose,
  ports 5432/8000/5173, and the local `.env` configuration.
- **Dashboard loads but has no new event:** check the lab mirror and engine
  readiness first, then run one bounded scenario with
  `./scripts/lab/port-scan.sh`. Compare the resulting event time and ingestion
  time to the current session before describing it as live. Do not create a
  dashboard record manually or lower detector thresholds.
- **Runtime restart fails because services are already running:** use
  `./scripts/stop-intriqo.sh`, inspect `./scripts/status-intriqo.sh`, then
  retry `./scripts/start-demo.sh`. Do not remove the PostgreSQL volume.

## Claims discipline

**Validated:** existing deterministic detector, Control Plane, agent, finding,
audit, authentication/RBAC, frontend, locked-ML integration, and controlled-v2
isolation evidence cited by the repository; the new scripts' shell/Python
static checks.

**Environment-gated:** privileged live TAP capture through the host's available
libpcap build, PostgreSQL/Docker availability, live analyst credentials, and a
complete live ML anomaly occurrence from the locked model. These must be
observed in the target environment before being called live-demo evidence.
