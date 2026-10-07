# INTRIQO live demonstration runbook

Target duration: **10–15 minutes**. This runbook is deliberately narrow: one
analyst, one isolated sensor, two deterministic scenarios, one validated ML
path, and one failure-isolation check. Do not open database consoles or create
records manually during the demo.

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

## 08:00–10:00 — SYN_FLOOD

Run the second authorized scenario:

```bash
./scripts/lab/syn-flood.sh
```

Repeat the same short path: engine log, real `SYN_FLOOD` event, incident,
investigation task, finding evidence, audit trail, and permitted incident
lifecycle. Point out the detector receipt fields for initial SYN attempts,
incomplete handshakes, ratio, rate, destination port, and observation window.

## 10:00–12:00 — ML anomaly

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

## 12:00–13:00 — ML failure isolation

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

## 13:00–15:00 — RBAC, audit, and close

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

## Claims discipline

**Validated:** existing deterministic detector, Control Plane, agent, finding,
audit, authentication/RBAC, frontend, locked-ML integration, and controlled-v2
isolation evidence cited by the repository; the new scripts' shell/Python
static checks.

**Environment-gated:** privileged live TAP capture through the host's available
libpcap build, PostgreSQL/Docker availability, live analyst credentials, and a
complete live ML anomaly occurrence from the locked model. These must be
observed in the target environment before being called live-demo evidence.
