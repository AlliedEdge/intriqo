# Intriqo Core v1 runtime recovery

This page documents bounded local recovery for the Core v1 stack. It is an
operational guide, not a production deployment procedure. The launcher owns
startup order, PostgreSQL readiness, migrations, process PIDs, logs, and
graceful shutdown.

## Recovery matrix

| Component | Failure | Expected behavior | Recovery |
|---|---|---|---|
| PostgreSQL | unavailable | `/ready` returns `503`; Control Plane is unhealthy; data is not re-created | Restore/start PostgreSQL, then run `./scripts/status-intriqo.sh`; restart the stack if needed |
| Control Plane | crash | Engine's existing bounded HTTP sink behavior applies; persisted data remains in PostgreSQL | `./scripts/start-intriqo.sh` after the process is stopped |
| ML worker | crash or invalid locked artifact | ML reports `FAILED`/degraded; deterministic IDS continues without ML | Fix the local ML configuration or restart with `INTRIQO_ML_ENABLED=false`; restart with the ML environment when ready |
| Agents | crash | Events and incidents remain persisted; investigation tasks remain recoverable | Restart the stack; the poller retries `PENDING`/`IN_PROGRESS` investigation tasks without duplicate findings |
| Frontend | crash | Backend, engine, database, and audit pipeline continue | Restart the stack or the Vite process; verify `http://127.0.0.1:5173/` |
| Engine | crash | No false healthy status; persisted records remain intact | Inspect `logs/engine.log`, correct the source/configuration, and restart |

## Standard recovery commands

```bash
./scripts/status-intriqo.sh
./scripts/logs-intriqo.sh --follow all
./scripts/stop-intriqo.sh --keep-postgres
./scripts/start-intriqo.sh
./scripts/smoke-intriqo.sh
```

`start-intriqo.sh` refuses to layer a second application stack over running
processes. `stop-intriqo.sh` stops the application processes and, unless
`--keep-postgres` is supplied, stops the PostgreSQL container without deleting
its volume.

## Database recovery

The Control Plane readiness endpoint is database-aware:

```bash
curl -i http://127.0.0.1:8000/ready
```

After PostgreSQL returns, confirm readiness and then run the smoke test. The
launcher reruns the idempotent Alembic command:

```bash
./scripts/start-intriqo.sh
```

Only an intentional local reset should remove the database volume:

```bash
docker compose down -v --remove-orphans
./scripts/start-intriqo.sh
```

This destroys local records and is not a normal recovery action. Do not edit
tables manually or run ad-hoc migration SQL.

## Failure-isolation boundaries

- ML is optional and disabled by default. It consumes a bounded native-v2
  stream and cannot block the C++ deterministic packet path.
- Agent retries are database-backed through event/task/finding identifiers and
  the `(task_id, agent_name)` finding uniqueness constraint.
- Control Plane and dashboard are separate host processes; dashboard failure
  does not stop backend persistence.
- The C++ engine retains its existing bounded event-sink and feature-sink
  behavior. A failed destination is observable in engine logs and exit status;
  it is not replaced with an unbounded queue.

## Validation evidence

The release-candidate validation exercises PostgreSQL, Control Plane, ML,
Agents, frontend, engine, and runtime-stack failure paths from a stopped local
state. Live packet capture remains separately validated at engine level but is
not claimed as full-stack validated when libpcap is unavailable in the host
environment.

## Release-candidate evidence

The following evidence was collected during the Core v1 validation on 2026-10-06
without changing protected model, threshold, schema, or corpus files:

| Check | Observed result |
|---|---|
| Zero-volume database initialization | `docker compose down -v --remove-orphans` followed by `./scripts/start-intriqo.sh` completed; Alembic reported `0005 (head)` and the authenticated smoke flow passed. |
| Database restart | `/ready` returned HTTP `503` with `database: error` while PostgreSQL was stopped, then returned `ready` after restart; previously persisted ML event data remained queryable. |
| Agent failure/recovery | With the poller stopped, the freshness-hardened smoke command returned nonzero with a `PENDING` task; after the poller restarted, the recoverable task completed with one finding. |
| Control Plane restart | `stop-intriqo.sh --keep-postgres` followed by `start-intriqo.sh` preserved PostgreSQL data and the smoke flow passed again. |
| Frontend failure/recovery | Stopping only Vite left Control Plane `/ready` at HTTP `200` while the dashboard became unreachable; restarting only the frontend restored HTTP `200` for both dashboard and backend. |
| Invalid ML artifact | The worker wrote `state: FAILED` with `artifact_validation_failed`; deterministic engine operation remained independently runnable. |
| ML-enabled runtime | The worker reported `READY`; a manifest-validated native-v2 record produced an authenticated `ML_ANOMALY`, which an analyst promoted to an incident before agent investigation and audit verification. |
| Control Plane unavailable | The C++ engine stopped with a controlled delivery error (`event_sink_failures=1`) and a bounded queue peak; it did not continue with an unbounded backlog. |
| Freshness and token regressions | Smoke rejects old events/tasks when Agents are stopped; launcher-owned expired development JWTs are refreshed, while explicit credentials are preserved. |
