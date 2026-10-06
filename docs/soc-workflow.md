# Intriqo SOC workflow

This document describes the persisted analyst workflow implemented by the
existing local stack:

```text
detection → SecurityEvent → correlation → Incident → Investigation
          → Finding → audit trail → dashboard
```

The Control Plane is authoritative for event type, provenance, severity,
status, timestamps, relationships, and audit records. The React dashboard
only renders those REST responses; it does not recalculate security state.

## Detection and event semantics

The supported event types remain distinct:

| Event type | Detection source | Detector receipt |
| --- | --- | --- |
| `PORT_SCAN` | `DETERMINISTIC` | `details.detector` (`port_scan` from the C++ engine) |
| `SYN_FLOOD` | `DETERMINISTIC` | `details.detector` (`syn_flood` from the C++ engine) |
| `ML_ANOMALY` | `ML` | `details.detector` (`isolation_forest_v2`) |

The event ID supplied by the engine is the durable event identity. A repeated
event ID is rejected with `409 DUPLICATE_EVENT`; the Control Plane does not
create a second logical event. Deterministic events are persisted with an
explicit `details.detection_source=DETERMINISTIC`. ML events retain the
payload-free detector/model receipt from the locked ML worker.

## Correlation rules

`PORT_SCAN` and `SYN_FLOOD` are automatically correlated. The stable,
directional correlation key is:

```text
EVENT_TYPE.upper() | SOURCE_ADDRESS.lower() | DESTINATION_ADDRESS.lower()
```

Events with the same key and event timestamps within **300 seconds** are
linked to one active (`OPEN`, `INVESTIGATING`, or `CONTAINED`) incident. The
incident keeps the highest observed severity. Severity is not part of the
key, so a later severity change does not fork the situation. PostgreSQL
transaction advisory locking serializes concurrent arrivals for one key.

`ML_ANOMALY` does not create an incident by itself. This preserves the
existing analyst-only promotion boundary. When an analyst links an ML event,
the Control Plane reuses an already-active deterministic incident for the same
directional endpoints and five-minute window when one exists; otherwise it
creates a new analyst-linked incident. This lets a controlled `PORT_SCAN` +
ML situation share a timeline without collapsing their provenance.

## Incident lifecycle

The required lifecycle is explicit and persisted:

```text
OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED
  └→ FALSE_POSITIVE
```

`FALSE_POSITIVE` remains a compatibility terminal state and is available from
`OPEN`, `INVESTIGATING`, or `CONTAINED`. Invalid skips are rejected. Repeating
the current state is an idempotent no-op on the incident and still records
the analyst action. Completing an investigation task never changes incident
state: investigation completion is separate from containment and resolution.

## Investigation and findings

An analyst or controlled workflow creates an `INVESTIGATION` AgentTask with
both `event_id` and `incident_id`. The existing poller or one-shot runner
passes that task to `InvestigationAgent`. Supported handlers are:

- `PORT_SCAN`: structured port/count/attempt evidence;
- `SYN_FLOOD`: source, destination port, SYN count, incomplete handshake
  count, ratio, rate, window, and detector evidence;
- `ML_ANOMALY`: flow ID, score, threshold, model/threshold hashes, model
  version, detector, engine instance, and frozen feature schema version.

No handler executes arbitrary host commands, stores packet payloads, includes
ground-truth labels, or performs remediation. ML severity is the worker's
current fixed `MEDIUM` severity and is experimental; this milestone does not
add dynamic severity scoring or retrain the model.

Finding responses include the event, incident, task, severity, source,
structured evidence, provenance, status, confidence, and creation timestamp.
The database uniqueness constraint `(task_id, agent_name)` makes a retry of a
finding submission return the existing finding. Task idempotency keys and
engine event IDs provide the corresponding durable retry boundaries.

## Audit and timeline

Important mutations write append-only audit records containing actor, action,
resource type, resource ID, outcome, timestamp, and structured metadata:

- event ingestion and correlation;
- incident creation/linking and state updates;
- task creation and status transitions;
- finding submission.

Incident, task, finding, and event detail pages query their own audit records.
Timeline order is the Control Plane's persisted `created_at` descending order;
timestamps are actual database timestamps, not generated UI timestamps. When
two records have equal display precision, the database ordering remains the
authoritative order returned by the API.

## Authorization

`ADMIN` has full administrative access. `ANALYST` can view SOC records,
create/update incidents, create tasks, and read audit data. `AGENT` is a
service identity that can read assigned workflow data, update its task, and
submit findings; it cannot change incident lifecycle or administer users.
Missing, invalid, and disallowed bearer tokens remain `401`/`403` responses.

## Dashboard workflow

The dashboard uses authenticated REST with initial fetches and explicit
refresh; it does not add WebSockets or SSE. Analysts can navigate:

```text
Event → Incident → AgentTask → Finding → Evidence → Audit
Incident → Events / Tasks / Findings / Timeline / Audit
```

The dashboard shows persisted events, provenance, severity, active/recent
incidents, task status, findings, structured evidence, relationship IDs, and
audit records. Loading, empty, and API/network error states are displayed
without substituting fake counters or fixture data.

## Known limitations

- Task creation remains an explicit analyst/controlled-workflow action; this
  milestone does not add a new broker or autonomous response loop.
- ML promotion to an incident requires an analyst, except when it is attached
  to an existing deterministic situation by the analyst link operation.
- The ML detector and artifacts remain experimental and locked to the existing
  controlled-v2 assets.
- This is a local reproducible workflow, not a production-readiness claim.
