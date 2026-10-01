# Phase 3 — Java → Python SecurityEvent Integration

## Status

**Phase 3 is complete and verified end to end.** A **real** `SecurityEvent` produced by the
existing Java detection pipeline (network-flow JSON → ingestion → detection engine → port-scan
detector) is serialized to a stable JSON contract and consumed by the **existing, unmodified**
Python agent foundation (adapter → `AgentOrchestrator` → `InvestigationAgent` → deterministic
tools → `AgentResult`).

The boundary is explicit, minimal, and proven by a deterministic integration test that runs both
halves for real.

---

## End-to-end flow (verified)

```
security-lab/traffic-data/port-scan-flows.json      (real Phase 2 fixture)
        ↓
Java NetworkFlowIngestionService                    (EXISTING, unmodified)
        ↓
Java DetectionEngine + PortScanDetector             (EXISTING, unmodified)
        ↓
REAL Java SecurityEvent
        ↓
SecurityEventExportDto                              (Phase 3 contract DTO)
        ↓  JSON Lines on stdout
SecurityEventBridgeCli                              (Phase 3 transport half)
        ↓  build/phase3-contract/port-scan-events.jsonl
JavaEventAdapter (Python)                           (Phase 3 adapter half)
        ↓
Python SecurityEvent                                (EXISTING, unmodified)
        ↓
AgentOrchestrator                                   (EXISTING, unmodified)
        ↓
InvestigationAgent + deterministic mock tools       (EXISTING, unmodified)
        ↓
AgentResult
```

There is **no** Kafka, Redis, RabbitMQ, REST API, gRPC, database, WebSocket, or cloud transport in
Phase 3. The transport is a local JSON Lines contract produced by a tiny CLI and written to a file
in `build/`. The transport can be replaced later without changing either domain model.

---

## Java SecurityEvent contract

Serialized by `com.intriqo.integration.SecurityEventExportDto`.

Every field is **required and non-null** in the emitted contract.

| Field | Type | Source | Notes |
|---|---|
| `event_id` | string (UUID) | `SecurityEvent.eventId()` | Unique per event |
| `event_type` | string | `SecurityEvent.eventType()` | Java `PortScanDetector` emits `PORT_SCAN` |
| `severity` | string enum | `SecurityEvent.severity().name()` | One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `timestamp` | string (ISO 8601 UTC, ms) | `SecurityEvent.timestamp()` | Format `yyyy-MM-dd'T'HH:mm:ss.SSS'Z'` |
| `source_address` | string | `SecurityEvent.sourceAddress()` | Attacker / source IP |
| `destination_address` | string | triggering `NetworkFlow.destinationAddress()` | **Not** carried by the Java `SecurityEvent` — see below |
| `description` | string | `SecurityEvent.description()` | Human-readable detection text |
| `details` | object | `SecurityEvent.details()` | Detector metadata as produced by `PortScanDetector` |

### Example JSON (real output, one line)

```json
{"event_id":"eba756ec-5ec8-478c-aad4-508cfc98f2e8","event_type":"PORT_SCAN","severity":"MEDIUM","timestamp":"2026-09-12T14:23:54.000Z","source_address":"172.20.0.10","destination_address":"172.20.0.20","description":"Port scan detected from 172.20.0.10: 10 distinct ports contacted","details":{"threshold":10,"timeWindowSeconds":300,"distinctPortCount":10,"targetedHosts":1,"sourceAddress":"172.20.0.10"}}
```

Format is **JSON Lines**: one contract object per emitted `SecurityEvent`.

### Why `destination_address` exists in the contract

The Java `SecurityEvent` domain record carries only `sourceAddress`. The Python `SecurityEvent`
requires a non-empty `target`. To satisfy that, the export layer attaches the destination address
of the flow that triggered the detection:

* `SecurityEventBridgeCli` builds a `source → first-destination` index from the ingested fixture
  and supplies it to `SecurityEventExportDto.fromSecurityEvent(event, destinationAddress)`.
* This is an explicit, documented decision. It adds no fields to the Java domain model and does
  not touch detection logic.

---

## Python SecurityEvent mapping

The adapter is `agents/integration/java_event_adapter.py`.

| Java contract field | Python `SecurityEvent` field | Transformation |
|---|---|---|
| `event_id` | `id` | Direct (must be non-empty string) |
| `event_type` | `event_type` | `EVENT_TYPE_MAP` translation (see below) |
| `severity` | `severity` | Must be in `VALID_SEVERITIES` (`LOW/MEDIUM/HIGH/CRITICAL`) |
| `timestamp` | `timestamp` | ISO 8601 → **timezone-aware** `datetime` (UTC) |
| `source_address` | `source` | Direct |
| `destination_address` | `target` | Direct |
| `description` | `metadata["description"]` | Stored in metadata (no top-level Python field) |
| `details` | `metadata` | Merged; description added alongside detector keys |

### Event type mapping

| Java `event_type` | Python `event_type` |
|---|---|
| `PORT_SCAN` | `PORT_SCAN_DETECTED` |

Unknown Java event types are passed through unchanged and a warning is logged, so a new Java
detector cannot silently break ingestion before its mapping is added.

### Adapter guarantees

* Rejects malformed JSON, missing required fields, `null` required values, wrong types, empty/blank
  strings, invalid severity enums, and unparseable timestamps.
* Raises `JavaEventAdapterError` (a `ValueError` subclass) with an actionable message.
* **Never** silently substitutes a default for an invalid security event.

---

## Integration boundary

```
Java package:   com.intriqo.integration
                  SecurityEventExportDto      — stable contract DTO
                  SecurityEventExportService  — SecurityEvent → contract JSON (used by tests)
                  SecurityEventBridgeCli      — process-level transport (stdout JSON Lines)

Python package: agents.integration
                  java_event_adapter          — contract JSON → Python SecurityEvent
```

**Prohibited crossings (enforced by construction):**

* Python never links against, loads, or inspects Java internals, memory, or databases.
* Java never manipulates Python agent internals.
* No circular dependency: Java has no knowledge of Python; Python only knows the JSON contract.
* Agents execute only in-process deterministic tools — no shell, no network, no infrastructure.
* Agents are **observational/investigative only**. There is no `ActionRequest`, no policy engine,
  and no response execution in Phase 3.

---

## Test commands

### Java (all tests)

```bash
./gradlew test
```

### Java (Phase 3 only)

```bash
./gradlew test --tests "com.intriqo.integration.*"
```

### Emit the real contract artefacts manually

```bash
./scripts/phase3_emit_contract.sh
# → build/phase3-contract/port-scan-events.jsonl      (real detections)
# → build/phase3-contract/normal-traffic-events.jsonl (empty — no detections)
```

The same pipeline is also available directly:

```bash
./gradlew emitSecurityEvents -Pfixture=security-lab/traffic-data/port-scan-flows.json -Pthreshold=10 -PtimeWindow=300
```

### Python (all tests)

```bash
PYTHONPATH=. python3 -m unittest discover -s agents/tests -p "test_*.py" -v
```

### Python (Phase 3 only)

```bash
PYTHONPATH=. python3 -m unittest agents.tests.test_java_event_adapter agents.tests.test_phase3_e2e -v
```

> The Python Phase 3 end-to-end test **runs the real Java pipeline** in `setUpClass` by invoking
> `scripts/phase3_emit_contract.sh`. It therefore requires a working JDK/Gradle. If the Java
> artefacts cannot be produced, the test **fails** — it never silently skips.

---

## Files created / modified in Phase 3

### Java — new

| File | Purpose |
|---|---|
| `src/main/java/com/intriqo/integration/SecurityEventExportDto.java` | Stable contract DTO + deterministic JSON serialization |
| `src/main/java/com/intriqo/integration/SecurityEventExportService.java` | `SecurityEvent` → contract JSON, wrapping `DetectionEngine` |
| `src/main/java/com/intriqo/integration/SecurityEventBridgeCli.java` | Process-level transport emitting JSON Lines to stdout |
| `src/test/java/com/intriqo/integration/SecurityEventExportDtoTest.java` | DTO unit + round-trip tests |
| `src/test/java/com/intriqo/integration/JavaToPythonContractIntegrationTest.java` | Contract shape + normal-traffic Java tests |
| `src/test/java/com/intriqo/integration/SecurityEventBridgeCliTest.java` | CLI transport tests (real fixtures) |
| `src/test/java/com/intriqo/integration/Phase3ContractEmitterTest.java` | Writes real contract artefacts for Python |

### Python — new

| File | Purpose |
|---|---|
| `agents/integration/__init__.py` | Integration package marker |
| `agents/integration/java_event_adapter.py` | Java contract JSON → Python `SecurityEvent` |
| `agents/tests/test_java_event_adapter.py` | Adapter unit tests (validation, mapping, errors) |
| `agents/tests/test_phase3_e2e.py` | **Real** end-to-end test invoking the Java pipeline |

### Tooling / docs — new or modified

| File | Change |
|---|---|
| `scripts/phase3_emit_contract.sh` | New — runs the real Java pipeline, writes contract artefacts |
| `build.gradle` | Added `emitSecurityEvents` JavaExec task |
| `docs/phase3-integration.md` | This document |
| `agents/README.md` | Documents the Java integration boundary |

### Unmodified

All pre-existing Java domain/detection/ingestion classes and all pre-existing Python models,
orchestrator, agents, and tools are **untouched**. Detection logic and `PortScanDetector` were not
modified. No persistence, broker, or new runtime dependency was introduced.

---

## Known limitations

1. **Transport is a local process/file boundary, not a production message bus.** Real events cross
   the boundary as JSON Lines produced by `SecurityEventBridgeCli` and written to `build/`. This
   deliberately proves the *domain and contract* boundary first; a broker can replace it later
   without changing either domain model.
2. **`destination_address` is synthesized from the triggering flow** because the Java
   `SecurityEvent` has no destination field (documented above).
3. **Event type dualism.** Java emits `PORT_SCAN`; the Python `InvestigationAgent` handles
   `PORT_SCAN_DETECTED`. The adapter bridges the gap. Unify if the Java literal ever changes.
4. **Only the port-scan path is integrated.** Other detectors (brute force, SYN flood, etc.) do not
   yet exist in the Java core, so no other event type is exercised.
5. **No response capability.** Agents cannot act on infrastructure. The planned
   `ActionRequest → Java Policy Engine → ALLOW/HUMAN APPROVAL/DENY → Controlled Action` flow is
   future work and is **not** implemented.
6. **No LLM, RAG, vector store, embeddings, or autonomous response** exist in this phase.

## Technical debt

| Item | Origin | Description |
|---|---|---|
| `IntriqoApplicationTests` `@Disabled` | Pre-Phase 3 | Full Spring context test disabled pending DB/Kafka setup. Still skipped — reported, not weakened. |
| No production transport | Phase 4+ | Replace the CLI/file boundary with a real transport when required |
| Event type dualism | Phase 4+ | Unify Java `PORT_SCAN` with Python `PORT_SCAN_DETECTED` |
| `destination_address` synthesis | Phase 3 | Add destination to the Java `SecurityEvent` domain model if the contract stabilizes |
