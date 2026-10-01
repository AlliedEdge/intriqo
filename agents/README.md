# Intriqo — Python Agent Foundation

The Python Agent Foundation is the core reasoning and orchestration subsystem for **Intriqo**, an autonomous multi-agent cybersecurity SOC.

The main Intriqo backend is a separate **Java 21 + Spring Boot** application implementing the detection engine and system policies. The Python agent foundation is intentionally decoupled from the Java backend, external databases, messaging buses, and specific LLM providers. It is fully executable and testable locally using deterministic mock data.

---

## 1. Architectural Principles

### Autonomous Reasoning decoupled from Execution Authority
The Python agent layer is strictly a **reasoning and orchestration engine**. It does **NOT** possess unrestricted authority over infrastructure, operating systems, databases, or firewalls.

```
+-------------------------------------------------------------+
|               PYTHON AGENT REASONING LAYER                  |
|                                                             |
|   SecurityEvent -> AgentTask -> Agent -> Tool -> AgentResult|
|                                     │                       |
|                                     ▼                       |
|                          ActionRequest (Future)             |
+─────────────────────────────────────┼───────────────────────+
                                      │
                                      ▼
+-------------------------------------------------------------+
|                  JAVA POLICY & CONTROL LAYER                |
|                                                             |
|       Policy Evaluation (ALLOW / DENY / REQUIRE APPROVAL)   |
|                                     │                       |
|                                     ▼                       |
|                    Controlled Infrastructure Action         |
+-------------------------------------------------------------+
```

### Decoupled Contracts
The subsystem does not import Java classes or depend on a shared filesystem with Java. It uses decoupled, value-oriented domain models with JSON-compatible serialization contracts.

### Zero Infrastructure & Zero External Runtime Dependencies
The core foundation is implemented entirely using Python's standard library (`dataclasses`, `typing`, `datetime`, `abc`, `logging`, `json`, `uuid`). It runs out of the box without requiring Kafka, Redis, PostgreSQL, or remote LLM API keys.

---

## 2. Component Structure

```
agents/
├── core/
│   ├── agent.py                 # Abstract Agent protocol/base class
│   └── investigation_agent.py   # InvestigationAgent implementation
├── models/
│   ├── security_event.py        # Immutable SecurityEvent model & validation
│   ├── task.py                  # Immutable AgentTask model & validation
│   └── result.py                # Machine-readable AgentResult model & factories
├── tools/
│   ├── base.py                  # Tool and ToolResult abstractions
│   └── mock_tools.py            # query_network_flows, query_historical_alerts, etc.
├── orchestration/
│   ├── registry.py              # Capability-based AgentRegistry
│   ├── orchestrator.py          # Event-to-task routing and agent execution
│   └── main.py                  # Standalone runnable demo
├── integration/                  # Java → Python integration boundary (Phase 3)
│   └── java_event_adapter.py     # Java SecurityEvent JSON contract → Python SecurityEvent
├── tests/
│   ├── fixtures.py              # Representative mock event fixtures
│   ├── test_models.py           # Domain model unit tests & validation
│   ├── test_tools.py            # Tool execution and error handling tests
│   ├── test_investigation_agent.py # End-to-end investigation agent tests
│   ├── test_orchestrator.py     # Orchestrator routing & failure recovery tests
│   ├── test_contracts.py        # Contract serialization and fixture tests
│   ├── test_java_event_adapter.py # Adapter validation & mapping tests
│   └── test_phase3_e2e.py       # Real Java pipeline → Python agent end-to-end test
├── requirements.txt             # Development requirements (pytest)
└── pyproject.toml               # Package configuration
```

### Java → Python integration (Phase 3)

The agent foundation consumes **real** `SecurityEvent`s from the Java detection core via an
explicit JSON contract. The adapter `agents/integration/java_event_adapter.py` validates and
converts the Java contract into the existing `SecurityEvent` model:

```
REAL Java SecurityEvent → JSON contract → java_event_adapter → Python SecurityEvent
        → AgentOrchestrator → InvestigationAgent → deterministic tools → AgentResult
```

See [`docs/phase3-integration.md`](../docs/phase3-integration.md) for the contract, field
mapping, and the end-to-end test command.

---

## 3. End-to-End Data Flow

```
1. Ingest SecurityEvent
      │
      ▼
2. Orchestrator creates AgentTask
      │ (Maps event severity -> priority: CRITICAL -> URGENT, HIGH -> HIGH)
      ▼
3. Orchestrator discovers Agent via Registry
      │ (Matches task_type="INVESTIGATION" to Agent with "investigation" capability)
      ▼
4. InvestigationAgent receives AgentTask
      │
      ▼
5. InvestigationAgent selects appropriate Tool
      │ (e.g., selects "query_network_flows" for PORT_SCAN_DETECTED)
      ▼
6. Tool executes against deterministic telemetry
      │ (Validates input schema, queries mock store)
      ▼
7. ToolResult returned to Agent
      │ (Contains flow records or structured error details)
      ▼
8. InvestigationAgent aggregates evidence & computes confidence
      │ (Extracts probed ports, flow volume, bytes)
      ▼
9. AgentResult returned to Orchestrator
```

---

## 4. Domain Models

### `SecurityEvent`
Represents an immutable, validated security detection event:
* `id` (str): Unique identifier.
* `timestamp` (datetime): Detection timestamp (UTC).
* `event_type` (str): Type of event (e.g. `PORT_SCAN_DETECTED`, `BRUTE_FORCE_DETECTED`).
* `severity` (str): One of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
* `source` (str): Source IP/hostname.
* `target` (str): Target IP/hostname.
* `metadata` (dict): Contextual metadata (flow stats, detector details).

### `AgentTask`
Represents an assigned unit of investigation work:
* `task_id` (str): Unique task identifier.
* `task_type` (str): Task classification (`INVESTIGATION`).
* `description` (str): Human-readable task description.
* `security_event` (SecurityEvent): Underlying event to investigate.
* `priority` (str): `LOW`, `MEDIUM`, `HIGH`, `URGENT`.
* `context` (dict): Working context for the task.
* `created_at` (datetime): Creation timestamp.

### `AgentResult`
Represents the structured, machine-readable findings:
* `task_id` (str): Associated task identifier.
* `agent_name` (str): Name of executing agent.
* `status` (str): `SUCCESS`, `FAILED`, or `INCONCLUSIVE`.
* `findings` (tuple[str, ...]): Structured findings.
* `evidence` (tuple[dict, ...]): Machine-readable evidence artifacts (port distributions, flow counts).
* `confidence` (float): Confidence score between `0.0` and `1.0`.
* `summary` (Optional[str]): Human-readable summary.
* `error` (Optional[dict]): Structured failure details if `status="FAILED"`.

---

## 5. Tool Abstraction & Security Controls

Every tool inherits from `Tool` and returns a `ToolResult`:
* **Input Schema Validation**: Inputs are validated against explicit schemas before execution.
* **Controlled Access**: No shell execution or arbitrary commands (`subprocess`, `os.system` are prohibited).
* **Fault Isolation**: Tool failures and unhandled exceptions are caught and wrapped into structured `ToolResult.fail()` objects without crashing the agent.

### Included Mock Tools
1. `NetworkFlowQueryTool` (`query_network_flows`): Queries deterministic flow telemetry for source and target hosts.
2. `HistoricalAlertsQueryTool` (`query_historical_alerts`): Queries prior security incidents for an IP.
3. `HostActivityQueryTool` (`query_host_activity`): Queries endpoint host telemetry (running services, open ports).
4. `FailingMockTool`: Deterministic failure/error simulation tool for resilience testing.

---

## 6. Running Tests and Verification

### Running Tests (Standard Library `unittest`)
Zero dependencies required:
```bash
python3 -m unittest discover -s agents/tests -v
```

### Running Tests (via `pytest`)
If pytest is installed in your virtual environment:
```bash
pytest agents/tests -v
```

### Running the Standalone Demo
```bash
python3 agents/orchestration/main.py
```
or:
```bash
python3 agents/main.py
```

---

## 7. Current Limitations & Deliberately Deferred Scope

In alignment with Phase 0 / Foundation scope, the following are **deliberately not implemented**:
* **LLM Reasoning Providers**: No external LLM dependencies (OpenAI, Anthropic, LangChain, etc.). Agents operate deterministically.
* **Autonomous Feedback Loop**: The full `observe -> plan -> investigate -> correlate -> respond -> verify -> repeat` cycle is deferred to subsequent phases.
* **Specialized Peer Agents**: Threat Intelligence Agent, Correlation Agent, and Response Agent are planned for future phases.
* **Java Backend Integration**: A narrow, file/JSON-contract integration with the Java detection core now exists (Phase 3, see `docs/phase3-integration.md`). Production transports (HTTP/gRPC/Kafka) remain deferred.
* **Infrastructure**: No Kafka brokers, Redis caches, or PostgreSQL databases are required or integrated at this stage.
* **Automated Action Execution**: Response actions will require Java Policy Engine validation in future phases.
