# Tool Layer

← [Back to Agent Overview](overview.md) · [Back to README](../../README.md)

---

## Why Tools?

Agents must not hallucinate system information. Every piece of evidence an agent uses must come from a real data source returned through a structured, validated tool call.

Tools enforce:
- **Least privilege** — agents call only the functions they need
- **Input validation** — every input is checked against a typed schema before execution
- **Auditability** — every tool call is logged
- **Correctness** — tools return actual data, not AI-generated guesses

---

## Tool Abstraction

**File:** `agents/src/intriqo_agents/tools/base.py`

```python
class Tool(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def description(self) -> str: ...

    @property
    @abstractmethod
    def input_schema(self) -> dict[str, Any]: ...

    def execute(self, input_data: dict[str, Any]) -> ToolResult:
        # 1. validate_input()  — raises on missing/empty required fields
        # 2. _run()            — subclass implementation
        # Returns ToolResult(success, data, error, metadata)
```

```python
@dataclass(frozen=True)
class ToolResult:
    success:  bool
    data:     dict[str, Any]   # structured response
    error:    str | None       # error message if success=False
    metadata: dict[str, Any]   # timing, source, etc.
```

Any exception inside `_run()` is caught and wrapped in a `ToolResult.fail(...)` — agents are never exposed to raw exceptions from tool execution.

---

## Execution Chain

```
Agent calls tool.execute(input_data)
      ↓
tool.validate_input(input_data)     ← raises ValueError if required field missing
      ↓
tool._run(input_data)               ← subclass implementation
      ↓
returns ToolResult
      ↓
Agent inspects result.success
  True  → use result.data
  False → return AgentResult.failure(...)
```

---

## Currently Implemented Tools (Mock)

**File:** `agents/src/intriqo_agents/tools/mock_tools.py`

These return deterministic data for testing. They will be replaced by real implementations backed by the control plane API.

### NetworkFlowQueryTool

```python
tool = NetworkFlowQueryTool()
result = tool.execute({"source_ip": "10.0.0.10", "target_ip": "10.0.0.20", "limit": 100})

# result.data:
{
    "count": 10,
    "flows": [
        {"flow_id": "flow-001", "src_ip": "10.0.0.10", "dst_ip": "10.0.0.20",
         "dst_port": 21, "protocol": "TCP", "flags": "SYN", "packet_count": 1},
        ...
    ]
}
```

### HistoricalAlertsQueryTool

```python
result = tool.execute({"ip_address": "10.0.0.10"})

# result.data:
{
    "ip_address":   "10.0.0.10",
    "alert_count":  1,
    "alerts": [
        {"alert_id": "hist-alert-901", "type": "RECON_PROBE",
         "severity": "LOW", "timestamp": "2026-09-11T18:30:00Z"}
    ]
}
```

### HostActivityQueryTool

```python
result = tool.execute({"host_ip": "10.0.0.20"})

# result.data:
{
    "host_ip": "10.0.0.20",
    "found":   True,
    "telemetry": {
        "hostname":        "srv-prod-web01",
        "os":              "Linux 6.6",
        "active_services": ["nginx", "sshd", "postgresql"],
        "open_ports":      [22, 80, 443, 5432]
    }
}
```

### FailingMockTool

Used exclusively in tests to verify agent error-handling behaviour.

```python
tool = FailingMockTool(should_raise=True, error_message="Simulated failure")
result = tool.execute({})
# result.success == False, result.error == "Execution error: Simulated failure"
```

---

## Engine Event Adapter

**File:** `agents/src/intriqo_agents/tools/engine_event_adapter.py`

This is a special-purpose adapter — not a `Tool` subclass, but part of the tools package — that translates raw engine JSON into a typed `SecurityEvent`.

```python
from intriqo_agents.tools.engine_event_adapter import adapt_from_json, EngineEventAdapterError

event = adapt_from_json('{"event_id": "...", "event_type": "PORT_SCAN", ...}')
# → SecurityEvent(id=..., event_type="PORT_SCAN_DETECTED", ...)
```

**Guarantees:**
- Rejects malformed JSON, missing fields, null required values, wrong types
- Maps engine event type literals → Python literals (`PORT_SCAN` → `PORT_SCAN_DETECTED`)
- Returns a timezone-aware `datetime` for the timestamp
- Never silently substitutes a default for an invalid event

---

## Planned Real Tool Implementations

When the control plane REST API routes are implemented, mock tools will be replaced:

| Tool | Backend Endpoint | Status |
|---|---|---|
| `query_network_flows` | `GET /api/v1/flows` | 📋 Planned |
| `query_historical_alerts` | `GET /api/v1/alerts` | 📋 Planned |
| `query_host_activity` | `GET /api/v1/hosts/{ip}` | 📋 Planned |
| `query_auth_events` | `GET /api/v1/auth-events` | 📋 Planned |
| `lookup_ip_reputation` | External API + cache | 📋 Planned |
| `request_block_ip` | `POST /api/v1/actions` | 📋 Planned |
| `request_isolate_host` | `POST /api/v1/actions` | 📋 Planned |
| `verify_response_action` | `GET /api/v1/actions/{id}` | 📋 Planned |

The mock/real switch is transparent to agents — they call `tool.execute(input)` either way.

---

→ Next: [Agent Communication](communication.md)
