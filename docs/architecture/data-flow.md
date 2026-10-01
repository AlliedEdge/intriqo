# Data Flow

## Detection path (engine → control plane)

```
Network interface / PCAP file
        │
        ▼  raw bytes
CaptureSource.start() → PacketCallback
        │
        ▼  PacketView
ProtocolParser.parse() → ParsedPacket
        │
        ▼  ParsedPacket
FlowTable.update() → NetworkFlow (aggregated)
        │
        ▼  NetworkFlow
FlowFeatures::from_flow() → FlowFeatures
        │
        ▼  NetworkFlow + FlowFeatures
Detector.evaluate() × N → []SecurityEvent
        │
        ▼  SecurityEvent
SecurityEvent::to_json() → JSON Lines (contracts/events/security_event_v1.json)
        │
        ▼  HTTP POST / gRPC stream
control-plane: engine_client/adapter.py → parse_engine_event()
        │
        ▼  validated dict
IncidentService.create_from_engine_event() → Incident (persisted)
```

## Investigation path (control plane → agents → control plane)

```
Incident created
        │
        ▼
InvestigationService.dispatch_task(incident) → AgentTask
        │
        ▼  AgentTask JSON (contracts/agents/agent_task_v1.json)
AgentOrchestrator.process_event(security_event)
        │
        ▼  task_type = INVESTIGATION
AgentRegistry.find_agent_by_capability("investigation")
        │
        ▼
InvestigationAgent.execute(task)
        │
        ├── Tool: query_network_flows()   → ToolResult
        ├── Tool: query_historical_alerts() → ToolResult
        └── Tool: query_host_activity()   → ToolResult
        │
        ▼  AgentResult (SUCCESS / INCONCLUSIVE / FAILED)
AgentResult JSON (contracts/agents/agent_result_v1.json)
        │
        ▼
InvestigationService.record_result(result)
        │  ├── Update Investigation record
        │  └── Extract any ActionRequests from findings
        ▼
PolicyEngine.evaluate(action_request) → PolicyDecision
        │
        ├── ALLOW          → execute, audit
        ├── DENY           → reject, audit
        └── HUMAN_APPROVAL → enqueue, surface on dashboard
```

## Dashboard path (control plane → frontend)

```
GET  /api/v1/incidents          → IncidentListResponse
GET  /api/v1/incidents/{id}     → IncidentDetailResponse
GET  /api/v1/investigations     → InvestigationListResponse
WS   /ws/events                 → live SecurityEvent stream
WS   /ws/agent-activity         → live agent task updates
POST /api/v1/approvals/{id}     → approve or reject pending action
GET  /api/v1/audit              → AuditLogResponse
```
