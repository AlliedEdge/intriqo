# Component Diagram

## Engine subsystems

```
engine/
├── capture/        CaptureSource (abstract) — live / PCAP replay
├── packet/         PacketView (raw) → ParsedPacket (L3/L4 headers)
├── protocol/       ProtocolParser — Ethernet → IP → TCP/UDP/ICMP
├── flow/           FlowKey, NetworkFlow, FlowTable, FlowLifecycle
├── features/       FlowFeatures::from_flow()
├── rules/          Rule (stateless predicates)
├── detection/      Detector (abstract, stateful) — owns time windows
├── anomaly/        AnomalyDetector (abstract, statistical baseline)
├── events/         SecurityEvent, Severity, EventType
├── pipeline/       Pipeline (abstract) — wires subsystems together
├── runtime/        Engine (abstract) — top-level wiring + lifecycle
└── metrics/        EngineMetrics snapshot
```

## Control-plane modules

```
control-plane/src/intriqo/
├── api/            FastAPI app factory, routers (thin HTTP layer)
├── auth/           JWT, RBAC, FastAPI dependencies
├── domains/        Incident, Investigation, Evidence, ActionRequest, Audit
├── services/       IncidentService, InvestigationService, EventIngestionService
├── repositories/   SQLAlchemy async repositories per domain
├── database/       Session management, migration coordination
├── messaging/      Event bus adapters (in-process → Kafka when justified)
├── engine_client/  SecurityEvent JSON → control-plane domain model
├── policy/         PolicyEngine, ActionRequest, PolicyDecision
├── observability/  Structured logging, Prometheus metrics, tracing
└── config/         Pydantic Settings, environment variable loading
```

## Agent platform modules

```
agents/src/intriqo_agents/
├── contracts/      SecurityEvent (inbound boundary model)
├── state/          AgentTask, AgentResult
├── core/           Agent (abstract base class)
├── tools/          Tool, ToolResult, mock tools, engine_event_adapter
├── orchestrator/   AgentOrchestrator, AgentRegistry
├── investigation/  InvestigationAgent
├── correlation/    (future) CorrelationAgent
├── threat_intel/   (future) ThreatIntelAgent
├── response/       (future) ResponseAgent
├── policies/       (future) Agent-side policy primitives
├── memory/         (future) Working memory, episodic memory
├── llm/            (future) LLM client abstraction
└── workflows/      (future) Multi-step investigation workflows
```

## Frontend features

```
frontend/dashboard/src/features/
├── overview/       SOC overview — system health, live metrics
├── incidents/      Incident list, detail, timeline
├── investigations/ Investigation progress, agent findings
├── agents/         Agent activity monitor, task queue
├── detections/     Live detection feed
├── approvals/      Human-approval queue for agent-proposed actions
└── audit/          Audit log viewer
```
