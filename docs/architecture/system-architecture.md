# System Architecture

← [Back to README](../../README.md)

---

## Overview

Intriqo is built around four distinct technical layers, each with a clearly scoped responsibility. No layer reaches into another layer's domain.

```mermaid
flowchart TB
    subgraph Engine["⚙️ C++ IDS ENGINE"]
        E1[Packet Capture]
        E2[Protocol Parsing]
        E3[Flow Tracking]
        E4[Feature Extraction]
        E5[Rule Detectors]
        E6[Anomaly Detectors]
        E7[SecurityEvent JSON]
    end

    subgraph CP["🐍 PYTHON CONTROL PLANE — FastAPI"]
        CP1[Engine Client / Adapter]
        CP2[Incident Service]
        CP3[Investigation Service]
        CP4[Policy Engine]
        CP5[REST API + WebSocket]
        CP6[PostgreSQL Repositories]
    end

    subgraph Agents["🤖 PYTHON AGENT PLATFORM"]
        direction TB
        A0[Orchestrator]
        A1[Investigation Agent]
        A2[Threat Intel Agent]
        A3[Correlation Agent]
        A4[Response Agent]
        A0 --> A1
        A0 --> A2
        A0 --> A3
        A0 --> A4
    end

    subgraph UI["🖥️ REACT SOC DASHBOARD"]
        UI1[Overview · Detections · Incidents]
        UI2[Investigations · Agents]
        UI3[Approvals · Audit]
    end

    subgraph Data["💾 PERSISTENCE"]
        DB[(PostgreSQL)]
        Cache[(Redis)]
    end

    E7 -->|SecurityEvent JSON\ncontracts/events/| CP1
    CP1 --> CP2 --> CP3
    CP3 -->|AgentTask\ncontracts/agents/| A0
    A4 -->|ActionRequest\ncontracts/actions/| CP4
    CP4 -->|PolicyDecision| A4
    CP5 --> DB
    CP5 --> Cache
    DB --> UI1
    CP5 -->|WebSocket| UI2

    style Engine  fill:#fff4e1
    style CP      fill:#e1f5ff
    style Agents  fill:#ffe1f5
    style UI      fill:#e1ffe1
    style Data    fill:#f5f5f5
```

---

## Technology Split

| Layer | Language / Framework | Why |
|---|---|---|
| IDS Engine | C++20 / CMake | Line-rate packet processing — no GC pauses, zero-copy buffers |
| Control Plane | Python 3.10+ / FastAPI | Async I/O, Pydantic validation, clean layered architecture |
| Agent Platform | Python 3.10+ | LLM/agent/ML ecosystem dominance |
| SOC Dashboard | React 18 / TypeScript / Vite | Typed, component-based, real-time WebSocket |

---

## End-to-End Data Flow

```mermaid
flowchart TD
    A[Network interface or PCAP file] --> B[CaptureSource]
    B --> C[ProtocolParser\nEthernet → IP → TCP/UDP]
    C --> D[FlowTable.update\nAggregate packets into flows]
    D --> E[FlowFeatures::from_flow\nBytes/pkt · pps · SYN count]
    E --> F[Detector.evaluate × N]
    F --> G{Detection fires?}
    G -->|Yes| H[SecurityEvent::to_json\ncontracts/events/security_event_v1.json]
    G -->|No| I[Discard flow]
    H --> J[HTTP POST to Control Plane]
    J --> K[engine_client/adapter.py\nValidate + normalise]
    K --> L[IncidentService.create_from_event]
    L --> M[InvestigationService.dispatch_task]
    M --> N[AgentOrchestrator.process_event]
    N --> O[InvestigationAgent.execute\nvia tool calls]
    O --> P[AgentResult\nfindings + evidence + confidence]
    P --> Q[ResponseAgent proposes ActionRequest]
    Q --> R[PolicyEngine.evaluate]
    R --> S{Decision}
    S -->|ALLOW| T[Execute + Verify + Audit]
    S -->|DENY| U[Reject + Audit]
    S -->|HUMAN_APPROVAL| V[Dashboard approval queue]
    V --> W{Operator decision}
    W -->|Approve| T
    W -->|Deny| U
    T --> X[Update incident + notify dashboard]

    style F fill:#ffe1e1
    style R fill:#ffe1e1
    style O fill:#e1f5ff
    style T fill:#e1ffe1
    style U fill:#ffcccc
    style V fill:#fff4e1
```

---

## Architectural Boundaries

```mermaid
flowchart LR
    subgraph EngineLayer["⚙️ ENGINE LAYER (C++)"]
        EL[Packet capture\nFlow tracking\nDetection\nEvent emission]
    end

    subgraph ContractE["📋 contracts/events/\nsecurity_event_v1.json"]
    end

    subgraph CPLayer["🐍 CONTROL PLANE (Python)"]
        CPL[Auth · RBAC · Incidents\nPersistence · Policy\nAPI · WebSocket]
    end

    subgraph ContractA["📋 contracts/agents/\nagent_task_v1.json\nagent_result_v1.json"]
    end

    subgraph AgentLayer["🤖 AGENT PLATFORM (Python)"]
        AL[Orchestrator\nSpecialist agents\nTool layer\nLLM integration]
    end

    subgraph ContractAct["📋 contracts/actions/\naction_request_v1.json\npolicy_decision_v1.json"]
    end

    subgraph FrontLayer["🖥️ DASHBOARD (React/TS)"]
        FL[SOC UI\nREST consumption\nWebSocket live feed]
    end

    EngineLayer --> ContractE --> CPLayer
    CPLayer --> ContractA --> AgentLayer
    AgentLayer --> ContractAct --> CPLayer
    CPLayer --> FrontLayer

    style ContractE   fill:#fff4e1
    style ContractA   fill:#fff4e1
    style ContractAct fill:#fff4e1
```

**Rule:** No layer imports another layer's internal types. All cross-boundary communication uses the versioned JSON Schema contracts in `contracts/`.

---

## Security Event Lifecycle

```mermaid
stateDiagram-v2
    [*] --> DETECTED: C++ engine fires

    DETECTED --> INVESTIGATING: Orchestrator creates AgentTask

    INVESTIGATING --> EVIDENCE_GATHERED: Investigation Agent completes

    EVIDENCE_GATHERED --> CORRELATED: Correlation Agent processes

    CORRELATED --> INCIDENT_CREATED: Incident formally created

    INCIDENT_CREATED --> RESPONSE_PROPOSED: Response Agent recommends

    RESPONSE_PROPOSED --> AUTO_EXECUTING: PolicyEngine → ALLOW

    RESPONSE_PROPOSED --> AWAITING_APPROVAL: PolicyEngine → HUMAN_APPROVAL

    RESPONSE_PROPOSED --> DENIED: PolicyEngine → DENY

    AWAITING_APPROVAL --> AUTO_EXECUTING: Operator approves

    AWAITING_APPROVAL --> DENIED: Operator denies

    AUTO_EXECUTING --> VERIFIED: Response confirmed

    VERIFIED --> CLOSED: Incident resolved

    DENIED --> ESCALATED: Escalated to operator

    CLOSED --> [*]
    ESCALATED --> [*]
```

---

## Deployment Topology

### Local Development (current)

```
docker compose up
  ├── postgres:5432
  ├── redis:6379
  └── (optional profile) prometheus:9090, grafana:3000

Host processes:
  ├── uvicorn intriqo.api.app:app --reload --port 8000
  ├── python -m intriqo_agents.orchestrator.main  (demo)
  └── cd frontend/dashboard && npm run dev  (:5173)

Engine:
  make engine-build && ./engine/build/intriqo_engine  (when implemented)
```

### Target Production Topology

```mermaid
flowchart TB
    subgraph Network["Network Tap / Mirror Port"]
        NIC[Raw packets]
    end

    subgraph EngineHost["Bare-metal or privileged pod\nNET_RAW capability required"]
        ENG[C++ IDS Engine]
    end

    subgraph AppTier["Standard containers"]
        CP2[Control Plane\nFastAPI :8000]
        AP[Agent Platform\nPython]
        FE[SOC Dashboard\nReact :443]
    end

    subgraph DataTier["Data tier"]
        PG[(PostgreSQL)]
        RD[(Redis)]
    end

    subgraph ObsTier["Observability"]
        PR[Prometheus]
        GR[Grafana]
    end

    Network --> EngineHost
    EngineHost -->|SecurityEvent JSON| CP2
    CP2 -->|AgentTask| AP
    AP -->|ActionRequest| CP2
    CP2 --> PG
    CP2 --> RD
    CP2 --> FE
    CP2 --> PR
    PR --> GR

    style EngineHost fill:#ffe1e1
    style AppTier    fill:#e1f5ff
    style DataTier   fill:#f5f5f5
    style ObsTier    fill:#e1ffe1
```

---

→ Related: [Component Diagram](component-diagram.md) · [Data Flow](data-flow.md) · [Deployment](deployment-architecture.md)
