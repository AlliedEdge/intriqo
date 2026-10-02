<div align="center">

  <img src="assets/branding/intriqo-logo.svg" alt="Intriqo" width="180" />

  <h1>Intriqo</h1>

  <p><strong>Autonomous Multi-Agent Security Operations Center</strong></p>

  <p><em>Real-time threat detection · Autonomous investigation · Controlled response</em></p>

  <p>
    <a href="https://github.com/AlliedEdge/intriqo/actions/workflows/ci.yml">
      <img src="https://github.com/AlliedEdge/intriqo/actions/workflows/ci.yml/badge.svg" alt="CI" />
    </a>
    <img src="https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white" alt="C++20" />
    <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white" alt="Python 3.10+" />
    <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black" alt="React 18" />
    <img src="https://img.shields.io/badge/Architecture-Agentic%20AI-FF6B6B" alt="Agentic AI" />
    <img src="https://img.shields.io/badge/Status-Architecture%20Phase-yellow" alt="Status" />
    <a href="LICENSE">
      <img src="https://img.shields.io/badge/License-See%20LICENSE-blue" alt="License" />
    </a>
  </p>

</div>

---

## What is Intriqo?

Intriqo is an **autonomous multi-agent Security Operations Center (SOC)**. It detects network threats in real time using a high-performance C++ IDS engine, autonomously investigates them using specialized AI agents, enforces every proposed response through a deterministic policy boundary, and surfaces everything to a live React dashboard — all without requiring a human to manually drive each step.

```
Network Traffic
      ↓
C++ IDS Engine          ← line-rate packet capture, flow tracking, detection
      ↓  SecurityEvent JSON
Python Control Plane    ← FastAPI, incidents, policy enforcement, persistence
      ↓  AgentTask
Autonomous Agent Team   ← investigation · correlation · threat intel · response
      ↓  PolicyDecision
Controlled Action       ← ALLOW / DENY / HUMAN_APPROVAL
      ↓
React SOC Dashboard     ← live feed, approvals, audit, agent activity
```

> **Status: 🚧 Architecture Phase** — Engine interfaces and agent foundation are complete and tested. Subsystem implementations are in progress. See [Current Status](#current-status).

---

## Documentation

The full documentation is split into focused pages. Click any section to go straight to the detail.

### 🏗 Architecture

| Page | Description |
|---|---|
| [System Architecture](docs/architecture/system-architecture.md) | Full system diagram, layer responsibilities, data flow |
| [Component Diagram](docs/architecture/component-diagram.md) | Per-subsystem breakdown of all four layers |
| [Data Flow](docs/architecture/data-flow.md) | Detection → investigation → response → dashboard path |
| [Deployment Architecture](docs/architecture/deployment-architecture.md) | Local dev topology, target production layout |

### 🤖 Autonomous Agents

| Page | Description |
|---|---|
| [Agent Overview & Autonomous Loop](docs/agents/overview.md) | The control loop, agent team design, and coordination model |
| [Investigation Agent](docs/agents/investigation-agent.md) | Evidence gathering, tool invocation, finding generation |
| [Threat Intelligence Agent](docs/agents/threat-intelligence-agent.md) | IP/domain reputation, threat feed enrichment |
| [Correlation Agent](docs/agents/correlation-agent.md) | Multi-event incident reconstruction, attack sequence building |
| [Response Agent](docs/agents/response-agent.md) | Action proposal, policy submission, verification |
| [Orchestrator](docs/agents/orchestrator.md) | Task routing, state management, autonomous loop control |
| [Tool Layer](docs/agents/tools.md) | Tool abstraction, input schema, mock and real tools |
| [Agent Communication](docs/agents/communication.md) | Typed domain contracts between agents |

### ⚙️ IDS Engine

| Page | Description |
|---|---|
| [C++ IDS Engine](docs/engine/ids-engine.md) | Subsystems, pipeline, detection approach, why C++ |

### 🛡 Security

| Page | Description |
|---|---|
| [Policy Boundary](docs/security/policy-boundary.md) | How agents are constrained — ALLOW / DENY / HUMAN_APPROVAL flow |
| [Human Supervision Model](docs/security/human-supervision.md) | START / STOP / PAUSE / EMERGENCY STOP, operator capabilities |

### 🧪 Security Lab

| Page | Description |
|---|---|
| [Controlled Security Lab](docs/lab/security-lab.md) | Lab environment, attack scenarios, PCAP tooling |

### 📐 Architecture Decisions

| ADR | Decision |
|---|---|
| [ADR 001](docs/adr/001-modular-monorepo.md) | Modular monorepo structure |
| [ADR 002](docs/adr/002-cpp-ids-engine.md) | C++ for the IDS engine (replaces Java detection core) |
| [ADR 003](docs/adr/003-python-control-plane.md) | Python + FastAPI for the control plane |
| [ADR 004](docs/adr/004-python-agent-platform.md) | Python for the autonomous agent platform |
| [ADR 005](docs/adr/005-explicit-contracts.md) | Explicit cross-boundary JSON Schema contracts |
| [ADR 006](docs/adr/006-deferred-distributed-infrastructure.md) | Defer distributed infrastructure until benchmarks justify it |

### 🔬 Research & Performance

| Page | Description |
|---|---|
| [Research Methodology](docs/research/methodology.md) | Research questions, hypotheses, evaluation plan |
| [Benchmarks & Metrics](docs/performance/benchmarks.md) | Detection, investigation, response, and engine metrics |

---

## Repository Layout

```
intriqo/
├── engine/           C++ IDS engine        (CMake, C++20, GoogleTest)
├── control-plane/    Python control plane  (FastAPI, SQLAlchemy, Pydantic)
├── agents/           Python agent platform (intriqo_agents, 79 tests)
├── frontend/         React SOC dashboard   (Vite, TypeScript)
├── contracts/        JSON Schema contracts (5 cross-boundary schemas)
├── ml/               Anomaly models        (training, evaluation, experiments)
├── security-lab/     Attack scenarios      (Docker, PCAP tooling, fixtures)
├── infrastructure/   Services              (PostgreSQL, Redis, Prometheus, Grafana)
├── tests/            Cross-system tests    (e2e, integration, performance, security)
├── benchmarks/       Performance suite     (engine, detection, agents, end-to-end)
├── scripts/          Developer helpers     (dev, build, lab, benchmark)
└── docs/             All documentation     (architecture, ADRs, agents, engine, …)
    └── archive/      Preserved history     (Java-era architecture)
```

---

## Quick Start

**Prerequisites:** CMake ≥ 3.24, Python ≥ 3.10, Node.js ≥ 20, Docker + Compose.

```bash
# Start infrastructure
docker compose up -d

# C++ engine — build and test
make engine-build
make engine-test

# Python agent platform — install and test
make agents-install
make agents-test

# Run the agents demo
make agents-demo

# Python control plane — install and test
make control-install
make control-test

# SOC dashboard — install and start dev server
make frontend-install
cd frontend/dashboard && npm run dev

# Run everything
make test-all
```

---

## Current Status

| Layer | Status | Details |
|---|---|---|
| **C++ Engine** | 🟢 Phase 2 complete | IPv4 parser, flows, port-scan detection, SecurityEvent JSON, PCAP replay, HTTP sink, 19 tests |
| **Python Agents** | 🟢 Foundation complete | `intriqo_agents` package, 79 tests passing |
| **Control Plane** | 🟢 Phase 1 complete | FastAPI, PostgreSQL persistence, JWT/RBAC, events, incidents, tasks, findings, audit logs |
| **Frontend** | 🟡 Structure complete | Vite + React 18, SOC feature dirs, routing shell |
| **Contracts** | 🟢 Complete | 5 JSON Schema files across all boundaries |
| **CI / Tooling** | 🟢 Complete | cpp, python, frontend, security workflows |

**Not yet implemented:** autonomous agent execution · correlation/threat-intel/response agents · LLM integration · frontend features · live packet capture · Kafka (deferred).

---

## Security Model

Agents **propose**. The policy engine **decides**. The execution layer **acts**.

No agent has unrestricted shell access, raw SQL, arbitrary network access, or direct filesystem write access. Every side-effect goes through an explicit `Tool` → `PolicyEngine` → `AuditLog` chain.

→ Full detail: [Policy Boundary](docs/security/policy-boundary.md)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security Reporting

Do not use public issues. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

See [LICENSE](LICENSE).

---

## Authors

- **Rayan Mohammed Rafeeq** — [GitHub](https://github.com/Rayan-Mohammed-Rafeeq)
- **Hemanth Kumar** — [GitHub](https://github.com/hemanth-kumar-n-1)
- **Sumit Patil** — [GitHub](https://github.com/sumitpatil93463-png)
- **Rakshith Y** — [GitHub](https://github.com/rakshithy3185)
