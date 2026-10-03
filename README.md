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

Intriqo is an open-source network security monitoring and autonomous SOC platform under development. Its implemented C++ IDS runtime passively captures authorized Linux interface traffic, parses IPv4, tracks flows, and emits deterministic port-scan `SecurityEvent` JSON to the FastAPI/PostgreSQL control plane. Additional detectors, agents and response capabilities are future work; the complete autonomous vision is not implemented.

The diagram below describes the target platform flow; it is not a claim that
every autonomous-agent/response stage is implemented.

```
Network Traffic
      ↓
C++ IDS Engine          ← passive capture, parsing, flow tracking, detection
      ↓  SecurityEvent JSON
Python Control Plane    ← FastAPI, incidents, policy enforcement, persistence
      ↓  AgentTask
Autonomous Agent Team   ← investigation · correlation · threat intel · response
      ↓  PolicyDecision
Controlled Action       ← ALLOW / DENY / HUMAN_APPROVAL
      ↓
React SOC Dashboard     ← live feed, approvals, audit, agent activity
```

> **Status:** A runnable IDS runtime and Linux live-capture vertical slice are implemented and tested. Full autonomous SOC functionality remains incomplete. See [Current Status](#current-status) and [IDS runtime documentation](docs/engine/ids-engine.md).

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
├── infrastructure/   PostgreSQL and reserved future service directories
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

### Run the IDS

Requires C++20 and CMake ≥ 3.24; live capture additionally needs Linux, libpcap
development headers (`libpcap-dev` on Debian/Ubuntu), and authorized capture
privileges. Offline modes require neither libpcap nor a physical interface.

```bash
cmake -S . -B build/runtime-release -DCMAKE_BUILD_TYPE=Release -DINTRIQO_BUILD_TESTS=ON
cmake --build build/runtime-release --parallel
ctest --test-dir build/runtime-release --output-on-failure

build/runtime-release/engine/intriqo-engine --help
build/runtime-release/engine/intriqo-engine --synthetic --output events.jsonl
build/runtime-release/engine/intriqo-engine --pcap authorized-input.pcap --output events.jsonl
# Run only with approved privileges and an interface you are authorized to observe:
build/runtime-release/engine/intriqo-engine --interface eth0 --filter "tcp" --no-promiscuous

# Token comes from the existing authentication/service-identity API; never a CLI argument.
export INTRIQO_CONTROL_PLANE_URL=http://127.0.0.1:8000
export INTRIQO_CONTROL_PLANE_TOKEN="$IDS_ENGINE_JWT"
build/runtime-release/engine/intriqo-engine --interface eth0 --filter "tcp" --sink http

# Reproducible Release benchmark (full raw-packet runtime, not pre-parsed input):
python3 scripts/benchmark/runtime_benchmark.py --build build/runtime-release
```

`--sink file|http`, `--output`, `--snaplen`, `--no-promiscuous`,
`--portscan-window`, `--portscan-unique-port-threshold`,
`--portscan-minimum-attempts`, and `--log-level error|info|debug` configure the
runtime. `INTRIQO_CONTROL_PLANE_ENDPOINT` defaults to `/api/v1/events`.
The existing HTTP sink is plain HTTP only: use it on a trusted local/isolated
network, not across an untrusted network with bearer credentials.

Startup reports the mode/source/registry/sink/configuration and capture
readiness; SIGINT/SIGTERM stop capture, flush flows/sink, and print measured
packet/flow/detection/delivery/failure/duration counters. Failed capture or
delivery returns nonzero; no per-packet logs or credentials are printed.

**Visibility is local to the configured traffic source.** Network-wide
monitoring requires an authorized SPAN/mirror port, TAP, or equivalent network
configuration. Promiscuous mode alone does not supply network-wide visibility.
See [limitations and configuration](docs/engine/ids-engine.md) and
[actual verification/benchmark results](docs/engine/runtime-validation.md).

| Layer | Status | Details |
|---|---|---|
| **C++ Engine** | 🟢 Runtime/live slice implemented | Concrete Engine, Linux libpcap, synthetic/classic PCAP, detector registry, file/HTTP sinks, graceful signals, counters; 43 CTest entries including all original 19 tests |
| **Python Agents** | 🟢 Foundation complete | `intriqo_agents` package, 79 tests passing |
| **Control Plane** | 🟢 Phase 1 complete | FastAPI, PostgreSQL persistence, JWT/RBAC, events, incidents, tasks, findings, audit logs |
| **Frontend** | 🟡 Structure complete | Vite + React 18, SOC feature dirs, routing shell |
| **Contracts** | 🟢 Complete | 5 JSON Schema files across all boundaries |
| **CI / Tooling** | 🟢 Complete | cpp, python, frontend, security workflows |

**Future/deferred in this IDS phase:** additional detectors · missing agents · LLM integration · response/blocking · packet injection · Kafka/Redis/Kubernetes · streaming UI · Prometheus. Existing agent/control-plane/frontend responsibilities are unchanged.

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
