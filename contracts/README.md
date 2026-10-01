# Contracts

Cross-boundary schemas shared between the C++ IDS engine, Python control
plane, Python agent platform, and React frontend.

## Purpose

Each architectural layer has its own internal domain model.  When data
crosses a boundary it must be serialised to an explicit, versioned contract
defined here.  This prevents every layer from independently coupling to
another layer's implementation details.

## Boundary map

```
C++ Engine ──────────────────── SecurityEvent JSON ──────────────────────► Control Plane
Control Plane ───────────────── AgentTask JSON ──────────────────────────► Agent Platform
Agent Platform ──────────────── AgentResult / Finding JSON ──────────────► Control Plane
Control Plane ───────────────── REST API (OpenAPI) ──────────────────────► Frontend
```

## Directory layout

```
contracts/
├── events/       Engine → Control Plane event schemas
├── agents/       Control Plane ↔ Agent Platform schemas
└── actions/      Agent-proposed action / policy-decision schemas
```

## Schema format

JSON Schema (draft-07).  Each schema file is named after the domain concept
it describes and is versioned in the filename (`security_event_v1.json`).

The Python control plane and agent platform import these schemas for
validation.  The C++ engine serialises to these contracts in its output layer.
The frontend TypeScript types are generated from these schemas.
