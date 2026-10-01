# ADR 005 — Explicit Cross-Boundary Contracts

**Status:** Accepted  
**Date:** 2026-09-30

## Context

Intriqo has four layers implemented in two programming languages (C++ and
Python) with a TypeScript frontend.  Without explicit contracts at each
boundary, each layer will independently evolve its representation of shared
concepts (SecurityEvent, AgentTask, etc.), leading to:

- Implicit coupling through shared internal models
- Serialisation bugs discovered at runtime, not at schema validation time
- Inability to independently evolve one layer without breaking another
- No single source of truth for what each event looks like on the wire

## Decision

All cross-boundary data transfer uses **explicit, versioned JSON Schema
contracts** defined in `contracts/`.

```
contracts/
├── events/    security_event_v1.json        (engine → control plane)
├── agents/    agent_task_v1.json            (control plane → agents)
│              agent_result_v1.json          (agents → control plane)
└── actions/   action_request_v1.json        (agents → policy engine)
               policy_decision_v1.json       (policy engine → agents)
```

Each layer has its own **internal domain model**.  At the boundary, data is
serialised to the contract schema and deserialised into the receiving layer's
domain model.  No layer imports another layer's internal types.

Schema versioning: breaking changes require a new schema version
(`security_event_v2.json`).  Both versions are supported during a transition
window.

## Consequences

**Positive**
- Any layer can be replaced without affecting others, provided the contract
  is honoured.
- Contract validation catches malformed events at the entry point before they
  corrupt internal state.
- TypeScript types for the frontend can be generated from the JSON Schema.
- Contract tests can verify that each layer's serialiser produces valid output.

**Negative / mitigations**
- Mapping between contract and internal domain model requires adapter code →
  `engine_event_adapter.py` (agents) and `engine_client/adapter.py`
  (control plane) contain this logic and are well-tested.
- Schema evolution requires discipline → versioned filenames and a transition
  policy make breaking changes explicit and reviewable.

## Alternatives rejected

- **Protobuf/gRPC:** Viable for the engine↔control-plane boundary once
  performance justifies it.  JSON is sufficient and much easier to debug
  during the foundation phase.
- **Shared internal models:** Creates tight coupling between layers and makes
  independent deployment impossible.
