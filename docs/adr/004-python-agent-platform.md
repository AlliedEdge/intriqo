# ADR 004 — Python for the Autonomous Agent Platform

**Status:** Accepted  
**Date:** 2026-09-30

## Context

Intriqo's autonomous SOC requires agents that can reason about security
events, gather evidence, correlate signals, and propose responses.  These
agents will eventually integrate with LLMs, vector stores, and structured
tool systems.  The agent platform must be:

- Modular and independently testable
- Safe: agents must not have unrestricted access to infrastructure
- Observable: every tool call and decision must be auditable
- Evolvable: new agent types can be added without disrupting existing ones

## Decision

The autonomous agent platform is implemented in **Python**, packaged as
`intriqo-agents` under `agents/src/intriqo_agents/`.

**Security boundary (non-negotiable):**

```
Agent proposes
      ↓
Tool (strictly scoped, validated)
      ↓
Policy Engine (deterministic, auditable)
      ↓
Authorisation check
      ↓
Controlled execution
      ↓
Audit log
```

Agents **never** receive: a shell, a raw SQL cursor, unrestricted network
access, or direct filesystem access.  All side-effects are mediated by
explicit `Tool` subclasses with typed `input_schema`.

**Package structure:**

```
orchestrator/   Event routing, task dispatch, result aggregation
investigation/  Investigation agent
correlation/    (future) Cross-event correlation agent
threat_intel/   (future) Threat intelligence enrichment agent
response/       (future) Controlled response agent
tools/          Tool abstraction + mock tools + engine event adapter
state/          AgentTask, AgentResult (internal domain state)
contracts/      SecurityEvent (inbound boundary model)
policies/       (future) Agent-side policy primitives
memory/         (future) Agent working memory / episodic memory
llm/            (future) LLM integration (OpenAI, Anthropic, local)
workflows/      (future) Multi-step investigation workflows
```

## Consequences

**Positive**
- Python has the richest LLM ecosystem (LangChain, LlamaIndex, OpenAI SDK,
  Anthropic SDK, DSPy).
- The `Tool` abstraction with `input_schema` and `validate_input()` makes it
  structurally impossible to give agents unstructured access.
- Agents are deterministically testable without real infrastructure.
- The agent platform is deployable independently from the control plane.

**Negative / mitigations**
- Python performance is insufficient for packet processing → the agent
  platform never touches packets; it receives structured SecurityEvents.
- Async LLM calls require careful resource management → the `llm/` module
  will own connection pooling and retry logic.

## Alternatives rejected

- **LangChain agents with tool use:** Useful as an implementation detail inside
  `llm/`; the architecture does not depend on LangChain's abstractions at the
  boundary level.
- **Java agents:** Java has a weaker LLM ecosystem and would require maintaining
  two JVM services.
