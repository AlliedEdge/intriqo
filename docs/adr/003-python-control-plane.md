# ADR 003 — Python + FastAPI for the Control Plane

**Status:** Accepted  
**Date:** 2026-09-30

## Context

The control plane needs to expose a REST API to the SOC dashboard, manage
incidents and investigations, coordinate agent tasks, enforce policies, handle
authentication/authorisation, and persist data.  These are classic
application-layer concerns where developer velocity and ecosystem richness
matter more than raw throughput.

## Decision

The control plane is implemented in **Python 3.10+ with FastAPI**.

Layer structure (strict top-down dependency direction):

```
FastAPI Router  →  Application Service  →  Domain Logic  →  Repository / Adapter
```

FastAPI route handlers contain only: input validation (Pydantic), service
calls, and response serialisation.  No business logic, no SQL, no direct
engine calls inside handlers.

Authentication and authorisation are explicit modules (`auth/`) injected as
FastAPI dependencies — not middleware that is easy to bypass.

The C++ engine is accessed exclusively through the `engine_client/` adapter.
The agent platform is accessed exclusively through a typed service boundary.
No Python code outside `engine_client/` may contact the engine directly.

## Consequences

**Positive**
- FastAPI's async support handles many concurrent WebSocket connections for
  the live SOC dashboard without thread-per-connection overhead.
- Pydantic v2 provides fast, typed request/response validation.
- SQLAlchemy 2.0 async ORM integrates cleanly with FastAPI.
- Alembic provides database migration management.
- Rich testing ecosystem (pytest-asyncio, httpx).

**Negative / mitigations**
- Python's GIL limits CPU-bound concurrency → CPU-bound work (packet
  processing, ML inference) lives in C++; the control plane is I/O-bound.
- Loose typing discipline can degrade architecture → `mypy --strict` and
  `ruff` are enforced in CI on every PR.

## Alternatives rejected

- **Java (Spring Boot):** Retained from previous architecture only as the
  detection core; removed from the control plane. Spring's annotation-based
  magic obscures dependency direction. FastAPI's explicit dependency injection
  makes the architecture visible.
- **Go:** Viable; rejected due to team expertise and the rich Python async
  ecosystem for this workload.
- **Node.js (NestJS):** Frontend team uses TypeScript; the backend should
  remain separate to allow independent scaling.
