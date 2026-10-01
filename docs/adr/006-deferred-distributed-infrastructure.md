# ADR 006 — Deferred Distributed Infrastructure

**Status:** Accepted  
**Date:** 2026-09-30

## Context

A security platform of this scope might be expected to use Kafka for event
streaming, Redis for caching, Kubernetes for orchestration, a service mesh,
and multiple microservices.  Introducing all of this at the foundation stage
would create enormous operational complexity before a single detection is
proven correct.

## Decision

Distributed infrastructure is introduced **only when benchmarks justify it**.

**Current infrastructure (docker-compose.yml):**
- PostgreSQL — persistence (required from day one)
- Redis — optional caching (available, not yet wired)
- Prometheus + Grafana — observability (optional profile)

**Explicitly deferred until justified by measurement:**
- Kafka — will be introduced when event volume exceeds what PostgreSQL
  LISTEN/NOTIFY + async polling can handle at acceptable latency.
- Kubernetes — will be introduced when horizontal scaling of individual
  components is needed.
- Service mesh (Istio/Linkerd) — will be introduced if/when mTLS between
  services becomes a compliance requirement.
- Separate microservices — will be introduced per component only when that
  component's scaling requirements diverge from the rest.

The `infrastructure/kafka/` directory exists with scaffolding so that Kafka
can be wired in without restructuring the repository.

## Consequences

**Positive**
- The system is understandable and runnable with `docker compose up`.
- Development iteration is fast — no Kafka broker, no schema registry, no
  consumer group management to debug before the first detector works.
- The agent↔control-plane boundary is defined as a typed Python interface now,
  making future message-bus insertion transparent to both sides.

**Negative / mitigations**
- Early adopters may hit throughput limits at high packet rates → this is
  the benchmark signal that triggers Kafka introduction; the `benchmarks/`
  directory provides the harness.
- Message ordering guarantees differ between in-process calls and Kafka →
  the control plane service layer is designed to be idempotent, making the
  transition safe.

## Review trigger

Re-evaluate this decision when any of the following is true:

1. The engine emits > 10,000 SecurityEvents/sec sustained.
2. The control plane's PostgreSQL write queue consistently exceeds 500 ms.
3. Multi-region deployment becomes a requirement.
