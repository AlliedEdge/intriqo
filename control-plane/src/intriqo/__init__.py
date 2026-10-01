"""
intriqo — Intriqo Control Plane.

Package layout
──────────────
api/            FastAPI routers (thin HTTP layer only — no business logic)
auth/           Authentication and authorisation (JWT, RBAC)
domains/        Domain models (Incident, Investigation, Evidence, ActionRequest…)
services/       Application services (orchestrate domain logic, no HTTP concerns)
repositories/   Data access layer (SQLAlchemy repositories)
database/       DB session, migrations coordination
messaging/      Event bus / message broker adapters
engine_client/  Adapter for the C++ IDS engine
policy/         Policy evaluation (authorise actions before execution)
observability/  Metrics, structured logging, tracing
config/         Settings and environment configuration
"""
