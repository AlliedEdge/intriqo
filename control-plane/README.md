# Intriqo Control Plane

Python / FastAPI application layer for the Intriqo autonomous SOC.

## Responsibilities

- REST API for the SOC dashboard
- Authentication (JWT) and authorisation (RBAC)
- Incident and investigation management
- SecurityEvent ingestion from the C++ IDS engine
- Agent task dispatch and result collection
- Policy evaluation for all agent-proposed actions
- Audit logging

## Architecture

```
HTTP Request
      ↓
FastAPI Router         (HTTP only — no business logic)
      ↓
Application Service    (orchestrates domain logic)
      ↓
Domain Model           (pure Python, no infrastructure)
      ↓
Repository             (SQLAlchemy, async)
      ↓
PostgreSQL
```

## Running locally

```bash
pip install -e ".[dev]"
uvicorn intriqo.api.app:app --reload --port 8000
```

## Testing

```bash
pytest tests/ -v
```
