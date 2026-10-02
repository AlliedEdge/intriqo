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
- Email verification and password recovery through Resend

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

### Account email configuration

The browser only calls the FastAPI auth endpoints. Configure transactional
email on the control plane; never add these values to the frontend environment:

```dotenv
RESEND_API_KEY=re_...
RESEND_FROM_EMAIL=Intriqo Security <no-reply@example.com>
FRONTEND_BASE_URL=http://localhost:5173
```

Verification links expire after 60 minutes and password-reset links expire
after 30 minutes by default. Both are single-use and only their SHA-256
digests are persisted. In local development without `RESEND_API_KEY`, email
delivery is skipped so the API and tests remain usable; configure Resend to
exercise the complete email delivery path.

Public registration always creates an `ANALYST` account. Existing service
accounts and administrative role changes remain outside the public signup
flow.

The auth routes also include a bounded process-local sliding-window guard for
obvious bursts on signup, login, email requests, and token consumption. A
multi-instance deployment should complement it with a shared gateway or Redis
limiter rather than treating the local guard as a distributed control.

## Testing

```bash
pytest tests/ -v
```
