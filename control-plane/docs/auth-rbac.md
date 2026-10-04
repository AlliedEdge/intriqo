# Intriqo Control Plane — Authentication & RBAC Reference

> **Scope:** This document covers the authentication and role-based access control
> model for the Intriqo Control Plane API. It does not cover the C++ IDS engine,
> frontend, or Python agent internals.

---

## Role Model

The system defines exactly three roles. No other roles exist or should be added
without deliberate architectural review.

| Role | Kind | Purpose |
|---|---|---|
| `ADMIN` | Human | Full administrative access — user management, audit logs, all SOC operations |
| `ANALYST` | Human | SOC operator — investigate incidents, manage findings, interact with agent tasks |
| `AGENT` | Machine | Service identity — used by the C++ IDS engine and Python agent services |

### Extensibility note

The role column is stored as a plain `VARCHAR` with a non-native SQLAlchemy enum.
Adding a future `VIEWER` role requires: a new `UserRole` enum member, a new
`_require_role` dependency alias, and a targeted Alembic migration. No other
architectural change is needed.

---

## Registration

`POST /api/v1/auth/register`

- Accepts: `email`, `password`, `full_name` (or legacy `username`)
- **Always assigns `ANALYST`.** The role is hardcoded server-side.
- Any `role` field in the request body is silently dropped via
  `model_config = {"extra": "ignore"}` on `UserCreate`.
- There is no query-parameter or header mechanism to influence the assigned role.
- An attacker cannot self-register as `ADMIN` or `AGENT`.

```
POST /api/v1/auth/register
{"email": "...", "password": "...", "role": "ADMIN"}
→ 201  {"role": "ANALYST"}          ← role field ignored
```

### ADMIN provisioning

There is currently no public endpoint to create `ADMIN` accounts. Elevation must
be performed via direct database access:

```sql
UPDATE users SET role = 'ADMIN' WHERE username = 'desired_admin';
```

A future `POST /api/v1/admin/users` endpoint protected by `AdminUser` would be
the appropriate application-layer path when user management is implemented.

### AGENT provisioning

`AGENT` accounts are service identities and must not be created through public
registration. Provisioning is performed via direct database access or a future
controlled admin endpoint. The agent authenticates identically to human users
(JWT Bearer token) but its `role = AGENT` claim restricts it to machine-facing
operations only.

---

## Login

`POST /api/v1/auth/login`

- Accepts: `{"username": "...", "password": "..."}`
- Returns: `{"access_token": "<JWT>", "token_type": "bearer"}`
- Unrecognised username and wrong password return the same `401 INVALID_CREDENTIALS`
  response — no account-existence oracle.
- Inactive accounts return `403 ACCOUNT_DISABLED`.
- Unverified accounts return `403 EMAIL_NOT_VERIFIED` when email verification is
  enforced (production/staging with a configured Resend API key).
- Successful login is recorded in the audit log.

---

## JWT

Tokens are signed HS256 JWTs created by `python-jose`.

### Claims

| Claim | Value | Notes |
|---|---|---|
| `sub` | username | Sign-in identifier |
| `role` | `ADMIN` \| `ANALYST` \| `AGENT` | Assigned at login from the DB; cannot be overridden by the client |
| `user_id` | UUID string | Database primary key |
| `iat` | Unix timestamp | Issued-at |
| `exp` | Unix timestamp | Expiry (default 30 min, configurable via `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`) |

### What is never in a JWT

Passwords, password hashes, reset tokens, verification tokens, secrets.

### Token validation

Every protected route runs `decode_access_token()` which calls `jose.jwt.decode()`.
This verifies:

- HMAC-SHA256 signature against `JWT_SECRET_KEY`
- Token expiry (`exp`)
- Algorithm — only `HS256` is accepted; `alg=none` attacks are rejected

A payload-tampered token (e.g. flipping `role` to `ADMIN` without re-signing)
fails signature verification and returns `401 INVALID_TOKEN`.

### No server-side session

JWTs are stateless. There is no revocation list or refresh token. A compromised
token remains valid until its 30-minute expiry. Role changes in the database are
not reflected in existing tokens until they expire.

---

## Authorization Matrix

Authorization is enforced server-side via FastAPI `Depends()` injection.
Frontend route guards are supplementary and not relied upon for security.

```
Dependency          Allowed roles
──────────────────────────────────────────────────────────
AuthUser            ADMIN  ANALYST  AGENT   (any valid JWT)
AnalystUser         ADMIN  ANALYST
AgentUser           ADMIN  ANALYST  AGENT   (all roles)
AdminUser           ADMIN
```

### Route matrix

```
Endpoint                        ADMIN   ANALYST   AGENT   Unauthenticated
────────────────────────────────────────────────────────────────────────────
GET    /health                    ✓       ✓         ✓         ✓
GET    /auth/me                   ✓       ✓         ✓         ✗ 401

POST   /auth/register             ✓       ✓         ✓         ✓
POST   /auth/login                ✓       ✓         ✓         ✓
GET    /auth/verify-email         ✓       ✓         ✓         ✓
POST   /auth/verify-email         ✓       ✓         ✓         ✓
POST   /auth/resend-verification  ✓       ✓         ✓         ✓
POST   /auth/forgot-password      ✓       ✓         ✓         ✓
POST   /auth/reset-password       ✓       ✓         ✓         ✓

POST   /events                    ✓       ✓         ✓         ✗ 401
GET    /events                    ✓       ✓         ✓         ✗ 401
GET    /events/{id}               ✓       ✓         ✓         ✗ 401

POST   /incidents                 ✓       ✓         ✗ 403     ✗ 401
GET    /incidents                 ✓       ✓         ✗ 403     ✗ 401
GET    /incidents/{id}            ✓       ✓         ✓         ✗ 401
PATCH  /incidents/{id}            ✓       ✓         ✗ 403     ✗ 401

POST   /agent-tasks               ✓       ✓         ✗ 403     ✗ 401
GET    /agent-tasks               ✓       ✓         ✓         ✗ 401
GET    /agent-tasks/{id}          ✓       ✓         ✓         ✗ 401
PATCH  /agent-tasks/{id}          ✓       ✓         ✓         ✗ 401

POST   /findings                  ✓       ✓         ✓         ✗ 401
GET    /findings                  ✓       ✓         ✓         ✗ 401
GET    /findings/{id}             ✓       ✓         ✓         ✗ 401

GET    /audit                     ✓       ✓         ✗ 403     ✗ 401
────────────────────────────────────────────────────────────────────────────
```

**Design rationale for `AgentUser` routes:**  
`AgentUser` (`require_agent`) allows ADMIN, ANALYST, and AGENT. On routes such as
`POST /events`, `POST /findings`, and `PATCH /agent-tasks/{id}`, machine agents
need write access. Analysts and admins retaining access to these routes is
intentional — they can ingest test events or review findings directly.

---

## Password Security

- Hashed with `bcrypt` (direct library, not passlib) using a per-password random salt.
- Passwords are never stored, logged, or included in JWT payloads.
- The 72-byte bcrypt input limit is enforced at the Pydantic schema layer for
  registration and validated in the login handler before `checkpw` is called.
- Login error responses are identical for wrong password and unknown username —
  no account-existence oracle.

---

## Password Reset

`POST /api/v1/auth/forgot-password` → `POST /api/v1/auth/reset-password`

- Reset tokens are `secrets.token_urlsafe(32)` values stored as SHA-256 digests.
- Tokens are single-use and expire (default 30 min).
- Consuming a reset token **only** updates `hashed_password` and `updated_at`.
  The account's `role` is never touched.
- The forgot-password endpoint returns the same response for known and unknown
  email addresses — enumeration-safe.
- Any extra fields (e.g. `"role": "ADMIN"`) in the reset payload are rejected
  by `model_config = {"extra": "forbid"}` on `ResetPasswordRequest`.

---

## Email Verification

`POST /api/v1/auth/verify-email`

- Consuming a verification token **only** sets `email_verified_at`.
  The account's `role` is never touched.
- Verification is enforced (`403 EMAIL_NOT_VERIFIED`) in production/staging
  environments where a Resend API key is configured.
- In local development without a Resend key, verification is advisory — accounts
  can log in without completing it. All token persistence and endpoint behavior
  is still exercised.

---

## Agent Authentication

The C++ IDS engine and Python agent services authenticate as standard JWT Bearer
clients using an account with `role = AGENT`.

**Environment variables consumed by agents:**

| Variable | Used by |
|---|---|
| `INTRIQO_AGENT_TOKEN` | Python `ControlPlaneClient` |
| `INTRIQO_CONTROL_PLANE_TOKEN` | Fallback alias |
| `INTRIQO_CONTROL_PLANE_URL` | Target control-plane base URL |
| `INTRIQO_CONTROL_PLANE_ENDPOINT` | Event submission endpoint |

The token is a standard JWT obtained by calling `POST /auth/login` with the
agent's credentials. There is no separate API-key or mTLS mechanism — role
distinction is achieved entirely through the `role` claim in the shared JWT
framework.

---

## Audit Logging

All security-relevant actions are recorded by `audit_service.record()`. Failures
to write audit records do not abort the primary operation.

| Action constant | Triggered by |
|---|---|
| `USER_REGISTERED` | Successful registration |
| `USER_LOGIN` | Successful login |
| `USER_LOGIN_FAILED` | Failed login attempt |
| `USER_EMAIL_VERIFIED` | Email verification token consumed |
| `USER_VERIFICATION_RESENT` | Verification email resent |
| `USER_PASSWORD_RESET_REQUESTED` | Forgot-password email sent |
| `USER_PASSWORD_RESET` | Password reset token consumed |
| `EVENT_INGESTED` | Security event received from IDS |
| `INCIDENT_CREATED` | Incident created |
| `INCIDENT_UPDATED` | Incident updated |
| `TASK_CREATED` | Agent task created |
| `TASK_STATUS_UPDATED` | Task status changed |
| `TASK_STARTED / COMPLETED / FAILED` | Task lifecycle transitions |
| `FINDING_SUBMITTED` | Agent finding submitted |

Audit records are **never** populated with: passwords, JWT secrets, reset tokens,
or email verification secrets.

The audit log endpoint (`GET /audit`) is restricted to `ADMIN` and `ANALYST`
only. `AGENT` accounts cannot read audit logs.

---

## Rate Limiting

All auth endpoints are protected by an in-process sliding-window rate limiter.

| Endpoint group | Limit |
|---|---|
| Registration | 60 req/min per IP |
| Login | 20 req/min per IP + username |
| Email/reset requests (forgot-password, resend) | 8 req/min per IP + email |
| Token consumption (verify, reset) | Separate per-IP bucket |

**Note:** the rate limiter is in-process only. It does not coordinate across
multiple worker processes or load-balancer instances. For production deployments
behind a load balancer, a Redis-backed rate limiter should be considered.

---

## Database Schema (auth-related tables)

### `users`

| Column | Type | Notes |
|---|---|---|
| `id` | `VARCHAR(36)` | UUID, PK |
| `username` | `VARCHAR(128)` | Unique, indexed |
| `email` | `VARCHAR(256)` | Unique, indexed, stored lowercase |
| `full_name` | `VARCHAR(256)` | Optional display name |
| `hashed_password` | `VARCHAR(256)` | bcrypt hash |
| `role` | `VARCHAR(16)` | `ADMIN` \| `ANALYST` \| `AGENT` |
| `is_active` | `BOOLEAN` | Soft-disable flag |
| `created_at` | `TIMESTAMPTZ` | |
| `updated_at` | `TIMESTAMPTZ` | Auto-updated |
| `email_verified_at` | `TIMESTAMPTZ` | `NULL` = unverified |

### `auth_tokens`

Single-use, expiring tokens for email verification and password reset.

| Column | Type | Notes |
|---|---|---|
| `id` | `VARCHAR(36)` | UUID, PK |
| `user_id` | `VARCHAR(36)` | FK → `users.id` ON DELETE CASCADE |
| `token_hash` | `VARCHAR(64)` | SHA-256 hex digest, UNIQUE |
| `token_type` | `VARCHAR(32)` | `EMAIL_VERIFICATION` \| `PASSWORD_RESET` |
| `created_at` | `TIMESTAMPTZ` | |
| `expires_at` | `TIMESTAMPTZ` | Indexed |
| `used_at` | `TIMESTAMPTZ` | `NULL` = not yet consumed |

Raw tokens are never stored. Only the SHA-256 digest is persisted.

---

## Migrations

| Revision | Summary |
|---|---|
| `0001` | Initial schema — all core tables including `users` with `role VARCHAR(16)` |
| `0002` | Adds `email_verified_at` to `users`; creates `auth_tokens` table; backfills existing accounts as verified |
| `0003` | Adds `full_name VARCHAR(256)` to `users` |

No migration has modified the role column. The role enum is stored as a plain
`VARCHAR` and validated at the application layer.

---

## Known Limitations

1. **No user management API.** There is no `GET /users`, `PATCH /users/{id}`, or
   role-assignment endpoint. Admin role elevation currently requires direct DB
   access. A `AdminUser`-gated `/users` router is the correct next step.

2. **No admin bootstrap flow.** A fresh deployment has no `ADMIN` account and no
   application-level way to create one. Planned mitigation: a one-time
   `POST /api/v1/admin/bootstrap` endpoint that creates the first admin only when
   no admin accounts exist, then permanently disables itself.

3. **No JWT revocation.** Tokens remain valid until expiry (30 min). A compromised
   token cannot be invalidated without restarting the server or rotating
   `JWT_SECRET_KEY` (which invalidates all tokens). A Redis-backed token deny-list
   or refresh-token rotation scheme would address this.

4. **No logout endpoint.** Logout is purely client-side token discard. Follows
   directly from the stateless JWT model.

5. **In-process rate limiter only.** Does not protect against distributed
   brute-force across multiple processes or server instances.

6. **AGENT provisioning is manual.** Creating service accounts requires direct DB
   access. A future `POST /api/v1/admin/agents` endpoint would be the clean path.

---

## Definition of Done — Verification

| Requirement | Status |
|---|---|
| Exactly ADMIN / ANALYST / AGENT roles | ✅ `UserRole` enum in `db/models/user.py` |
| Public registration always creates ANALYST | ✅ Hardcoded in `auth/service.py`; tested |
| Client cannot self-register as ADMIN | ✅ `extra="ignore"` on `UserCreate`; tested |
| Client cannot self-register as AGENT | ✅ Same mechanism; tested |
| Existing ADMIN accounts preserved | ✅ No migration touches role column |
| Existing AGENT authentication preserved | ✅ JWT Bearer flow unchanged |
| JWT role handling verified | ✅ Unit tests + integration tests |
| Backend authorization audited | ✅ Full route matrix documented and tested |
| ADMIN permissions verified | ✅ All routes accessible |
| ANALYST permissions verified | ✅ SOC routes accessible; admin denied |
| AGENT permissions verified | ✅ Machine routes accessible; human/admin denied |
| Password reset cannot change role | ✅ Tested in `test_privilege_escalation.py` |
| Email verification cannot change role | ✅ Tested in `test_privilege_escalation.py` |
| Privilege escalation tests added | ✅ `tests/security/test_privilege_escalation.py` |
| Auth regression tests pass | ✅ 131/131 |
| Control Plane tests pass | ✅ 131/131 |
| No C++ engine changes | ✅ Confirmed — no engine files touched |
| No frontend redesign | ✅ Confirmed — no frontend files touched |
| No unrelated architecture changes | ✅ Confirmed |
