# Authorization Architecture

Authorization is enforced via Role-Based Access Control (RBAC) and deterministic policy enforcement.

## Roles
- `VIEWER`: Read-only access to dashboard feeds and metrics.
- `ANALYST`: Can trigger manual investigations, review evidence, and comment on incidents.
- `ADMIN`: Can approve active response actions (IP block, isolate host) and configure detection rules.

## Autonomous Action Authorization
Autonomous agent actions require verification against `PolicyDecision` contracts before dispatch to the execution layer.
