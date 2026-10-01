"""Policy module — the deterministic security boundary for all agent-proposed actions.

Every action an agent proposes must pass through a Policy before execution.
Policies are deterministic, auditable, and independent of the agent platform.

Execution flow (enforced architecturally):

    Agent proposes ActionRequest
          ↓
    PolicyEngine.evaluate(request, context) → PolicyDecision
          ↓
    ALLOW  → AuthorisedExecution.execute()
    DENY   → Reject, log, notify
    HUMAN  → Enqueue for operator approval
          ↓
    AuditLog.record(decision, outcome)

Architecture rules:
  - The policy engine has NO knowledge of LLM reasoning or agent internals.
  - Policy decisions are deterministic given the same input.
  - Every ALLOW must be logged before execution begins.
  - Every DENY must be logged with the reason.
  - HUMAN_APPROVAL responses are queued and surfaced on the SOC dashboard.
"""
