# Correlation Agent

← [Back to Agent Overview](overview.md) · [Back to README](../../README.md)

---

## Purpose

The Correlation Agent connects individual security events into cohesive incidents. Where the Investigation Agent answers *"what happened in this single event?"*, the Correlation Agent answers *"do these five events represent one coordinated attack?"*

Instead of presenting five separate alerts to the operator, the Correlation Agent reconstructs the complete attack sequence and creates a single, prioritised incident with a full timeline.

**Status:** 📋 Planned — module stub exists at `agents/src/intriqo_agents/correlation/`

---

## Responsibilities

| Capability | Description |
|---|---|
| Event grouping | Identify events sharing source IP, target, time window, or attack pattern |
| Attack sequence reconstruction | Order events into a logical kill-chain narrative |
| Incident timeline building | Produce a chronological timeline with timestamps |
| Duplicate / noise suppression | Merge redundant events that represent the same activity |
| Composite severity scoring | Elevate severity based on the complete attack picture, not individual events |
| Related incident lookup | Check if the current events extend a previously known incident |

---

## Correlation Example

**Input — five independent SecurityEvents:**

```
10:25:00  PORT_SCAN           172.20.0.10 → 172.20.0.0/24
10:30:15  BRUTE_FORCE_SSH     172.20.0.10 → 172.20.0.20
10:33:42  SUCCESSFUL_AUTH     172.20.0.10 → 172.20.0.20 (srv-prod-db-01)
10:35:20  PRIVILEGE_ESCALATION              172.20.0.20 (root shell)
10:40:15  LARGE_OUTBOUND      172.20.0.20 → 203.0.113.42 (2.3 GB)
```

**Output — one correlated incident:**

```
INCIDENT #1042: Multi-Stage Attack — Reconnaissance to Exfiltration

ATTACK SEQUENCE:
  1. Reconnaissance   10:25:00  Port scan of /24 subnet
  2. Credential Attack 10:30:15  SSH brute force — 127 failures over 3 minutes
  3. Initial Access   10:33:42  Successful auth to srv-prod-db-01
  4. Privilege Escalation 10:35:20  Root shell obtained via sudo
  5. Possible Exfiltration 10:40:15  2.3 GB transfer to known-malicious 203.0.113.42

TIMELINE SPAN:  15 minutes
SEVERITY:       CRITICAL  (elevated from individual HIGH events)
CONFIDENCE:     HIGH
RELATED INCIDENTS: None (first appearance of 172.20.0.10)
```

---

## Correlation Strategies (planned)

| Strategy | Description |
|---|---|
| **Source IP grouping** | Events sharing the same source IP within a time window |
| **Target grouping** | Events targeting the same host from multiple sources |
| **Kill-chain mapping** | Match events to MITRE ATT&CK stages (recon → access → escalation → exfil) |
| **Temporal clustering** | Events within a configurable sliding window |
| **Indicator overlap** | Events sharing IPs, domains, or hashes |

---

## Planned Tool Interface

```python
find_related_events(event_id: str, window_seconds: int) -> List[SecurityEvent]
search_incidents(filters: dict) -> List[Incident]
get_event_timeline(event_ids: List[str]) -> Timeline
```

---

## Output Contract

The Correlation Agent produces an `AgentResult` whose `evidence` field contains:

```python
{
    "type":           "correlated_incident",
    "incident_title": "Multi-Stage Attack — Recon to Exfiltration",
    "event_count":    5,
    "event_ids":      ["evt-001", "evt-002", "evt-003", "evt-004", "evt-005"],
    "timeline":       [...],
    "attack_stages":  ["RECONNAISSANCE", "CREDENTIAL_ATTACK", "INITIAL_ACCESS",
                       "PRIVILEGE_ESCALATION", "EXFILTRATION"],
    "composite_severity": "CRITICAL",
}
```

---

→ Next: [Response Agent](response-agent.md)
