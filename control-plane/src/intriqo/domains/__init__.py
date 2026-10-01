"""Domain models for the Intriqo control plane.

Each sub-module owns a single bounded context:
  incident.py         — Incident lifecycle
  investigation.py    — Investigation lifecycle
  evidence.py         — Evidence records
  action_request.py   — Structured action requests from agents
  audit.py            — Audit log entries

Architecture rule: domain models are pure Python dataclasses / Pydantic models.
They have no knowledge of HTTP, SQL, or message brokers.
"""
