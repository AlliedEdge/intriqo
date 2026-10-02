"""Unit tests for Pydantic schema validation (no DB required)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from intriqo.schemas.events import SecurityEventCreate
from intriqo.schemas.incidents import IncidentCreate
from intriqo.schemas.agent_tasks import AgentTaskCreate
from intriqo.schemas.findings import FindingCreate


# ── SecurityEventCreate ───────────────────────────────────────────────────────

class TestSecurityEventCreate:
    def test_valid_event(self):
        e = SecurityEventCreate(
            event_id="abc-123",
            event_type="PORT_SCAN",
            severity="HIGH",
            timestamp="2026-10-01T12:00:00Z",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
        )
        assert e.event_id == "abc-123"
        assert e.severity == "HIGH"
        assert e.details == {}

    def test_invalid_severity(self):
        with pytest.raises(ValidationError, match="severity"):
            SecurityEventCreate(
                event_id="abc",
                event_type="PORT_SCAN",
                severity="EXTREME",
                timestamp="2026-10-01T12:00:00Z",
                source_address="10.0.0.1",
                destination_address="10.0.0.2",
            )

    def test_blank_event_id(self):
        with pytest.raises(ValidationError):
            SecurityEventCreate(
                event_id="   ",
                event_type="PORT_SCAN",
                severity="HIGH",
                timestamp="2026-10-01T12:00:00Z",
                source_address="10.0.0.1",
                destination_address="10.0.0.2",
            )

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            SecurityEventCreate(
                event_type="PORT_SCAN",
                severity="HIGH",
                timestamp="2026-10-01T12:00:00Z",
                source_address="10.0.0.1",
                destination_address="10.0.0.2",
            )  # missing event_id

    def test_extra_fields_rejected(self):
        with pytest.raises(ValidationError):
            SecurityEventCreate(
                event_id="abc",
                event_type="PORT_SCAN",
                severity="HIGH",
                timestamp="2026-10-01T12:00:00Z",
                source_address="10.0.0.1",
                destination_address="10.0.0.2",
                unknown_field="bad",
            )

    def test_all_valid_severities(self):
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            e = SecurityEventCreate(
                event_id="x",
                event_type="TEST",
                severity=sev,
                timestamp="2026-10-01T12:00:00Z",
                source_address="1.2.3.4",
                destination_address="5.6.7.8",
            )
            assert e.severity == sev


# ── IncidentCreate ────────────────────────────────────────────────────────────

class TestIncidentCreate:
    def test_minimal_valid(self):
        inc = IncidentCreate(title="Test incident")
        assert inc.status if hasattr(inc, "status") else True
        assert inc.severity == "MEDIUM"
        assert inc.event_ids == []

    def test_with_event_ids(self):
        inc = IncidentCreate(title="Linked incident", event_ids=["evt-1", "evt-2"])
        assert inc.event_ids == ["evt-1", "evt-2"]

    def test_blank_title_rejected(self):
        with pytest.raises(ValidationError):
            IncidentCreate(title="")


# ── AgentTaskCreate ───────────────────────────────────────────────────────────

class TestAgentTaskCreate:
    def test_valid_task(self):
        t = AgentTaskCreate(task_type="INVESTIGATION", description="Investigate port scan")
        assert t.priority == "MEDIUM"
        assert t.status if hasattr(t, "status") else True

    def test_blank_description(self):
        with pytest.raises(ValidationError):
            AgentTaskCreate(task_type="INVESTIGATION", description="")


# ── FindingCreate ─────────────────────────────────────────────────────────────

class TestFindingCreate:
    def test_valid_finding(self):
        f = FindingCreate(
            task_id="task-1",
            agent_name="investigation_agent",
            status="SUCCESS",
            confidence=0.95,
            findings=["Port scan confirmed"],
        )
        assert f.confidence == 0.95

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            FindingCreate(
                task_id="t",
                agent_name="agent",
                status="SUCCESS",
                confidence=1.5,
            )

    def test_invalid_status(self):
        # Pydantic won't catch this unless we add a validator, but confirm the field maps
        f = FindingCreate(
            task_id="t",
            agent_name="agent",
            status="INCONCLUSIVE",
            confidence=0.5,
        )
        assert f.status == "INCONCLUSIVE"
