"""Tests for the standalone agent entrypoint and polling loop."""

from __future__ import annotations

import signal
import threading

import pytest

from intriqo_agents.control_plane.client import ControlPlaneError, ControlPlaneNotFound
from intriqo_agents.orchestrator import main as entrypoint


class _Client:
    def __init__(self, tasks, calls=None):
        self.tasks = tasks
        self.calls = calls if calls is not None else []
        self.claimed_task_ids = []

    def list_tasks(self, *, task_type):
        assert task_type == "INVESTIGATION"
        return self.tasks

    def claim_task(self, task_id):
        self.calls.append(("claim", task_id))
        self.claimed_task_ids.append(task_id)
        return {"task_id": task_id, "status": "IN_PROGRESS"}


class _Orchestrator:
    def __init__(self, calls=None):
        self.calls = calls if calls is not None else []
        self.task_ids = []

    def execute_task(self, task_id):
        self.calls.append(("execute", task_id))
        self.task_ids.append(task_id)
        return type("Result", (), {"status": "SUCCESS"})()


def test_poll_once_processes_only_recoverable_investigations():
    calls = []
    client = _Client(
        [
            {"task_id": "pending", "task_type": "INVESTIGATION", "status": "PENDING"},
            {"task_id": "in-progress", "task_type": "INVESTIGATION", "status": "IN_PROGRESS"},
            {"task_id": "done", "task_type": "INVESTIGATION", "status": "COMPLETED"},
            {"task_id": "other", "task_type": "CORRELATION", "status": "PENDING"},
        ],
        calls,
    )
    orchestrator = _Orchestrator(calls)

    assert entrypoint.poll_once(client, orchestrator) == 2
    assert client.claimed_task_ids == ["pending", "in-progress"]
    assert orchestrator.task_ids == ["pending", "in-progress"]
    assert calls == [
        ("claim", "pending"),
        ("execute", "pending"),
        ("claim", "in-progress"),
        ("execute", "in-progress"),
    ]


def test_poll_once_does_not_execute_after_claim_conflict():
    class ConflictClient(_Client):
        def claim_task(self, task_id):
            super().claim_task(task_id)
            raise ControlPlaneError("already claimed", status_code=409)

    client = ConflictClient([
        {"task_id": "contended", "task_type": "INVESTIGATION", "status": "PENDING"},
    ])
    orchestrator = _Orchestrator()

    assert entrypoint.poll_once(client, orchestrator) == 0
    assert client.claimed_task_ids == ["contended"]
    assert orchestrator.task_ids == []


def test_poll_once_does_not_execute_after_claim_api_failure():
    class FailingClient(_Client):
        def claim_task(self, task_id):
            super().claim_task(task_id)
            raise ControlPlaneError("service unavailable", status_code=503)

    client = FailingClient([
        {"task_id": "unavailable", "task_type": "INVESTIGATION", "status": "IN_PROGRESS"},
    ])
    orchestrator = _Orchestrator()

    assert entrypoint.poll_once(client, orchestrator) == 0
    assert client.claimed_task_ids == ["unavailable"]
    assert orchestrator.task_ids == []


def test_poll_once_does_not_execute_after_claim_not_found():
    class MissingClient(_Client):
        def claim_task(self, task_id):
            super().claim_task(task_id)
            raise ControlPlaneNotFound("missing", status_code=404)

    client = MissingClient([
        {"task_id": "missing", "task_type": "INVESTIGATION", "status": "PENDING"},
    ])
    orchestrator = _Orchestrator()

    assert entrypoint.poll_once(client, orchestrator) == 0
    assert client.claimed_task_ids == ["missing"]
    assert orchestrator.task_ids == []


def test_main_dispatches_opt_in_polling(monkeypatch):
    monkeypatch.setattr(entrypoint, "run_polling", lambda interval: interval)

    assert entrypoint.main(["--poll", "--poll-interval", "0.25"]) == 0.25


def test_run_task_claims_before_execute(monkeypatch, capsys):
    calls = []

    class ContextClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def claim_task(self, task_id):
            calls.append(("claim", task_id))
            return {"task_id": task_id, "status": "IN_PROGRESS"}

    class Result:
        status = "SUCCESS"

        def to_dict(self):
            return {"status": self.status}

    class FakeOrchestrator:
        def __init__(self, _registry, _client):
            pass

        def execute_task(self, task_id):
            calls.append(("execute", task_id))
            return Result()

    monkeypatch.setattr(entrypoint, "ControlPlaneClient", ContextClient)
    monkeypatch.setattr(entrypoint, "AgentRegistry", lambda _agents: object())
    monkeypatch.setattr(entrypoint, "InvestigationAgent", lambda: object())
    monkeypatch.setattr(entrypoint, "AgentOrchestrator", FakeOrchestrator)

    assert entrypoint.run_task("one-shot") == 0
    assert calls == [("claim", "one-shot"), ("execute", "one-shot")]
    assert '"status": "SUCCESS"' in capsys.readouterr().out


def test_polling_stops_on_sigterm_and_restores_handlers(monkeypatch):
    stop_event = threading.Event()
    calls = []
    handlers = {}

    def fake_signal(signum, handler):
        calls.append((signum, handler))
        previous = handlers.get(signum, signal.SIG_DFL)
        handlers[signum] = handler
        return previous

    class ContextClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    def fake_poll_once(_client, _orchestrator):
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        return 0

    monkeypatch.setattr(entrypoint.signal, "signal", fake_signal)
    monkeypatch.setattr(entrypoint, "poll_once", fake_poll_once)

    assert entrypoint.run_polling(0, client_factory=ContextClient, stop_event=stop_event) == 0
    assert stop_event.is_set()
    assert [signum for signum, _ in calls] == [
        signal.SIGINT,
        signal.SIGTERM,
        signal.SIGINT,
        signal.SIGTERM,
    ]


def test_negative_poll_interval_is_rejected():
    with pytest.raises(SystemExit):
        entrypoint.main(["--poll", "--poll-interval", "-1"])
