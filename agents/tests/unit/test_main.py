"""Tests for the standalone agent entrypoint and polling loop."""

from __future__ import annotations

import signal
import threading

import pytest

from intriqo_agents.orchestrator import main as entrypoint


class _Client:
    def __init__(self, tasks):
        self.tasks = tasks

    def list_tasks(self, *, task_type):
        assert task_type == "INVESTIGATION"
        return self.tasks


class _Orchestrator:
    def __init__(self):
        self.task_ids = []

    def execute_task(self, task_id):
        self.task_ids.append(task_id)
        return type("Result", (), {"status": "SUCCESS"})()


def test_poll_once_processes_only_recoverable_investigations():
    client = _Client(
        [
            {"task_id": "pending", "task_type": "INVESTIGATION", "status": "PENDING"},
            {"task_id": "in-progress", "task_type": "INVESTIGATION", "status": "IN_PROGRESS"},
            {"task_id": "done", "task_type": "INVESTIGATION", "status": "COMPLETED"},
            {"task_id": "other", "task_type": "CORRELATION", "status": "PENDING"},
        ]
    )
    orchestrator = _Orchestrator()

    assert entrypoint.poll_once(client, orchestrator) == 2
    assert orchestrator.task_ids == ["pending", "in-progress"]


def test_main_dispatches_opt_in_polling(monkeypatch):
    monkeypatch.setattr(entrypoint, "run_polling", lambda interval: interval)

    assert entrypoint.main(["--poll", "--poll-interval", "0.25"]) == 0.25


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
