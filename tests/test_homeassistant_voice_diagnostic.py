"""Owned prefix boundaries and read-only metadata collection; no application calls."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest

from tests.integration.homeassistant import component_matrix, harness, matrix
from tests.integration.homeassistant import diagnose_voice as driver
from tests.integration.homeassistant import voice_diagnostics as diagnostic


def setup_driver(monkeypatch: pytest.MonkeyPatch) -> tuple[list[Any], dict[str, Any]]:
    events: list[Any] = []
    written: dict[str, Any] = {}
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "current")
    monkeypatch.setattr(harness, "admit", lambda: events.append("admit"))
    monkeypatch.setattr(harness, "PHASES", [])
    monkeypatch.setattr(driver, "write", lambda name, value: written.update({name: value}))
    monkeypatch.setattr(driver, "capture", lambda label, point: events.append((label, point)))

    def typed(label: str, *args: Any, **kwargs: Any) -> str:
        events.append((label, args, kwargs))
        harness.PHASES.append({"label": label})
        return label

    monkeypatch.setattr(harness, "typed", typed)
    return events, written


def test_same_call_arguments_canonical_phases_cleanup_and_stop_before35(monkeypatch: pytest.MonkeyPatch) -> None:
    events, written = setup_driver(monkeypatch)
    config = object()

    def run_matrix() -> None:
        try:
            cast(Any, matrix).typed("03-normal-plan", config, plan=True)
            for label in sorted(diagnostic.LABELS):
                cast(Any, component_matrix).typed(
                    label, config, failure=label.startswith("33"), stable=not label.startswith("33")
                )
            pytest.fail("reached phase35")
        finally:
            events.append("peer-cleanup")

    monkeypatch.setattr(matrix, "run", run_matrix)
    driver.run()
    summary = written["VOICE-DIAGNOSTIC.json"]
    assert summary["completed_through34"] is True
    assert summary["typed_labels_reached"] == ["03-normal-plan", *sorted(diagnostic.LABELS)]
    assert summary["phases"] == [{"label": label} for label in summary["typed_labels_reached"]]
    assert events[0] == "admit"
    assert events[-1] == "peer-cleanup"
    assert ("03-normal-plan", (config,), {"plan": True}) in events
    for label in diagnostic.LABELS:
        assert (label, "before") in events
        assert (label, "after") in events
        assert (label, (config,), {"failure": label.startswith("33"), "stable": not label.startswith("33")}) in events


@pytest.mark.parametrize("failure_point", ["32-voice-current", "33-voice-missing-stt", "34-voice-recovery"])
def test_failure_and_partial_phases_survive_after_collector_failure(
    monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    events, written = setup_driver(monkeypatch)
    original = RuntimeError("owned original failure")

    def typed(label: str) -> None:
        harness.PHASES.append({"label": label})
        raise original

    def capture(label: str, point: str) -> None:
        events.append((label, point))
        if point == "after":
            raise OSError("owned evidence failure")

    monkeypatch.setattr(harness, "typed", typed)
    monkeypatch.setattr(driver, "capture", capture)
    monkeypatch.setattr(matrix, "run", lambda: cast(Any, component_matrix).typed(failure_point))
    with pytest.raises(RuntimeError) as caught:
        driver.run()
    assert caught.value is original
    assert (failure_point, "after") in events
    assert written["VOICE-DIAGNOSTIC.json"]["completed_through34"] is False
    assert written["VOICE-DIAGNOSTIC.json"]["phases"] == [{"label": failure_point}]


def test_upgrade_refuses_before_admission_and_late_phase_before_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    events, written = setup_driver(monkeypatch)
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "upgrade")
    with pytest.raises(ValueError, match="requires the current"):
        driver.run()
    assert events == []
    assert written == {}
    monkeypatch.setenv("HOMEASSISTANT_FIXTURE_CASE", "current")
    monkeypatch.setattr(matrix, "run", lambda: cast(Any, component_matrix).typed("35-custom-install"))
    with pytest.raises(AssertionError, match="cannot enter phase35"):
        driver.run()
    assert events == ["admit"]


def test_metadata_commands_are_bounded_fixed_owned_and_not_application_journals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands = []
    written = {}

    def command(argv: list[str], *, timeout: float) -> dict[str, Any]:
        commands.append((argv, timeout))
        if argv[0] == "readlink":
            raise OSError("owned missing namespace")
        return {"exit": 0, "output": "-- No entries --", "truncated": False, "timed_out": False}

    monkeypatch.setattr(diagnostic, "bounded_command", command)
    monkeypatch.setattr(diagnostic, "write", lambda name, value: written.update({name: value}))
    result = diagnostic.capture("33-voice-missing-stt", "after")
    assert result["namespace"] == {"collection_failed": True, "error_type": "OSError"}
    assert len(commands) == 7
    assert all(0 < timeout <= 10 for _, timeout in commands)
    assert {argv[0] for argv, _ in commands} == {"readlink", "cat", "systemctl", "journalctl", "head"}
    journal = next(argv for argv, _ in commands if argv[0] == "journalctl")
    assert "_PID=1" in journal
    assert "--unit=homeassistant.service" in journal
    assert "--lines=100" in journal
    assert "missing evidence" in result["journal_limit"]
    assert "memory.events" in json.dumps(commands)
    assert "memory.max" in json.dumps(commands)
    assert "owned missing namespace" not in json.dumps(written)
    before = len(commands)
    with pytest.raises(ValueError, match="unexpected owned"):
        diagnostic.capture("35-custom-install", "before")
    assert len(commands) == before
