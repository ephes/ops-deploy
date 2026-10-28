"""Owned execution-boundary tests; simulated systemd is not native proof."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_reindex", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/reindex.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SETTINGS = {
    "username": "paperless",
    "service_name": "paperless",
    "env_file": "/home/paperless/site/.env",
    "python_bin": "/home/paperless/site/.venv/bin/python",
    "manage_dir": "/home/paperless/site/paperless-ngx/src",
}
UNITS = ("paperless.service", "paperless-worker.service", "paperless-scheduler.service", "paperless-consumer.service")


class Commands:
    def __init__(self, failure: str = "") -> None:
        self.failure = failure
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(argv)
        if argv[:2] == ["systemctl", "show"]:
            assert kwargs == {"capture": True}
            state = "active" if argv[-1] in {UNITS[0], UNITS[3]} else "inactive"
            if self.failure == "unstable":
                state = "activating"
            return subprocess.CompletedProcess(argv, 0, state + "\n", "")
        if argv[0] == "runuser":
            assert kwargs == {"cwd": SETTINGS["manage_dir"]}
            if self.failure == "exception":
                raise OSError("synthetic private content must not reach CLI")
            return subprocess.CompletedProcess(argv, 2 if self.failure in {"reindex", "both"} else 0, "", "")
        failed = (self.failure == "stop" and argv == ["systemctl", "stop", UNITS[1]]) or (
            self.failure in {"resume", "both"} and argv == ["systemctl", "start", UNITS[0]]
        )
        return subprocess.CompletedProcess(argv, int(failed), "", "")


def test_success_stops_all_and_resumes_only_previously_running(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands()
    monkeypatch.setattr(MODULE, "call", commands)
    assert MODULE.reindex(SETTINGS) == {"reindexed": True, "resumed_units": 2}
    assert commands.calls[4:8] == [["systemctl", "stop", unit] for unit in UNITS]
    assert commands.calls[-2:] == [["systemctl", "start", UNITS[0]], ["systemctl", "start", UNITS[3]]]
    assert commands.calls[8] == [
        "runuser",
        "-u",
        "paperless",
        "--",
        "bash",
        "-euc",
        "set -a; . /home/paperless/site/.env; set +a; exec "
        "/home/paperless/site/.venv/bin/python manage.py document_index reindex",
    ]


@pytest.mark.parametrize("failure", ["stop", "reindex", "resume", "both", "exception"])
def test_failure_resumes_every_previous_unit_and_normal_retry(failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands(failure)
    monkeypatch.setattr(MODULE, "call", commands)
    with pytest.raises((MODULE.ReindexFailure, OSError)):
        MODULE.reindex(SETTINGS)
    assert commands.calls[-2:] == [["systemctl", "start", UNITS[0]], ["systemctl", "start", UNITS[3]]]
    if failure == "stop":
        assert not any(argv[0] == "runuser" for argv in commands.calls)
    commands.failure = ""
    assert MODULE.reindex(SETTINGS)["reindexed"]


def test_unstable_state_refuses_before_service_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands("unstable")
    monkeypatch.setattr(MODULE, "call", commands)
    with pytest.raises(MODULE.ReindexFailure, match="stable"):
        MODULE.reindex(SETTINGS)
    assert all(argv[:2] == ["systemctl", "show"] for argv in commands.calls)


@pytest.mark.parametrize(
    ("key", "value"), [("username", "root"), ("manage_dir", "/srv/../etc"), ("env_file", "/tmp/a;id")]
)
def test_invalid_settings_refuse_before_command(key: str, value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    commands = Commands()
    monkeypatch.setattr(MODULE, "call", commands)
    with pytest.raises(ValueError, match=r"invalid|non-root"):
        MODULE.reindex(dict(SETTINGS, **{key: value}))
    assert not commands.calls


def test_application_output_never_enters_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen.update(kwargs)
        return subprocess.CompletedProcess(argv, 2, "", "")

    monkeypatch.setattr(MODULE.subprocess, "run", run)
    MODULE.call(["synthetic-application"])
    assert seen["stdout"] == subprocess.DEVNULL
    assert seen["stderr"] == subprocess.DEVNULL
    assert seen["stdin"] == subprocess.DEVNULL
