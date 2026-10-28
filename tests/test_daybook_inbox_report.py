"""Synthetic application-report contract; no real app, ledger, GUI or host call."""

from __future__ import annotations

import subprocess
import sys
import types
from importlib.resources import files
from typing import Any
from unittest.mock import Mock

import pytest

from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE


@pytest.fixture
def reporter(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name in ("ops_daybook_observer", "ops_inbox_python"):
        module = types.ModuleType(name)
        if name == "ops_daybook_observer":
            module.NativeProbes = Mock()  # type: ignore[attr-defined]
        else:
            module.require_root_inputs = Mock()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, name, module)
    result = types.ModuleType("owned_optional_report")
    exec(compile(files(PACKAGE).joinpath("files/inbox_report.py").read_bytes(), "<report>", "exec"), result.__dict__)
    return result


@pytest.fixture
def data() -> dict[str, Any]:
    return {
        "user": "fixture",
        "uid": 501,
        "home": "/Users/fixture",
        "policy": "/owned/policy.json",
        "python": "/owned/python",
        "checkout": "/owned/checkout",
    }


def test_availability_refuses_nonroot_without_any_app_or_uv_call(
    reporter: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reporter.os, "geteuid", lambda: 501)
    called = Mock(side_effect=AssertionError("must not execute"))
    monkeypatch.setattr(reporter.subprocess, "run", called)
    assert reporter.available({}) is False
    called.assert_not_called()


@pytest.mark.parametrize(
    ("rc", "stdout", "expected"),
    [
        (0, b'{"long_in_flight_count": 3,"private":"OWNED-DISCARD"}', {"reported": True, "long_in_flight_count": 3}),
        (0, b'truncated "long_in_flight_count":0 garbage', {"reported": True, "long_in_flight_count": 0}),
        (1, b'{"long_in_flight_count":2}', {"reported": False}),
        (0, b"private unparseable", {"reported": False}),
        (0, b'{"long_in_flight_count": -2}', {"reported": False}),
    ],
)
def test_original_best_effort_regex_retains_only_validated_aggregate(
    reporter: Any,
    data: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    rc: int,
    stdout: bytes,
    expected: dict[str, Any],
    capsys: Any,
) -> None:
    monkeypatch.setattr(reporter, "available", lambda _: True)
    called = Mock(return_value=subprocess.CompletedProcess([], rc, stdout=stdout, stderr=b"OWNED-PRIVATE-DISCARD"))
    monkeypatch.setattr(reporter.subprocess, "run", called)
    assert reporter.report(data) == expected
    kwargs = called.call_args.kwargs
    assert "timeout" not in kwargs
    assert kwargs["cwd"] == data["checkout"]
    argv = called.call_args.args[0]
    assert argv[:7] == ["/bin/launchctl", "asuser", "501", "/usr/bin/sudo", "-u", "fixture", "/usr/bin/env"]
    assert argv[-3:] == ["voice-memos", "status", "--summary-only"]
    assert "HOME=/Users/fixture" in argv
    assert "DAYBOOK_VOICE_MEMOS_POLICY=/owned/policy.json" in argv
    assert capsys.readouterr() == ("", "")


def test_failed_optional_report_cannot_become_a_new_refusal(
    reporter: Any, data: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reporter, "available", lambda _: True)
    monkeypatch.setattr(reporter.subprocess, "run", Mock(side_effect=OSError("OWNED-PRIVATE-ERROR")))
    assert reporter.report(data) == {"reported": False}


@pytest.mark.parametrize("success", [True, False])
@pytest.mark.parametrize(
    "body",
    [
        '{"reported":true,"long_in_flight_count":3}',
        '{"reported":false}',
        '{"reported":true,"long_in_flight_count":"PRIVATE"}',
        "PRIVATE-INVALID-JSON",
    ],
)
def test_actual_sdk_report_command_logs_only_validated_count_and_preserves_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    success: bool,
    body: str,
) -> None:
    from types import SimpleNamespace
    from typing import cast

    from pyinfra import logger
    from pyinfra.api import Host, State
    from pyinfra.connectors.util import CommandOutput, OutputLine

    from ops_deploy.services.daybook_voice_memo_inbox import report as api

    output = CommandOutput([OutputLine("stdout", body), OutputLine("stderr", "PRIVATE-STDERR")])
    target = cast(Host, SimpleNamespace(run_shell_command=Mock(return_value=(success, output))))
    state = cast(State, SimpleNamespace(print_input=False, print_output=False))
    logged: list[str] = []
    monkeypatch.setattr(logger, "info", logged.append)
    result, actual_output = api._ReportCommand("owned synthetic report").execute(state, target, {})
    assert result is success
    assert actual_output is output
    assert logged == (
        ["Inbox interruption summary: 3 long-lane item(s) in flight"]
        if success and body == '{"reported":true,"long_in_flight_count":3}'
        else ["Optional Inbox interruption summary unavailable"]
    )
    assert "PRIVATE" not in repr(logged)
