"""Actual controller declaration keeps executor/report work out of facts."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig, transition_daybook_runtime
from ops_deploy.services.daybook_voice_memo_inbox import report as report_api
from ops_deploy.testing import run_deploy_fake
from tests.test_daybook_inbox_declaration import config
from tests.test_daybook_inbox_deploy import source  # noqa: F401 - pytest fixture


def test_actual_transition_controller_only_declares_one_managed_executor_operation(
    source: tuple[SourceTree, Path],  # noqa: F811
) -> None:
    tree, _bundle = source
    cfg = DaybookRuntimeConfig(user="fixture", revision=tree.commit, action="cutover", confirmed=True, start=True)
    secret = "UNUSABLE-OWNED-EXECUTOR-PRIVATE-ONLY"
    run = run_deploy_fake(
        transition_daybook_runtime, cfg, {"executor_token": secret}, tree, responses={"uname -s": ["Darwin"]}
    )
    assert run.succeeded, run.error
    assert len(run.ops) == 1
    assert len(run.mutating_changed_ops) == 1
    assert run.ops[0].read_only is False
    assert run.fact_commands == ["uname -s"]
    assert run.uploaded_paths == []
    assert run.fish_unsafe_commands == []
    assert secret not in repr(run.events)


@pytest.mark.parametrize("available", [True, False])
def test_optional_report_controller_only_facts_metadata_and_manages_actual_report(
    monkeypatch: pytest.MonkeyPatch, available: bool
) -> None:
    commands: list[str] = []

    def fact(_kind: Any, **kwargs: Any) -> str:
        command = kwargs.get("command", "uname -s")
        commands.append(command)
        if command == "uname -s":
            return "Darwin"
        if command == "/usr/bin/id -u fixture":
            assert kwargs["_ignore_errors"] is True
            return "501"
        assert kwargs["_ignore_errors"] is True
        assert command.endswith(" available")
        assert "operations status" not in command
        assert "voice-memos status" not in command
        return json.dumps({"available": available})

    from pyinfra.connectors.util import CommandOutput

    def execute(_command: Any, _state: Any, _host: Any, _args: Any) -> Any:
        # @fake intentionally rejects stream stdin. Actual SDK execution/result
        # validation has separate direct tests plus the owned SSH fixture.
        return True, CommandOutput([])

    monkeypatch.setattr(report_api._ReportCommand, "execute", execute)
    monkeypatch.setattr(report_api, "host", SimpleNamespace(get_fact=fact))
    run = run_deploy_fake(report_api.report_daybook_inbox_interruption, config())
    assert run.succeeded, run.error
    assert len(run.ops) == int(available)
    assert len(run.mutating_changed_ops) == int(available)
    assert all(row.read_only is False for row in run.ops)
    assert len(commands) == 3
    assert run.uploaded_paths == []
