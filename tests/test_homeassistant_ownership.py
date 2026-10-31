"""SDK ownership wiring; real filesystem behavior is a separate owned fixture."""

from __future__ import annotations

import json

import pytest
from pyinfra import state
from pyinfra.api import Config

from ops_deploy.services.homeassistant import ownership
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake


@pytest.mark.parametrize("matter", [False, True])
@pytest.mark.parametrize("answer", ["current", "pending"])
def test_exact_owned_path_and_managed_change(matter: bool, answer: str, monkeypatch: pytest.MonkeyPatch) -> None:
    observed = []
    cfg = HomeAssistantRuntimeConfig()

    def probe(command: str, *, name: str, stdin: str) -> str:
        observed.append(json.loads(stdin))
        return answer

    monkeypatch.setattr(ownership, "probe", probe)
    run = run_deploy_fake(lambda: ownership.environment_ownership(cfg, matter=matter))
    assert run.succeeded, run.error
    assert len(run.mutating_changed_ops) == int(answer == "pending")
    assert run.uploads == []
    expected = cfg.matter_server_virtualenv_path if matter else cfg.virtualenv_path
    assert observed
    assert all(value == {"root": expected, "user": cfg.user, "group": cfg.group, "apply": False} for value in observed)
    if answer == "pending":
        assert json.loads(run.stdin[-1][1]) == {"root": expected, "user": cfg.user, "group": cfg.group, "apply": True}


@pytest.mark.parametrize("answer", [None, "unknown", "changed"])
def test_unknown_probe_does_not_run_repair(answer: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ownership, "probe", lambda *a, **kw: answer)
    run = run_deploy_fake(lambda: ownership.environment_ownership(HomeAssistantRuntimeConfig()))
    assert not run.succeeded
    assert run.executed_commands == []
    assert run.uploads == []


def test_declared_cold_plan_deferral_still_checks_at_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    phases = []

    def probe(*args: object, **kwargs: object) -> str:
        phases.append(state.is_executing)
        return "current"

    monkeypatch.setattr(ownership, "probe", probe)
    run = run_deploy_fake(
        lambda: ownership.environment_ownership(HomeAssistantRuntimeConfig(), deferred=True),
        pyinfra_config=Config(DIFF=True),
    )
    assert run.succeeded, run.error
    assert phases == [True]
    assert run.mutating_changed_ops == []


def test_repair_failure_is_not_a_successful_zero_change(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ownership, "probe", lambda *a, **kw: "pending")
    run = run_deploy_fake(
        lambda: ownership.environment_ownership(HomeAssistantRuntimeConfig()),
        responses={"ha-venv-ownership": {"success": False}},
    )
    assert not run.succeeded
    assert run.ops[0].succeeded is False
    assert len(run.executed_commands) == 1
