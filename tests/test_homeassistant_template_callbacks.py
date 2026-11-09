"""Selected callbacks through real SDK/local protected writes, no host services."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops

from ops_deploy.services.homeassistant import services, trust
from ops_deploy.services.homeassistant.configuration import ConfigurationPolicy
from ops_deploy.services.homeassistant.configuration_deploy import configure_files, protected_template
from ops_deploy.services.homeassistant.configuration_render import ConfigurationValues
from tests.test_homeassistant_configuration_deploy import config
from tests.test_homeassistant_trust import fixture


def test_actual_sdk_stage_capture_and_selected_include_render_are_fresh(tmp_path: Path) -> None:
    cfg = config(tmp_path)
    root = Path(cfg.config_path)
    root.mkdir()
    (root / "configuration.yaml").write_text("owned-before\n")
    (root / "present.yaml").write_text("owned-preserved\n")
    captures: dict[bool, dict[str, bytes]] = {False: {}, True: {}}
    calls: list[tuple[str, str | None, bool]] = []

    def capture(stage: str, executing: bool) -> None:
        captures[executing][stage] = (root / "configuration.yaml").read_bytes()

    def render(kind: str, item: str | None, executing: bool) -> SecretStr:
        calls.append((kind, item, executing))
        assert "unifi" in captures[executing]
        if kind == "secrets":
            assert "configuration_stat" not in captures[executing]
            return SecretStr("owned_secret: synthetic-only\n")
        assert captures[executing]["configuration_stat"] == b"owned-before\n"
        assert kind == "include"
        assert item == "absent.yaml"
        return SecretStr("[]\n")

    state = State(Inventory((["@local"], {})), Config(DIFF=True))
    try:
        connect_all(state)
        add_deploy(
            state,
            configure_files,
            cfg,
            ConfigurationPolicy(manage_secrets=True, manage_configuration=True, manage_includes=True),
            ConfigurationValues(),
            include_files=("present.yaml", "absent.yaml"),
            task_capture=capture,
            task_renderer=render,
        )
        assert (root / "configuration.yaml").read_bytes() == b"owned-before\n"
        assert not (root / "secrets.yaml").exists()
        assert not (root / "absent.yaml").exists()
        run_ops(state)
        assert not state.failed_hosts
        assert (root / "configuration.yaml").read_bytes() == b"owned-before\n"
        assert (root / "present.yaml").read_bytes() == b"owned-preserved\n"
        assert (root / "absent.yaml").read_bytes() == b"[]\n"
        assert captures[False] == captures[True]
        assert {executing for _, _, executing in calls} == {False, True}
        assert not any(kind == "configuration" or item == "present.yaml" for kind, item, _ in calls)
    finally:
        disconnect_all(state)


def test_actual_custom_unit_writes_preserve_changed_notifications_and_repeat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = config(tmp_path).model_copy(
        update={
            "manage_matter_server": True,
            "systemd_unit_path": str(tmp_path / "ha.service"),
            "matter_server_systemd_unit_path": str(tmp_path / "matter.service"),
        }
    )
    monkeypatch.setattr(
        services,
        "protected_template",
        lambda cfg, **kwargs: protected_template(cfg, user=cfg.user, group=cfg.group, **kwargs),
    )
    calls: list[tuple[str, bool]] = []

    def render(kind: str, item: str | None, executing: bool) -> SecretStr:
        assert item is None
        calls.append((kind, executing))
        return SecretStr("[Service]\n# owned " + kind + "\n")

    for changed in (True, False):
        state = State(Inventory((["@local"], {})), Config(DIFF=True))
        result: list[services.UnitChanges] = []
        try:
            connect_all(state)
            add_deploy(state, lambda result=result: result.append(services.write_units(cfg, task_renderer=render)))
            run_ops(state)
            assert not state.failed_hosts
            assert result[0].homeassistant_changed() is changed
            assert result[0].matter_changed() is changed
            assert result[0].reload_required() is changed
        finally:
            disconnect_all(state)
    assert all((kind, True) in calls for kind in ("homeassistant_unit", "matter_unit"))


def test_actual_original_trust_program_accepts_only_matching_private_stdin_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg, _ = fixture(tmp_path, monkeypatch)
    body = "[Service]\nEnvironment=UV_SYSTEM_CERTS=1\n# owned custom template\n"
    Path(cfg.uv_system_certs_dropin_path).write_text(body)
    digest = hashlib.sha256(body.encode()).hexdigest()
    command = trust.trust_command(cfg, "verify", protected_digest=True)
    assert digest not in command
    assert body not in command
    env = {**os.environ, "PATH": str(tmp_path / "commands") + os.pathsep + os.environ["PATH"]}
    for payload, admitted in (({"expected_sha256": digest}, True), ({"expected_sha256": "0" * 64}, False), ({}, False)):
        run = subprocess.run(
            ["bash", "-c", command + " --proc " + shlex.quote(str(tmp_path / "proc"))],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )
        assert digest not in run.stdout + run.stderr
        assert body not in run.stdout + run.stderr
        if not payload:
            assert run.returncode != 0
        else:
            assert run.returncode == 0
            report: dict[str, Any] = json.loads(run.stdout)
            assert (report["problems"] == []) is admitted
            assert report["managed_dropin"] is admitted


def test_actual_render_failure_is_accounted_and_does_not_log_private_exception(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = config(tmp_path)
    target = tmp_path / "never-written"
    state = State(Inventory((["@local"], {})), Config(DIFF=True))
    results = []

    def render() -> SecretStr:
        raise ValueError("owned-private-exception-canary")

    def deploy() -> None:
        results.append(
            protected_template(
                cfg, label="Owned failing render", path=str(target), content=render, user=cfg.user, group=cfg.group
            )
        )

    try:
        connect_all(state)
        add_deploy(state, deploy)
        assert not target.exists()
        with pytest.raises(PyinfraError):
            run_ops(state)
        assert state.failed_hosts
        assert results[0].is_complete()
        assert not results[0].did_succeed()
        assert not results[0].did_change()
        assert not target.exists()
        assert "owned-private-exception-canary" not in caplog.text
    finally:
        disconnect_all(state)
