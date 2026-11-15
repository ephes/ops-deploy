"""Python security policy and real isolated inspector execution, never HA."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from pyinfra.api import DeployError, OperationError

from ops_deploy.services.homeassistant import security
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from tests.fakehost import command_host


def test_environment_selection() -> None:
    cfg = HomeAssistantRuntimeConfig(manage_matter_server=True, site_path="/srv/owned")
    assert [env.model_dump() for env in cfg.python_security_environments] == [
        {"path": "/srv/owned/.venv", "label": "Home Assistant environment"},
        {"path": "/srv/owned/.venv-matter-server", "label": "Matter server environment"},
    ]
    without_matter = HomeAssistantRuntimeConfig(manage_matter_server=False, site_path="/srv/owned")
    assert [env.model_dump() for env in without_matter.python_security_environments] == [
        {"path": "/srv/owned/.venv", "label": "Home Assistant environment"}
    ]
    assert HomeAssistantRuntimeConfig(python_security_environments=()).python_security_environments == ()


def report(version: str = "2026.10.19") -> dict[str, Any]:
    return {
        "python_version": "3.14.8",
        "packages": {
            "certifi": {
                "installed": True,
                "version": version,
                "in_environment": True,
                "bundle_fingerprints": [],
            }
        },
    }


def test_old_floor_fails_before_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "_read", lambda *args, **kwargs: "present")
    monkeypatch.setattr(security, "_report", lambda *args, **kwargs: report("2026.10.18"))
    run = run_deploy_fake(lambda: security.security_preflight(HomeAssistantRuntimeConfig(uv_system_certs=False)))
    assert not run.succeeded
    assert "2026.10.19" in str(run.error)
    assert run.ops == []
    assert run.uploads == []


def test_post_install_uses_fresh_report_and_is_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: list[str] = []

    def read(target: Any, command: str, **kwargs: Any) -> str:
        observed.append(command)
        return "present" if "os.lstat" in command else json.dumps(report())

    monkeypatch.setattr(security, "_read", read)
    cfg = HomeAssistantRuntimeConfig(uv_system_certs=False)

    def deploy() -> None:
        security.security_preflight(cfg)
        security.verify_security(cfg)

    run = run_deploy_fake(deploy)
    assert run.succeeded, run.error
    assert len(observed) == 3  # stat + planning report + fresh execution report
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert len(run.changed_ops) == 1


def test_post_install_still_rejects_old_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "_report", lambda *args, **kwargs: report("2026.10.18"))
    run = run_deploy_fake(lambda: security.verify_security(HomeAssistantRuntimeConfig()))
    assert not run.succeeded
    assert run.uploads == []


def test_missing_only_skipped_preflight(monkeypatch: pytest.MonkeyPatch) -> None:
    def read(target: Any, command: str, **kwargs: Any) -> str:
        if "os.lstat" in command:
            return "absent"
        raise AssertionError("missing interpreter must not be inspected before install")

    monkeypatch.setattr(security, "_read", read)
    run = run_deploy_fake(lambda: security.security_preflight(HomeAssistantRuntimeConfig(uv_system_certs=False)))
    assert run.succeeded
    assert run.ops == []


@pytest.mark.parametrize("bad", ["permission-denied", "", "present\nabsent"])
def test_stat_errors_are_not_missing(monkeypatch: pytest.MonkeyPatch, bad: str) -> None:
    monkeypatch.setattr(security, "_read", lambda *args, **kwargs: bad)
    with pytest.raises(DeployError, match="invalid result"):
        security.security_preflight(HomeAssistantRuntimeConfig())


def test_distrusted_system_store_before_any_write(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = HomeAssistantRuntimeConfig(python_security_floor_enabled=False)
    monkeypatch.setattr(
        security, "_report", lambda *args, **kwargs: {"fingerprints": [cfg.security.distrusted_roots[0].sha256.lower()]}
    )
    run = run_deploy_fake(lambda: security.security_preflight(cfg))
    assert not run.succeeded
    assert "emSign" in str(run.error)
    assert run.ops == []
    assert run.uploads == []


def test_disabled_checks_have_no_commands() -> None:
    cfg = HomeAssistantRuntimeConfig(python_security_floor_enabled=False, uv_system_certs=False)

    def deploy() -> None:
        security.security_preflight(cfg)
        security.write_constraints(cfg)
        security.verify_security(cfg)

    run = run_deploy_fake(deploy)
    assert run.succeeded
    assert run.ops == []
    assert run.executed_commands == []


def test_real_isolated_inspector_ignores_pythonpath_and_never_imports_application(tmp_path: Path) -> None:
    poison = tmp_path / "homeassistant.py"
    poison.write_text("raise RuntimeError('application import must not happen')\n")
    cfg = HomeAssistantRuntimeConfig(security={"become": False})
    command = security.environment_command(cfg, sys.executable)
    argv = shlex.split(command)
    assert argv[1:4] == ["-I", "-B", "-c"]
    result = subprocess.run(
        argv, env={**os.environ, "PYTHONPATH": str(tmp_path)}, cwd=tmp_path, capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
    assert set(json.loads(result.stdout)["packages"]) == {"certifi", "pip"}
    assert sorted(p.name for p in tmp_path.iterdir()) == ["homeassistant.py"]


def test_service_user_command_preserves_quoted_identity_and_isolation() -> None:
    cfg = HomeAssistantRuntimeConfig(user="ha_owned", home="/srv/owned-home")
    argv = shlex.split(security.environment_command(cfg, "/srv/owned env/bin/python"))
    assert argv[:9] == [
        "runuser",
        "-u",
        "ha_owned",
        "--",
        "env",
        "HOME=/srv/owned-home",
        "/srv/owned env/bin/python",
        "-I",
        "-B",
    ]


def test_actual_lstat_counts_dangling_link_as_existing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def read(target: Any, command: str, **kwargs: Any) -> str:
        result = subprocess.run(shlex.split(command), capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        return result.stdout

    monkeypatch.setattr(security, "_read", read)
    path = tmp_path / "python"
    assert not security._present(Mock(), str(path), sys.executable)
    path.symlink_to(tmp_path / "missing-target")
    assert security._present(Mock(), str(path), sys.executable)


def test_failed_command_names_declared_context_but_does_not_export_stderr() -> None:
    target = command_host(Mock(return_value=(False, Mock(stderr="untrusted-private-error"))))
    with pytest.raises(OperationError, match="Owned environment: inspection command failed") as caught:
        security._read(target, "synthetic-command", label="Owned environment")
    assert "untrusted-private-error" not in str(caught.value)
