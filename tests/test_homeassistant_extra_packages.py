"""Declared managed resolution and original post-success notification, not native UV."""

from __future__ import annotations

import shlex
from typing import Any

import pytest
from pyinfra.api import Config
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.services.homeassistant.extra_packages import (
    extra_packages_changed,
    extra_packages_command,
    install_extra_packages,
)
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake


@pytest.mark.parametrize(
    "output", ["Audited 10 packages", "Installed 1 package", "Updated", "Uninstalled", "Prepared", "Built"]
)
@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_actual_managed_execution_and_output_bound_notification(output: str, stream: str) -> None:
    cfg = HomeAssistantRuntimeConfig(extra_package_specs=("owned-extra==1.0",))
    result: list[OperationMeta | None] = []

    def deploy() -> None:
        result.append(install_extra_packages(cfg))
        server.shell(commands=["synthetic-deferred-restart"], _if=lambda: extra_packages_changed(result[0]))

    response: dict[str, Any] = {stream: [output]}
    run = run_deploy_fake(deploy, responses={"pip install": response}, pyinfra_config=Config(DIFF=True))
    assert run.succeeded, run.error
    assert run.ops[0].changed is True
    assert run.ops[0].read_only is False
    assert run.executed_commands[0] == extra_packages_command(cfg)
    changed = output != "Audited 10 packages"
    assert extra_packages_changed(result[0]) is changed
    assert ("synthetic-deferred-restart" in run.executed_commands) is changed
    assert len(run.mutating_changed_ops) == 1 + int(changed)
    assert run.uploads == []


def test_failed_install_does_not_trigger_notification_or_become_zero_success() -> None:
    cfg = HomeAssistantRuntimeConfig(extra_package_specs=("owned-extra==1.0",))
    result: list[OperationMeta | None] = []

    def deploy() -> None:
        result.append(install_extra_packages(cfg))
        server.shell(commands=["synthetic-deferred-restart"], _if=lambda: extra_packages_changed(result[0]))

    run = run_deploy_fake(deploy, responses={"pip install": {"success": False, "stderr": ["Installed then failed"]}})
    assert not run.succeeded
    assert run.ops[0].succeeded is False
    assert not extra_packages_changed(result[0])
    assert "synthetic-deferred-restart" not in run.executed_commands


def test_empty_specs_do_not_register_any_execution() -> None:
    results = []
    run = run_deploy_fake(lambda: results.append(install_extra_packages(HomeAssistantRuntimeConfig())))
    assert run.succeeded, run.error
    assert results == [None]
    assert not extra_packages_changed(None)
    assert run.ops == []
    assert run.executed_commands == []


def test_premature_change_classification_is_not_assumed_false() -> None:
    with pytest.raises(RuntimeError, match="before execution"):
        extra_packages_changed(OperationMeta("owned", True))


@pytest.mark.parametrize("constraints", [False, True])
def test_original_argv_each_spec_single_argument_and_constraint_order(constraints: bool) -> None:
    cfg = HomeAssistantRuntimeConfig(
        user="owned",
        home="/srv/owned",
        python_security_floor_enabled=constraints,
        extra_package_specs=("owned-one==1", "owned-two; python_version >= '3.12'"),
    )
    command = extra_packages_command(cfg)
    assert command.startswith("cd /srv/owned/site && ")
    assert shlex.split(command.split(" && ", 1)[1]) == [
        "runuser",
        "-u",
        "owned",
        "--",
        "env",
        "HOME=/srv/owned",
        "/usr/local/bin/uv",
        "pip",
        "install",
        "--python",
        cfg.virtualenv_path,
        *(["--constraint", cfg.python_security_constraints_path] if constraints else []),
        *cfg.extra_package_specs,
    ]


def test_notification_expression_matches_bound_original_task() -> None:
    import re
    from pathlib import Path

    import jinja2
    import yaml
    from pyinfra.connectors.util import CommandOutput, OutputLine

    tasks = yaml.safe_load((Path(__file__).parent / "parity/homeassistant/python.yml").read_text())
    task = next(row for row in tasks if row["name"] == "Install Home Assistant extra Python packages via uv pip")
    expression = task["changed_when"]
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.tests["search"] = lambda value, pattern: re.search(pattern, value) is not None
    original = env.compile_expression(expression)
    for stdout, stderr in [
        ("Audited", ""),
        ("", "Prepared 1 package"),
        ("Un", "installed"),
        ("installed", ""),
        ("Built", ""),
    ]:
        result = OperationMeta("owned", True)
        result.set_complete(
            True, ["declared-install"], CommandOutput([OutputLine("stdout", stdout), OutputLine("stderr", stderr)])
        )
        expected = bool(original(_ha_extra_package_install={"stdout": stdout, "stderr": stderr}))
        assert extra_packages_changed(result) is expected
