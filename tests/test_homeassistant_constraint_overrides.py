"""Bound original defaults and command tasks, with literal argv and no installs."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

from ops_deploy.services.homeassistant.application import application_command, install_application
from ops_deploy.services.homeassistant.extra_packages import extra_packages_command
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake

FIXTURES = Path(__file__).parent / "parity/homeassistant"


def original(overrides: dict[str, Any], *, matter: bool = False, extras: bool = False) -> list[str]:
    defaults = yaml.safe_load((FIXTURES / "defaults.yml").read_text())
    env = NativeEnvironment(undefined=StrictUndefined)
    env.filters["bool"] = bool
    env.filters["quote"] = shlex.quote
    context = {
        "homeassistant_uv_path": "/usr/local/bin/uv",
        "homeassistant_virtualenv_path": "/home/homeassistant/site/.venv",
        "homeassistant_matter_server_virtualenv_path": "/home/homeassistant/site/.venv-matter-server",
        "homeassistant_package_spec": "homeassistant",
        "homeassistant_matter_server_package_spec": "python-matter-server[server]",
        "homeassistant_python_security_floor_enabled": True,
        "homeassistant_python_security_constraints_path": "/home/homeassistant/site/.python-security-constraints.txt",
        "homeassistant_extra_package_specs": ["owned; python_version >= '3.12'"],
        **{"homeassistant_" + key: value for key, value in overrides.items()},
    }
    for suffix in ("argv", "args"):
        constraint_field = "homeassistant_python_security_constraint_" + suffix
        if constraint_field not in context:
            context[constraint_field] = env.from_string(defaults[constraint_field]).render(**context)
    tasks = yaml.safe_load((FIXTURES / ("matter_server.yml" if matter else "python.yml")).read_text())
    commands = [row["ansible.builtin.command"] for row in tasks if "ansible.builtin.command" in row]
    if extras:
        command = next(row["argv"] for row in commands if "homeassistant_extra_package_specs" in str(row))
        context["homeassistant_python_security_constraint_argv"] = list(
            context["homeassistant_python_security_constraint_argv"]
        )
        return list(env.from_string(command).render(**context))
    command = next(row["cmd"] for row in commands if "homeassistant_python_security_constraint_args" in str(row))
    return shlex.split(env.from_string(command).render(**context))


def typed_argv(command: str) -> list[str]:
    # Strip the existing runuser/env prefix; shell quoting must preserve each argument.
    return shlex.split(command.split(" && ", 1)[1])[6:]


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {"python_security_floor_enabled": False},
        {"python_security_constraints_path": "/srv/owned-constraints.txt"},
        {"python_security_constraint_argv": ()},
        {"python_security_constraint_args": ""},
        {"python_security_constraint_argv": ("--constraint", "/srv/other constraints.txt", "--no-deps")},
        {"python_security_constraint_args": "--constraint '/srv/application only.txt' --no-deps"},
        {
            "python_security_floor_enabled": False,
            "python_security_constraint_argv": ("--constraint", "/srv/extras only.txt"),
            "python_security_constraint_args": "--constraint '/srv/application only.txt'",
        },
        {
            "python_security_constraint_argv": ("--constraint", "/srv/literal$(id); constraints"),
            "python_security_constraint_args": "--constraint '/srv/literal$(id); app'",
        },
    ],
)
@pytest.mark.parametrize("kind", ["homeassistant", "matter", "extras"])
def test_effective_argv_matches_original_tasks(overrides: dict[str, Any], kind: str) -> None:
    cfg = HomeAssistantRuntimeConfig.model_validate(
        {"extra_package_specs": ("owned; python_version >= '3.12'",), **overrides}
    )
    command = (
        extra_packages_command(cfg)
        if kind == "extras"
        else application_command(cfg, "matter" if kind == "matter" else "homeassistant")
    )
    assert typed_argv(command) == original(overrides, matter=kind == "matter", extras=kind == "extras")
    assert HomeAssistantRuntimeConfig.model_validate_json(cfg.model_dump_json()) == cfg


def test_malformed_constraint_suffix_fails_before_operations() -> None:
    cfg = HomeAssistantRuntimeConfig(python_security_constraint_args="--constraint 'unterminated")
    result = run_deploy_fake(lambda: install_application(cfg))
    assert not result.succeeded
    assert result.ops == []
    assert result.executed_commands == []
