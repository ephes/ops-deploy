"""Install command argv with constraint overrides (golden), no installs."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from ops_deploy.services.homeassistant.application import application_command, install_application
from ops_deploy.services.homeassistant.extra_packages import extra_packages_command
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
from ops_deploy.testing import run_deploy_fake
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "homeassistant"


def typed_argv(command: str) -> list[str]:
    # Strip the existing runuser/env prefix; shell quoting must preserve each argument.
    return shlex.split(command.split(" && ", 1)[1])[6:]


OVERRIDES: list[dict[str, Any]] = [
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
]


def test_effective_install_argv_is_golden() -> None:
    """The uv install argv (constraints, extras, quoting) is what hosts run today."""

    argv: dict[str, list[str]] = {}
    for index, overrides in enumerate(OVERRIDES):
        cfg = HomeAssistantRuntimeConfig.model_validate(
            {"extra_package_specs": ("owned; python_version >= '3.12'",), **overrides}
        )
        assert HomeAssistantRuntimeConfig.model_validate_json(cfg.model_dump_json()) == cfg
        argv[f"{index} homeassistant"] = typed_argv(application_command(cfg, "homeassistant"))
        argv[f"{index} matter"] = typed_argv(application_command(cfg, "matter"))
        argv[f"{index} extras"] = typed_argv(extra_packages_command(cfg))
    assert_golden(GOLDEN / "install-argv.json", json.dumps(argv, indent=1) + "\n")


def test_malformed_constraint_suffix_fails_before_operations() -> None:
    cfg = HomeAssistantRuntimeConfig(python_security_constraint_args="--constraint 'unterminated")
    result = run_deploy_fake(lambda: install_application(cfg))
    assert not result.succeeded
    assert result.ops == []
    assert result.executed_commands == []
