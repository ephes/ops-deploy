"""deploy_open_webui_remove against the open_webui_venv_remove role: order, opt-in flags, what stays."""

from __future__ import annotations

import json
import stat
from typing import Any
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services._lifecycle import media_remove as common
from ops_deploy.services.open_webui import OpenWebUIRemoveConfig, deploy_open_webui_remove
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

UNIT = "/etc/systemd/system/open-webui.service"
ROUTE = "/etc/traefik/dynamic/open-webui.yml"
# What `just remove-one open_webui` passes besides confirm (ops-control justfiles/remove.just).
FULL_WIPE = ("remove_site_dir", "remove_data", "remove_log_dir", "remove_traefik_config", "remove_user", "remove_group")


def run(cfg: OpenWebUIRemoveConfig, *, present: bool = True, active: bool = True) -> FakeRun:
    def selected(command: str, **kwargs: Any) -> str | None:
        assert command == common._command("inspect")
        request = json.loads(kwargs["stdin"])
        directory = {"mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 0}
        return json.dumps(
            {
                "paths": {path: directory if present else None for path in request["paths"]},
                "user": {"uid": 990, "gid": 990, "home": "/home/openwebui"} if present and request["user"] else None,
                "group": 990 if present and request["group"] else None,
                "packages": [],
            }
        )

    with patch.object(common, "probe", side_effect=selected):
        return run_deploy_fake(
            deploy_open_webui_remove,
            cfg,
            responses={
                **fakehost.LINUX,
                "cat /proc/1/comm": ["systemd"],
                "for unit in": [
                    "Id=open-webui.service",
                    "LoadState=loaded" if present else "LoadState=not-found",
                    "ActiveState=active" if present and active else "ActiveState=inactive",
                    "UnitFileState=enabled" if present and active else "UnitFileState=disabled",
                    "---",
                ],
            },
        )


def test_confirm_refuses_before_facts_or_commands() -> None:
    result = run(OpenWebUIRemoveConfig.model_validate(dict.fromkeys(FULL_WIPE, True)))

    assert not result.succeeded
    assert "not confirmed" in str(result.error)
    assert not result.events


def test_role_defaults_remove_only_the_unit() -> None:
    result = run(OpenWebUIRemoveConfig(confirm=True))

    assert result.succeeded, result.error
    assert result.executed_commands == [
        "systemctl stop open-webui.service || true",
        "systemctl disable open-webui.service || true",
        f"rm -rf -- {UNIT}",
        "systemctl daemon-reload",
    ]


def test_full_wipe_order_and_what_stays() -> None:
    cfg = OpenWebUIRemoveConfig.model_validate({"confirm": True, **dict.fromkeys(FULL_WIPE, True)})

    result = run(cfg)

    assert result.succeeded, result.error
    commands = result.executed_commands
    assert commands[:3] == [
        "systemctl stop open-webui.service || true",
        "systemctl disable open-webui.service || true",
        f"rm -rf -- {UNIT}",
    ]
    removed = [c.removeprefix("rm -rf -- ") for c in commands if c.startswith("rm -rf -- ")]
    assert removed == [UNIT, ROUTE, "/opt/open-webui", "/var/lib/open-webui", "/var/log/open-webui"]
    assert commands.index(route_guard_command()) == commands.index(f"rm -rf -- {ROUTE}") - 1
    assert commands[-2].endswith(" accounts")
    assert commands[-1] == "systemctl daemon-reload"
    # The deploy's data directory, uv and Traefik itself are not touched.
    assert not any("/mnt/cryptdata" in c or "/usr/local/bin/uv" in c for c in commands)
    assert not any("traefik" in c and "systemctl" in c for c in commands)


def test_env_and_venv_flags_follow_the_site_dir() -> None:
    cfg = OpenWebUIRemoveConfig(confirm=True, remove_env_file=True, remove_venv=True, site_dir="/srv/owui")

    result = run(cfg)

    assert result.succeeded, result.error
    assert "rm -rf -- /srv/owui/open-webui.env" in result.executed_commands
    assert "rm -rf -- /srv/owui/.venv" in result.executed_commands
    assert "rm -rf -- /srv/owui" not in result.executed_commands


@pytest.mark.parametrize(
    ("flag", "kept"),
    [
        ("remove_site_dir", "/opt/open-webui"),
        ("remove_data", "/var/lib/open-webui"),
        ("remove_log_dir", "/var/log/open-webui"),
        ("remove_traefik_config", ROUTE),
    ],
)
def test_each_flag_alone_keeps_its_path(flag: str, kept: str) -> None:
    flags = {"confirm": True, **dict.fromkeys(FULL_WIPE, True), flag: False}

    result = run(OpenWebUIRemoveConfig.model_validate(flags))

    assert result.succeeded, result.error
    assert f"rm -rf -- {kept}" not in result.executed_commands


def test_keeping_user_and_group_runs_no_account_change() -> None:
    flags = {"confirm": True, **dict.fromkeys(FULL_WIPE, True), "remove_user": False, "remove_group": False}

    result = run(OpenWebUIRemoveConfig.model_validate(flags))

    assert result.succeeded, result.error
    assert not any(c.endswith(" accounts") for c in result.executed_commands)


def test_a_removed_install_changes_nothing() -> None:
    cfg = OpenWebUIRemoveConfig.model_validate({"confirm": True, **dict.fromkeys(FULL_WIPE, True)})

    result = run(cfg, present=False)

    assert result.succeeded, result.error
    assert not result.executed_commands
    assert not result.changed_ops


@pytest.mark.parametrize("path", ["/", "/opt", "/var/lib", "/mnt/cryptdata", "/tmp/../root"])
def test_system_roots_are_refused(path: str) -> None:
    with pytest.raises(ValidationError):
        OpenWebUIRemoveConfig(site_dir=path)
