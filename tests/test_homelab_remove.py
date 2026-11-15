"""The homelab_remove port; synthetic units, files and accounts only."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from ops_deploy.services.homelab import HomelabRemoveConfig, remove_homelab
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

UNIT = "/etc/systemd/system/homelab.service"
ROUTE = "/etc/traefik/dynamic/homelab.yml"
DB = "/home/homelab/site/db.sqlite3"
MEDIA = "/home/homelab/site/media"
HOME = "/home/homelab"


def confirmed(**values: Any) -> HomelabRemoveConfig:
    return HomelabRemoveConfig(confirm=True, auto_confirm=True, **values)


def present(path: str) -> str:
    return f"{{ test -e {path} || test -L {path}; }} && echo yes"


def host(*paths: str, account: bool = True, **unit: Any) -> dict[str, Any]:
    state = {"enabled": True, "active": "active", "load": "loaded", **unit}
    responses: dict[str, Any] = {
        "import json, subprocess, sys": [json.dumps(dict(success=True, **state))],
        **fakehost.LINUX,
        **{present(path): ["yes"] for path in paths},
    }
    for path in paths:
        responses.update(fakehost.directory(path))
    if account:
        responses.update(fakehost.system_account("homelab", HOME))
    return responses


def commands(run: Any) -> list[str]:
    return [command for command in run.executed_commands if "import json, subprocess" not in command]


def test_defaults_remove_everything_after_confirmation() -> None:
    cfg = HomelabRemoveConfig()
    assert cfg.confirm is False
    assert cfg.auto_confirm is False
    for flag in ("user", "home", "database", "media", "traefik_config"):
        assert getattr(cfg, "remove_" + flag) is True
    assert (cfg.user, cfg.service_name) == ("homelab", "homelab")
    assert (cfg.home, cfg.database_path, cfg.media_root) == (HOME, DB, MEDIA)
    assert (cfg.systemd_unit_path, cfg.traefik_config_path) == (UNIT, ROUTE)


def test_confirmation_and_inconsistent_flags_precede_every_probe() -> None:
    for cfg, message in (
        (HomelabRemoveConfig(), "set confirm"),
        (confirmed(remove_database=False), "remove_home=false"),
        (confirmed(remove_media=False, remove_home=False), "remove_user=false"),
    ):
        run = run_deploy_fake(remove_homelab, cfg)
        assert not run.succeeded
        assert message in str(run.error)
        assert not run.events
        assert not run.ops


def test_keeping_the_data_with_home_and_user_is_allowed() -> None:
    cfg = confirmed(remove_database=False, remove_media=False, remove_home=False, remove_user=False)
    run = run_deploy_fake(remove_homelab, cfg, responses=host(UNIT, ROUTE, DB, MEDIA, HOME))
    assert run.succeeded, run.error
    executed = commands(run)
    assert executed[:4] == [
        "systemctl stop homelab",
        "systemctl disable homelab",
        "rm -rf " + UNIT,
        "systemctl daemon-reload",
    ]
    assert len(executed) == 6
    assert "traefik-route-guard" in executed[4]
    assert executed[5] == "rm -rf " + ROUTE
    assert not any(DB in command or MEDIA in command or "userdel" in command for command in commands(run))


@pytest.mark.parametrize("values", [{"home": "/"}, {"home": "/home"}, {"media_root": "/home/../etc"}, {"user": "root"}])
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"removal paths|root cannot"):
        confirmed(**values)


def test_full_removal_order() -> None:
    run = run_deploy_fake(remove_homelab, confirmed(), responses=host(UNIT, ROUTE, DB, DB + "-wal", MEDIA, HOME))
    assert run.succeeded, run.error
    executed = commands(run)
    assert executed[:4] == [
        "systemctl stop homelab",
        "systemctl disable homelab",
        "rm -rf " + UNIT,
        "systemctl daemon-reload",
    ]
    assert "traefik-route-guard" in executed[4]
    assert executed[5:] == [
        "rm -rf " + ROUTE,
        "rm -rf " + DB,
        "rm -rf " + DB + "-wal",
        "rm -rf " + MEDIA,
        "userdel -r homelab",
    ]


def test_without_the_unit_the_service_tasks_are_skipped() -> None:
    run = run_deploy_fake(remove_homelab, confirmed(), responses=host(HOME))
    assert run.succeeded, run.error
    assert commands(run) == ["userdel -r homelab"]


def test_a_removed_host_changes_nothing() -> None:
    run = run_deploy_fake(remove_homelab, confirmed(), responses=host(account=False))
    assert run.succeeded, run.error
    assert commands(run) == []


def test_stop_and_disable_failures_are_ignored() -> None:
    responses = {"systemctl stop": {"success": False}, **host(UNIT, HOME)}
    run = run_deploy_fake(remove_homelab, confirmed(), responses=responses)
    assert run.error is None
    assert commands(run)[-1] == "userdel -r homelab"


def test_kept_user_with_removed_home_removes_the_directory() -> None:
    run = run_deploy_fake(remove_homelab, confirmed(remove_user=False), responses=host(HOME))
    assert run.succeeded, run.error
    assert commands(run) == ["rm -rf " + HOME]


def test_removed_user_with_kept_home_keeps_it() -> None:
    cfg = confirmed(remove_home=False)
    run = run_deploy_fake(remove_homelab, cfg, responses=host(HOME))
    assert run.succeeded, run.error
    assert commands(run) == ["userdel homelab"]


def test_data_deletion_asks_first_unless_auto_confirmed() -> None:
    cfg = HomelabRemoveConfig(confirm=True)
    with patch("sys.stdin.isatty", return_value=False):
        run = run_deploy_fake(remove_homelab, cfg, responses=host(UNIT, DB, HOME))
    assert not run.succeeded
    assert run.ops[0].name == "Remove homelab | Confirm the irreversible database and media deletion"
    assert not run.ops[0].succeeded
    assert commands(run) == []
    with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="no"):
        run = run_deploy_fake(remove_homelab, cfg, responses=host(UNIT, DB, HOME))
    assert not run.succeeded
    assert commands(run) == []
    with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="yes"):
        run = run_deploy_fake(remove_homelab, cfg, responses=host(UNIT, DB, HOME))
    assert run.succeeded, run.error
    assert "userdel -r homelab" in commands(run)


def test_no_question_without_data_to_delete() -> None:
    cfg = HomelabRemoveConfig(confirm=True)
    with patch("sys.stdin.isatty", return_value=False):
        run = run_deploy_fake(remove_homelab, cfg, responses=host(UNIT, HOME))
    assert run.succeeded, run.error
