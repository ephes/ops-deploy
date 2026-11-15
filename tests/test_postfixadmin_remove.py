"""The postfixadmin_remove port; synthetic sites, pools and services only."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.postfixadmin import PostfixAdminRemoveConfig, remove_postfixadmin
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

ENABLED = "/etc/nginx/sites-enabled/postfixadmin"
AVAILABLE = "/etc/nginx/sites-available/postfixadmin"
ROUTE = "/etc/traefik/dynamic/postfixadmin.yml"
POOL = "/etc/php/8.3/fpm/pool.d/postfixadmin.conf"


def test_defaults() -> None:
    assert PostfixAdminRemoveConfig().model_dump(mode="json") == {
        "backup_path": "/mnt/cryptdata/backups/postfixadmin",
        "confirm": False,
        "install_path": "/opt/postfixadmin",
        "remove_application": True,
        "remove_backups": False,
        "remove_nginx_config": True,
        "remove_php_pool": True,
        "remove_traefik_config": True,
        "traefik_config_path": "/etc/traefik/dynamic/postfixadmin.yml",
    }


def test_confirmation_precedes_every_target_probe() -> None:
    run = run_deploy_fake(remove_postfixadmin, PostfixAdminRemoveConfig())
    assert not run.succeeded
    assert "explicit confirmation" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize("values", [{"install_path": "/opt"}, {"install_path": "/opt/../etc"}, {"backup_path": "/"}])
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        PostfixAdminRemoveConfig(confirm=True, **values)


def host(*, present: bool = True, php: str = "8.3", running: bool = True) -> dict[str, Any]:
    paths: dict[str, Any] = {}
    if present:
        paths.update(fakehost.symlink(ENABLED, AVAILABLE))
        for path in (AVAILABLE, ROUTE, POOL):
            paths.update(fakehost.file(path, "x"))
        paths.update(fakehost.directory("/opt/postfixadmin", user="www-data"))
        paths.update(fakehost.directory("/mnt/cryptdata/backups/postfixadmin"))
    return {
        **fakehost.LINUX,
        "command -v php": [php] if php else [],
        **fakehost.service("nginx.service", running=running),
        **fakehost.service(f"php{php}-fpm.service", running=running),
        **paths,
    }


def test_the_role_defaults_and_their_handlers() -> None:
    run = run_deploy_fake(remove_postfixadmin, PostfixAdminRemoveConfig(confirm=True), responses=host())
    assert run.succeeded, run.error
    assert run.executed_commands == [
        f"rm -rf {ENABLED}",
        f"rm -rf {AVAILABLE}",
        route_guard_command(),
        f"rm -rf {ROUTE}",
        f"rm -rf {POOL}",
        "rm -rf /opt/postfixadmin",
        "systemctl reload nginx.service",
        "systemctl restart php8.3-fpm.service",
    ]
    # No database connection, no Traefik reload, the backups stay.
    commands = "\n".join(run.executed_commands)
    assert "psql" not in commands
    assert "/mnt/cryptdata/backups" not in commands
    assert not any("systemctl" in command and "traefik" in command for command in run.executed_commands)


def test_stopped_services_are_started_as_reloaded_and_restarted_do() -> None:
    run = run_deploy_fake(remove_postfixadmin, PostfixAdminRemoveConfig(confirm=True), responses=host(running=False))
    assert run.succeeded, run.error
    assert run.executed_commands[-2:] == ["systemctl start nginx.service", "systemctl start php8.3-fpm.service"]


def test_remove_backups_removes_the_backup_directory() -> None:
    run = run_deploy_fake(
        remove_postfixadmin, PostfixAdminRemoveConfig(confirm=True, remove_backups=True), responses=host()
    )
    assert run.succeeded, run.error
    assert run.executed_commands.index("rm -rf /mnt/cryptdata/backups/postfixadmin") == 6


def test_without_php_the_pool_and_its_restart_are_skipped() -> None:
    run = run_deploy_fake(remove_postfixadmin, PostfixAdminRemoveConfig(confirm=True), responses=host(php=""))
    assert run.succeeded, run.error
    assert not any("php" in command for command in run.executed_commands)


def test_a_removed_install_changes_nothing() -> None:
    run = run_deploy_fake(remove_postfixadmin, PostfixAdminRemoveConfig(confirm=True), responses=host(present=False))
    assert run.succeeded, run.error
    assert run.executed_commands == []
