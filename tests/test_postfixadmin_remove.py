"""The postfixadmin_remove port; synthetic sites, pools and services only."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.postfixadmin import PostfixAdminRemoveConfig, remove_postfixadmin
from ops_deploy.services.postfixadmin.remove import PHP_VERSION
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/postfixadmin/remove"
ENABLED = "/etc/nginx/sites-enabled/postfixadmin"
AVAILABLE = "/etc/nginx/sites-available/postfixadmin"
ROUTE = "/etc/traefik/dynamic/postfixadmin.yml"
POOL = "/etc/php/8.3/fpm/pool.d/postfixadmin.conf"


def role(name: str) -> Any:
    return yaml.safe_load((PARITY / name).read_text())


def test_fixtures_are_the_recorded_role_files() -> None:
    manifest = json.loads((PARITY / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (PARITY / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / entry["source"]).read_bytes()


def test_defaults_are_the_roles() -> None:
    defaults = role("defaults.yml")
    shared = role("shared_defaults.yml")
    cfg = PostfixAdminRemoveConfig()
    assert cfg.confirm is defaults["postfixadmin_remove_confirm"] is False
    for field in ("application", "nginx_config", "traefik_config", "php_pool", "backups"):
        assert getattr(cfg, "remove_" + field) is defaults["postfixadmin_remove_" + field], field
    for field in ("install_path", "traefik_config_path", "backup_path"):
        assert getattr(cfg, field) == shared["postfixadmin_" + field], field
    # Not ported: the opt-in table drops stay off, as by default.
    assert defaults["postfixadmin_remove_admin_tables"] is False
    assert defaults["postfixadmin_remove_mail_tables"] is False
    assert "remove_admin_tables" not in PostfixAdminRemoveConfig.model_fields


def test_role_task_order_and_handlers_are_the_ported_ones() -> None:
    tasks = role("tasks.yml")
    names = [task["name"] for task in tasks]
    assert names == [
        "Require confirmation for removal",
        "Warn about mail table removal",
        "Remove nginx configuration",
        "Remove Traefik configuration",
        "Detect PHP version for pool removal",
        "Remove PHP-FPM pool",
        "Remove PostfixAdmin application directory",
        "Remove PostfixAdmin admin tables",
        "Remove PostfixAdmin mail tables (DESTRUCTIVE)",
        "Remove backup directory",
        "Flush handlers",
        "Report removal completion",
    ]
    nginx = tasks[2]["block"]
    assert [task["ansible.builtin.file"]["path"] for task in nginx] == [ENABLED, AVAILABLE]
    assert nginx[0]["notify"] == "reload nginx"
    assert "notify" not in nginx[1]
    assert tasks[4]["ansible.builtin.command"] == PHP_VERSION
    assert tasks[5]["ansible.builtin.file"]["path"] == (
        "/etc/php/{{ php_version_detect.stdout | default('8.3') }}/fpm/pool.d/postfixadmin.conf"
    )
    assert tasks[5]["when"] == ["postfixadmin_remove_php_pool | bool", "php_version_detect.rc == 0"]
    assert tasks[7]["when"] == "postfixadmin_remove_admin_tables | bool"
    assert tasks[8]["when"] == "postfixadmin_remove_mail_tables | bool"
    handlers = role("handlers.yml")
    assert [(h["name"], h["ansible.builtin.service"]["state"]) for h in handlers] == [
        ("reload nginx", "reloaded"),
        ("reload traefik", "reloaded"),
        ("restart php-fpm", "restarted"),
    ]
    assert not any(h.get("ignore_errors") for h in handlers)


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
