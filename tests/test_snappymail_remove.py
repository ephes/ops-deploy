"""The snappymail_remove port; synthetic sites, pools, sockets and accounts only."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.snappymail import SnappyMailRemoveConfig, remove_snappymail
from ops_deploy.services.snappymail.remove import FIND, php_services
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/snappymail/remove"
AVAILABLE = "/etc/nginx/sites-available/snappymail"
ENABLED = "/etc/nginx/sites-enabled/snappymail"
ROUTE = "/etc/traefik/dynamic/snappymail.yml"
POOL = "/etc/php/8.3/fpm/pool.d/snappymail.conf"
SOCKET = "/run/php/php8.3-fpm-snappymail.sock"


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
    cfg = SnappyMailRemoveConfig()
    assert cfg.confirm is defaults["snappymail_confirm_removal"] is False
    assert defaults["snappymail_remove_install_dir"] == "{{ snappymail_install_dir }}"
    assert defaults["snappymail_remove_data_dir"] == "{{ snappymail_data_dir }}"
    assert cfg.install_dir == shared["snappymail_install_dir"]
    assert cfg.data_dir == shared["snappymail_data_dir"]
    assert (cfg.user, cfg.group) == (shared["snappymail_user"], shared["snappymail_group"])
    for field in ("nginx_site_path", "nginx_enabled_path", "traefik_config", "php_pools_glob", "php_socket_glob"):
        assert getattr(cfg, field) == defaults["snappymail_remove_" + field], field


def test_role_task_order_and_ignored_failures() -> None:
    tasks = role("tasks.yml")
    assert [task["name"] for task in tasks] == [
        "Fail unless removal is confirmed",
        "Find SnappyMail PHP-FPM pool configs",
        "Derive PHP-FPM services from pool paths",
        "Stop nginx (best effort)",
        "Stop Traefik (best effort)",
        "Stop PHP-FPM services (best effort)",
        "Remove nginx site (available)",
        "Remove nginx site (enabled)",
        "Remove Traefik config",
        "Remove PHP-FPM pool configs",
        "Remove PHP-FPM sockets",
        "Delete PHP-FPM sockets",
        "Remove SnappyMail install directory",
        "Remove SnappyMail data directory",
        "Remove SnappyMail system user",
        "Remove SnappyMail system group",
        "Report SnappyMail removal completion",
    ]
    ignored = [index for index, task in enumerate(tasks) if task.get("ignore_errors")]
    # The stops (not ported) and everything from the socket find on.
    assert ignored == [3, 4, 5, 10, 11, 12, 13, 14, 15]
    assert tasks[1]["ansible.builtin.find"] == {
        "paths": "/etc/php",
        "patterns": "{{ snappymail_remove_php_pools_glob | basename }}",
        "recurse": True,
        "file_type": "file",
    }
    assert tasks[10]["ansible.builtin.find"]["paths"] == "/run/php"
    assert tasks[10]["ansible.builtin.find"]["file_type"] == "any"
    assert tasks[14]["ansible.builtin.user"]["remove"] is True
    assert [(t["notify"]) for t in tasks if "notify" in t] == [
        "reload nginx",
        "reload nginx",
        "reload traefik",
        "reload php-fpm",
    ]
    handlers = role("handlers.yml")
    assert [(h["name"], h["ansible.builtin.systemd"]["state"], h["ignore_errors"]) for h in handlers] == [
        ("reload nginx", "reloaded", True),
        ("reload traefik", "reloaded", True),
        ("reload php-fpm", "reloaded", True),
    ]


def test_php_services_are_derived_from_fpm_pools_only() -> None:
    assert php_services([POOL, "/etc/php/8.4/fpm/pool.d/snappymail.conf", "/etc/php/8.3/cli/snappymail.conf"]) == [
        "php8.3-fpm",
        "php8.4-fpm",
    ]


def find(root: Path, pattern: str, kind: str) -> list[str]:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", FIND, str(root), pattern, kind],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return [path.removeprefix(str(root)) for path in json.loads(result.stdout)]


def test_find_matches_the_find_module(tmp_path: Path) -> None:
    (tmp_path / "8.3/fpm/pool.d").mkdir(parents=True)
    (tmp_path / "8.3/fpm/pool.d/snappymail.conf").write_text("pool")
    (tmp_path / "8.3/cli").mkdir(parents=True)
    (tmp_path / "8.3/cli/snappymail.conf").write_text("odd but found")
    (tmp_path / "8.3/fpm/pool.d/.snappymail.conf").write_text("hidden")
    (tmp_path / "linked").symlink_to(tmp_path / "8.3/fpm/pool.d/snappymail.conf")
    (tmp_path / "8.3/fpm/snappymail.conf").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere/snappymail.conf").symlink_to(tmp_path / "8.3/cli/snappymail.conf")
    assert find(tmp_path, "snappymail.conf", "file") == ["/8.3/cli/snappymail.conf", "/8.3/fpm/pool.d/snappymail.conf"]
    (tmp_path / "php8.3-fpm-snappymail.sock").write_text("")
    (tmp_path / "php8.3-fpm-postfixadmin.sock").write_text("")
    assert find(tmp_path, "*snappymail*.sock", "any") == ["/php8.3-fpm-snappymail.sock"]
    assert find(tmp_path / "missing", "*.sock", "any") == []


def test_confirmation_precedes_every_target_probe() -> None:
    run = run_deploy_fake(remove_snappymail, SnappyMailRemoveConfig())
    assert not run.succeeded
    assert "confirm" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize(
    "values",
    [{"install_dir": "/opt"}, {"data_dir": "/mnt/cryptdata"}, {"user": "root"}, {"php_pools_glob": "/etc/php/*;x"}],
)
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SnappyMailRemoveConfig(confirm=True, **values)


def host(*, present: bool = True, pools: Any = None, running: bool = True) -> dict[str, Any]:
    pools = [POOL] if pools is None and present else pools or []
    paths: dict[str, Any] = {}
    if present:
        paths.update(fakehost.symlink(ENABLED, AVAILABLE))
        for path in (AVAILABLE, ROUTE, POOL, SOCKET):
            paths.update(fakehost.file(path, "x"))
        for path in ("/opt/snappymail", "/mnt/cryptdata/snappymail"):
            paths.update(fakehost.directory(path, user="snappymail"))
        paths.update(fakehost.accounts({"snappymail": "/home/snappymail"}))
    return {
        **fakehost.LINUX,
        "/etc/php snappymail.conf file": [json.dumps(pools)],
        "/run/php '*snappymail*.sock' any": [json.dumps([SOCKET] if present else [])],
        **fakehost.service("nginx.service", running=running),
        **fakehost.service("php8.3-fpm.service", running=running),
        **paths,
    }


def test_the_recipes_removal_follows_the_role_order() -> None:
    run = run_deploy_fake(remove_snappymail, SnappyMailRemoveConfig(confirm=True), responses=host())
    assert run.succeeded, run.error
    assert run.executed_commands == [
        f"rm -rf {AVAILABLE}",
        f"rm -rf {ENABLED}",
        route_guard_command(),
        f"rm -rf {ROUTE}",
        f"rm -rf {POOL}",
        # The handlers right after the pool, before the sockets and the account.
        "systemctl reload nginx.service",
        "systemctl reload php8.3-fpm.service",
        f"rm -rf {SOCKET}",
        "rm -rf /opt/snappymail",
        "rm -rf /mnt/cryptdata/snappymail",
        "userdel -r snappymail",
        # The fake's group list is static; on a host userdel took the group.
        "groupdel snappymail",
    ]
    # Never stopped; Traefik is neither stopped nor reloaded.
    assert not any("systemctl stop" in command for command in run.executed_commands)
    assert not any("systemctl" in command and "traefik" in command for command in run.executed_commands)


def test_stopped_services_are_started_as_reloaded_does() -> None:
    run = run_deploy_fake(remove_snappymail, SnappyMailRemoveConfig(confirm=True), responses=host(running=False))
    assert run.succeeded, run.error
    assert run.executed_commands[5:7] == ["systemctl start nginx.service", "systemctl start php8.3-fpm.service"]


def test_a_worker_still_running_is_ended_before_userdel() -> None:
    responses = {"ps -u snappymail -o pid=": ["4242"], **host()}
    run = run_deploy_fake(remove_snappymail, SnappyMailRemoveConfig(confirm=True), responses=responses)
    assert run.succeeded, run.error
    commands = run.executed_commands
    end = "pkill -u snappymail; sleep 5; pkill -9 -u snappymail; true"
    assert commands.index(end) == commands.index("userdel -r snappymail") - 1
    assert commands.index(end) > commands.index("rm -rf /mnt/cryptdata/snappymail")


def test_a_removed_install_changes_nothing_and_starts_nothing() -> None:
    run = run_deploy_fake(
        remove_snappymail, SnappyMailRemoveConfig(confirm=True), responses=host(present=False, running=False)
    )
    assert run.succeeded, run.error
    # The role would leave nginx and Traefik stopped here; nothing is touched.
    assert run.executed_commands == []


def test_handler_failures_and_ignored_steps_do_not_fail_the_removal() -> None:
    responses = {
        "systemctl reload nginx": {"success": False},
        "userdel -r snappymail": {"success": False},
        "rm -rf /opt/snappymail": {"success": False},
        **host(),
    }
    run = run_deploy_fake(remove_snappymail, SnappyMailRemoveConfig(confirm=True), responses=responses)
    assert run.error is None
    assert "rm -rf /mnt/cryptdata/snappymail" in run.executed_commands
    assert "systemctl reload php8.3-fpm.service" in run.executed_commands


def test_an_unreadable_pool_listing_stops_before_any_change() -> None:
    responses = {**host(), "/etc/php snappymail.conf file": ["not json"]}
    run = run_deploy_fake(remove_snappymail, SnappyMailRemoveConfig(confirm=True), responses=responses)
    assert not run.succeeded
    assert "PHP-FPM pools" in str(run.error)
    assert run.executed_commands == []
