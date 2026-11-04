"""The mastodon_remove port; synthetic units, files and accounts only."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.services.mastodon import MastodonRemoveConfig, remove_mastodon
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PARITY = Path(__file__).parent / "parity/mastodon/remove"
SERVICES = ["mastodon-web", "mastodon-sidekiq", "mastodon-streaming", "mastodon-nginx"]
UNITS = [f"/etc/systemd/system/{name}.service" for name in SERVICES]
ROUTE = "/etc/traefik/dynamic/mastodon.yml"


def role(name: str) -> Any:
    return yaml.safe_load((PARITY / name).read_text())


def confirmed(**values: Any) -> MastodonRemoveConfig:
    return MastodonRemoveConfig(confirm=True, **values)


def host(*paths: str, account: bool = True, load: str = "loaded") -> dict[str, Any]:
    observed = dict(success=load != "not-found", enabled=True, active="active", load=load)
    responses: dict[str, Any] = {"import json, subprocess, sys": [json.dumps(observed)], **fakehost.LINUX}
    for path in paths:
        responses.update(fakehost.directory(path))
    if account:
        responses.update(fakehost.system_account("mastodon", "/home/mastodon"))
    return responses


def commands(run: Any) -> list[str]:
    return [command for command in run.executed_commands if "import json, subprocess" not in command]


def test_fixtures_are_the_recorded_role_files() -> None:
    manifest = json.loads((PARITY / "source.json").read_text())
    for name, entry in manifest["files"].items():
        body = (PARITY / name).read_bytes()
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        if os.environ.get("OPS_LIBRARY_PATH"):
            assert body == (Path(os.environ["OPS_LIBRARY_PATH"]) / entry["source"]).read_bytes()


def test_defaults_are_the_shared_roles() -> None:
    shared = role("shared-defaults.yml")
    assert role("defaults.yml") is None  # mastodon_remove keeps its defaults in mastodon_shared
    cfg = MastodonRemoveConfig()
    assert cfg.confirm is shared["mastodon_confirm_removal"] is False
    for flag in (
        "site",
        "media",
        "env_file",
        "traefik_config",
        "systemd_units",
        "nginx_config",
        "logs",
        "logrotate",
        "user",
    ):
        assert getattr(cfg, "remove_" + flag) is shared["mastodon_remove_" + flag]
    assert (cfg.user, cfg.group) == (shared["mastodon_user"], shared["mastodon_group"])
    assert shared["mastodon_home_path"] == "/home/{{ mastodon_user }}"
    assert shared["mastodon_site_path"] == "{{ mastodon_home_path }}/live"
    assert shared["mastodon_env_file"] == "{{ mastodon_site_path }}/.env.production"
    assert shared["mastodon_media_path"] == "{{ mastodon_site_path }}/public/system"
    assert (cfg.site_path, cfg.env_file, cfg.media_path) == (
        "/home/mastodon/live",
        "/home/mastodon/live/.env.production",
        "/home/mastodon/live/public/system",
    )
    assert shared["mastodon_nginx_enabled"] is True
    names = [shared[f"mastodon_{kind}_service_name"] for kind in ("web", "sidekiq", "streaming", "nginx")]
    assert list(cfg.services) == names == SERVICES
    assert shared["mastodon_systemd_unit_dir"] == "/etc/systemd/system"
    assert list(cfg.systemd_units) == UNITS
    assert cfg.traefik_config_path == shared["mastodon_traefik_config_path"] == ROUTE
    assert shared["mastodon_nginx_conf_dir"] == "/etc/mastodon"
    assert cfg.nginx_config_path == "/etc/mastodon/nginx.conf"
    assert cfg.nginx_logrotate_path == shared["mastodon_nginx_logrotate_path"]
    assert cfg.nginx_log_dir == shared["mastodon_nginx_log_dir"]


def test_role_task_order_is_the_ported_one() -> None:
    tasks = role("tasks.yml")
    modules = [next(key for key in task if key.startswith("ansible.")) for task in tasks]
    assert modules == [
        "ansible.builtin.assert",
        "ansible.builtin.systemd",  # stop + disable, failed_when: false
        "ansible.builtin.file",  # units
        "ansible.builtin.systemd",  # daemon_reload, unconditional
        "ansible.builtin.file",  # env
        "ansible.builtin.file",  # traefik
        "ansible.builtin.file",  # nginx config
        "ansible.builtin.file",  # logrotate
        "ansible.builtin.file",  # site
        "ansible.builtin.file",  # media
        "ansible.builtin.file",  # nginx logs
        "ansible.builtin.user",
        "ansible.builtin.group",
        "ansible.builtin.debug",
    ]
    assert tasks[1]["ansible.builtin.systemd"] == {"name": "{{ item }}", "state": "stopped", "enabled": False}
    assert tasks[1]["failed_when"] is False
    assert "when" not in tasks[3]
    assert [task["when"] for task in tasks[4:11]] == [
        "mastodon_remove_env_file | bool",
        "mastodon_remove_traefik_config | bool",
        "mastodon_remove_nginx_config | bool",
        "mastodon_remove_logrotate | bool",
        "mastodon_remove_site | bool",
        "mastodon_remove_media | bool",
        "mastodon_remove_logs | bool",
    ]
    assert tasks[11]["ansible.builtin.user"]["remove"] is True


def test_confirmation_precedes_every_probe() -> None:
    run = run_deploy_fake(remove_mastodon, MastodonRemoveConfig())
    assert not run.succeeded
    assert "not confirmed" in str(run.error)
    assert not run.events
    assert not run.ops


@pytest.mark.parametrize(
    "values", [{"site_path": "/"}, {"site_path": "/home"}, {"env_file": "/home/../etc/x"}, {"user": "root"}]
)
def test_unsafe_targets_are_refused(values: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"removal paths|root cannot|canonical absolute path"):
        confirmed(**values)


def test_full_removal_follows_the_role_order() -> None:
    cfg = confirmed()
    paths = (*UNITS, cfg.env_file, ROUTE, cfg.nginx_config_path, cfg.nginx_logrotate_path, cfg.site_path)
    run = run_deploy_fake(remove_mastodon, cfg, responses=host(*paths, cfg.media_path, cfg.nginx_log_dir))
    assert run.succeeded, run.error
    executed = commands(run)
    stops = [command for name in SERVICES for command in (f"systemctl disable {name}", f"systemctl stop {name}")]
    assert executed[:8] == stops
    assert executed[8:12] == [f"rm -rf {unit}" for unit in UNITS]
    assert executed[12] == "systemctl daemon-reload"
    assert executed[13] == f"rm -rf {cfg.env_file}"
    assert "traefik-route-guard" in executed[14]
    # The media lives under the site directory, so it goes with it (remove_site);
    # the nginx logs stay (role default); the home goes with userdel -r.
    assert executed[15:] == [
        f"rm -rf {ROUTE}",
        f"rm -rf {cfg.nginx_config_path}",
        f"rm -rf {cfg.nginx_logrotate_path}",
        f"rm -rf {cfg.site_path}",
        "userdel -r mastodon",
        "groupdel mastodon",
    ]


def test_opted_in_media_and_logs_go_and_kept_units_stay() -> None:
    cfg = confirmed(remove_media=True, remove_logs=True, remove_systemd_units=False, remove_user=False)
    run = run_deploy_fake(remove_mastodon, cfg, responses=host(*UNITS, cfg.media_path, cfg.nginx_log_dir))
    assert run.succeeded, run.error
    executed = commands(run)
    assert not any(unit in command for unit in UNITS for command in executed)
    assert executed[-3:] == ["systemctl daemon-reload", f"rm -rf {cfg.media_path}", f"rm -rf {cfg.nginx_log_dir}"]


def test_a_removed_host_changes_only_the_unconditional_reload() -> None:
    run = run_deploy_fake(remove_mastodon, confirmed(), responses=host(account=False, load="not-found"))
    # The systemd task fails on absent units; the role ignores that.
    assert run.error is None
    assert commands(run) == ["systemctl daemon-reload"]


def test_a_failed_userdel_stops_the_removal() -> None:
    responses = {"userdel": {"success": False}, **host()}
    run = run_deploy_fake(remove_mastodon, confirmed(), responses=responses)
    assert not run.succeeded
    assert "groupdel" not in "\n".join(commands(run))
