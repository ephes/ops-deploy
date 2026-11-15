"""The mastodon_remove port; synthetic units, files and accounts only."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ops_deploy.services.mastodon import MastodonRemoveConfig, remove_mastodon
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

SERVICES = ["mastodon-web", "mastodon-sidekiq", "mastodon-streaming", "mastodon-nginx"]
UNITS = [f"/etc/systemd/system/{name}.service" for name in SERVICES]
ROUTE = "/etc/traefik/dynamic/mastodon.yml"


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


def test_defaults_keep_media_and_logs() -> None:
    cfg = MastodonRemoveConfig()
    assert cfg.confirm is False
    removed = ("site", "env_file", "traefik_config", "systemd_units", "nginx_config", "logrotate", "user")
    assert all(getattr(cfg, "remove_" + flag) is True for flag in removed)
    assert cfg.remove_media is False
    assert cfg.remove_logs is False
    assert (cfg.user, cfg.group) == ("mastodon", "mastodon")
    assert (cfg.site_path, cfg.env_file, cfg.media_path) == (
        "/home/mastodon/live",
        "/home/mastodon/live/.env.production",
        "/home/mastodon/live/public/system",
    )
    assert list(cfg.services) == SERVICES
    assert list(cfg.systemd_units) == UNITS
    assert cfg.traefik_config_path == ROUTE
    assert cfg.nginx_config_path == "/etc/mastodon/nginx.conf"
    assert cfg.nginx_logrotate_path == "/etc/logrotate.d/mastodon-nginx"
    assert cfg.nginx_log_dir == "/var/log/mastodon-nginx"


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
