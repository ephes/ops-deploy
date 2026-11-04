"""Port of the ``mastodon_remove`` role: its defaults, order and ignored failures.

``mastodon_shared``'s paths and removal flags. Never dispatched without
``confirm``. With the defaults the units, the environment file, the Traefik
route, the nginx config and logrotate entry, the site directory (and with it
the local media under ``live/public/system``) and the account (``userdel -r``,
the whole home) go; the role keeps the nginx log directory. ``remove_media``
matters only for a media directory outside the site.
PostgreSQL, Redis and the S3 bucket are not touched, as by the role.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Self

from pydantic import StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.services._lifecycle.ansible_remove import absent, service_absent, user_absent


class MastodonRemoveConfig(RoleConfig):
    """``mastodon_shared``'s defaults for what ``mastodon_remove`` reads."""

    confirm: StrictBool = False
    user: UnixUser = "mastodon"
    group: UnixUser = "mastodon"
    site_path: AbsolutePath = "/home/mastodon/live"
    env_file: AbsolutePath = "/home/mastodon/live/.env.production"
    media_path: AbsolutePath = "/home/mastodon/live/public/system"
    services: tuple[ServiceName, ...] = ("mastodon-web", "mastodon-sidekiq", "mastodon-streaming", "mastodon-nginx")
    systemd_units: tuple[AbsolutePath, ...] = (
        "/etc/systemd/system/mastodon-web.service",
        "/etc/systemd/system/mastodon-sidekiq.service",
        "/etc/systemd/system/mastodon-streaming.service",
        "/etc/systemd/system/mastodon-nginx.service",
    )
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/mastodon.yml"
    nginx_config_path: AbsolutePath = "/etc/mastodon/nginx.conf"
    nginx_logrotate_path: AbsolutePath = "/etc/logrotate.d/mastodon-nginx"
    nginx_log_dir: AbsolutePath = "/var/log/mastodon-nginx"
    remove_site: StrictBool = True
    remove_media: StrictBool = False
    remove_env_file: StrictBool = True
    remove_traefik_config: StrictBool = True
    remove_systemd_units: StrictBool = True
    remove_nginx_config: StrictBool = True
    remove_logs: StrictBool = False
    remove_logrotate: StrictBool = True
    remove_user: StrictBool = True

    @model_validator(mode="after")
    def bounded(self) -> Self:
        paths = (
            self.site_path,
            self.env_file,
            self.media_path,
            *self.systemd_units,
            self.traefik_config_path,
            self.nginx_config_path,
            self.nginx_logrotate_path,
            self.nginx_log_dir,
        )
        for value in paths:
            path = PurePosixPath(value)
            if len(path.parts) < 3 or ".." in path.parts:
                raise ValueError("removal paths must not be root, a top-level directory or contain traversal")
        if "root" in (self.user, self.group):
            raise ValueError("root cannot be the Mastodon service account")
        return self


@deploy("Remove Mastodon")
def remove_mastodon(cfg: MastodonRemoveConfig) -> None:
    if not cfg.confirm:
        raise DeployError("Mastodon removal not confirmed. Set confirm to proceed.")
    require_linux("Mastodon removal")
    # One systemd task per unit (state: stopped, enabled: false), failures ignored.
    for service in cfg.services:
        service_absent(
            name=f"Stop and disable {service}",
            service=service,
            label="Mastodon removal",
            _ignore_errors=True,
        )
    if cfg.remove_systemd_units:
        for unit in cfg.systemd_units:
            absent(f"Remove {unit}", unit)
    # Unconditional, as in the role.
    systemd.daemon_reload(name="Reload systemd after the Mastodon unit removal")
    for path, enabled in (
        (cfg.env_file, cfg.remove_env_file),
        (cfg.traefik_config_path, cfg.remove_traefik_config),
        (cfg.nginx_config_path, cfg.remove_nginx_config),
        (cfg.nginx_logrotate_path, cfg.remove_logrotate),
        (cfg.site_path, cfg.remove_site),
        (cfg.media_path, cfg.remove_media),
        (cfg.nginx_log_dir, cfg.remove_logs),
    ):
        if enabled:
            absent(f"Remove {path}", path)
    if cfg.remove_user:
        user_absent(name=f"Remove user {cfg.user}", user=cfg.user, remove_home=True)
        server.group(name=f"Remove group {cfg.group}", group=cfg.group, present=False)
