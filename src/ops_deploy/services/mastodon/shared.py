"""``mastodon_shared``'s identity and paths, as the lifecycle ports read them.

The removal, backup and restore ports share these fields and defaults; the
selected-release deploy has its own config.
"""

from __future__ import annotations

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.services._lifecycle.canonical import CanonicalPath

# mastodon_systemd_services / mastodon_systemd_units with mastodon_nginx_enabled.
SERVICES: tuple[str, ...] = ("mastodon-web", "mastodon-sidekiq", "mastodon-streaming", "mastodon-nginx")
UNIT_DIR = "/etc/systemd/system"


class MastodonSite(RoleConfig):
    """``mastodon_shared``'s defaults for the account, the site and the units."""

    user: UnixUser = "mastodon"
    group: UnixUser = "mastodon"
    site_path: CanonicalPath = "/home/mastodon/live"
    env_file: CanonicalPath = "/home/mastodon/live/.env.production"
    media_path: CanonicalPath = "/home/mastodon/live/public/system"
    services: tuple[ServiceName, ...] = SERVICES
    systemd_units: tuple[CanonicalPath, ...] = tuple(f"{UNIT_DIR}/{name}.service" for name in SERVICES)
    traefik_config_path: CanonicalPath = "/etc/traefik/dynamic/mastodon.yml"
    nginx_config_path: CanonicalPath = "/etc/mastodon/nginx.conf"


__all__ = ["SERVICES", "UNIT_DIR", "MastodonSite"]
