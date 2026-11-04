"""Port of the ``postfixadmin_remove`` role with its defaults.

Never dispatched without ``confirm``. The role's defaults remove the nginx
site, the Traefik route, the PHP-FPM pool and ``install_path`` and keep every
database table, the backup directory and the mail data (the Postfix/Dovecot
tables stay in use). ``remove_backups`` is ported; the role's opt-in table
drops (``postfixadmin_remove_admin_tables``/``_mail_tables``) are not, and the
removal never connects to PostgreSQL.

Handlers as the role's ``flush_handlers``: nginx is reloaded (started when it
is down, as ``service: state=reloaded``) after the enabled site went, and the
PHP-FPM service of the detected version is restarted after its pool went.
Unlike the role, Traefik is not reloaded: its unit has no ``ExecReload``, so
the role's handler fails, which also skips the PHP-FPM restart after it; the
file provider drops the route. The route is removed behind the Traefik
transaction guard.
"""

from __future__ import annotations

import re

from pydantic import StrictBool
from pyinfra.api import DeployError, deploy
from pyinfra.operations import systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, output
from ops_deploy.services._lifecycle.ansible_remove import absent
from ops_deploy.services._lifecycle.media_remove import ResourcePath

# The role's version probe; its output is used only when it looks like one.
PHP_VERSION = "php -r 'printf(\"%s.%s\", PHP_MAJOR_VERSION, PHP_MINOR_VERSION);'"
_VERSION = re.compile(r"[0-9]+\.[0-9]+")


class PostfixAdminRemoveConfig(RoleConfig):
    """The role's defaults plus the ``postfixadmin_shared`` paths it reads (prefix dropped)."""

    confirm: StrictBool = False
    remove_application: StrictBool = True
    remove_nginx_config: StrictBool = True
    remove_traefik_config: StrictBool = True
    remove_php_pool: StrictBool = True
    remove_backups: StrictBool = False
    install_path: ResourcePath = "/opt/postfixadmin"
    traefik_config_path: ResourcePath = "/etc/traefik/dynamic/postfixadmin.yml"
    backup_path: ResourcePath = "/mnt/cryptdata/backups/postfixadmin"


def php_version() -> str | None:
    """``php -r`` (failures ignored): the version, or ``None`` when php is missing or fails."""

    found = output(f"command -v php >/dev/null 2>&1 && {PHP_VERSION}").strip()
    return found if _VERSION.fullmatch(found) else None


@deploy("Remove PostfixAdmin")
def remove_postfixadmin(cfg: PostfixAdminRemoveConfig) -> None:
    if not cfg.confirm:
        raise DeployError("PostfixAdmin removal requires explicit confirmation (confirm=true)")
    nginx_site = None
    if cfg.remove_nginx_config:
        nginx_site = absent("Disable nginx site", "/etc/nginx/sites-enabled/postfixadmin")
        absent("Remove nginx site configuration", "/etc/nginx/sites-available/postfixadmin")
    if cfg.remove_traefik_config:
        absent(f"Remove {cfg.traefik_config_path}", cfg.traefik_config_path)
    pool = None
    version = php_version() if cfg.remove_php_pool else None
    if version is not None:
        pool = absent("Remove PHP-FPM pool", f"/etc/php/{version}/fpm/pool.d/postfixadmin.conf")
    if cfg.remove_application:
        absent(f"Remove {cfg.install_path}", cfg.install_path)
    if cfg.remove_backups:
        absent(f"Remove {cfg.backup_path}", cfg.backup_path)
    # flush_handlers, in the handlers file's order (Traefik's not ported).
    if nginx_site is not None:
        systemd.service(
            name="Reload nginx (the role's handler)",
            service="nginx",
            running=True,
            reloaded=True,
            _if=any_changed(nginx_site),
        )
    if pool is not None:
        systemd.service(
            name=f"Restart php{version}-fpm (the role's handler)",
            service=f"php{version}-fpm",
            running=True,
            restarted=True,
            _if=any_changed(pool),
        )
