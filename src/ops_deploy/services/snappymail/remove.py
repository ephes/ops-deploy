"""Port of the ``snappymail_remove`` role: its paths, order and ignored failures.

Never dispatched without ``confirm``. The PHP-FPM pools and sockets are
found as the role's ``find`` tasks do (by base name, recursively, hidden names
skipped, links not followed; pools must be regular files), the services to
reload are derived from the pools under ``/etc/php/<version>/fpm/``.

Unlike the role, nginx, Traefik and PHP-FPM are never stopped. The role stops
all three first and relies on its ``reloaded`` handlers to start them again,
but a handler runs only when its files were removed: on a host without the
SnappyMail route (a second run) Traefik, and with it every route on the host,
stays down. Here the files go while the services run; nginx and the PHP-FPM
services are reloaded (started when down, as ``state: reloaded`` does) right
after their files were removed, before the sockets, directories and account,
with failures ignored as in the role; whatever still runs as the SnappyMail
user is then ended (SIGTERM, SIGKILL after 5 s), as the role's PHP-FPM stop
did, so ``userdel`` finds no process. Traefik is not reloaded: its file
provider drops the route, which is removed behind the Traefik transaction
guard. The handlers' end state is the role's.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Generator
from typing import Any

from pydantic import Field, StrictBool
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.server import Command
from pyinfra.operations import server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, output
from ops_deploy.services._lifecycle.ansible_remove import absent, user_absent
from ops_deploy.services._lifecycle.media_remove import Identity, ResourcePath

# ansible.builtin.find with recurse: true, hidden: false, follow: false;
# file_type "file" takes regular files only (lstat), "any" every entry.
FIND = r"""import fnmatch, json, os, stat, sys
root, pattern, kind = sys.argv[1:4]
found = []
for top, dirs, files in os.walk(root, followlinks=False):
    for name in files + dirs:
        path = os.path.join(top, name)
        if name.startswith('.') or not fnmatch.fnmatch(name, pattern):
            continue
        try:
            mode = os.lstat(path).st_mode
        except FileNotFoundError:
            continue
        if kind == 'file' and not stat.S_ISREG(mode):
            continue
        found.append(path)
print(json.dumps(sorted(found)))
"""
# The role's ``select('match', '.*/etc/php/[^/]+/fpm/.*')`` and ``regex_replace``.
_SERVICE = r"^/etc/php/([^/]+)/fpm/"


class SnappyMailRemoveConfig(RoleConfig):
    """The role's defaults plus the ``snappymail_shared`` values they derive from."""

    confirm: StrictBool = False
    install_dir: ResourcePath = "/opt/snappymail"
    data_dir: ResourcePath = "/mnt/cryptdata/snappymail"
    nginx_site_path: ResourcePath = "/etc/nginx/sites-available/snappymail"
    nginx_enabled_path: ResourcePath = "/etc/nginx/sites-enabled/snappymail"
    traefik_config: ResourcePath | None = "/etc/traefik/dynamic/snappymail.yml"
    php_pools_glob: str = Field(default="/etc/php/*/fpm/pool.d/snappymail.conf", pattern=r"^/[A-Za-z0-9*?._/-]+$")
    php_socket_glob: str = Field(default="/run/php/*snappymail*.sock", pattern=r"^/[A-Za-z0-9*?._/-]+$")
    user: Identity = "snappymail"
    group: Identity = "snappymail"


def _find(root: str, glob: str, kind: str) -> list[str] | None:
    """The paths ``find`` returns below ``root`` (none when it is missing), ``None`` when the probe failed."""

    pattern = glob.rsplit("/", 1)[1]
    raw = output(shlex.join(["/usr/bin/python3", "-I", "-B", "-c", FIND, root, pattern, kind]))
    try:
        found = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(found, list) or not all(isinstance(path, str) for path in found):
        return None
    return found


def php_services(pools: list[str]) -> list[str]:
    return [re.sub(_SERVICE + ".*$", r"php\1-fpm", path) for path in pools if re.match(_SERVICE, path)]


@operation()
def _processes_ended(user: str) -> Generator[StringCommand, None, None]:
    """SIGTERM, then after 5 s SIGKILL, to what still runs as ``user`` when this executes."""

    quoted = shlex.quote(user)
    if host.get_fact(Command, command=f"ps -u {quoted} -o pid= || true"):
        yield StringCommand(f"pkill -u {quoted}; sleep 5; pkill -9 -u {quoted}; true")


@deploy("Remove SnappyMail")
def remove_snappymail(cfg: SnappyMailRemoveConfig) -> None:
    if not cfg.confirm:
        raise DeployError("SAFETY CHECK: SnappyMail removal requires confirm=true")
    pools = _find("/etc/php", cfg.php_pools_glob, "file")
    if pools is None:
        # The role's pool find is not ignored.
        raise DeployError("Cannot list the SnappyMail PHP-FPM pools")
    services = php_services(pools)
    nginx = [
        absent("Remove nginx site (available)", cfg.nginx_site_path),
        absent("Remove nginx site (enabled)", cfg.nginx_enabled_path),
    ]
    if cfg.traefik_config:
        absent("Remove Traefik config", cfg.traefik_config)
    removed_pools = [absent(f"Remove PHP-FPM pool {path}", path) for path in pools]
    # The handlers, in their file's order, failures ignored (Traefik's not
    # ported), run here instead of at the end: nginx stops passing requests
    # to the pool and PHP-FPM drops it before the files and the account go.
    handler: dict[str, Any] = {"running": True, "reloaded": True, "_ignore_errors": True}
    systemd.service(name="Reload nginx (the role's handler)", service="nginx", _if=any_changed(*nginx), **handler)
    if removed_pools:
        for service in services:
            systemd.service(
                name=f"Reload {service} (the role's handler)",
                service=service,
                _if=any_changed(*removed_pools),
                **handler,
            )
    # find (ignore_errors) and delete each socket (ignore_errors).
    for path in _find("/run/php", cfg.php_socket_glob, "any") or []:
        absent(f"Delete PHP-FPM socket {path}", path, _ignore_errors=True)
    absent(f"Remove {cfg.install_dir}", cfg.install_dir, _ignore_errors=True)
    absent(f"Remove {cfg.data_dir}", cfg.data_dir, _ignore_errors=True)
    # The role's PHP-FPM stop ended every pool worker; a worker still
    # finishing a request after the reload would make userdel fail.
    _processes_ended(name=f"End the remaining processes of {cfg.user}", user=cfg.user, _ignore_errors=True)
    user_absent(name=f"Remove user {cfg.user}", user=cfg.user, remove_home=True, _ignore_errors=True)
    server.group(name=f"Remove group {cfg.group}", group=cfg.group, present=False, _ignore_errors=True)
