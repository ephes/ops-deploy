"""Port of the ``homelab_remove`` role: its defaults, checks, order and ignored failures.

Destructive by default, like the role: the unit, the Traefik route, the SQLite
database (with ``-wal``/``-shm``), the media directory, the home directory and
the account go. Never dispatched without ``confirm``. The database and media
live inside the home directory, so keeping them while removing the home or the
user is refused before any probe, as the role refuses it.

Where the role pauses for ENTER before deleting an existing database or media
directory, this port asks on the controller's terminal before the first change;
without a terminal it refuses unless ``auto_confirm`` is set (the role's
``homelab_remove_auto_confirm``).
"""

from __future__ import annotations

import shlex
import sys
from pathlib import PurePosixPath
from typing import Self

from pydantic import StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import python, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.services._lifecycle.ansible_remove import absent, service_absent, user_absent


class HomelabRemoveConfig(RoleConfig):
    """``homelab_remove``'s defaults with ``homelab_shared``'s paths."""

    confirm: StrictBool = False
    auto_confirm: StrictBool = False
    user: UnixUser = "homelab"
    home: AbsolutePath = "/home/homelab"
    database_path: AbsolutePath = "/home/homelab/site/db.sqlite3"
    media_root: AbsolutePath = "/home/homelab/site/media"
    service_name: ServiceName = "homelab"
    systemd_unit_path: AbsolutePath = "/etc/systemd/system/homelab.service"
    traefik_config_path: AbsolutePath = "/etc/traefik/dynamic/homelab.yml"
    remove_user: StrictBool = True
    remove_home: StrictBool = True
    remove_database: StrictBool = True
    remove_media: StrictBool = True
    remove_traefik_config: StrictBool = True

    @model_validator(mode="after")
    def bounded(self) -> Self:
        for value in (self.home, self.database_path, self.media_root, self.systemd_unit_path, self.traefik_config_path):
            path = PurePosixPath(value)
            if len(path.parts) < 3 or ".." in path.parts:
                raise ValueError("removal paths must not be root, a top-level directory or contain traversal")
        if self.user == "root":
            raise ValueError("root cannot be the homelab service account")
        return self


def _present(path: str) -> bool:
    # ``stat`` does not follow links: a dangling symlink exists for the role.
    quoted = shlex.quote(path)
    return output(f"{{ test -e {quoted} || test -L {quoted}; }} && echo yes").strip() == "yes"


def _ask(prompt: str) -> None:
    if not sys.stdin.isatty():
        raise DeployError(f"homelab_remove: {prompt} No terminal to ask on; set auto_confirm to proceed.")
    answer = input(f"{prompt} Type 'yes' to continue: ")
    if answer.strip().lower() != "yes":
        raise DeployError("homelab_remove: aborted")


@deploy("Remove homelab")
def remove_homelab(cfg: HomelabRemoveConfig) -> None:
    # validation.yml: the confirmation, then the inconsistent combination.
    if not cfg.confirm:
        raise DeployError(
            "homelab_remove: removal blocked; set confirm to proceed. "
            "This removes the homelab service and potentially deletes data."
        )
    if (not cfg.remove_database or not cfg.remove_media) and (cfg.remove_home or cfg.remove_user):
        raise DeployError(
            f"homelab_remove: remove_database=false / remove_media=false keeps {cfg.database_path} / "
            f"{cfg.media_root}, which live inside {cfg.home}. Also set remove_home=false and "
            "remove_user=false (or take a backup first) to preserve them."
        )
    require_linux("homelab removal")
    unit_present = _present(cfg.systemd_unit_path)
    deletes_data = (cfg.remove_database and _present(cfg.database_path)) or (
        cfg.remove_media and _present(cfg.media_root)
    )
    if deletes_data and not cfg.auto_confirm:
        python.call(
            name="Confirm the irreversible database and media deletion",
            function=_ask,
            prompt="THE HOMELAB DATABASE AND/OR MEDIA WILL BE PERMANENTLY DELETED. Run `just backup homelab` first.",
        )
    # service.yml: only for an existing unit file; stop and disable ignore failures.
    if unit_present:
        service_absent(
            name=f"Stop {cfg.service_name}",
            service=cfg.service_name,
            label="homelab removal",
            disable=False,
            _ignore_errors=True,
        )
        service_absent(
            name=f"Disable {cfg.service_name}",
            service=cfg.service_name,
            label="homelab removal",
            stop=False,
            _ignore_errors=True,
        )
        absent(f"Remove {cfg.systemd_unit_path}", cfg.systemd_unit_path)
        systemd.daemon_reload(name="Reload systemd after the homelab unit removal")
    # traefik.yml
    if cfg.remove_traefik_config:
        absent(f"Remove {cfg.traefik_config_path}", cfg.traefik_config_path)
    # user.yml: the home is checked before the database goes.
    home_present = _present(cfg.home)
    if cfg.remove_database:
        for suffix in ("", "-wal", "-shm"):
            absent(f"Remove {cfg.database_path}{suffix}", cfg.database_path + suffix)
    if cfg.remove_media:
        absent(f"Remove {cfg.media_root}", cfg.media_root)
    if cfg.remove_home and home_present and not cfg.remove_user:
        absent(f"Remove {cfg.home}", cfg.home)
    if cfg.remove_user:
        user_absent(name=f"Remove user {cfg.user}", user=cfg.user, remove_home=cfg.remove_home)
