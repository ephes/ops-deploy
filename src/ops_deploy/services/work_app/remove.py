"""work_app removal (the ``work_app_remove`` role).

Destructive by default, like the role: the service, unit, Traefik config,
database, home directory, user and group all go, and ``confirm`` must be set.
The database lives inside the home directory, so keeping it means keeping the
home and the user too (``remove_database=False`` together with
``remove_home``/``remove_user`` is refused). A second run finds nothing left.

Where the role pauses for ENTER before deleting a database, this module asks
on the controller's terminal during the run (before the first change); without
a terminal it refuses unless ``auto_confirm`` is set.
"""

from __future__ import annotations

import shlex
import sys

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import File
from pyinfra.facts.server import Users
from pyinfra.operations import files, python, server

from ops_deploy.base._common import output
from ops_deploy.helpers.traefik import route_absent
from ops_deploy.services.work_app._lifecycle import WorkAppPaths


class WorkAppRemoveConfig(WorkAppPaths):
    remove_user: bool = True
    remove_home: bool = True
    remove_database: bool = True
    remove_traefik_config: bool = True
    # Required for any removal.
    confirm: bool = False
    # Skip the question asked before the database is deleted.
    auto_confirm: bool = False


def _exists(path: str) -> bool:
    return output(f"test -e {shlex.quote(path)} && echo yes").strip() == "yes"


def _ask(prompt: str) -> None:
    if not sys.stdin.isatty():
        raise DeployError(f"work_app_remove: {prompt} No terminal to ask on; set auto_confirm to proceed.")
    answer = input(f"{prompt} Type 'yes' to continue: ")
    if answer.strip().lower() != "yes":
        raise DeployError("work_app_remove: aborted")


@deploy("work_app remove")
def deploy_work_app_remove(cfg: WorkAppRemoveConfig) -> None:
    """Stop and remove the work app, its route and, as configured, its data and user."""

    if not cfg.confirm:
        raise DeployError(
            "work_app_remove: removal blocked; set confirm to proceed. "
            "This removes the work app service and potentially deletes data."
        )
    if not cfg.remove_database and (cfg.remove_home or cfg.remove_user):
        raise DeployError(
            f"work_app_remove: remove_database=false keeps {cfg.database_path}, which lives inside {cfg.home}; "
            "also set remove_home=false and remove_user=false (or take a backup first) to preserve it."
        )
    unit_present = _exists(cfg.unit_path)
    database_present = _exists(cfg.database_path)
    home_present = _exists(cfg.home)
    user_present = cfg.user in host.get_fact(Users)

    if cfg.remove_database and database_present and not cfg.auto_confirm:
        python.call(
            name="Confirm the irreversible database deletion",
            function=_ask,
            prompt=(
                f"THE DATABASE {cfg.database_path} WILL BE PERMANENTLY DELETED. Run a backup first if you have not."
            ),
        )

    unit = shlex.quote(cfg.unit)
    if unit_present:
        # As the role, a unit that cannot be stopped or disabled does not stop the removal.
        server.shell(name="Stop work-app", commands=[f"systemctl stop {unit} || true"])
        server.shell(name="Disable work-app", commands=[f"systemctl disable {unit} || true"])
        files.file(name=f"Remove {cfg.unit_path}", path=cfg.unit_path, present=False)
        server.shell(name="Reload systemd", commands=["systemctl daemon-reload"])
    if cfg.remove_traefik_config and host.get_fact(File, path=cfg.traefik_config_path):
        route_absent(name=f"Remove {cfg.traefik_config_path}", path=cfg.traefik_config_path)
    if cfg.remove_database and home_present:
        for suffix in ("", "-wal", "-shm"):
            path = cfg.database_path + suffix
            if _exists(path):
                files.file(name=f"Remove {path}", path=path, present=False)
    if cfg.remove_home and home_present and not (cfg.remove_user and user_present):
        # The user module removes the home directory with the user; without one
        # (kept, or already gone) it is removed here.
        files.directory(name=f"Remove {cfg.home}", path=cfg.home, present=False)
    if cfg.remove_user and user_present:
        flag = "-r " if cfg.remove_home else ""
        script = f"userdel {flag}{shlex.quote(cfg.user)}"
        if cfg.remove_home:
            # userdel -r must have taken the home directory with it.
            script += f" && [ ! -e {shlex.quote(cfg.home)} ]"
        server.shell(name=f"Remove user {cfg.user}", commands=[script])
    if cfg.remove_user and output(f"getent group {shlex.quote(cfg.group)}").strip():
        # userdel already drops a user's private group.
        group = shlex.quote(cfg.group)
        server.shell(
            name=f"Remove group {cfg.group}",
            commands=[f"if getent group {group} >/dev/null; then groupdel {group}; fi"],
        )
