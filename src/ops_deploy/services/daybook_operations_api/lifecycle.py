"""Operations API backup, restore and removal (the ``daybook_operations_api_{backup,restore,remove}`` roles).

The archive format belongs to Daybook: ``services/operations_api/lifecycle.py``
in the installed site writes and reads it (a mode-0600 tar of the custom-format
database dump, the server environment, ``profiles.json`` and a SHA-256
manifest). These deploys only call that tool as the service account, exactly as
the roles do, so either tool restores the other's archives.

- Backup: the ``0700`` backup root owned by the service account, then
  ``lifecycle.py backup`` to ``<root>/<UTC %Y%m%dT%H%M%S%fZ>.tar`` (or the given
  ``archive``). The path is printed; nothing is fetched or pruned, as with the
  role.
- Restore: refused unless ``confirmed`` and ``clients_quiesced`` are set and the
  archive is an absolute path (``validate_only`` needs the path only, see
  below). ``lifecycle.py validate`` runs before either unit is touched; then
  both units are stopped and disabled and ``lifecycle.py restore
  --clients-quiesced`` runs (it writes its own safety backup and rolls back on
  failure). Both units stay stopped, as with the role.
- Remove: refused unless ``confirmed`` and ``clients_quiesced`` are set. Stops
  and disables the units that exist, removes the two unit files and the Traefik
  route, and keeps the database, account, site, configuration and every backup.

Deliberate differences from the roles:

- ``validate_only`` (``just pyinfra-restore ... DRY_RUN=true``, ops-control's
  ``just restore-check``) runs only ``lifecycle.py validate`` (it unpacks the
  archive into a temporary directory below the backup root, checks the
  manifest and removes the directory) and stops before the units; the role has
  no such mode. It needs the archive's absolute path but neither
  confirmation: those guard the stop and the restore it never reaches.
- ``required_mount`` (ops-control sets macmini's ``/opt/backups``) stops a
  backup before its first write when the backup root is not on that mount.
- The removal reloads systemd only when it removed a unit file, so a second
  removal changes nothing; the role reloads on every run.
- The Traefik route is removed only while no Traefik transaction holds its
  lock, like every route writer on the host.
"""

from __future__ import annotations

import shlex
from datetime import UTC, datetime
from pathlib import PurePosixPath

from pydantic import StrictBool, model_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import files, python, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.base._units import ACTIVE, ENABLED, unit_states
from ops_deploy.core.config import UnixUser
from ops_deploy.services._lifecycle import exists
from ops_deploy.services._lifecycle.local_backup import MountGuard, mount_check
from ops_deploy.services._traefik_routes import route_absent

UNITS = ("daybook-operations", "daybook-operations-reconcile")
UNIT_DIR = "/etc/systemd/system"
STAMP_FORMAT = "%Y%m%dT%H%M%S%fZ"
# ``systemctl stop`` also waits for a unit that is still shutting down, so
# nothing of it runs while the restore or removal goes on.
STOPPABLE = ACTIVE | {"deactivating"}


class _Tool(RoleConfig):
    """The installed lifecycle tool and the account it runs as (the roles' defaults)."""

    user: UnixUser = "daybook-operations"
    python: AbsolutePath = "/home/daybook-operations/venv/bin/python"
    script: AbsolutePath = "/home/daybook-operations/site/services/operations_api/lifecycle.py"
    config: AbsolutePath = "/etc/daybook-operations/lifecycle.json"

    def command(self, action: str, archive: str, *extra: str) -> str:
        argv = [self.python, self.script, action, *extra, "--config", self.config, "--archive", archive]
        return shlex.join(["runuser", "-u", self.user, "--", *argv])


class OperationsApiBackupConfig(_Tool, MountGuard):
    root: AbsolutePath = "/opt/backups/daybook_operations"
    # Empty: a new ``<root>/<UTC timestamp>.tar``.
    archive: AbsolutePath | None = None

    def guarded_paths(self) -> dict[str, str]:
        paths = {"root": self.root}
        if self.archive:
            paths["archive"] = self.archive
        return paths

    def destination(self, now: datetime | None = None) -> str:
        if self.archive:
            return self.archive
        return f"{self.root}/{(now or datetime.now(UTC)).strftime(STAMP_FORMAT)}.tar"


class OperationsApiRestoreConfig(_Tool):
    archive: str = ""
    confirmed: StrictBool = False
    clients_quiesced: StrictBool = False
    validate_only: StrictBool = False


class OperationsApiRemoveConfig(RoleConfig):
    confirmed: StrictBool = False
    clients_quiesced: StrictBool = False
    traefik_path: AbsolutePath = "/etc/traefik/dynamic/daybook-operations.yml"

    @model_validator(mode="after")
    def _route_file(self) -> OperationsApiRemoveConfig:
        if PurePosixPath(self.traefik_path).suffix != ".yml":
            raise ValueError("traefik_path must name the route's .yml file")
        return self


def _stop_disable(units: tuple[str, ...], purpose: str) -> None:
    """Ansible ``systemd_service: state=stopped enabled=false``: disable, then stop.

    Read from ``ActiveState``, so a unit waiting in ``auto-restart`` (its
    ``Restart=on-failure`` pending, ActiveState ``activating``) is stopped too,
    and one still ``deactivating`` is waited for;
    pyinfra's ``SubState``-based check would leave that restart pending. A
    failing ``systemctl`` fails the run, as it fails the role.
    """

    states = unit_states(list(units))
    for unit in units:
        quoted = shlex.quote(f"{unit}.service")
        if states[unit].get("UnitFileState") in ENABLED:
            server.shell(name=f"Disable {unit} {purpose}", commands=[f"systemctl disable {quoted}"])
        if states[unit].get("ActiveState") in STOPPABLE:
            server.shell(name=f"Stop {unit} {purpose}", commands=[f"systemctl stop {quoted}"])


def _print_archive(path: str) -> None:
    print(path)


@deploy("Daybook Operations API backup")
def deploy_daybook_operations_api_backup(cfg: OperationsApiBackupConfig) -> None:
    destination = cfg.destination()
    if cfg.required_mount:
        server.shell(
            name="Check the backup root is on its mount",
            commands=[mount_check(cfg.required_mount, cfg.root, destination)],
            _shell_executable="bash",
        )
    files.directory(name="Create protected backup directory", path=cfg.root, user=cfg.user, group=cfg.user, mode="0700")
    server.shell(
        name="Back up database with replay keyring and profile configuration",
        commands=[cfg.command("backup", destination)],
    )
    python.call(name="Report protected archive location", function=_print_archive, path=destination)


@deploy("Daybook Operations API restore")
def deploy_daybook_operations_api_restore(cfg: OperationsApiRestoreConfig) -> None:
    if cfg.validate_only:
        # Validation reads the archive only; the confirmations guard the stop
        # and the restore below, which a validation never reaches.
        if not cfg.archive.startswith("/"):
            raise DeployError("Name the archive by its absolute path to validate it (there is no 'latest').")
        server.shell(name="Validate the archive (no service change)", commands=[cfg.command("validate", cfg.archive)])
        return
    if not (cfg.confirmed and cfg.clients_quiesced and cfg.archive.startswith("/")):
        raise DeployError("Quiesce every client and explicitly confirm this archive before restoring.")
    server.shell(name="Validate before stopping services", commands=[cfg.command("validate", cfg.archive)])
    _stop_disable(UNITS, "before the unprivileged restore")
    server.shell(
        name="Restore with safety backup and leave both services stopped",
        commands=[cfg.command("restore", cfg.archive, "--clients-quiesced")],
    )


@deploy("Daybook Operations API remove")
def deploy_daybook_operations_api_remove(cfg: OperationsApiRemoveConfig) -> None:
    if not (cfg.confirmed and cfg.clients_quiesced):
        raise DeployError("Quiesce clients and confirm removal; database and replay evidence are retained.")
    # Like service_facts: only units systemd knows (a missing one is not-found).
    states = unit_states(list(UNITS))
    _stop_disable(tuple(u for u in UNITS if states[u].get("LoadState") not in {None, "", "not-found"}), "for removal")
    removed = [
        files.file(name=f"Remove {path}", path=path, present=False)
        for path in (f"{UNIT_DIR}/{unit}.service" for unit in UNITS)
        if exists(path)
    ]
    if exists(cfg.traefik_path):
        route_absent(name=f"Remove {cfg.traefik_path}", path=cfg.traefik_path)
    if removed:
        systemd.daemon_reload(name="Reload systemd")
