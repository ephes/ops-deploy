"""Port of the ``paperless_remove`` role: its defaults, order and ignored failures.

Never dispatched without ``confirm``. Every ``remove_*`` flag has the role's
default; the caller turns on what it wants removed (ops-control passes the
flags of ``just remove-one paperless``). The role's paths derive from
``username``, ``site_root`` and ``external_storage_root`` as its defaults do.

Like the role: the external storage root itself, the scanner group (unless
``userdel`` of the scanner user takes it as its private group, as on Ubuntu)
and every Echoport archive stay, and sshd is not reloaded after its drop-in is
removed. Unlike the role: with ``remove_sftp_chroot`` the scanner inbox's
``/etc/fstab`` bind line (``<external_storage_root>/consume <sftp_chroot_dir>/inbox
none bind 0 0``, the line the deploy writes) is deleted right after the inbox
is unmounted; the role leaves it, and without ``nofail`` it fails the next
boot once its directories are gone. Only a line with exactly these fields
goes; every other line stays byte for byte. The route is removed
behind the Traefik transaction guard; nothing reloads Traefik (the role does
not either). The databases are dropped as ``postgres_become_user`` over the
local socket on the default port, as the role's PostgreSQL modules do.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Callable, Generator
from typing import Any, Literal

from pydantic import StrictBool, model_validator
from pyinfra import host
from pyinfra.api import DeployError, FunctionCommand, OperationError, StringCommand, deploy, operation
from pyinfra.facts.server import Command
from pyinfra.operations import server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.helpers.probes import StdinLines, probe, probe_command, probe_output
from ops_deploy.services._lifecycle.ansible_remove import absent, service_absent, user_absent
from ops_deploy.services._lifecycle.media_remove import Identity, ResourcePath, ServiceName

from .commands import host_command

# PostgreSQL identifiers the role's modules quote; plain names only here.
PgName = Identity


class PaperlessRemoveConfig(RoleConfig):
    """The role's defaults (``paperless_`` prefix dropped)."""

    confirm: StrictBool = False
    service_units: tuple[ServiceName, ...] = (
        "paperless",
        "paperless-worker",
        "paperless-scheduler",
        "paperless-consumer",
    )
    systemd_unit_dir: AbsolutePath = "/etc/systemd/system"
    remove_service_units: StrictBool = True
    traefik_config_path: ResourcePath = "/etc/traefik/dynamic/paperless.yml"
    remove_traefik_config: StrictBool = True
    scanner_sshd_config_path: ResourcePath = "/etc/ssh/sshd_config.d/sftp-scanner.conf"
    remove_scanner_config: StrictBool = True
    username: Identity = "paperless"
    group: Identity = "paperless"
    # Derived as in the role (see ``derived``): /home/<username>, <home>/site.
    home_path: ResourcePath = "/home/paperless"
    site_root: ResourcePath = "/home/paperless/site"
    temp_dir: ResourcePath = "/tmp/paperless"
    external_storage_root: ResourcePath = "/mnt/cryptdata/paperless"
    sftp_chroot_dir: ResourcePath = "/srv/sftp-scanner"
    remove_site_root: StrictBool = True
    # The role defaults both to remove_site_root (see ``derived``).
    remove_virtualenv: StrictBool = True
    remove_current_symlink: StrictBool = True
    remove_temp_dir: StrictBool = True
    remove_media_dir: StrictBool = False
    remove_data_dir: StrictBool = False
    remove_consume_dir: StrictBool = False
    remove_export_dir: StrictBool = False
    remove_backup_dir: StrictBool = False
    remove_tmp_dir: StrictBool = False
    remove_sftp_chroot: StrictBool = False
    remove_user: StrictBool = False
    remove_group: StrictBool = False
    remove_scanner_user: StrictBool = False
    scanner_username: Identity = "scanner"
    remove_postgres_database: StrictBool = False
    remove_postgres_user: StrictBool = False
    postgres_database: PgName = "paperless"
    postgres_user: PgName = "paperless"
    postgres_become_user: Identity = "postgres"

    @model_validator(mode="before")
    @classmethod
    def derived(cls, value: Any) -> Any:
        # The role's derived defaults, filled in only where the caller left them out.
        if not isinstance(value, dict):
            return value
        data = dict(value)
        data.setdefault("home_path", "/home/" + str(data.get("username", "paperless")))
        data.setdefault("site_root", str(data["home_path"]) + "/site")
        data.setdefault("remove_virtualenv", data.get("remove_site_root", True))
        data.setdefault("remove_current_symlink", data.get("remove_site_root", True))
        return data

    @property
    def scanner_inbox_path(self) -> str:
        return f"{self.sftp_chroot_dir}/inbox"

    @property
    def scanner_fstab_line(self) -> str:
        """The bind line the deploy writes (``operations.scanner_mount``)."""
        return f"{self.external_storage_root}/consume {self.scanner_inbox_path} none bind 0 0"


def _psql(cfg: PaperlessRemoveConfig, sql: str) -> str:
    # community.postgresql without login_host/port: the local socket, port 5432,
    # the maintenance database, as become_user.
    return shlex.join(
        [
            "runuser",
            "-u",
            cfg.postgres_become_user,
            "--",
            "psql",
            "-XAtq",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            "postgres",
            "-c",
            sql,
        ]
    )


def _unreadable(what: str) -> Callable[[], None]:
    def fail() -> None:
        raise OperationError(f"Cannot read the PostgreSQL {what} state")

    return fail


@operation()
def _postgres_absent(
    cfg: PaperlessRemoveConfig, kind: Literal["database", "role"], target: str
) -> Generator[StringCommand | FunctionCommand, None, None]:
    """``postgresql_db``/``postgresql_user`` with ``state: absent``: drop only what exists."""

    catalog = "pg_database where datname" if kind == "database" else "pg_roles where rolname"
    raw = host.get_fact(Command, command=probe_command(_psql(cfg, f"select 'present' from {catalog} = '{target}'")))
    state = probe_output(raw or "")
    if state is None or state.strip() not in ("", "present"):
        yield FunctionCommand(_unreadable(kind), (), {})
    elif state.strip() == "present":
        verb = "DROP DATABASE" if kind == "database" else "DROP ROLE"
        yield StringCommand(_psql(cfg, f'{verb} "{target}"'))


@operation()
def _unmounted(path: str) -> Generator[StringCommand, None, None]:
    """``mountpoint -q`` (failures ignored), then ``umount`` only when it is a mount point."""

    quoted = shlex.quote(path)
    if host.get_fact(Command, command=f"mountpoint -q {quoted} && echo mounted || true") == "mounted":
        yield StringCommand("umount", quoted)


@operation()
def _fstab_line_absent(cfg: PaperlessRemoveConfig) -> Generator[StringCommand, None, None]:
    """Delete the scanner inbox's own ``/etc/fstab`` bind line (exact fields), if it is there."""

    settings = {
        "source": f"{cfg.external_storage_root}/consume",
        "target": cfg.scanner_inbox_path,
        "apply": False,
    }
    answer = probe(
        host_command("scanner_fstab_absent"), name="Paperless scanner fstab line", stdin=json.dumps(settings)
    )
    try:
        value = json.loads(answer or "")
        if not isinstance(value, dict) or set(value) != {"change"} or type(value["change"]) is not bool:
            raise ValueError
    except ValueError:
        raise DeployError("Paperless scanner fstab line inspection failed") from None
    if value["change"]:
        settings["apply"] = True
        yield StringCommand(
            host_command("scanner_fstab_absent"), _stdin=StdinLines(json.dumps(settings)), _get_pty=False
        )


@deploy("Remove Paperless-ngx")
def remove_paperless(cfg: PaperlessRemoveConfig) -> None:
    if not cfg.confirm:
        raise DeployError("Paperless removal not confirmed (confirm=true)")
    site = cfg.site_root
    if cfg.remove_service_units:
        # One systemd task per unit (stopped and enabled: false), failures ignored.
        for unit in cfg.service_units:
            service_absent(
                name=f"Stop and disable {unit}", service=unit, label="Paperless removal", _ignore_errors=True
            )
        for unit in cfg.service_units:
            path = f"{cfg.systemd_unit_dir}/{unit}.service"
            absent(f"Remove {path}", path)
        systemd.daemon_reload(name="Reload systemd daemon")
    if cfg.remove_traefik_config:
        absent(f"Remove {cfg.traefik_config_path}", cfg.traefik_config_path)
    if cfg.remove_scanner_config:
        absent(f"Remove {cfg.scanner_sshd_config_path}", cfg.scanner_sshd_config_path)
    application: list[tuple[bool, str]] = [
        (cfg.remove_site_root, site),
        (cfg.remove_virtualenv, f"{site}/.venv"),
        (cfg.remove_current_symlink, f"{site}/paperless-ngx"),
        (cfg.remove_site_root, f"{site}/.env"),
        (cfg.remove_temp_dir, cfg.temp_dir),
    ]
    root = cfg.external_storage_root
    storage: list[tuple[bool, str]] = [
        (cfg.remove_media_dir, f"{root}/media"),
        (cfg.remove_data_dir, f"{root}/data"),
        (cfg.remove_consume_dir, f"{root}/consume"),
        (cfg.remove_export_dir, f"{root}/export"),
        (cfg.remove_backup_dir, f"{root}/backup"),
        (cfg.remove_tmp_dir, f"{root}/tmp"),
    ]
    for enabled, path in application + storage:
        if enabled:
            absent(f"Remove {path}", path)
    if cfg.remove_sftp_chroot:
        _unmounted(name=f"Unmount the scanner inbox {cfg.scanner_inbox_path}", path=cfg.scanner_inbox_path)
        _fstab_line_absent(name=f"Remove the /etc/fstab line '{cfg.scanner_fstab_line}'", cfg=cfg)
        absent(f"Remove {cfg.sftp_chroot_dir}", cfg.sftp_chroot_dir)
    if cfg.remove_user:
        user_absent(name=f"Remove user {cfg.username}", user=cfg.username, remove_home=cfg.remove_site_root)
    if cfg.remove_group:
        server.group(name=f"Remove group {cfg.group}", group=cfg.group, present=False)
    if cfg.remove_scanner_user:
        user_absent(
            name=f"Remove user {cfg.scanner_username}",
            user=cfg.scanner_username,
            remove_home=cfg.remove_sftp_chroot,
        )
    if cfg.remove_postgres_database:
        _postgres_absent(
            name=f"Drop PostgreSQL database {cfg.postgres_database}",
            cfg=cfg,
            kind="database",
            target=cfg.postgres_database,
        )
    if cfg.remove_postgres_user:
        _postgres_absent(
            name=f"Drop PostgreSQL role {cfg.postgres_user}", cfg=cfg, kind="role", target=cfg.postgres_user
        )
