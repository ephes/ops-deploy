"""fail2ban for sshd and an sshd hardening drop-in (the ``ssh_guard_deploy`` role).

Both files are byte-identical to the role's templates, header included, so
switching a host between the tools rewrites nothing and restarts nothing.
fail2ban is restarted only when its jail file changed and ssh is reloaded only
when the drop-in changed. A changed drop-in is checked with ``sshd -t`` before
the reload; when the check fails the drop-in is removed and the deploy fails,
as the role's ``rescue`` does, so a bad value never reaches a reload.
"""

from __future__ import annotations

import shlex
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux, require_systemd

# The role's header line, kept byte for byte.
HEADER = "# Managed by ops-library ssh_guard_deploy. Do not edit.\n"
JAIL_PATH = "/etc/fail2ban/jail.d/ssh-guard.local"
# The role validates the main config, which includes every drop-in.
SSHD_CONFIG = "/etc/ssh/sshd_config"
# A value rendered into one line of a config file: no line breaks or other control characters.
Line = Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]*$")]
UnitName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@:-]+$")]
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]+$")]
# The jail name is the ``[section]`` header; brackets or ``=`` would change it.
JailName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+$")]


class SshGuardConfig(RoleConfig):
    fail2ban_enabled: bool = True
    fail2ban_package: Package = "fail2ban"
    fail2ban_service_name: UnitName = "fail2ban"
    fail2ban_jail_name: JailName = "sshd"
    fail2ban_backend: Line = "systemd"
    fail2ban_filter: Line = "sshd"
    fail2ban_port: Line = "ssh"
    fail2ban_maxretry: int = 5
    fail2ban_findtime: Line = "10m"
    fail2ban_bantime: Line = "1h"
    # Empty: no ``ignoreip`` line.
    fail2ban_ignoreip: Line = "127.0.0.1/8 ::1 100.64.0.0/10"

    sshd_dropin_enabled: bool = True
    sshd_dropin_path: AbsolutePath = "/etc/ssh/sshd_config.d/99-ssh-guard.conf"
    sshd_service_name: UnitName = "ssh"
    # Empty string: the directive is left out. None is refused (as in the role).
    per_source_max_startups: Line | None = "5"
    max_auth_tries: Line = ""
    login_grace_time: Line = ""

    @model_validator(mode="after")
    def _role_asserts(self) -> SshGuardConfig:
        # The role's two ``assert`` tasks, each only for the enabled part.
        if self.fail2ban_enabled and self.fail2ban_maxretry <= 0:
            raise ValueError("fail2ban_maxretry must be > 0")
        if self.sshd_dropin_enabled and self.per_source_max_startups is None:
            raise ValueError("use an empty string to omit PerSourceMaxStartups (None is invalid)")
        path = PurePosixPath(self.sshd_dropin_path)
        if self.sshd_dropin_enabled and (path.name in ("", ".", "..") or str(path.parent) == "/"):
            raise ValueError("sshd_dropin_path must be a file below a directory, not in /")
        return self

    @property
    def dropin_dir(self) -> str:
        return str(PurePosixPath(self.sshd_dropin_path).parent)


def render_jail(cfg: SshGuardConfig) -> str:
    """``fail2ban-sshd.local.j2`` from the role, byte for byte."""

    ignore = f"ignoreip = {cfg.fail2ban_ignoreip}\n" if cfg.fail2ban_ignoreip else ""
    return (
        f"{HEADER}[{cfg.fail2ban_jail_name}]\nenabled = true\n"
        f"backend = {cfg.fail2ban_backend}\nfilter = {cfg.fail2ban_filter}\nport = {cfg.fail2ban_port}\n"
        f"maxretry = {cfg.fail2ban_maxretry}\nfindtime = {cfg.fail2ban_findtime}\nbantime = {cfg.fail2ban_bantime}\n"
        f"{ignore}"
    )


def render_dropin(cfg: SshGuardConfig) -> str:
    """``sshd-guard.conf.j2`` from the role, byte for byte; empty values are left out."""

    directives = (
        ("PerSourceMaxStartups", cfg.per_source_max_startups),
        ("MaxAuthTries", cfg.max_auth_tries),
        ("LoginGraceTime", cfg.login_grace_time),
    )
    return HEADER + "".join(f"{key} {value}\n" for key, value in directives if value)


def validate_command(cfg: SshGuardConfig) -> str:
    """``sshd -t``; on failure remove the drop-in and fail (the role's ``rescue``)."""

    path = shlex.quote(cfg.sshd_dropin_path)
    message = shlex.quote(f"Invalid sshd config; removed {cfg.sshd_dropin_path}.")
    return f"sshd -t -f {SSHD_CONFIG} || {{ rm -f -- {path}; echo {message} >&2; exit 1; }}"


def reload_command(service: str) -> str:
    """The role handler's ``state: reloaded``: reload a running unit, start a stopped one."""

    unit = shlex.quote(service)
    return f"if systemctl is-active --quiet {unit}; then systemctl reload {unit}; else systemctl start {unit}; fi"


@deploy("SSH guard")
def deploy_ssh_guard(cfg: SshGuardConfig) -> None:
    require_linux("ssh_guard")
    require_systemd("ssh_guard")

    if cfg.sshd_dropin_enabled:
        files.directory(name=f"Ensure {cfg.dropin_dir}", path=cfg.dropin_dir, user="root", group="root", mode="0755")

    if cfg.fail2ban_enabled:
        if not host.get_fact(Which, command="apt-get"):
            raise DeployError("ssh_guard installs fail2ban with apt; a Debian-family host is required")
        # As the role's ``package`` task: no apt cache refresh.
        apt.packages(name=f"Install {cfg.fail2ban_package}", packages=[cfg.fail2ban_package])
        systemd.service(
            name=f"Ensure {cfg.fail2ban_service_name}",
            service=cfg.fail2ban_service_name,
            running=True,
            enabled=True,
        )
        jail = files.put(
            name=f"Write {JAIL_PATH}",
            src=StringIO(render_jail(cfg)),
            dest=JAIL_PATH,
            user="root",
            group="root",
            mode="0644",
        )
        # A shell step, not ``systemd.service(restarted=True)``: that restarts
        # only a unit running while planning, so a fresh install would keep the
        # package's config. ``systemctl restart`` also starts a stopped unit,
        # as the role's handler does.
        server.shell(
            name=f"Restart {cfg.fail2ban_service_name} for the new jail",
            commands=[f"systemctl restart {shlex.quote(cfg.fail2ban_service_name)}"],
            _if=jail.did_change,
        )

    if cfg.sshd_dropin_enabled:
        dropin = files.put(
            name=f"Write {cfg.sshd_dropin_path}",
            src=StringIO(render_dropin(cfg)),
            dest=cfg.sshd_dropin_path,
            user="root",
            group="root",
            mode="0644",
        )
        server.shell(
            name="Validate the sshd configuration",
            commands=[validate_command(cfg)],
            _if=dropin.did_change,
        )
        server.shell(
            name=f"Reload {cfg.sshd_service_name} for the new drop-in",
            commands=[reload_command(cfg.sshd_service_name)],
            _if=dropin.did_change,
        )
