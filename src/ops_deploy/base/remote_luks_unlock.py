"""Dropbear in the initramfs for remote LUKS unlock (the ``remote_luks_unlock`` role).

Ported with the role's enabled path and its ``grub_ip_param`` network method:
the ``ip=`` kernel parameter goes on ``GRUB_CMDLINE_LINUX_DEFAULT``. The role's
``initramfs_conf`` method and its cleanup when disabled are not ported.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from io import StringIO
from typing import Annotated, Literal

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.files import FileContents
from pyinfra.operations import apt, files, server
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, output, require_linux

PACKAGE = "dropbear-initramfs"
DROPBEAR_DIR = "/etc/dropbear/initramfs"
INITRAMFS_CONF = "/etc/initramfs-tools/initramfs.conf"
GRUB = "/etc/default/grub"
CMDLINE_KEY = "GRUB_CMDLINE_LINUX_DEFAULT"
# The role's template, with its Ansible header kept so a converged host shows no change.
KEYS_HEADER = "# Authorized SSH keys for remote LUKS unlock\n# Managed by Ansible - DO NOT EDIT MANUALLY\n"

Interface = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*$")]
# One authorized_keys line: no line breaks, no NUL.
KeyLine = Annotated[str, Field(pattern=r"^[^\r\n\x00]+$")]
# Appended to DROPBEAR_OPTIONS="..."; nothing that ends or escapes the quotes.
DropbearOptions = Annotated[str, Field(pattern=r"^[A-Za-z0-9 ._,:/=+-]*$")]


class RemoteLuksUnlockConfig(RoleConfig):
    interface: Interface
    ip_mode: Literal["dhcp", "static"] = "dhcp"
    static_ip: str = ""
    static_gateway: str = ""
    static_netmask: str = "255.255.255.0"
    # The role defaults this to ``ansible_hostname``; here it is required for static.
    static_hostname: Hostname | Literal[""] = ""
    port: int = Field(default=2222, ge=1, le=65535)
    idle_timeout: int = Field(default=600, ge=0)
    no_password_auth: bool = True
    disable_forwarding: bool = True
    extra_dropbear_options: DropbearOptions = ""
    authorized_keys: tuple[KeyLine, ...] = Field(min_length=1)
    # False when another step renders /etc/default/grub with :func:`ip_param`
    # already in its command line (``boot_visible_i915.grub_extra_params``);
    # then this deploy leaves the file alone: that step must carry ip_param.
    edit_grub: bool = True

    @model_validator(mode="after")
    def _static_settings(self) -> RemoteLuksUnlockConfig:
        if self.ip_mode == "static":
            for name in ("static_ip", "static_gateway", "static_netmask"):
                value = getattr(self, name)
                try:
                    ipaddress.IPv4Address(value)
                except ValueError:
                    raise ValueError(f"static mode needs an IPv4 {name}, got {value!r}") from None
            if not self.static_hostname:
                raise ValueError("static mode needs static_hostname")
        return self


def ip_param(cfg: RemoteLuksUnlockConfig) -> str:
    """The kernel ``ip=`` parameter, as the role builds it."""

    if cfg.ip_mode == "dhcp":
        return f"ip=:::::{cfg.interface}:dhcp"
    return f"ip={cfg.static_ip}::{cfg.static_gateway}:{cfg.static_netmask}:{cfg.static_hostname}:{cfg.interface}:none"


def dropbear_options(cfg: RemoteLuksUnlockConfig) -> str:
    parts = [
        f"-p {cfg.port}",
        f"-I {cfg.idle_timeout}",
        "-s" if cfg.no_password_auth else "",
        "-j -k" if cfg.disable_forwarding else "",
        cfg.extra_dropbear_options,
    ]
    return " ".join(part for part in parts if part)


def authorized_keys_file(keys: tuple[str, ...]) -> str:
    return KEYS_HEADER + "".join(f"{key}\n" for key in keys)


def cmdline_tokens(lines: list[str]) -> list[str] | None:
    """Tokens of the first ``GRUB_CMDLINE_LINUX_DEFAULT=`` line (shell-unquoted,
    as the role reads it), or None without one."""

    for line in lines:
        if line.startswith(f"{CMDLINE_KEY}="):
            raw = line.split("=", 1)[1].strip()
            try:
                return " ".join(shlex.split(raw, posix=True)).split()
            except ValueError:
                if raw and raw[0] in "'\"" and raw[-1] == raw[0]:
                    raw = raw[1:-1]
                return raw.split()
    return None


def set_line(lines: list[str], pattern: str, line: str) -> list[str]:
    """Ansible ``lineinfile`` with ``regexp``: replace the last matching line, else append."""

    matches = [index for index, current in enumerate(lines) if re.search(pattern, current)]
    if not matches:
        return [*lines, line]
    result = list(lines)
    result[matches[-1]] = line
    return result


def grub_with_ip(lines: list[str], cfg: RemoteLuksUnlockConfig) -> list[str] | None:
    """/etc/default/grub with this interface's ``ip=`` (any other ``ip=`` for
    the same interface removed), or None when the command line already has it."""

    current = cmdline_tokens(lines) or []
    ours = re.compile(rf"ip=.*:{re.escape(cfg.interface)}:")
    new = [token for token in current if not ours.search(token)] + [ip_param(cfg)]
    if new == current:
        return None
    return set_line(lines, rf"^{CMDLINE_KEY}=", f'{CMDLINE_KEY}="{" ".join(new)}"')


def text(lines: list[str]) -> str:
    return "".join(f"{line}\n" for line in lines)


@deploy("Remote LUKS unlock")
def deploy_remote_luks_unlock(cfg: RemoteLuksUnlockConfig) -> None:
    require_linux("remote_luks_unlock")
    initramfs: list[OperationMeta] = []
    if PACKAGE not in (host.get_fact(DebPackages) or {}):
        initramfs.append(apt.packages(name=f"Install {PACKAGE}", packages=[PACKAGE], update=True, cache_time=3600))
    files.directory(name=f"Ensure {DROPBEAR_DIR}", path=DROPBEAR_DIR, user="root", group="root", mode="0755")
    initramfs.append(
        files.line(
            name="Enable Dropbear in initramfs", path=INITRAMFS_CONF, line=r"^DROPBEAR=.*$", replace="DROPBEAR=y"
        )
    )
    initramfs.append(
        files.put(
            name="Configure Dropbear authorized_keys",
            src=StringIO(authorized_keys_file(cfg.authorized_keys)),
            dest=f"{DROPBEAR_DIR}/authorized_keys",
            user="root",
            group="root",
            mode="0600",
        )
    )
    initramfs.append(
        files.line(
            name="Configure Dropbear options",
            path=f"{DROPBEAR_DIR}/dropbear.conf",
            line=r"^DROPBEAR_OPTIONS=.*$",
            replace=f'DROPBEAR_OPTIONS="{dropbear_options(cfg)}"',
        )
    )
    # The role drops DEVICE= and IP= when DEVICE names this interface (the
    # ip= kernel parameter configures it instead).
    if output(f"grep '^DEVICE=' {INITRAMFS_CONF} | cut -d= -f2").strip() == cfg.interface:
        for key in ("DEVICE", "IP"):
            initramfs.append(
                files.line(
                    name=f"Remove {key}= from initramfs.conf", path=INITRAMFS_CONF, line=rf"^{key}=.*$", present=False
                )
            )

    grub = None
    if cfg.edit_grub:
        lines = host.get_fact(FileContents, path=GRUB)
        if lines is None:
            raise DeployError(f"remote_luks_unlock: {GRUB} is missing")
        new = grub_with_ip(lines, cfg)
        if new is not None:
            server.shell(name=f"Back up {GRUB}", commands=[backup_command(GRUB)])
            grub = files.put(
                name=f"Add {ip_param(cfg)} to {CMDLINE_KEY}",
                src=StringIO(text(new)),
                dest=GRUB,
                user="root",
                group="root",
                mode="0644",
            )

    server.shell(name="Rebuild initramfs", commands=["update-initramfs -u -k all"], _if=any_changed(*initramfs))
    if grub is not None:
        server.shell(name="Update GRUB", commands=["update-grub"], _if=any_changed(grub))


def backup_command(path: str) -> str:
    """A timestamped copy next to ``path``, like Ansible's ``backup: yes``."""

    quoted = shlex.quote(path)
    return f'cp -p {quoted} {quoted}."$(date +%Y-%m-%d@%H:%M:%S)"~'
