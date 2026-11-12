"""An NFSv4 mount as a rendered systemd ``.mount`` unit over a sealed mount point.

Whatever ``enabled`` says, the host gets ``nfs-common``, the ``/etc/hosts``
lines (tlshd checks the server certificate against the reverse lookup of the
server address) and, with ``tls``, the client side of
:mod:`ops_deploy.base.tlshd`, so a hand-made staging mount works before the
switch. Only with ``enabled`` are the mount units written, enabled and
started; with it off they are stopped, disabled and removed.

Before a unit is started its mount point must be *sealed*: an empty
directory, ``root:root``, mode ``0000``, immutable, not a mount point. While
the NFS mount is absent nothing can then be written there, so a service
started without the mount fails instead of filling the local disk. The deploy
asserts that state and refuses otherwise; it never creates, changes or
removes the mount point. See ``docs/base.md#nfs_client_mount``.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, StrictInt, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, output, require_linux, require_systemd
from ops_deploy.base._nfs import check_options, check_path, wants_tls
from ops_deploy.base._packages import install_packages
from ops_deploy.base._units import ACTIVE, ENABLED, unit_states
from ops_deploy.base.external_bind_storage import mount_unit
from ops_deploy.base.tlshd import SERVICE as TLSHD_SERVICE
from ops_deploy.base.tlshd import TlshdConfig, tlshd_operations
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.systemd import UNIT_DIR

PACKAGE = "nfs-common"
HOSTS = "/etc/hosts"
DOCKER_DROPIN_DIR = str(UNIT_DIR / "docker.service.d")
HEADER = "# Managed by ops-deploy base.nfs_client_mount; local changes are overwritten.\n"
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
# Verdicts of the mount point probe that allow the deploy to go on.
SEALED = "sealed"
MOUNTED = "mounted-ok"


def _ipv4(value: str, what: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError as error:
        raise ValueError(f"{what} must be an IPv4 address") from error
    if str(address) != value:
        raise ValueError(f"{what} must be a plain dotted IPv4 address")
    return value


class NfsHostsEntry(RoleConfig):
    """One ``<address> <name>`` line in ``/etc/hosts``."""

    address: str
    name: str

    @field_validator("address")
    @classmethod
    def _address(cls, value: str) -> str:
        return _ipv4(value, "hosts entry address")

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _HOSTNAME.match(value):
            raise ValueError("hosts entry name must be a hostname")
        return value

    @property
    def line(self) -> str:
        return f"{self.address} {self.name}"


class NfsClientMount(RoleConfig):
    where: PurePosixPath
    # <ipv4>:<absolute export path>
    what: str
    # Mount options; the module appends _netdev.
    options: tuple[str, ...]
    requires_mounts_for: tuple[PurePosixPath, ...] = ()
    # A boot with the server away fails the mount after this long instead of hanging.
    timeout_sec: Annotated[StrictInt, Field(ge=1)] = 90
    # docker.service drop-in After=<unit> (ordering only), for mounts that carry container binds.
    order_docker_after: bool = False

    @field_validator("where")
    @classmethod
    def _where(cls, value: PurePosixPath) -> PurePosixPath:
        check_path(value, "where")
        if "\\" in mount_unit(str(value)):
            raise ValueError("where must not need systemd escaping (no '-', no leading '.')")
        return value

    @field_validator("what")
    @classmethod
    def _what(cls, value: str) -> str:
        address, sep, path = value.partition(":")
        if not sep:
            raise ValueError("what must be <ipv4>:<absolute path>")
        _ipv4(address, "what's server")
        check_path(PurePosixPath(path), "what's export path")
        return value

    @field_validator("options")
    @classmethod
    def _options(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if "_netdev" in value:
            raise ValueError("_netdev is added by the deploy")
        return check_options(value, "mount")

    @field_validator("requires_mounts_for")
    @classmethod
    def _requires(cls, value: tuple[PurePosixPath, ...]) -> tuple[PurePosixPath, ...]:
        for path in value:
            check_path(path, "requires_mounts_for")
        return value

    @property
    def unit(self) -> str:
        return mount_unit(str(self.where))

    @property
    def unit_path(self) -> str:
        return str(UNIT_DIR / self.unit)

    @property
    def docker_dropin(self) -> str:
        return f"{DOCKER_DROPIN_DIR}/{self.unit.removesuffix('.mount')}.conf"


class NfsClientConfig(RoleConfig):
    # The switch: the mount units exist and run only while this is on.
    enabled: bool
    mounts: tuple[NfsClientMount, ...] = ()
    hosts_entries: tuple[NfsHostsEntry, ...] = ()
    # tlshd's client side; required for xprtsec=tls or xprtsec=mtls.
    tls: TlshdConfig | None = None

    @model_validator(mode="after")
    def _consistent(self) -> NfsClientConfig:
        wheres = [mount.where for mount in self.mounts]
        if len(set(wheres)) != len(wheres):
            raise ValueError("mount points must be unique")
        for field in ("address", "name"):
            values = [getattr(entry, field) for entry in self.hosts_entries]
            if len(set(values)) != len(values):
                raise ValueError(f"each hosts entry {field} may appear once")
        if self.tls is None:
            if any(wants_tls(mount.options) for mount in self.mounts):
                raise ValueError("xprtsec=tls or xprtsec=mtls needs tls (the tlshd client certificate)")
        elif self.tls.role != "client":
            raise ValueError("the NFS client's tls must have role 'client'")
        return self


def render_unit(mount: NfsClientMount, *, tls: bool) -> str:
    after = "network-online.target" + (f" {TLSHD_SERVICE}" if tls else "")
    requires = "".join(f"RequiresMountsFor={path}\n" for path in mount.requires_mounts_for)
    return (
        f"{HEADER}[Unit]\nDescription=NFS {mount.what} at {mount.where}\n"
        f"Wants={after}\nAfter={after}\n{requires}"
        f"\n[Mount]\nWhat={mount.what}\nWhere={mount.where}\nType=nfs4\n"
        f"Options={','.join((*mount.options, '_netdev'))}\nTimeoutSec={mount.timeout_sec}\n"
        "\n[Install]\nWantedBy=remote-fs.target\n"
    )


def render_docker_dropin(mount: NfsClientMount) -> str:
    """Ordering only: Docker still starts when the mount fails."""

    return f"{HEADER}[Unit]\nAfter={mount.unit}\n"


def seal_probe(mount: NfsClientMount) -> str:
    """Shell that prints one verdict for ``mount.where``.

    ``mounted-ok`` (an nfs4 mount of exactly ``what``), ``sealed`` (empty
    directory, ``root:root``, mode ``0000``, immutable, not a mount point) or
    ``refuse <reason>``. Read-only.
    """

    where, what = shlex.quote(str(mount.where)), shlex.quote(f"nfs4 {mount.what}")
    return (
        f'p={where}; m=$(findmnt -rn -o FSTYPE,SOURCE --mountpoint "$p" 2>/dev/null); '
        f'if [ -n "$m" ]; then if [ "$m" = {what} ]; then echo {MOUNTED}; else echo "refuse mounted: $m"; fi; '
        'elif [ -L "$p" ]; then echo "refuse symlink"; '
        'elif [ ! -d "$p" ]; then echo "refuse not a directory"; '
        'elif mountpoint -q "$p"; then echo "refuse mount point"; '
        'elif [ "$(stat -c %U:%G "$p")" != root:root ]; then echo "refuse owner $(stat -c %U:%G "$p")"; '
        'elif [ "$(stat -c %a "$p")" != 0 ]; then echo "refuse mode $(stat -c %a "$p")"; '
        'elif ! lsattr -d "$p" 2>/dev/null | awk \'{print $1}\' | grep -q i; then echo "refuse not immutable"; '
        'elif [ -n "$(ls -A "$p" 2>/dev/null)" ]; then echo "refuse not empty"; '
        f"else echo {SEALED}; fi"
    )


def guard_command(mount: NfsClientMount) -> str:
    """Fails unless the probe still allows the start (state may change after planning)."""

    return (
        f'v=$({seal_probe(mount)}); case "$v" in {SEALED}|{MOUNTED}) ;; *) echo "{mount.where}: $v" >&2; exit 1;; esac'
    )


def verdict(mount: NfsClientMount) -> str:
    return output(seal_probe(mount)).strip() or "refuse no answer from the mount point probe"


def hosts_lines() -> list[tuple[str, list[str]]]:
    """``(address, names)`` of every non-comment line of ``/etc/hosts``."""

    result = []
    for line in host.get_fact(FileContents, path=HOSTS) or []:
        fields = line.split("#", 1)[0].split()
        if fields:
            result.append((fields[0], fields[1:]))
    return result


def hosts_operations(cfg: NfsClientConfig) -> None:
    """Append missing entries; refuse when the address or name already means something else."""

    lines = hosts_lines()
    for entry in cfg.hosts_entries:
        same_address = [names for address, names in lines if address == entry.address]
        if any(names != [entry.name] for names in same_address):
            raise DeployError(f"{HOSTS} already has another line for {entry.address}; not rewriting it")
        if any(entry.name in names for address, names in lines if address != entry.address):
            raise DeployError(f"{HOSTS} already maps {entry.name} to another address; not rewriting it")
        if same_address:
            continue
        line = shlex.quote(entry.line)
        server.shell(
            name=f"Add '{entry.line}' to {HOSTS}",
            commands=[
                f"grep -qxF -- {line} {HOSTS} || "
                f'{{ [ -z "$(tail -c 1 {HOSTS})" ] || echo >> {HOSTS}; echo {line} >> {HOSTS}; }}'
            ],
        )


def mount_on(mount: NfsClientMount, *, tls: bool) -> None:
    state = verdict(mount)
    if state not in (SEALED, MOUNTED):
        raise DeployError(f"nfs_client_mount: {mount.where} is not a sealed mount point ({state}); refusing")
    written: list[OperationMeta] = [
        files.put(
            name=f"Install {mount.unit_path}",
            src=StringIO(render_unit(mount, tls=tls)),
            dest=mount.unit_path,
            user="root",
            group="root",
            mode="0644",
        )
    ]
    if mount.order_docker_after:
        # mode=None: the directory may be managed elsewhere (external_bind_storage keeps it 0700).
        files.directory(name=f"Ensure {DOCKER_DROPIN_DIR}", path=DOCKER_DROPIN_DIR, user="root", group="root")
        written.append(
            files.put(
                name=f"Install {mount.docker_dropin}",
                src=StringIO(render_docker_dropin(mount)),
                dest=mount.docker_dropin,
                user="root",
                group="root",
                mode="0644",
            )
        )
    else:
        written.append(files.file(name=f"Remove {mount.docker_dropin}", path=mount.docker_dropin, present=False))
    # Never a restart or reload of docker.service: the drop-in is ordering for its next start.
    systemd.daemon_reload(name=f"Reload systemd for {mount.unit}", _if=any_changed(*written))
    unit = unit_states([mount.unit])[mount.unit]
    quoted = shlex.quote(mount.unit)
    if unit.get("UnitFileState") not in ENABLED:
        server.shell(name=f"Enable {mount.unit}", commands=[f"systemctl enable -- {quoted}"])
    if state == SEALED:
        mark_read_only(
            server.shell(name=f"Check {mount.where} is still a sealed mount point", commands=[guard_command(mount)])
        )
        server.shell(name=f"Start {mount.unit}", commands=[f"systemctl start -- {quoted}"])


def mount_off(mount: NfsClientMount) -> list[OperationMeta]:
    unit = unit_states([mount.unit])[mount.unit]
    quoted = shlex.quote(mount.unit)
    if unit.get("ActiveState") in ACTIVE:
        server.shell(name=f"Stop {mount.unit}", commands=[f"systemctl stop -- {quoted}"])
    if unit.get("UnitFileState") in ENABLED:
        server.shell(name=f"Disable {mount.unit}", commands=[f"systemctl disable -- {quoted}"])
    return [
        files.file(name=f"Remove {mount.unit_path}", path=mount.unit_path, present=False),
        files.file(name=f"Remove {mount.docker_dropin}", path=mount.docker_dropin, present=False),
    ]


@deploy("NFS client mount")
def deploy_nfs_client_mount(cfg: NfsClientConfig) -> None:
    require_linux("nfs_client_mount")
    require_systemd("nfs_client_mount")
    install_packages([PACKAGE], what="nfs_client_mount")
    hosts_operations(cfg)
    if cfg.tls is not None:
        tlshd_operations(cfg.tls)
    if cfg.enabled:
        for mount in cfg.mounts:
            mount_on(mount, tls=cfg.tls is not None)
        return
    removed = [meta for mount in cfg.mounts for meta in mount_off(mount)]
    if removed:
        systemd.daemon_reload(name="Reload systemd for the removed NFS mounts", _if=any_changed(*removed))
