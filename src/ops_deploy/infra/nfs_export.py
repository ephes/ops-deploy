"""NFSv4 exports from rendered ``/etc/exports.d`` files, optionally over RPC-with-TLS.

``nfs-kernel-server`` with one ``/etc/exports.d/<name>.exports`` per export,
``exportfs -ra`` when one changed, and ``manage-gids=n`` for ``rpc.mountd``:
Ubuntu's default ``manage-gids=y`` makes the server replace the groups an
``AUTH_SYS`` client sends with the server's own idea of the user's groups,
which breaks group writes for client-only accounts. ZFS ``sharenfs`` is not
used. With ``tls`` the server side of :mod:`ops_deploy.base.tlshd` is deployed
too. See ``docs/services/nfs_export.md``.
"""

from __future__ import annotations

import ipaddress
import shlex
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, StrictInt, field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import RoleConfig, require_linux, require_systemd
from ops_deploy.base._nfs import check_options, check_path, option_key, wants_tls
from ops_deploy.base._packages import install_packages
from ops_deploy.base.tlshd import TlshdConfig, tlshd_operations
from ops_deploy.helpers.checks import mark_read_only

PACKAGE = "nfs-kernel-server"
SERVICE = "nfs-server.service"
MOUNTD = "nfs-mountd.service"
EXPORTS_DIR = "/etc/exports.d"
NFS_CONF_DIR = "/etc/nfs.conf.d"
NFS_CONF_PATH = f"{NFS_CONF_DIR}/ops-deploy.conf"
HEADER = "# Managed by ops-deploy infra.nfs_export; local changes are overwritten.\n"


class NfsExportClient(RoleConfig):
    # An IPv4 address or network (CIDR) as exports(5) takes it.
    host: str
    # Export options without fsid= (set per export).
    options: tuple[str, ...]

    @field_validator("host")
    @classmethod
    def _ipv4(cls, value: str) -> str:
        try:
            ipaddress.IPv4Network(value, strict=True)
        except ValueError as error:
            raise ValueError("client host must be an IPv4 address or network") from error
        return value

    @field_validator("options")
    @classmethod
    def _options(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(option_key(option) == "fsid" for option in value):
            raise ValueError("fsid= is set per export, not in client options")
        return check_options(value, "export")


class NfsExport(RoleConfig):
    # File stem of /etc/exports.d/<name>.exports.
    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")]
    path: PurePosixPath
    # Fixed so a client's file handles survive a server restart or a dataset remount.
    fsid: Annotated[StrictInt, Field(ge=1)]
    clients: tuple[NfsExportClient, ...] = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def _path(cls, value: PurePosixPath) -> PurePosixPath:
        return check_path(value, "export path")

    @model_validator(mode="after")
    def _unique_clients(self) -> NfsExport:
        hosts = [client.host for client in self.clients]
        if len(set(hosts)) != len(hosts):
            raise ValueError(f"export {self.name}: client hosts must be unique")
        return self


class NfsExportConfig(RoleConfig):
    exports: tuple[NfsExport, ...] = Field(min_length=1)
    # tlshd's server side; required for xprtsec=tls or xprtsec=mtls.
    tls: TlshdConfig | None = None

    @model_validator(mode="after")
    def _consistent(self) -> NfsExportConfig:
        for field in ("name", "path", "fsid"):
            values = [getattr(export, field) for export in self.exports]
            if len(set(values)) != len(values):
                raise ValueError(f"export {field}s must be unique")
        if self.tls is None:
            if any(wants_tls(client.options) for export in self.exports for client in export.clients):
                raise ValueError("xprtsec=tls or xprtsec=mtls needs tls (the tlshd server certificate)")
        elif self.tls.role != "server":
            raise ValueError("the NFS server's tls must have role 'server'")
        return self


def exports_path(export: NfsExport) -> str:
    return f"{EXPORTS_DIR}/{export.name}.exports"


def export_line(export: NfsExport) -> str:
    """``<path> <host>(<options>,fsid=<n>) ...``"""

    clients = " ".join(
        f"{client.host}({','.join((*client.options, f'fsid={export.fsid}'))})" for client in export.clients
    )
    return f"{export.path} {clients}"


def render_exports(export: NfsExport) -> str:
    return f"{HEADER}{export_line(export)}\n"


def render_nfs_conf() -> str:
    """mountd uses the groups the client sends (up to 16), not the server's user database."""

    return f"{HEADER}[mountd]\nmanage-gids=n\n"


def exports_check_command(cfg: NfsExportConfig) -> str:
    """``exportfs -v`` lists every export path (a long path stands alone on its line)."""

    checks = " && ".join(
        f"printf '%s' \"$listed\" | grep -qxF -- {shlex.quote(str(export.path))}" for export in cfg.exports
    )
    return (
        "listed=$(exportfs -v | awk '{print $1}') && "
        f"{checks} || {{ echo 'exportfs -v does not list every configured export' >&2; exit 1; }}"
    )


@deploy("NFS export")
def deploy_nfs_export(cfg: NfsExportConfig) -> None:
    require_linux("nfs_export")
    require_systemd("nfs_export")
    install_packages([PACKAGE], what="nfs_export")
    files.directory(name=f"Ensure {NFS_CONF_DIR}", path=NFS_CONF_DIR, user="root", group="root", mode="0755")
    nfs_conf = files.put(
        name=f"Install {NFS_CONF_PATH} (manage-gids=n)",
        src=StringIO(render_nfs_conf()),
        dest=NFS_CONF_PATH,
        user="root",
        group="root",
        mode="0644",
    )
    files.directory(name=f"Ensure {EXPORTS_DIR}", path=EXPORTS_DIR, user="root", group="root", mode="0755")
    exports = [
        files.put(
            name=f"Install {exports_path(export)}",
            src=StringIO(render_exports(export)),
            dest=exports_path(export),
            user="root",
            group="root",
            mode="0644",
        )
        for export in cfg.exports
    ]
    if cfg.tls is not None:
        tlshd_operations(cfg.tls)
    systemd.service(name=f"Enable {SERVICE}", service=SERVICE, running=None, enabled=True)
    # rpc.mountd reads nfs.conf at start only. nfs-mountd is PartOf
    # nfs-server, so this also restarts zfs-share (a no-op share -a): a few
    # seconds of blocked I/O on clients. Only when the file changed.
    server.shell(
        name=f"Restart {MOUNTD} and {SERVICE} for {NFS_CONF_PATH}",
        commands=[f"systemctl restart {MOUNTD} {SERVICE}"],
        _if=any_changed(nfs_conf),
    )
    systemd.service(name=f"Start {SERVICE}", service=SERVICE, running=True)
    server.shell(name="Re-export (exportfs -ra)", commands=["exportfs -ra"], _if=any_changed(*exports))
    mark_read_only(server.shell(name="Check exportfs -v lists every export", commands=[exports_check_command(cfg)]))
