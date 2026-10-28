"""Original scanner account, SFTP, bind mount and default ACL composition."""

from __future__ import annotations

import shlex
from collections.abc import Generator

from pydantic import SecretStr
from pyinfra import host, state
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, File
from pyinfra.facts.server import Which
from pyinfra.operations import files, server

from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe

from . import operations
from .commands import scanner_password_payload
from .config import PaperlessConfig, PaperlessCredentials
from .render import render


@operation()
def restart_changed_ssh(changed: OperationMeta) -> Generator[StringCommand, None, None]:
    needed = changed.did_change() if state.is_executing else changed.will_change
    if needed:
        yield StringCommand("systemctl enable ssh")
        yield StringCommand("systemctl restart ssh")


def configure_scanner(cfg: PaperlessConfig, credentials: PaperlessCredentials) -> None:
    if not cfg.scanner_enabled:
        return
    server.group(name="Ensure scanner system group", group=cfg.scanner_group, system=True)
    account = server.user(
        name="Ensure scanner system account",
        user=cfg.scanner_username,
        group=cfg.scanner_group,
        groups=[cfg.group],
        append=True,
        system=True,
        shell="/bin/false",
        home=cfg.sftp_chroot_dir,
        ensure_home=False,
        create_home=False,
    )
    operations.scanner_password(
        name="Converge scanner password when different",
        payload=SecretStr(scanner_password_payload(cfg, credentials, apply=False)),
        deferred=account.will_change,
    )
    files.directory(
        name="Ensure root-owned scanner chroot", path=cfg.sftp_chroot_dir, user="root", group="root", mode="0755"
    )
    inbox = f"{cfg.sftp_chroot_dir}/inbox"
    # A mounted inbox is the consume directory. Chowning it to scanner first
    # would mutate the source, then undo it on every healthy repeat.
    mount_query = (
        f"findmnt --mountpoint {shlex.quote(inbox)} >/dev/null; rc=$?; "
        "case $rc in 0) echo mounted ;; 1) echo absent ;; *) exit 1 ;; esac"
    )
    mount_status = probe(shlex.join(["sh", "-c", mount_query]), name="Paperless scanner inbox coverage")
    if mount_status not in {"mounted", "absent"}:
        raise DeployError("Paperless scanner inbox mount state is unknown")
    active = mount_status == "mounted"
    files.directory(
        name="Ensure scanner inbox",
        path=inbox,
        user=None if active else cfg.scanner_username,
        group=None if active else cfg.scanner_group,
        mode=None if active else "0755",
    )
    if cfg.scanner_bind_mount_enabled:
        missing_directories = not host.get_fact(Directory, path=inbox) or not host.get_fact(
            Directory, path=f"{cfg.external_storage_root}/consume"
        )
        operations.scanner_mount(name="Converge scanner fstab and bind mount", cfg=cfg, deferred=missing_directories)
    if not host.get_fact(File, path="/etc/ssh/ssh_host_rsa_key"):
        server.shell(
            name="Create missing scanner-compatible RSA host key",
            commands=[
                shlex.join(["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", "/etc/ssh/ssh_host_rsa_key", "-N", ""])
            ],
        )
    files.directory(
        name="Ensure SSH drop-in directory", path="/etc/ssh/sshd_config.d", user="root", group="root", mode="0755"
    )
    ssh = operations.scanner_ssh(
        name="Validate and publish scanner SSH drop-in", content=render("sshd_sftp_scanner.conf.j2", cfg, credentials)
    )
    mark_read_only(
        server.shell(
            name="Validate combined SSH configuration before restart",
            commands=[
                shlex.join(
                    [
                        "sh",
                        "-c",
                        "sshd -t >/dev/null 2>&1 || { echo 'Combined SSH configuration is invalid' >&2; exit 1; }",
                    ]
                )
            ],
        )
    )
    restart_changed_ssh(name="Restart SSH only after scanner configuration changes", changed=ssh)
    if cfg.configure_scanner_acl:
        operations.scanner_acl(
            name="Converge recursive scanner default ACL",
            cfg=cfg,
            deferred=account.will_change
            or not host.get_fact(Which, command="setfacl")
            or not host.get_fact(Directory, path=f"{cfg.external_storage_root}/consume"),
        )
