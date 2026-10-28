"""Literal delegated source/restore-access preparation from the original backup play."""

from __future__ import annotations

import base64
import json
import shlex
import struct
from collections.abc import Generator
from io import StringIO
from pathlib import Path
from typing import Literal

from pydantic import SecretStr, model_validator
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.operations import files

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux
from ops_deploy.helpers.probes import StdinLines, probe

from .common import key_input, known_host, mail_key_input, private_key
from .config import Hostname, literal_values
from .render import ENV


class BackupSourceConfig(RoleConfig):
    minio_enabled: bool = True
    mail_enabled: bool = True
    minio_source_path: AbsolutePath = "/opt/backups/minio"
    minio_command_path: AbsolutePath = "/usr/local/sbin/minio-offsite-rsync-allow.sh"
    mail_stage_path: AbsolutePath = "/mnt/cryptdata/mail-backup-stage"
    mail_vmail_path: AbsolutePath = "/mnt/cryptdata/vmail"
    mail_stage_command: AbsolutePath = "/usr/local/sbin/mail-backup-stage.sh"
    mail_command_path: AbsolutePath = "/usr/local/sbin/mail-offsite-allow.sh"
    mail_restore_key_path: AbsolutePath = "/root/.ssh/mail-offsite-replication-ed25519"
    mail_restore_host: Hostname | Literal[""] = ""
    ssh_dir: AbsolutePath = "/root/.ssh"
    known_hosts_path: AbsolutePath = "/root/.ssh/known_hosts"

    @model_validator(mode="after")
    def _literals(self) -> BackupSourceConfig:
        literal_values(self.model_dump())
        if self.mail_enabled and not self.mail_restore_host:
            raise ValueError("original enabled mail restore access requires its configured peer")
        for value in self.model_dump().values():
            if isinstance(value, str) and value.startswith("/") and ".." in Path(value).parts:
                raise ValueError("source paths must be canonical")
        return self


class BackupRestoreAccessConfig(RoleConfig):
    command_path: AbsolutePath = "/usr/local/sbin/mail-restore-allow.sh"
    authorized_keys_path: AbsolutePath = "/root/.ssh/authorized_keys"


def source_render(cfg: BackupSourceConfig, resource: str) -> str:
    return ENV.get_template(resource + ".j2").render(
        fractal_minio_offsite_replication_source_path=cfg.minio_source_path,
        fractal_mail_offsite_replication_source_stage_path=cfg.mail_stage_path,
        fractal_mail_offsite_replication_source_vmail_path=cfg.mail_vmail_path,
        fractal_mail_backup_stage_script_path=cfg.mail_stage_command,
    )


def public_key_input(value: SecretStr | None) -> SecretStr:
    key = key_input(value)
    try:
        text = key.get_secret_value().strip()
        if any(c in text for c in "\r\n\0"):
            raise ValueError
        fields = text.split()
        if len(fields) < 2 or fields[0] not in {
            "ssh-ed25519",
            "ssh-rsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        }:
            raise ValueError
        raw = base64.b64decode(fields[1], validate=True)
        size = struct.unpack(">I", raw[:4])[0]
        if raw[4 : 4 + size] != fields[0].encode():
            raise ValueError
    except (ValueError, struct.error):
        raise DeployError("Original source public key is invalid; material suppressed") from None
    return key


AUTH_SCRIPT = (Path(__file__).parents[1] / "files/backup_authorized_key.py").read_text()


@operation()
def authorize(path: str, key: SecretStr, command_path: str, comment: str) -> Generator[StringCommand, None, None]:
    content = json.dumps({"path": path, "key": key.get_secret_value(), "command": command_path, "comment": comment})

    def command(action: str) -> str:
        return shlex.join(["python3", "-I", "-B", "-c", AUTH_SCRIPT, action])

    state = probe(command("check"), name="Original selected forced-command key RAM comparison", stdin=content)
    if state == "current":
        host.noop("Original selected forced-command authorization is current")
    elif state == "pending":
        yield StringCommand(command("apply"), _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Source forced-command authorization admission failed; no auth write")


def put(cfg: BackupSourceConfig, name: str, destination: str, mode: str = "0755") -> None:
    files.put(
        name="Original delegated source program " + name,
        src=StringIO(source_render(cfg, name)),
        dest=destination,
        user="root",
        group="root",
        mode=mode,
    )


@deploy("Prepare original delegated backup source")
def deploy_backup_source(
    cfg: BackupSourceConfig,
    minio_public_key: SecretStr | None = None,
    mail_public_key: SecretStr | None = None,
    mail_private_key: SecretStr | None = None,
    restore_client: bool = True,
) -> None:
    # Original pre-task assertions require these public/private source fields
    # before installing wrappers, including when client preparation is deferred.
    # Validation is retained; macmini authorization remains owned elsewhere.
    minio = public_key_input(minio_public_key) if cfg.minio_enabled else None
    mail = public_key_input(mail_public_key) if cfg.mail_enabled else None
    private = key_input(mail_private_key) if cfg.mail_enabled else None
    if minio is None and mail is None:
        return
    require_linux("original backup source")
    files.directory(
        name="Original root source SSH directory",
        path=cfg.ssh_dir,
        user="root",
        group="root",
        mode="0700",
    )
    if minio is not None:
        put(cfg, "minio-offsite-rsync-allow.sh", cfg.minio_command_path)

    if mail is not None and private is not None:
        put(cfg, "mail-backup-stage.sh", cfg.mail_stage_command, "0750")
        put(cfg, "mail-offsite-allow.sh", cfg.mail_command_path)

        if restore_client:
            deploy_backup_restore_client(cfg=cfg, mail_private_key=private)


@deploy("Prepare original Fractal mail restore access")
def deploy_backup_restore_access(cfg: BackupRestoreAccessConfig, mail_public_key: SecretStr) -> None:
    material = public_key_input(mail_public_key)
    require_linux("original mail restore access")
    files.directory(
        name="Original root restore SSH directory",
        path=str(Path(cfg.authorized_keys_path).parent),
        user="root",
        group="root",
        mode="0700",
    )
    files.put(
        name="Original mail restore allow program",
        src=StringIO(ENV.get_template("mail-restore-allow.sh.j2").render()),
        dest=cfg.command_path,
        user="root",
        group="root",
        mode="0755",
    )
    authorize(
        name="Original macmini mail restore forced-command key",
        path=cfg.authorized_keys_path,
        key=material,
        command_path=cfg.command_path,
        comment="macmini mail offsite restore",
    )


@deploy("Prepare original macmini mail restore client")
def deploy_backup_restore_client(cfg: BackupSourceConfig, mail_private_key: SecretStr) -> None:
    if not cfg.mail_enabled:
        return
    private = mail_key_input(mail_private_key)
    require_linux("original mail restore client")
    private_key(
        name="Original macmini mail restore key private stdin",
        path=cfg.mail_restore_key_path,
        content=private,
        kind="ssh",
    )
    known_host(
        name="Original fresh restore peer keyscan",
        path=cfg.known_hosts_path,
        peer=cfg.mail_restore_host,
        key_type="ed25519",
    )
