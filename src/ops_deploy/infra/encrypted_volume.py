"""Open and mount an existing LUKS data volume (the ``encrypted_volume_prepare`` role).

Configure path of the role only, for a volume that already exists: the
device must be the configured LUKS container (checked by header UUID), the
passphrase is written as the keyfile ``cryptsetup open`` and ``/etc/crypttab``
use, and the filesystem inside is mounted through its ``/etc/fstab`` entry.

Things the deploy never does, by construction: format a device or a mapper
(the role's ``allow_format``), close a mapper, unmount, read or change the
LUKS header or keyslots, or switch the device path (the role's
``device_by_id``; ``device`` is resolved and recorded as it is today).

Unlike the role, a converged host gets no write at all and nothing is
remounted: one read-only admission on the host (``files/encrypted_volume_host.py``,
``blkid -p``, ``lsblk``, ``findmnt``; no ``cryptsetup`` call, so not even a
LUKS lock file) decides while planning whether the open/crypttab/fstab/mount
step is needed, and refuses before any operation when the device is not the
configured container, the mapper name is open on another device or the device
is mapped under another name, the mapper holds no or another filesystem,
something else is mounted at the mount point, the mount is read-only or
``/etc/fstab`` has more than one entry for it. The step itself re-runs that
admission, and a final read-only probe must find nothing left to do.

Other deploys whose data lives on the volume call :func:`deploy_encrypted_volume`
first, as the Ansible plays import the role's playbook first.
"""

from __future__ import annotations

import base64
import json
import re
import shlex
from importlib.resources import files as files_of
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, SecretStr, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.ops.secret_file import secret_file

HOST_SCRIPT = files_of("ops_deploy.infra").joinpath("files/encrypted_volume_host.py").read_text()
CRYPTTAB = "/etc/crypttab"
FSTAB = "/etc/fstab"

Uuid = Annotated[str, Field(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")]
Mode = Annotated[str, Field(pattern=r"^0?[0-7]{3,4}$")]
# fstab and crypttab fields: no whitespace, no comment sign, nothing fstab would escape.
Word = Annotated[str, Field(pattern=r"^[A-Za-z0-9_=,.:/+@-]+$")]
MapperName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")]
PackageName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]{0,99}$")]


class EncryptedVolumeConfig(RoleConfig):
    """The ``encrypted_volume_*`` role variables of the configure path (role defaults).

    ``device`` and ``expected_luks_uuid`` have no default. Not ported:
    ``device_by_id`` (the device path is never switched), ``use_keyfile``
    (always the keyfile, the production setting), ``allow_format``,
    ``validate_only``, ``fs_label`` and ``no_log``.
    """

    device: AbsolutePath
    expected_luks_uuid: Uuid
    mapper_name: MapperName = "cryptdata"
    mount_point: AbsolutePath = "/mnt/cryptdata"
    fs_type: Annotated[str, Field(pattern=r"^[a-z0-9]+$")] = "ext4"
    mount_opts: Word = "defaults,noatime"
    fstab_dump: Annotated[str, Field(pattern=r"^[0-9]$")] = "0"
    fstab_passno: Annotated[str, Field(pattern=r"^[0-9]$")] = "0"
    # None: the role's ``/root/.luks-key-<mapper_name>``.
    keyfile_path: AbsolutePath | None = None
    keyfile_owner: UnixUser = "root"
    keyfile_group: UnixUser = "root"
    keyfile_mode: Mode = "0400"
    crypttab_options: Word = "luks"
    mount_owner: UnixUser = "root"
    mount_group: UnixUser = "root"
    mount_mode: Mode = "0755"
    # Installed only while ``cryptsetup`` is missing, as the role does.
    packages: tuple[PackageName, ...] = ("cryptsetup", "cryptsetup-initramfs")

    @model_validator(mode="after")
    def _paths(self) -> EncryptedVolumeConfig:
        mount = PurePosixPath(self.mount_point)
        keyfile = PurePosixPath(self.keyfile)
        if mount == PurePosixPath("/") or ".." in mount.parts:
            raise ValueError("mount_point must be a directory below /")
        if ".." in keyfile.parts or keyfile.parent == keyfile:
            raise ValueError("keyfile_path must be a file path")
        if keyfile.is_relative_to(mount):
            raise ValueError("keyfile_path must not be on the volume it unlocks")
        if not self.packages:
            raise ValueError("packages must name cryptsetup's packages")
        return self

    @property
    def keyfile(self) -> str:
        return self.keyfile_path or f"/root/.luks-key-{self.mapper_name}"

    @property
    def mapper_path(self) -> str:
        return f"/dev/mapper/{self.mapper_name}"


def host_payload(cfg: EncryptedVolumeConfig) -> dict[str, str]:
    """What the host script reads (no secret)."""

    return {
        "device": cfg.device,
        "expected_uuid": cfg.expected_luks_uuid,
        "mapper_name": cfg.mapper_name,
        "mount_point": cfg.mount_point,
        "fs_type": cfg.fs_type,
        "mount_opts": cfg.mount_opts,
        "dump": cfg.fstab_dump,
        "passno": cfg.fstab_passno,
        "keyfile": cfg.keyfile,
        "crypttab_options": cfg.crypttab_options,
    }


def host_command(cfg: EncryptedVolumeConfig, action: str) -> str:
    """``python3 -I -B -c <script> <action> <config>``; source and config base64 (fish-safe)."""

    if action not in ("check", "apply"):
        raise ValueError(f"unknown action {action!r}")
    script = base64.b64encode(HOST_SCRIPT.encode()).decode()
    config = base64.b64encode(json.dumps(host_payload(cfg), sort_keys=True).encode()).decode()
    loader = f"import base64;exec(compile(base64.b64decode('{script}'),'<encrypted-volume>','exec'))"
    return shlex.join(["python3", "-I", "-B", "-c", loader, action, config])


_REFUSED = re.compile(r"^refused: (?P<reason>.+)$")


def admission(cfg: EncryptedVolumeConfig) -> tuple[str, ...]:
    """The steps the host still needs (empty: converged); refuses while planning, before any operation."""

    result = probe(host_command(cfg, "check"), name="encrypted volume admission")
    lines = (result or "").strip().splitlines()
    if not lines:
        raise DeployError(f"encrypted_volume: the read-only admission of {cfg.device} failed; nothing was changed")
    refused = _REFUSED.match(lines[-1])
    if refused:
        raise DeployError(f"encrypted_volume: {refused['reason']}; nothing was changed")
    if len(lines) < 2 or not lines[-2].startswith("pending=") or lines[-1] not in ("changed=true", "changed=false"):
        raise DeployError("encrypted_volume: the admission answered something unexpected; nothing was changed")
    pending = tuple(step for step in lines[-2].removeprefix("pending=").split(",") if step)
    if bool(pending) != (lines[-1] == "changed=true"):
        raise DeployError("encrypted_volume: the admission contradicts itself; nothing was changed")
    return pending


@deploy("Prepare encrypted volume")
def deploy_encrypted_volume(cfg: EncryptedVolumeConfig, passphrase: SecretStr) -> None:
    secret = passphrase.get_secret_value()
    if not secret:
        raise ValueError("the encrypted volume passphrase must not be empty")
    if "\0" in secret:
        raise ValueError("the encrypted volume passphrase must not contain NUL")
    require_linux("encrypted_volume")
    pending = admission(cfg)

    if not host.get_fact(Which, command="cryptsetup"):
        apt.packages(name="Install cryptsetup", packages=list(cfg.packages))
    keyfile = PurePosixPath(cfg.keyfile)
    files.directory(name=f"Ensure {keyfile.parent}", path=str(keyfile.parent), user="root", group="root", mode="0700")
    secret_file(
        name=f"Write the keyfile {keyfile}",
        path=keyfile,
        content=SecretContent(secret),
        user=cfg.keyfile_owner,
        group=cfg.keyfile_group,
        mode=cfg.keyfile_mode,
    )
    # Before the mount, as the role does: on a mounted volume this is the filesystem's root.
    files.directory(
        name=f"Ensure the mount point {cfg.mount_point}",
        path=cfg.mount_point,
        user=cfg.mount_owner,
        group=cfg.mount_group,
        mode=cfg.mount_mode,
    )
    if pending:
        server.shell(
            name=f"Open, record and mount {cfg.mapper_path} ({', '.join(pending)})",
            commands=[host_command(cfg, "apply")],
        )
    files.file(name=f"Ensure {CRYPTTAB} ownership and mode", path=CRYPTTAB, user="root", group="root", mode="0640")
    files.file(name=f"Ensure {FSTAB} ownership and mode", path=FSTAB, user="root", group="root", mode="0644")
    verify_probe(
        host_command(cfg, "check"), name=f"{cfg.mapper_path} mounted at {cfg.mount_point}", expect="changed=false"
    )
