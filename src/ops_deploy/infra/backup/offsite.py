"""Original SSH/directory preparation for the two explicitly typed pull jobs."""

from pathlib import PurePosixPath

from pydantic import SecretStr
from pyinfra.operations import files, server

from .common import known_host, private_key
from .config import OffsiteConfig


def prepare(cfg: OffsiteConfig, material: SecretStr | None) -> None:
    files.directory(
        name="Original replication SSH directory",
        path=str(PurePosixPath(cfg.ssh_key_path).parent),
        user="root",
        group="root",
        mode="0700",
    )
    if material is not None:
        private_key(
            name="Original offsite SSH key via private stdin", path=cfg.ssh_key_path, content=material, kind="ssh"
        )
    if cfg.manage_known_hosts:
        known_host(
            name="Original fresh peer keyscan/selected host-key reconciliation",
            path=cfg.ssh_known_hosts_path,
            peer=cfg.source_host,
            key_type=cfg.ssh_keyscan_type,
        )
    if cfg.destination_group != "root":
        server.group(name="Original backup destination group", group=cfg.destination_group, system=True)
    files.directory(
        name="Original offsite destination root metadata",
        path=cfg.destination_path,
        user=cfg.destination_owner,
        group=cfg.destination_group,
        mode=cfg.destination_mode,
    )
    files.directory(
        name="Original offsite status directory metadata",
        path=cfg.status_dir,
        user=cfg.status_owner,
        group=cfg.status_group,
        mode=cfg.status_mode,
    )
