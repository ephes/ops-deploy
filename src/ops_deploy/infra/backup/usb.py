"""Configure original USB rotation/anchors/retention; deploy never imports a drive."""

from pydantic import SecretStr
from pyinfra.api import deploy
from pyinfra.operations import files

from .common import key_input, original_file, prerequisites, private_key, resource, timer
from .config import UsbReplicationConfig


@deploy("Configure original rotating USB replication")
def deploy_usb_replication(cfg: UsbReplicationConfig, key: SecretStr | None = None) -> None:
    if not cfg.enabled:
        return
    material = key_input(key) if cfg.key_manage else None
    prerequisites(cfg)
    files.directory(name="Original USB status directory", path=cfg.state_dir, user="root", group="root", mode="0755")
    original_file("zfs_usb_replication_state.py", cfg.state_writer_path, "0755")
    files.directory(
        name="Original attended attestation directory",
        path=cfg.attestation_dir or cfg.state_dir + "/attestations",
        user="root",
        group="root",
        mode="0700",
    )
    original_file("zfs_snapshot_file_attestation.py", cfg.attestation_helper_path, "0750")
    if cfg.snapshot_retention:
        original_file("zfs_usb_snapshot_retention.py", cfg.retention_script_path, "0755")
    if cfg.anchor_mode == "bookmark":
        original_file("zfs_usb_bookmark_anchors.py", cfg.anchor_helper_path, "0755")
    if material is not None:
        private_key(
            name="Original USB pool key, private stdin/RAM equality", path=cfg.key_path, content=material, kind="zfs"
        )
    if cfg.alert_enabled:
        resource(cfg, "zfs-usb-alert.sh", cfg.alert_script_path)
    if cfg.spindown_enabled:
        resource(cfg, "zfs-usb-spindown.sh", cfg.spindown_script_path)
    resource(cfg, "zfs-usb-replication.sh", "/usr/local/bin/zfs-usb-replication.sh")
    timer(cfg, "zfs-usb")
