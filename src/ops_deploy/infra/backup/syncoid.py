"""Configure the original local syncoid jobs and timer without invoking syncoid."""

from pyinfra.api import deploy

from .common import prerequisites, resource, timer
from .config import SyncoidConfig


@deploy("Configure original local ZFS replication")
def deploy_syncoid(cfg: SyncoidConfig) -> None:
    if not cfg.enabled:
        return
    prerequisites(cfg)
    if cfg.alert_enabled:
        resource(cfg, "zfs-syncoid-alert.sh", cfg.alert_script_path)
    if cfg.spindown_enabled:
        resource(cfg, "zfs-syncoid-spindown.sh", cfg.spindown_script_path)
    resource(cfg, "zfs-syncoid-prune-conflicts.sh", cfg.prune_script_path)
    resource(cfg, "zfs-syncoid-abort-partial-receive.sh", cfg.abort_partial_receive_script_path)
    timer(cfg, "zfs-syncoid")
