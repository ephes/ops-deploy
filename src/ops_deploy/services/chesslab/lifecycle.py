"""Chesslab backup (``playbooks/chesslab/backup.yml``): one run of the registered ``echoport-backup`` runner."""

from __future__ import annotations

from pyinfra.api import deploy

from ops_deploy.base._common import AbsolutePath
from ops_deploy.core.config import ServiceName
from ops_deploy.services._lifecycle.echoport_runner import (
    EchoportRunnerBackupConfig,
    Label,
    Owner,
    Unit,
    echoport_runner_backup,
)


class ChesslabBackupConfig(EchoportRunnerBackupConfig):
    """The play's values: the runner stops ``chesslab.service`` and restores owner ``chesslab:chesslab``."""

    target: ServiceName = "chesslab"
    label: Label = "Chesslab"
    db_path: AbsolutePath = "/home/chesslab/data/chess.db"
    service_name: Unit | None = "chesslab.service"
    restore_owner: Owner | None = "chesslab:chesslab"


@deploy("Chesslab backup")
def deploy_chesslab_backup(cfg: ChesslabBackupConfig) -> None:
    echoport_runner_backup(cfg)


__all__ = ["ChesslabBackupConfig", "deploy_chesslab_backup"]
