"""Archive backup (``playbooks/archive/backup.yml``): one run of the registered ``echoport-backup`` runner."""

from __future__ import annotations

from pyinfra.api import deploy

from ops_deploy.base._common import AbsolutePath
from ops_deploy.core.config import ServiceName
from ops_deploy.services._lifecycle.echoport_runner import EchoportRunnerBackupConfig, Label, echoport_runner_backup


class ArchiveBackupConfig(EchoportRunnerBackupConfig):
    """The play's values: the Archive SQLite database, no service stop."""

    target: ServiceName = "archive"
    label: Label = "Archive"
    db_path: AbsolutePath = "/home/archive/site/db.sqlite3"


@deploy("Archive backup")
def deploy_archive_backup(cfg: ArchiveBackupConfig) -> None:
    echoport_runner_backup(cfg)


__all__ = ["ArchiveBackupConfig", "deploy_archive_backup"]
