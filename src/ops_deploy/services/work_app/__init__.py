"""work_app: the work ledger (port of the work_app_deploy role and its playbook wiring)."""

from ops_deploy.services.work_app.backup import WorkAppBackupConfig, deploy_work_app_backup
from ops_deploy.services.work_app.deploy import WorkAppConfig, deploy_work_app
from ops_deploy.services.work_app.remove import WorkAppRemoveConfig, deploy_work_app_remove
from ops_deploy.services.work_app.restore import WorkAppRestoreConfig, deploy_work_app_restore

__all__ = [
    "WorkAppBackupConfig",
    "WorkAppConfig",
    "WorkAppRemoveConfig",
    "WorkAppRestoreConfig",
    "deploy_work_app",
    "deploy_work_app_backup",
    "deploy_work_app_remove",
    "deploy_work_app_restore",
]
