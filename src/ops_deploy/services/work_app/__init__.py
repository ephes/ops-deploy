"""work_app: the work ledger (port of the work_app_deploy role and its playbook wiring)."""

from ops_deploy.services.work_app.deploy import WorkAppConfig, deploy_work_app

__all__ = ["WorkAppConfig", "deploy_work_app"]
