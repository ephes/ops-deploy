"""weeknotes.home: the daybook steering inbox (port of the weeknotes_home_deploy role and its playbook wiring)."""

from ops_deploy.services.weeknotes_home.deploy import WeeknotesHomeConfig, deploy_weeknotes_home

__all__ = ["WeeknotesHomeConfig", "deploy_weeknotes_home"]
