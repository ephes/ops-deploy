"""nyxmon: Django dashboard and monitoring agent (port of the nyxmon_deploy role)."""

from ops_deploy.services.nyxmon.deploy import NyxmonConfig, deploy_nyxmon

__all__ = ["NyxmonConfig", "deploy_nyxmon"]
