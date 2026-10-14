"""FastDeploy: deploy platform on PostgreSQL (port of the fastdeploy_deploy role)."""

from ops_deploy.services.fastdeploy.deploy import FastdeployConfig, deploy_fastdeploy

__all__ = ["FastdeployConfig", "deploy_fastdeploy"]
