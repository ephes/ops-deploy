"""Toy uv/Django web service that exercises the deploy helpers end to end."""

from ops_deploy.services.toyweb.deploy import ToywebConfig, deploy_toyweb

__all__ = ["ToywebConfig", "deploy_toyweb"]
