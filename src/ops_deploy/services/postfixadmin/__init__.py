"""PostfixAdmin ordinary deployment API."""

from pyinfra.api import deploy

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.postfixadmin.config import PostfixAdminConfig


@deploy("PostfixAdmin")
def deploy_postfixadmin(cfg: PostfixAdminConfig, secrets: SecretValues) -> None:
    from ops_deploy.services._mail_web.deploy import deploy as run

    run(cfg, secrets)


__all__ = ["PostfixAdminConfig", "deploy_postfixadmin"]
