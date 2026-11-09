"""SnappyMail ordinary deployment API."""

from pyinfra.api import deploy

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.snappymail.config import SnappyMailConfig


@deploy("SnappyMail")
def deploy_snappymail(cfg: SnappyMailConfig, secrets: SecretValues) -> None:
    from ops_deploy.services._mail_web.deploy import deploy as run

    run(cfg, secrets)


__all__ = ["SnappyMailConfig", "deploy_snappymail"]
