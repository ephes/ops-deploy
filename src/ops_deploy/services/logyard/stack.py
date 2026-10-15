"""logyard stack: core, ingress and the Vector producer in the playbook's order (``deploy-logyard.yml``)."""

from __future__ import annotations

from pyinfra.api import deploy

from ops_deploy.base import RoleConfig
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.logyard.core import LogyardConfig, core_steps
from ops_deploy.services.logyard.ingress import LogyardIngressConfig, ingress_steps
from ops_deploy.services.logyard.vector import LogyardVectorConfig, vector_steps


class LogyardStackConfig(RoleConfig):
    core: LogyardConfig
    ingress: LogyardIngressConfig
    vector: LogyardVectorConfig


@deploy("Deploy logyard")
def deploy_logyard(
    cfg: LogyardStackConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    core_steps(cfg.core, secrets, rsync)
    ingress_steps(cfg.ingress)
    vector_steps(cfg.vector)
