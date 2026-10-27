"""Native two-account OpsGate control plane and runner."""

from .config import OpsGateConfig, WorkspaceRepository
from .deploy import deploy_opsgate

__all__ = ["OpsGateConfig", "WorkspaceRepository", "deploy_opsgate"]

from .ingress import OpsGateIngressConfig, deploy_opsgate_ingress

__all__ += ["OpsGateIngressConfig", "deploy_opsgate_ingress"]
