"""zellij_ingress: the private redirect-only Traefik route for the Zellij web client.

Port of the ``zellij_ingress_deploy`` role and its playbook's single task list.
"""

from ops_deploy.services.zellij_ingress.deploy import (
    DEFAULT_ALLOWED_IP_RANGES,
    DEFAULT_CONFIG_PATH,
    ZellijIngressConfig,
    deploy_zellij_ingress,
    render_route,
)

__all__ = [
    "DEFAULT_ALLOWED_IP_RANGES",
    "DEFAULT_CONFIG_PATH",
    "ZellijIngressConfig",
    "deploy_zellij_ingress",
    "render_route",
]
