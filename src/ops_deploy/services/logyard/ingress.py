"""logyard ingress: the private Traefik route for Loki's push and readiness endpoints.

Port of the ``logyard_ingress_deploy`` role and ``playbooks/deploy-logyard-ingress.yml``.
Only the producer push path and the readiness probe are routed (Loki runs
without auth), from internal networks. The role's template is shipped
unchanged; the route file is byte-identical to what the role writes. Like the
role, nothing restarts Traefik: its file provider watches the directory.
"""

from __future__ import annotations

import ipaddress
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pyinfra.api import deploy

from ops_deploy.base import RoleConfig
from ops_deploy.helpers import TraefikRoute, traefik_route
from ops_deploy.helpers.traefik import DEFAULT_INTERNAL_IP_RANGES, Hostname
from ops_deploy.services.logyard._common import Part, Url, render_role

EXAMPLE_HOST = "logyard.example.com"
Method = Annotated[str, Field(pattern=r"^[A-Z]+$")]


class AllowedPath(Part):
    """One exact path and the HTTP methods routed to Loki."""

    path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")]
    methods: tuple[Method, ...] = Field(min_length=1)


# Vector's loki sink pushes to /loki/api/v1/push and its healthcheck reads /ready.
DEFAULT_ALLOWED_PATHS = (
    AllowedPath(path="/loki/api/v1/push", methods=("POST",)),
    AllowedPath(path="/ready", methods=("GET", "HEAD")),
)


class LogyardIngressConfig(RoleConfig):
    """The role's variables without the ``logyard_ingress_`` prefix (defaults from its defaults/main.yml)."""

    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    host: Hostname = EXAMPLE_HOST
    backend_url: Url = "http://127.0.0.1:3101"
    root_redirect_enabled: bool = True
    root_redirect_url: Annotated[str, Field(pattern=r"^(https?://[^\s\"'\\$`]+)?$")] = (
        "https://grafana.home.xn--wersdrfer-47a.de/d/logyard-home/logyard-overview"
    )
    middlewares: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9@_-]+$")], ...] = ()
    allowed_paths: tuple[AllowedPath, ...] = Field(default=DEFAULT_ALLOWED_PATHS, min_length=1)
    internal_ip_ranges: tuple[str, ...] = Field(default=DEFAULT_INTERNAL_IP_RANGES, min_length=1)

    @field_validator("internal_ip_ranges")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("internal_ip_ranges must contain IP networks") from None
        return value

    @model_validator(mode="after")
    def _role_asserts(self) -> LogyardIngressConfig:
        if self.host == EXAMPLE_HOST:
            raise ValueError(f"host must be set (not {EXAMPLE_HOST})")
        if self.root_redirect_enabled and not self.root_redirect_url:
            raise ValueError("root_redirect_url is required when the root redirect is enabled")
        if urlsplit(self.backend_url).port is None:
            raise ValueError("backend_url needs a port")
        return self


def role_vars(cfg: LogyardIngressConfig) -> dict[str, object]:
    return {
        "logyard_ingress_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "logyard_ingress_host": cfg.host,
        "logyard_ingress_backend_url": cfg.backend_url,
        "logyard_ingress_root_redirect_enabled": cfg.root_redirect_enabled,
        "logyard_ingress_root_redirect_url": cfg.root_redirect_url,
        "logyard_ingress_middlewares": list(cfg.middlewares),
        "logyard_ingress_allowed_paths": [
            {"path": entry.path, "methods": list(entry.methods)} for entry in cfg.allowed_paths
        ],
        "logyard_ingress_internal_ip_ranges": list(cfg.internal_ip_ranges),
    }


def render_route(cfg: LogyardIngressConfig) -> str:
    return render_role("traefik-logyard.yml.j2", role_vars(cfg))


def traefik_config(cfg: LogyardIngressConfig) -> TraefikRoute:
    # Only the file name and directory come from this; the role's own template renders the content.
    port = urlsplit(cfg.backend_url).port
    assert port is not None
    return TraefikRoute(name="logyard", host=cfg.host, app_port=port, cert_resolver=cfg.traefik_cert_resolver)


def ingress_steps(cfg: LogyardIngressConfig) -> None:
    traefik_route(traefik_config(cfg), renderer=lambda _route, _hash: render_route(cfg), restart="none")


@deploy("Deploy logyard ingress")
def deploy_logyard_ingress(cfg: LogyardIngressConfig) -> None:
    ingress_steps(cfg)
