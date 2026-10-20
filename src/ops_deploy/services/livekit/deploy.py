"""livekit: the LiveKit SFU and its Egress on compose_app, plus the role's own Traefik route.

Port of the ``livekit_deploy`` Ansible role. :meth:`LivekitConfig.compose_app`
maps the role's inputs onto a :class:`~ops_deploy.services.compose_app.ComposeAppConfig`
(the same project, container names, host networking, ``SYS_ADMIN`` and 1 GiB
``/dev/shm`` for Egress's Chrome, the two config files as bind mounts), so a
run decides from the applied stamp and read-only probes like every Compose
app: a converged host gets no mutating operation, and no container is
recreated or restarted unless its inputs changed.

The route is not compose_app's (that one fronts a published loopback port; both
services use the host network): :func:`render_route` writes the role's
template byte for byte, one public router with the forwarded-header
middleware, and Traefik's file provider picks it up (no restart).

Redis and the S3 bucket are external services on the host; this deploy only
points the config files at them.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from pathlib import PurePath, PurePosixPath
from typing import Annotated, Any, ClassVar, Self, cast

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pyinfra.api import deploy

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import TraefikRoute, traefik_route
from ops_deploy.helpers.traefik import Hostname
from ops_deploy.services.compose_app import (
    Bind,
    Checks,
    ComposeAppConfig,
    ComposeService,
    ConfigFile,
    Directory,
    EnvEntry,
    HttpCheck,
    Secret,
    SecretKeyed,
    deploy_compose_app,
)
from ops_deploy.services.compose_app.config import ComposeProject, ImageRef, PlainPath

TEMPLATE_PACKAGE = "ops_deploy.services.livekit"
ROUTE_NAME = "livekit"
SERVER = "livekit-server"
EGRESS = "livekit-egress"
# Where each container reads its config (the role's mount targets).
SERVER_CONFIG = PurePosixPath("/etc/livekit/livekit.yaml")
EGRESS_CONFIG = PurePosixPath("/etc/egress.yaml")

# One line in double quotes in YAML: no quotes, backslashes, ``$`` or whitespace.
Url = Annotated[str, Field(pattern=r"^https?://[^\s\"'\\$`]+$")]
Endpoint = Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]+:[0-9]{1,5}$")]
Bucket = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
Port = Annotated[int, Field(ge=1, le=65535)]


class LivekitConfig(BaseServiceConfig):
    """The role's inputs. Images are digest-pinned; secrets come from ``secrets``.

    ``traefik_host`` ``None`` writes no route (the role's
    ``livekit_traefik_enabled: false``; an existing route file is left alone).
    """

    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "api_key",
        "api_secret",
        "redis_password",
        "s3_access_key",
        "s3_secret_key",
    )

    service_name: ServiceName = "livekit"
    # The containers run as root (the server) and as the image's ``egress`` user.
    user: UnixUser = "root"
    site_path: PlainPath = PurePosixPath("/opt/livekit")
    config_dir: PlainPath = PurePosixPath("/etc/livekit")
    project: ComposeProject = "livekit"
    title: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ]{1,60}$")] = "LiveKit Stack"
    server_image: ImageRef
    egress_image: ImageRef
    http_port: Port = 7880
    rtc_tcp_port: Port = 7881
    rtc_port_range_start: Port = 50000
    rtc_port_range_end: Port = 50100
    # The LAN address written to ``rtc.node_ip`` (the ICE candidate clients receive).
    node_ip: str
    webhook_url: Url
    redis_address: Endpoint = "127.0.0.1:6379"
    s3_endpoint: Url = "http://127.0.0.1:9001"
    s3_bucket: Bucket = "recorder"
    traefik_host: Hostname | None
    # Seconds the HTTP check waits for the server after a run that applied.
    healthcheck_timeout: int = Field(default=60, ge=1, le=600)

    @field_validator("config_dir", mode="before")
    @classmethod
    def _config_dir_from_path(cls, value: Any, info: ValidationInfo) -> Any:
        # JSON and strings mode reject path instances, the validated default too
        # (BaseServiceConfig does the same for site_path).
        if info.mode != "python" and isinstance(value, PurePath):
            return str(value)
        return value

    @field_validator("node_ip")
    @classmethod
    def _ipv4(cls, value: str) -> str:
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError("node_ip must be an IPv4 address") from None
        return value

    @model_validator(mode="after")
    def _ports(self) -> Self:
        if self.rtc_port_range_start > self.rtc_port_range_end:
            raise ValueError("rtc_port_range_start must not be above rtc_port_range_end")
        if self.user != "root":
            raise ValueError("livekit runs as root; user must be root")
        if self.site_path == self.config_dir:
            raise ValueError("site_path and config_dir must differ")
        return self

    @property
    def server_config_path(self) -> PurePosixPath:
        return self.config_dir / "livekit.yaml"

    @property
    def egress_config_path(self) -> PurePosixPath:
        return self.config_dir / "egress.yaml"

    def server_config(self) -> dict[str, Any]:
        """``livekit.yaml``: the role's template as data."""

        return {
            "port": self.http_port,
            "rtc": {
                "tcp_port": self.rtc_tcp_port,
                "port_range_start": self.rtc_port_range_start,
                "port_range_end": self.rtc_port_range_end,
                "use_external_ip": False,
                "node_ip": self.node_ip,
            },
            "redis": {"address": self.redis_address, "password": Secret(secret="redis_password")},
            "keys": SecretKeyed(secret_key=Secret(secret="api_key"), value=Secret(secret="api_secret")),
            "webhook": {"api_key": Secret(secret="api_key"), "urls": [self.webhook_url]},
            "logging": {"level": "info"},
        }

    def egress_config(self) -> dict[str, Any]:
        """``egress.yaml``: the role's template as data."""

        return {
            "redis": {"address": self.redis_address, "password": Secret(secret="redis_password")},
            "api_key": Secret(secret="api_key"),
            "api_secret": Secret(secret="api_secret"),
            "ws_url": f"ws://127.0.0.1:{self.http_port}",
            "s3": {
                "access_key": Secret(secret="s3_access_key"),
                "secret": Secret(secret="s3_secret_key"),
                "region": "us-east-1",
                "endpoint": self.s3_endpoint,
                "bucket": self.s3_bucket,
                "force_path_style": True,
            },
            "logging": {"level": "info"},
        }

    def compose_app(self) -> ComposeAppConfig:
        """The Compose app: names, images, privileges and mounts of the role's compose file."""

        reason = "WebRTC media ports reach the NIC directly; Redis and S3 listen on host loopback"
        server = ComposeService(
            name=SERVER,
            image=self.server_image,
            container_name=SERVER,
            network_mode="host",
            host_network_reason=reason,
            command=("--config", str(SERVER_CONFIG)),
            binds=(Bind(source=self.server_config_path, target=SERVER_CONFIG, read_only=True),),
        )
        egress = ComposeService(
            name=EGRESS,
            image=self.egress_image,
            container_name=EGRESS,
            network_mode="host",
            host_network_reason=reason,
            environment=(EnvEntry(key="EGRESS_CONFIG_FILE", value=str(EGRESS_CONFIG)),),
            # Chrome (composite recordings) needs a large /dev/shm and its sandbox.
            shm_size="1g",
            cap_add=("SYS_ADMIN",),
            binds=(Bind(source=self.egress_config_path, target=EGRESS_CONFIG, read_only=True),),
        )
        return ComposeAppConfig(
            service_name=self.service_name,
            title=self.title,
            project=self.project,
            compose_file="docker-compose.yml",
            user="root",
            site_path=self.site_path,
            secrets=self.secrets,
            directories=(Directory(path=self.site_path), Directory(path=self.config_dir)),
            config_files=(
                # The server runs as root.
                ConfigFile(
                    path=self.server_config_path,
                    format="yaml",
                    data=self.server_config(),
                    mode="0600",
                    restarts=(SERVER,),
                ),
                # The egress image's user has primary group root (gid 0): group read is enough.
                ConfigFile(
                    path=self.egress_config_path,
                    format="yaml",
                    data=self.egress_config(),
                    mode="0640",
                    restarts=(EGRESS,),
                ),
            ),
            services=(server, egress),
            checks=Checks(
                http=(HttpCheck(url=f"http://127.0.0.1:{self.http_port}/", retries=self.healthcheck_timeout),)
            ),
        )

    def route(self) -> TraefikRoute | None:
        if self.traefik_host is None:
            return None
        return TraefikRoute(name=ROUTE_NAME, host=self.traefik_host, app_port=self.http_port)


def render_route(cfg: LivekitConfig) -> str:
    """The role's ``livekit-traefik.yml.j2``, byte for byte."""

    return render(TEMPLATE_PACKAGE, "livekit-traefik.yml.j2", cfg=cfg)


def check_livekit_secrets(cfg: LivekitConfig, secrets: SecretValues) -> None:
    """The role's asserts (set, not ``CHANGEME``) plus a set Redis password. Errors name keys only."""

    secrets.require(cfg.required_secret_keys)
    for key in cfg.required_secret_keys:
        if not secrets[key].strip():
            raise ValueError(f"secret {key} must be set")


def deploy_livekit(cfg: LivekitConfig, secrets: SecretValues) -> None:
    """The Compose app (``Deploy livekit | ...``), then the route (``Deploy livekit route | ...``)."""

    check_livekit_secrets(cfg, secrets)
    app = cfg.compose_app()
    route = cfg.route()
    text = render_route(cfg) if route is not None else None
    deploy_compose_app(app, secrets)
    if route is not None and text is not None:
        named = cast(Callable[[TraefikRoute, str], None], deploy(f"Deploy {cfg.service_name} route")(_route))
        named(route, text)


def _route(route: TraefikRoute, text: str) -> None:
    # The file provider watches the directory: Traefik is never restarted.
    traefik_route(route, renderer=lambda _route, _hash: text, restart="none")
