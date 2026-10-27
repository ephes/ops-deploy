"""The original voxhelm private ingress role, including its conditional handler."""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath
from typing import Self
from urllib.parse import urlsplit

import jinja2
import yaml
from pydantic import field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.operations import files, server

from ops_deploy.base import RoleConfig
from ops_deploy.base._common import require_linux
from ops_deploy.services._traefik_routes import route_put


class VoxhelmIngressConfig(RoleConfig):
    traefik_enabled: bool = True
    traefik_host: str = ""
    traefik_entrypoints: tuple[str, ...] = ("web-secure",)
    traefik_cert_resolver: str = ""
    traefik_config_path: str = "/etc/traefik/dynamic/voxhelm.yml"
    backend_url: str
    allowed_ip_ranges: tuple[str, ...] = ("127.0.0.1/32", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48")
    internal_api_enabled: bool = False
    internal_api_allowed_ip_ranges: tuple[str, ...] = ()
    internal_api_block_ip_ranges: tuple[str, ...] = ("255.255.255.255/32",)

    @field_validator("traefik_host")
    @classmethod
    def _host(cls, value: str) -> str:
        if value and not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value):
            raise ValueError("Traefik host must be a literal DNS hostname")
        return value

    @field_validator("backend_url")
    @classmethod
    def _backend(cls, value: str) -> str:
        parts = urlsplit(value)
        if (
            not re.fullmatch(r"https?://[A-Za-z0-9.:/\[\]_-]+", value)
            or not parts.hostname
            or parts.username
            or parts.password
        ):
            raise ValueError("backend URL must be HTTP(S) without credentials or template characters")
        if parts.port == 0:
            raise ValueError("backend port must be positive")
        return value

    @field_validator("traefik_entrypoints", "traefik_cert_resolver")
    @classmethod
    def _words(cls, value: tuple[str, ...] | str) -> tuple[str, ...] | str:
        for word in (value,) if isinstance(value, str) else value:
            if word and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", word) or yaml.safe_load(word) != word):
                raise ValueError("entrypoints and certificate resolver must be plain YAML words")
        return value

    @field_validator("traefik_config_path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not re.fullmatch(r"/etc/traefik/dynamic/[a-z0-9][a-z0-9_.-]*\.yml", value):
            raise ValueError("ingress path must be a single file in Traefik's dynamic directory")
        return value

    @field_validator("allowed_ip_ranges", "internal_api_allowed_ip_ranges", "internal_api_block_ip_ranges")
    @classmethod
    def _networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not re.fullmatch(r"[0-9A-Fa-f:.]+(/[0-9]{1,3})?", value):
                raise ValueError("source ranges must be literal IP addresses or CIDRs")
            ipaddress.ip_network(value, strict=False)
        return values

    @model_validator(mode="after")
    def _required(self) -> Self:
        if self.traefik_enabled and (
            not self.traefik_host or not self.allowed_ip_ranges or not self.traefik_entrypoints
        ):
            raise ValueError("enabled ingress requires its hostname, entrypoints and allowed source ranges")
        if self.traefik_enabled:
            selected = (
                self.internal_api_allowed_ip_ranges if self.internal_api_enabled else self.internal_api_block_ip_ranges
            )
            if not selected:
                raise ValueError("the selected worker-internal API policy requires explicit source ranges")
        return self


def render_ingress(cfg: VoxhelmIngressConfig) -> str:
    environment = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.voxhelm", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    environment.filters["bool"] = bool
    values = {"voxhelm_ingress_" + key: value for key, value in cfg.model_dump().items()}
    return environment.get_template("voxhelm-traefik.yml.j2").render(values)


@deploy("Deploy Voxhelm ingress")
def deploy_voxhelm_ingress(cfg: VoxhelmIngressConfig) -> None:
    if not cfg.traefik_enabled:
        return
    require_linux("Voxhelm ingress")
    files.directory(
        name="Ensure Traefik dynamic directory",
        path=str(PurePosixPath(cfg.traefik_config_path).parent),
        user="root",
        group="root",
        mode="0755",
    )
    route = route_put(name="Publish Voxhelm private ingress", src=render_ingress(cfg), dest=cfg.traefik_config_path)
    server.shell(
        name="Reload Traefik, restart only when reload fails",
        commands=[
            "systemctl reload traefik || { "
            "printf 'Traefik reload failed; trying restart\\n' >&2; systemctl restart traefik; }"
        ],
        _if=lambda: route.did_change(),
    )
