"""zellij_ingress: a private, redirect-only Traefik route for the Zellij web client.

Port of the ``zellij_ingress_deploy`` role. Zellij's web client stays on the
backend host's loopback behind an HTTPS front end; this deploy only writes
one Traefik dynamic config on the edge host that sends allowlisted clients
of a friendly host name to that fixed URL with a temporary redirect.

The role's template is shipped unchanged (header included) and rendered like
Ansible's ``template`` module, so the route file is byte-identical to what
the role writes and a converged host sees no change. Unlike the role, which
reloads (or, when reloading fails, restarts) Traefik after a change, nothing
here touches Traefik: its file provider watches the directory. Nothing
touches the backend, its front end, certificates or Traefik's static config.
"""

from __future__ import annotations

import ipaddress
import re
from functools import cache
from typing import Annotated, Any
from urllib.parse import urlsplit

import jinja2
import yaml
from pydantic import Field, field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.operations import files

from ops_deploy.base import RoleConfig
from ops_deploy.helpers.traefik import DYNAMIC_DIR
from ops_deploy.services._traefik_routes import route_put

TEMPLATE_PACKAGE = "ops_deploy.services.zellij_ingress"
TEMPLATE = "zellij-traefik.yml.j2"
DEFAULT_CONFIG_PATH = str(DYNAMIC_DIR / "zellij.yml")
# zellij_ingress_deploy/defaults/main.yml: loopback and the Tailscale ranges.
DEFAULT_ALLOWED_IP_RANGES = ("127.0.0.1/32", "::1/128", "100.64.0.0/10", "fd7a:115c:a1e0::/48")

_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = re.compile(rf"^{_LABEL}(\.{_LABEL})*$")
# Rendered unquoted into YAML (``- web-secure``, ``certResolver: x``).
_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
# Inside ClientIP(`...`) in a double-quoted YAML string.
_NETWORK = re.compile(r"^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$")
# The redirect target lands in a double-quoted YAML string and is a Traefik
# redirectRegex replacement (``$`` would name a capture group): only URL
# characters without quoting, escapes, ``$``, credentials, query or fragment.
_TARGET_CHARS = re.compile(r"^[A-Za-z0-9._~:/-]+$")
_TARGET_PATH = re.compile(r"^(/[A-Za-z0-9._~/-]*)?$")
_CONFIG_PATH = re.compile(rf"^{re.escape(str(DYNAMIC_DIR))}/[a-z0-9][a-z0-9_-]{{0,62}}\.yml$")

Name = Annotated[str, Field(max_length=64)]


def _yaml_word(value: str) -> bool:
    """A plain word that YAML reads back as the same string (not ``true``, ``1``, ``null``)."""

    return bool(_WORD.fullmatch(value)) and yaml.safe_load(value) == value


def _valid_target(value: str) -> bool:
    if not _TARGET_CHARS.fullmatch(value):
        return False
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or parts.query or parts.fragment:
        return False
    if not parts.netloc or "@" in parts.netloc or not _HOSTNAME.fullmatch(parts.hostname or ""):
        return False
    try:
        port = parts.port
    except ValueError:
        return False
    if port is None and parts.netloc.lower() != parts.hostname:
        return False  # a trailing ``:`` without a port
    if port == 0:
        return False
    return bool(_TARGET_PATH.fullmatch(parts.path)) and len(value) <= 2048


class ZellijIngressConfig(RoleConfig):
    """The role's variables without the ``zellij_ingress_`` prefix (defaults from its defaults/main.yml)."""

    traefik_enabled: bool = True
    # Required when enabled (the role asserts it then).
    traefik_host: Annotated[str, Field(max_length=253)] = ""
    # Always required, like the role's first assertion.
    redirect_target: str
    traefik_entrypoints: tuple[Name, ...] = ("web-secure",)
    traefik_cert_resolver: Name = ""
    # Below Traefik's watched dynamic directory only: the directory is what the role creates.
    traefik_config_path: str = DEFAULT_CONFIG_PATH
    allowed_ip_ranges: tuple[str, ...] = DEFAULT_ALLOWED_IP_RANGES

    @field_validator("traefik_host")
    @classmethod
    def _host(cls, value: str) -> str:
        if value and not _HOSTNAME.fullmatch(value):
            raise ValueError("traefik_host must be a DNS host name")
        return value

    @field_validator("redirect_target")
    @classmethod
    def _target(cls, value: str) -> str:
        if not value:
            raise ValueError("redirect_target is required")
        if not _valid_target(value):
            raise ValueError(
                "redirect_target must be an http(s) URL with a host name, optional port and plain path "
                "(no credentials, query, fragment, quotes, spaces or $)"
            )
        return value

    @field_validator("traefik_entrypoints")
    @classmethod
    def _entrypoints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # An empty list would render ``entryPoints:`` as null: every entry point.
        if not value:
            raise ValueError("traefik_entrypoints must not be empty")
        if not all(_yaml_word(item) for item in value):
            raise ValueError("traefik_entrypoints must be plain names")
        return value

    @field_validator("traefik_cert_resolver")
    @classmethod
    def _resolver(cls, value: str) -> str:
        if value and not _yaml_word(value):
            raise ValueError("traefik_cert_resolver must be a plain name")
        return value

    @field_validator("traefik_config_path")
    @classmethod
    def _config_path(cls, value: str) -> str:
        if not _CONFIG_PATH.fullmatch(value):
            raise ValueError(f"traefik_config_path must be a .yml file directly in {DYNAMIC_DIR}")
        return value

    @field_validator("allowed_ip_ranges")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not _NETWORK.fullmatch(item):
                raise ValueError("allowed_ip_ranges must contain IP networks in CIDR notation")
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("allowed_ip_ranges must contain IP networks in CIDR notation") from None
        return value

    @model_validator(mode="after")
    def _role_asserts(self) -> ZellijIngressConfig:
        if self.traefik_enabled:
            if not self.traefik_host:
                raise ValueError("traefik_host is required when Traefik is enabled")
            if not self.allowed_ip_ranges:
                raise ValueError("allowed_ip_ranges must not be empty when Traefik is enabled")
        return self


def role_vars(cfg: ZellijIngressConfig) -> dict[str, Any]:
    return {
        "zellij_ingress_traefik_enabled": cfg.traefik_enabled,
        "zellij_ingress_traefik_host": cfg.traefik_host,
        "zellij_ingress_redirect_target": cfg.redirect_target,
        "zellij_ingress_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "zellij_ingress_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "zellij_ingress_traefik_config_path": cfg.traefik_config_path,
        "zellij_ingress_allowed_ip_ranges": list(cfg.allowed_ip_ranges),
    }


@cache
def _environment() -> jinja2.Environment:
    # Rendered like Ansible's template module (trim_blocks), for byte parity.
    return jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render_route(cfg: ZellijIngressConfig) -> str:
    return _environment().get_template(TEMPLATE).render(**role_vars(cfg))


@deploy("Deploy Zellij ingress")
def deploy_zellij_ingress(cfg: ZellijIngressConfig) -> None:
    """Write the route file when enabled; disabled is the role's no-op (nothing is removed)."""

    if not cfg.traefik_enabled:
        return
    files.directory(
        name="Ensure Traefik dynamic directory",
        path=str(DYNAMIC_DIR),
        user="root",
        group="root",
        mode="0755",
    )
    route_put(name="Write Traefik route zellij", src=render_route(cfg), dest=cfg.traefik_config_path, mode="0644")
