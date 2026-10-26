"""Shared account, authentication and bind inputs of the two metrics endpoints.

The release switch remains in services._metrics_httpd. Credentials use the same
bcrypt verification/hash behavior as thermal_monitoring, without rewriting a
verifying htpasswd file or resetting an existing service account's home.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal

from pydantic import Field, StrictInt, model_validator
from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.ops import secret_file
from ops_deploy.services._metrics_httpd import HttpdSwitchFields
from ops_deploy.services.nyxmon_site_checks.deploy import PlainPath as PlainPath
from ops_deploy.services.thermal_monitoring.deploy import credentials_verify

CREDENTIAL_FIELD = "endpoint_password"
Bind = ipaddress.IPv4Address | Literal["tailscale", "tailscale-interface"]
Port = Annotated[StrictInt, Field(ge=1, le=65535)]
Word = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")]
UrlPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")]
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]*$")]


class EndpointConfig(BaseServiceConfig, HttpdSwitchFields):
    required_secret_keys: ClassVar[tuple[str, ...]] = (CREDENTIAL_FIELD,)
    user: UnixUser = "metrics"
    group: UnixUser | None = None
    site_path: PlainPath = PurePosixPath("/usr/local/bin")
    bind: Bind = "tailscale-interface"
    port: Port
    path: UrlPath
    auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")]
    server_path: PlainPath
    htpasswd_dir: PlainPath
    htpasswd_file: PlainPath | None = None
    packages: tuple[Package, ...]

    @model_validator(mode="after")
    def _auth_is_set(self) -> EndpointConfig:
        if self.auth_user == "CHANGE_ME":
            raise ValueError("auth_user is still the role placeholder")
        return self

    @property
    def group_name(self) -> str:
        return self.group or self.user

    @property
    def htpasswd_path(self) -> PurePosixPath:
        return self.htpasswd_file or self.htpasswd_dir / "htpasswd"


def password(secrets: SecretValues) -> str:
    value = secrets.get(CREDENTIAL_FIELD, "")
    if not value or value == "CHANGE_ME" or re.search(r"[\x00-\x1f\x7f]", value) or len(value.encode()) > 72:
        raise DeployError(
            "endpoint_password must be non-placeholder, at most 72 bcrypt bytes, without control characters"
        )
    return value


def bind_address(cfg: EndpointConfig) -> str:
    if not isinstance(cfg.bind, str):
        return str(cfg.bind)
    if cfg.bind == "tailscale":
        raw = (probe("tailscale ip --4", name="Tailscale IPv4 address") or "").strip()
        try:
            return str(ipaddress.IPv4Address(raw))
        except ValueError:
            raise DeployError("Tailscale must return exactly one IPv4 address") from None
    # Ansible's ansible_tailscale0.ipv4.address | default('127.0.0.1').
    interface = probe(
        "ip -json -4 address show dev tailscale0 2>/dev/null || printf '[]'", name="Tailscale interface IPv4 address"
    )
    if interface is None:
        raise DeployError("Cannot read the Tailscale interface state")
    try:
        addresses = [
            a["local"]
            for i in json.loads(interface or "[]")
            for a in i.get("addr_info", [])
            if a.get("family") == "inet"
        ]
        return str(ipaddress.IPv4Address(addresses[0])) if addresses else "127.0.0.1"
    except (ValueError, TypeError, KeyError):
        raise DeployError("Cannot determine the Tailscale interface IPv4 address") from None


def account(cfg: EndpointConfig) -> None:
    server.group(name=f"Ensure group {cfg.group_name}", group=cfg.group_name, system=True)
    server.user(
        name=f"Ensure endpoint user {cfg.user}",
        user=cfg.user,
        group=cfg.group_name,
        shell="/usr/sbin/nologin",
        system=True,
        ensure_home=False,
        create_home=False,
    )
    files.directory(
        name=f"Ensure {cfg.htpasswd_dir}", path=str(cfg.htpasswd_dir), user="root", group=cfg.group_name, mode="0750"
    )


def credentials(cfg: EndpointConfig, value: str) -> list[OperationMeta]:
    current = host.get_fact(FileContents, path=str(cfg.htpasswd_path))
    if credentials_verify(current, cfg.auth_user, value):
        files.file(
            name=f"Ensure owner and mode of {cfg.htpasswd_path}",
            path=str(cfg.htpasswd_path),
            user="root",
            group=cfg.group_name,
            mode="0640",
        )
        return []
    return [
        secret_file(
            name=f"Write {cfg.htpasswd_path}",
            path=cfg.htpasswd_path,
            content=SecretContent(f"{cfg.auth_user}:{hash_password(value)}\n"),
            user="root",
            group=cfg.group_name,
            mode="0640",
        )
    ]


def port_preflight(cfg: EndpointConfig, bind: str) -> None:
    from ops_deploy.helpers.checks import mark_read_only

    code = (Path(__file__).parent / "files" / "port_preflight.py").read_text()
    payload = json.dumps({"bind": bind, "port": cfg.port, "unit": cfg.service_name + ".service"})
    mark_read_only(
        server.shell(
            name="Check endpoint bind-port ownership", commands=[shlex.join(["python3", "-I", "-c", code, payload])]
        )
    )
