"""Traefik dynamic-config routes with optional basic auth.

Replaces ``webapp_deploy_internal`` ``traefik_config`` and the per-role
``traefik.yml.j2`` dual-router templates. Differences from the Ansible path:

- The bcrypt hash is computed on the controller (the password never reaches
  the target or a command line) in the format ``htpasswd -nB`` produces
  (``$2y$``, cost 5).
- The hash already in the deployed file is reused when it still matches the
  password. bcrypt salts are random, so re-hashing every run (what the roles
  do) would rewrite the file and restart Traefik on every deploy.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Generator
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Literal

import bcrypt
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pyinfra import host
from pyinfra.api import operation
from pyinfra.api.command import StringCommand
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.templates import render

DYNAMIC_DIR = PurePosixPath("/etc/traefik/dynamic")
BCRYPT_COST = 5  # htpasswd -B default, which the Ansible roles use

# Defaults from the Ansible roles (nyxmon_internal_ip_ranges and friends).
DEFAULT_INTERNAL_IP_RANGES = (
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
    "fd50:3e45:c454:0::/64",
)

_NAME = r"^[a-z0-9][a-z0-9_-]{0,62}$"
_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME = rf"^{_LABEL}(\.{_LABEL})*$"
_MIDDLEWARE = r"^[A-Za-z0-9@_-]+$"
_YAML_SAFE = r"^[^\"\\\n]*$"
_DURATION = r"^[0-9]+(ms|s|m|h)$"
_HASH_LINE = re.compile(r'^\s*- "(?P<user>[^:"]+):(?P<hash>\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53})"\s*$')

Hostname = Annotated[str, Field(pattern=_HOSTNAME, max_length=253)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class BasicAuth(_Model):
    user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")]
    password: SecretStr

    @field_validator("password")
    @classmethod
    def _password_usable(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if not secret:
            raise ValueError("basic auth password must not be empty")
        if len(secret.encode()) > 72:
            raise ValueError("basic auth password must be at most 72 bytes (bcrypt limit)")
        return value


class RedirectRegex(_Model):
    regex: Annotated[str, Field(pattern=_YAML_SAFE, min_length=1)]
    replacement: Annotated[str, Field(pattern=_YAML_SAFE, min_length=1)]
    permanent: bool = False


class HealthCheck(_Model):
    path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")] = "/"
    interval: Annotated[str, Field(pattern=_DURATION)] = "30s"
    timeout: Annotated[str, Field(pattern=_DURATION)] = "3s"


class TraefikRoute(_Model):
    """One service's routers, middlewares and backend in Traefik's file provider.

    With ``basic_auth`` this is the roles' dual-router pattern: clients in
    ``internal_ip_ranges`` reach the service without auth (priority 120),
    everyone else must authenticate (priority 100).
    """

    name: Annotated[str, Field(pattern=_NAME)]
    host: Hostname
    app_port: Annotated[int, Field(ge=1, le=65535)]
    app_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:\[\]-]+$")] = "127.0.0.1"
    # Lands in a YAML comment: no line breaks (LF or CR) or other control characters.
    title: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ._()-]*$")] = ""
    basic_auth: BasicAuth | None = None
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES
    middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    frame_options: Literal["DENY", "SAMEORIGIN"] = "DENY"
    redirect: RedirectRegex | None = None
    health_check: HealthCheck | None = None

    @field_validator("internal_ip_ranges")
    @classmethod
    def _valid_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("internal_ip_ranges must not be empty")
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("internal_ip_ranges must contain IP networks") from None
        return value

    @property
    def path(self) -> PurePosixPath:
        return DYNAMIC_DIR / f"{self.name}.yml"


def hash_password(password: str, *, cost: int = BCRYPT_COST) -> str:
    """bcrypt hash in ``htpasswd -B`` format (``$2y$``)."""

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost, prefix=b"2b")).decode()
    return "$2y$" + hashed[4:]


def existing_hash(lines: list[str] | None, user: str) -> str | None:
    """The bcrypt hash for ``user`` in a deployed route file, if any."""

    for line in lines or ():
        match = _HASH_LINE.match(line)
        if match and match["user"] == user:
            return match["hash"]
    return None


def resolve_hash(auth: BasicAuth, current: str | None) -> str:
    """Reuse ``current`` if it verifies against the password, else hash anew."""

    password = auth.password.get_secret_value()
    if current is not None:
        try:
            if bcrypt.checkpw(password.encode(), current.encode()):
                return current
        except ValueError:
            pass  # malformed hash (for example cost 00): replace it
    return hash_password(password)


def render_route(route: TraefikRoute, auth_hash: str | None) -> str:
    if (route.basic_auth is None) != (auth_hash is None):
        raise ValueError("auth_hash must be given exactly when the route has basic_auth")
    return render("ops_deploy.helpers", "traefik_route.yml.j2", route=route, auth_hash=auth_hash)


RouteRenderer = Callable[[TraefikRoute, str | None], str]


@operation()
def _route_file(route: TraefikRoute, renderer: RouteRenderer) -> Generator[StringCommand, None, None]:
    # The hash depends on the deployed file, so it is resolved inside the
    # operation (per host, at plan and execution time) rather than up front.
    auth_hash = None
    if route.basic_auth is not None:
        current = existing_hash(host.get_fact(FileContents, path=str(route.path)), route.basic_auth.user)
        auth_hash = resolve_hash(route.basic_auth, current)
    yield from files.put._inner(
        src=StringIO(renderer(route, auth_hash)),
        dest=str(route.path),
        user="root",
        group="root",
        mode="0644",
    )


def traefik_route(
    route: TraefikRoute,
    *,
    renderer: RouteRenderer = render_route,
    restart: Literal["traefik", "none"] = "traefik",
) -> OperationMeta:
    """Write ``/etc/traefik/dynamic/<name>.yml``; restart Traefik if it changed.

    ``renderer`` lets a service keep its own template (for byte parity with
    the file Ansible deployed); it receives the route and the resolved hash.
    The roles' ``reload traefik`` handler restarts Traefik; ``restart="none"``
    relies on the file provider's ``watch = true`` instead.
    """

    files.directory(
        name="Ensure Traefik dynamic directory",
        path=str(DYNAMIC_DIR),
        user="root",
        group="root",
        mode="0755",
    )
    route_op = _route_file(name=f"Write Traefik route {route.name}", route=route, renderer=renderer)
    if restart == "traefik":
        systemd.service(
            name=f"Restart Traefik for {route.name}",
            service="traefik.service",
            running=None,
            restarted=True,
            _if=any_changed(route_op),
        )
    return route_op
