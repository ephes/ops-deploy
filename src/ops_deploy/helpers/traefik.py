"""Traefik dynamic-config routes with optional basic auth.

Replaces ``webapp_deploy_internal`` ``traefik_config`` and the per-role
``traefik.yml.j2`` dual-router templates. Differences from the Ansible path:

- The bcrypt hash is computed on the controller (the password never reaches
  the target or a command line) in the format ``htpasswd -nB`` produces
  (``$2y$``, cost 5).
- The hash already in the deployed file is reused when it still matches the
  password. bcrypt salts are random, so re-hashing every run (what the roles
  do) would rewrite the file and restart Traefik on every deploy.
- A route file that holds a hash, now or on the host, is written with
  ``secret_file``: pyinfra's ``--diff`` would print the old and new hash.

Every write or removal of a dynamic file through this module (:func:`traefik_route`,
:func:`route_put`, :func:`route_absent`) first runs :data:`ROUTE_GUARD_SCRIPT`, which
refuses while a Traefik transaction holds its host lock (a changed route tree during
a binary update's acceptance would roll the update back). The guard runs only when the
operation changes something, so an unchanged deploy stays free of changes.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Callable, Generator, Iterable
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

import bcrypt
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pyinfra import host
from pyinfra.api import operation
from pyinfra.api.command import StringCommand
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.secrets import SecretContent
from ops_deploy.core.templates import render
from ops_deploy.ops.secret_file import secret_file

DYNAMIC_DIR = PurePosixPath("/etc/traefik/dynamic")
# The transaction engines' host lock (ops-library's and ops_deploy.infra.traefik_tx's).
TRANSACTION_LOCK = "/run/lock/traefik-transaction.lock"

# $1 the lock file, $2 the kernel's lock table (/proc/locks). Exit 1 while any process
# holds (or waits for) an flock on the lock file; exit 0 when there is none or no file.
# It only reads: taking the lock, even shared for an instant, could make a starting
# transaction refuse. /proc/locks names a lock by the file system's device (hex
# major:minor) and inode, decoded here from stat's device number as glibc does. No
# backslashes or single quotes, so pyinfra's sh -c wrapping leaves it unchanged.
ROUTE_GUARD_SCRIPT = """set -euo pipefail
lock=$1
table=$2
if [ ! -e "$lock" ]; then
    exit 0
fi
read -r dev ino < <(stat -L -c "%d %i" -- "$lock")
major=$(( ((dev >> 8) & 0xfff) | ((dev >> 32) & ~0xfff) ))
minor=$(( (dev & 0xff) | ((dev >> 12) & ~0xff) ))
key=$(printf "%02x:%02x:%d" "$major" "$minor" "$ino")
while read -r line; do
    case " $line " in
        *" FLOCK "*" $key "*)
            echo "traefik route guard: a Traefik transaction holds $lock; not changing routes" >&2
            exit 1
            ;;
    esac
done <"$table"
"""
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
# Any htpasswd hash marker (bcrypt, apr1, SHA1), well formed or not: never diffed.
_HASH_MARK = re.compile(r"\$(2[abxy]?|apr1)\$|\{SHA\}")

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
    everyone else must authenticate (priority 100). ``internal_only`` keeps
    the internal router and drops the external one.
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
    # One router for ``internal_ip_ranges`` and none for anyone else (no basic auth).
    internal_only: bool = False

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

    @model_validator(mode="after")
    def _one_access(self) -> TraefikRoute:
        if self.internal_only and self.basic_auth is not None:
            raise ValueError("an internal_only route takes no basic_auth")
        return self

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


def route_guard_command(lock: str = TRANSACTION_LOCK, table: str = "/proc/locks") -> str:
    """:data:`ROUTE_GUARD_SCRIPT` as one shell command; it fails while ``lock`` is held."""

    return shlex.join(["bash", "-c", ROUTE_GUARD_SCRIPT, "traefik-route-guard", lock, table])


def guarded(commands: Iterable[Any]) -> Generator[Any, None, None]:
    """``commands``, preceded by the transaction-lock guard when there is any to run."""

    items = iter(commands)
    first = next(items, None)
    if first is None:
        return
    yield StringCommand(route_guard_command())
    yield first
    yield from items


@operation()
def route_put(src: str, dest: str, mode: str = "0644", create_remote_dir: bool = True) -> Generator[Any, None, None]:
    """``files.put`` of a Traefik dynamic file (root-owned), refused while a transaction holds the lock."""

    yield from guarded(
        files.put._inner(
            src=StringIO(src), dest=dest, user="root", group="root", mode=mode, create_remote_dir=create_remote_dir
        )
    )


@operation()
def route_absent(path: str) -> Generator[Any, None, None]:
    """Remove a Traefik dynamic file if present, refused while a transaction holds the lock."""

    yield from guarded(files.file._inner(path=path, present=False))


@operation()
def _route_file(route: TraefikRoute, renderer: RouteRenderer) -> Generator[Any, None, None]:
    # The hash depends on the deployed file, so it is resolved inside the
    # operation (per host, at plan and execution time) rather than up front.
    current = host.get_fact(FileContents, path=str(route.path))
    auth_hash = None
    if route.basic_auth is not None:
        auth_hash = resolve_hash(route.basic_auth, existing_hash(current, route.basic_auth.user))
    text = renderer(route, auth_hash)
    if any(_HASH_MARK.search(line) for line in (*(current or ()), *text.splitlines())):
        # files.put --diff prints both versions: write it like a secret, which never shows content.
        yield from guarded(secret_file._inner(route.path, SecretContent(text), user="root", group="root", mode="0644"))
        return
    yield from guarded(
        files.put._inner(src=StringIO(text), dest=str(route.path), user="root", group="root", mode="0644")
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
