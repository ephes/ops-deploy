"""graphyard ingress: the Traefik routes for Graphyard and Grafana, and the app's proxy settings.

Port of the ``graphyard_ingress_deploy`` role and
``playbooks/deploy-graphyard-ingress.yml``. The role's template is shipped
unchanged, so the route file is byte-identical to the role's apart from the
bcrypt hash, which is reused while it still matches the password (the role
hashes anew on every run; see :mod:`ops_deploy.helpers.traefik`). Like the
role, nothing restarts Traefik: its file provider watches the directory.

The role also sets four lines of Graphyard's env file (``lineinfile``,
with a backup copy of the file before each change) and restarts the web and
agent units when one changed. The file holds secrets, so only those four
lines are read while planning and the edit runs on the host.
"""

from __future__ import annotations

import ipaddress
import shlex
from pathlib import PurePosixPath
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.operations import server

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import ServiceName
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers import BasicAuth, TraefikRoute, mark_read_only, traefik_route
from ops_deploy.helpers.traefik import DEFAULT_INTERNAL_IP_RANGES
from ops_deploy.services.graphyard._common import EnvValue, Hostname, Url, absolute, probe, render_role

EXAMPLE_GRAPHYARD = "graphyard.example.com"
EXAMPLE_GRAFANA = "grafana.example.com"
Middleware = Annotated[str, Field(pattern=r"^[A-Za-z0-9@_-]+$")]

# lineinfile on the host: replace the last line matching ``^KEY=`` or append,
# keep owner and mode, and copy the file to ``<path>.<pid>.<time>~`` first
# (Ansible's ``backup: true``). Prints which keys it changed, never values.
ENV_EDIT = """\
import os, shutil, sys, tempfile, time
path = sys.argv[1]
wanted = dict(pair.split("=", 1) for pair in sys.argv[2:])
with open(path) as handle:
    lines = handle.read().splitlines()
changed = []
for key, value in wanted.items():
    line = key + "=" + value
    matches = [index for index, text in enumerate(lines) if text.startswith(key + "=")]
    if matches and lines[matches[-1]] == line:
        continue
    if matches:
        lines[matches[-1]] = line
    else:
        lines.append(line)
    changed.append(key)
if changed:
    shutil.copy2(path, "%s.%s.%s~" % (path, os.getpid(), time.strftime("%Y-%m-%d@%H:%M:%S")))
    info = os.stat(path)
    fd, temp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".graphyard-env-")
    with os.fdopen(fd, "w") as handle:
        handle.write("\\n".join(lines) + "\\n")
    os.chown(temp, info.st_uid, info.st_gid)
    os.chmod(temp, info.st_mode & 0o7777)
    os.replace(temp, path)
print(" ".join(changed))
"""


class GraphyardIngressConfig(RoleConfig):
    """The role's variables without the ``graphyard_ingress_`` prefix (defaults from its defaults/main.yml).

    The basic-auth password is a deploy secret (``basic_auth_password``, and
    ``basic_auth_user`` when set there), not a config field.
    """

    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    graphyard_host: Hostname = EXAMPLE_GRAPHYARD
    grafana_host: Hostname = EXAMPLE_GRAFANA
    graphyard_backend_url: Url = "http://127.0.0.1:8051"
    grafana_backend_url: Url = "http://127.0.0.1:3300"
    graphyard_middlewares: tuple[Middleware, ...] = ()
    grafana_middlewares: tuple[Middleware, ...] = ()
    basic_auth_enabled: bool = True
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES
    # The private inventory POST router (host-bound bearer credentials).
    inventory_enabled: bool = False

    manage_graphyard_env: bool = True
    env_path: PurePosixPath = PurePosixPath("/etc/graphyard/graphyard.env")
    require_env_file: bool = True
    web_service_name: ServiceName = "graphyard-web"
    agent_service_name: ServiceName = "graphyard-agent"
    # None: the role's defaults, built from ``graphyard_host``.
    django_allowed_hosts: tuple[EnvValue, ...] | None = None
    django_csrf_trusted_origins: tuple[EnvValue, ...] | None = None
    # Empty: DJANGO_ADMIN_URL is left alone.
    django_admin_url: EnvValue = ""
    # None: ``https://<grafana_host>``.
    grafana_public_url: EnvValue | None = None

    @field_validator("internal_ip_ranges")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("internal_ip_ranges must contain IP networks") from None
        return value

    @field_validator("env_path")
    @classmethod
    def _env_absolute(cls, value: PurePosixPath) -> PurePosixPath:
        return absolute(value)

    @model_validator(mode="after")
    def _role_asserts(self) -> GraphyardIngressConfig:
        if self.graphyard_host == EXAMPLE_GRAPHYARD or self.grafana_host == EXAMPLE_GRAFANA:
            raise ValueError("graphyard_host and grafana_host must be set (not the examples)")
        if (self.basic_auth_enabled or self.inventory_enabled) and not self.internal_ip_ranges:
            raise ValueError("internal_ip_ranges must not be empty")
        if self.manage_graphyard_env and (self.allowed_hosts == () or self.csrf_trusted_origins == ()):
            raise ValueError("the Django allowed hosts and CSRF origins must not be empty")
        admin = self.django_admin_url
        if admin and (not admin.endswith("/") or admin.startswith("/")):
            raise ValueError("django_admin_url must be a relative path ending with '/' (example: admin/)")
        if urlsplit(self.graphyard_backend_url).port is None:
            raise ValueError("graphyard_backend_url needs a port")
        return self

    @property
    def allowed_hosts(self) -> tuple[str, ...]:
        if self.django_allowed_hosts is not None:
            return self.django_allowed_hosts
        return ("127.0.0.1", "localhost", self.graphyard_host)

    @property
    def csrf_trusted_origins(self) -> tuple[str, ...]:
        if self.django_csrf_trusted_origins is not None:
            return self.django_csrf_trusted_origins
        return ("http://127.0.0.1", "http://localhost", f"https://{self.graphyard_host}")

    @property
    def env_lines(self) -> dict[str, str]:
        """The env file lines the role sets, by key, in its order."""

        lines = {
            "DJANGO_ALLOWED_HOSTS": ",".join(self.allowed_hosts),
            "DJANGO_CSRF_TRUSTED_ORIGINS": ",".join(self.csrf_trusted_origins),
            "GRAFANA_BASE_URL": self.grafana_public_url or f"https://{self.grafana_host}",
        }
        if self.django_admin_url:
            lines["DJANGO_ADMIN_URL"] = self.django_admin_url
        return lines


def role_vars(cfg: GraphyardIngressConfig, auth_hash: str | None) -> dict[str, object]:
    return {
        "graphyard_ingress_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "graphyard_ingress_graphyard_host": cfg.graphyard_host,
        "graphyard_ingress_grafana_host": cfg.grafana_host,
        "graphyard_ingress_graphyard_backend_url": cfg.graphyard_backend_url,
        "graphyard_ingress_grafana_backend_url": cfg.grafana_backend_url,
        "graphyard_ingress_graphyard_middlewares": list(cfg.graphyard_middlewares),
        "graphyard_ingress_grafana_middlewares": list(cfg.grafana_middlewares),
        "graphyard_ingress_basic_auth_enabled": cfg.basic_auth_enabled,
        "graphyard_ingress_basic_auth_user": cfg.basic_auth_user,
        "graphyard_ingress_basic_auth_password_hash": auth_hash or "",
        "graphyard_ingress_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "graphyard_ingress_inventory_enabled": cfg.inventory_enabled,
    }


def render_route(cfg: GraphyardIngressConfig, auth_hash: str | None) -> str:
    return render_role("traefik-graphyard.yml.j2", role_vars(cfg, auth_hash))


def traefik_config(cfg: GraphyardIngressConfig, secrets: SecretValues | None) -> TraefikRoute:
    """The route's file name and basic auth; the role's own template renders the content."""

    auth = None
    if cfg.basic_auth_enabled:
        password = secrets.get("basic_auth_password", "") if secrets is not None else ""
        if not password or password == "CHANGEME":
            raise ValueError("secret basic_auth_password must be set when basic auth is enabled")
        user = (secrets.get("basic_auth_user") if secrets is not None else None) or cfg.basic_auth_user
        auth = BasicAuth(user=user, password=SecretStr(password))
    port = urlsplit(cfg.graphyard_backend_url).port
    assert port is not None
    return TraefikRoute(
        name="graphyard",
        host=cfg.graphyard_host,
        app_port=port,
        basic_auth=auth,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def ingress_steps(cfg: GraphyardIngressConfig, secrets: SecretValues | None) -> None:
    route = traefik_config(cfg, secrets)
    user = route.basic_auth.user if route.basic_auth is not None else cfg.basic_auth_user
    effective = cfg.model_copy(update={"basic_auth_user": user})
    traefik_route(route, renderer=lambda _route, auth_hash: render_route(effective, auth_hash), restart="none")
    if cfg.manage_graphyard_env:
        _env(cfg)


def _env(cfg: GraphyardIngressConfig) -> None:
    path = shlex.quote(str(cfg.env_path))
    present = probe(f"test -f {path} && echo present").strip() == "present"
    if cfg.require_env_file:
        mark_read_only(
            server.shell(
                name="Require the Graphyard environment file",
                commands=[
                    f"test -f {path} || {{ echo 'Graphyard environment file not found: {cfg.env_path}' >&2; exit 1; }}"
                ],
            )
        )
    elif not present:
        return
    wanted = cfg.env_lines
    keys = "|".join(wanted)
    # Only these keys' lines (no secrets among them) are read while planning.
    found = probe(f"grep -E '^({keys})=' {path}").splitlines()
    last = {line.split("=", 1)[0]: line for line in found if "=" in line}
    current = all(last.get(key) == f"{key}={value}" for key, value in wanted.items())
    pairs = [f"{key}={value}" for key, value in wanted.items()]
    if present and current:
        return
    server.shell(
        name="Set the reverse proxy hosts in the Graphyard environment",
        commands=[shlex.join(["python3", "-I", "-c", ENV_EDIT, str(cfg.env_path), *pairs]) + " >/dev/null"],
    )
    # The role's handlers.
    for unit in (cfg.web_service_name, cfg.agent_service_name):
        server.shell(name=f"Restart {unit}", commands=[f"systemctl restart {unit}.service"])


@deploy("Deploy graphyard ingress")
def deploy_graphyard_ingress(cfg: GraphyardIngressConfig, secrets: SecretValues | None = None) -> None:
    ingress_steps(cfg, secrets)
