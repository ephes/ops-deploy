"""Toy uv/Django web service.

Shaped like the small Django apps (nyxmon in its rendered-``pyproject.toml``
mode): a system user, a uv-managed venv, migrate/collectstatic, a systemd unit,
a Traefik route with basic auth, and post-restart checks. It exists to test
the helpers together; it is not deployed anywhere.
"""

from __future__ import annotations

from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, ClassVar

from pydantic import Field, SecretStr
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    django_manage,
    http_check,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
    wait_port,
)
from ops_deploy.helpers.traefik import Hostname

TEMPLATE_PACKAGE = "ops_deploy.services.toyweb"


class ToywebConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("basic_auth_password",)

    service_name: ServiceName = "toyweb"
    user: UnixUser = "toyweb"
    site_path: PurePosixPath = PurePosixPath("/home/toyweb/site")
    app_port: int = Field(default=10098, ge=1024, le=65535)
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.12"
    dependencies: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9._\[\]<>=!~, -]+$")], ...] = (
        "django>=5.2",
        "granian>=2.0",
    )
    traefik_host: Hostname = "toyweb.example.invalid"
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"

    @property
    def home(self) -> PurePosixPath:
        return PurePosixPath("/home") / self.user

    @property
    def app_path(self) -> PurePosixPath:
        return self.site_path / "app"

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv"

    @property
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env"

    @property
    def static_root(self) -> PurePosixPath:
        return self.site_path / "static"


def traefik_config(cfg: ToywebConfig, secrets: SecretValues) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        title=cfg.service_name,
        host=cfg.traefik_host,
        app_port=cfg.app_port,
        basic_auth=BasicAuth(user=cfg.basic_auth_user, password=SecretStr(secrets["basic_auth_password"])),
    )


@deploy("Deploy toyweb service")
def deploy_toyweb(cfg: ToywebConfig, secrets: SecretValues) -> None:
    secrets.require(cfg.required_secret_keys)

    system_user(cfg.user, home=cfg.home, directories=[cfg.site_path, cfg.app_path, cfg.static_root])

    def put(template: str, dest: PurePosixPath, mode: str) -> OperationMeta:
        return files.put(
            name=f"Write {dest}",
            src=StringIO(render(TEMPLATE_PACKAGE, template, cfg=cfg)),
            dest=str(dest),
            user=cfg.user,
            group=cfg.user,
            mode=mode,
        )

    pyproject = put("pyproject.toml.j2", cfg.site_path / "pyproject.toml", "0644")
    env = put("toyweb.env.j2", cfg.env_path, "0600")

    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        python=cfg.python_version,
        args=("--no-dev",),
        when_changed=[pyproject],
    )
    for command in (("migrate", "--noinput"), ("collectstatic", "--noinput")):
        django_manage(
            cfg.app_path,
            *command,
            user=cfg.user,
            home=cfg.home,
            venv=cfg.venv_path,
            env_file=cfg.env_path,
            when_changed=[deps],
        )

    unit = systemd_unit(cfg.service_name, render(TEMPLATE_PACKAGE, "toyweb.service.j2", cfg=cfg))
    traefik_route(traefik_config(cfg, secrets))
    service_rollout(cfg.service_name, units=[unit], restart_when=[deps, env])

    wait_port(cfg.app_port)
    http_check(f"http://127.0.0.1:{cfg.app_port}/", status=(200, 302), host_header=cfg.traefik_host)
