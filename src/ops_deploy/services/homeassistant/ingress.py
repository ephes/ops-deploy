"""Prepared original Traefik rendering and writes, without a service restart."""

from __future__ import annotations

from io import StringIO
from typing import Annotated

from pydantic import Field, SecretStr, StrictBool, StrictInt
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files

from ops_deploy.base._common import AbsolutePath, RoleConfig

from .render import templates


class HomeAssistantIngressConfig(RoleConfig):
    enabled: StrictBool = True
    domain: str = ""
    entrypoints: tuple[str, ...] = ("web-secure",)
    middlewares: tuple[str, ...] = ("homeassistant-headers",)
    local_middlewares: tuple[str, ...] = ("homeassistant-headers", "homeassistant-websocket")
    local_hostname: str = "homeassistant.local"
    dynamic_dir: AbsolutePath = "/etc/traefik/dynamic"
    certresolver: str = "letsencrypt"
    app_port: Annotated[StrictInt, Field(ge=1, le=65535)] = 10020
    default_ipv4: str | None = None
    reload_handler: str = "reload traefik config"


def render_ingress(cfg: HomeAssistantIngressConfig) -> SecretStr:
    context = {
        "homeassistant_traefik_" + key: value
        for key, value in cfg.model_dump(exclude={"app_port", "default_ipv4", "enabled"}).items()
    }
    context["homeassistant_app_port"] = cfg.app_port
    context["ansible_default_ipv4"] = {} if cfg.default_ipv4 is None else {"address": cfg.default_ipv4}
    return SecretStr(templates().get_template("homeassistant.traefik.yml.j2").render(**context))


def write_ingress(cfg: HomeAssistantIngressConfig, *, rendered: SecretStr | None = None) -> OperationMeta | None:
    """Original directory/file modes and only the template's notification.

    The stock handler only explains Traefik's file watcher. A caller selecting
    another original template can supply its exact protected rendered body; a
    selected handler belongs to the normal deploy's later handler boundary.
    This component never guesses a process reload/restart from a file change.
    """
    if not cfg.enabled:
        return None
    files.directory(
        name="Ensure Home Assistant Traefik dynamic directory",
        path=cfg.dynamic_dir,
        user="root",
        group="root",
        mode="0755",
    )
    body = render_ingress(cfg) if rendered is None else rendered
    return files.put(
        name="Write Home Assistant Traefik route",
        src=StringIO(body.get_secret_value()),
        dest=cfg.dynamic_dir.rstrip("/") + "/homeassistant.yml",
        user="root",
        group="root",
        mode="0644",
    )
