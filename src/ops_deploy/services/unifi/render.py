"""Role templates rendered with Ansible's whitespace behavior."""

from __future__ import annotations

from functools import cache
from typing import Any

import jinja2

from .config import UnifiConfig

PACKAGE = "ops_deploy.services.unifi"


@cache
def templates() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def role_vars(cfg: UnifiConfig) -> dict[str, Any]:
    values = {f"unifi_{key}": value for key, value in cfg.model_dump().items()}
    values.update(
        unifi_user="unifi",
        unifi_group="unifi",
        unifi_service_name="unifi",
        unifi_install_dir="/usr/lib/unifi",
        unifi_java_home="/usr/lib/jvm/java-17-openjdk-amd64",
        unifi_java_opts=(
            "-Djava.awt.headless=true -Dfile.encoding=UTF-8 -Dunifi.core.enabled=false "
            "-Dunifi.mongodb.service.enabled=false -Dlog4j2.formatMsgNoLookups=true"
        ),
        unifi_systemd_extra_env=[],
        unifi_mongodb_jvm_args_path="/etc/unifi-secrets/mongodb.jvmargs",
        unifi_mongodb_user="unifi",
        unifi_mongodb_host="127.0.0.1",
        unifi_mongodb_port=27017,
        unifi_mongodb_database="unifi",
        unifi_port_https=8443,
        unifi_traefik_certresolver=cfg.traefik_certresolver or "",
        unifi_mongodb_logrotate_path="/etc/logrotate.d/mongodb",
    )
    return values


def render_template(cfg: UnifiConfig, name: str, *, mongodb_password: str = "") -> str:
    return templates().get_template(name).render(**role_vars(cfg), unifi_mongodb_password=mongodb_password)
