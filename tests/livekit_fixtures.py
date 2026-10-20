"""A livekit config (made-up values) and the facts of hosts running it.

Two hosts: one where ops-deploy applied ``cfg`` and nothing changed since
(:func:`converged`), and one the ``livekit_deploy`` role deployed with the
same inputs (:func:`ansible_deployed`): its files, containers on the same
images, no applied stamp.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jinja2

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.compose_app.render import render_compose, render_config, render_unit
from ops_deploy.services.compose_app.state import desired_stamp
from ops_deploy.services.livekit import LivekitConfig, render_route
from tests import fakehost
from tests.test_infra_docker_vector import docker_converged

VENDORED = Path(__file__).parent / "parity" / "ansible"
SITE = "/opt/livekit"
COMPOSE = f"{SITE}/docker-compose.yml"
SERVER_YAML = "/etc/livekit/livekit.yaml"
EGRESS_YAML = "/etc/livekit/egress.yaml"
STATE = "/var/lib/ops-deploy/livekit"
UNIT = "/etc/systemd/system/livekit.service"
ROUTE = "/etc/traefik/dynamic/livekit.yml"
SERVER_IMAGE = "example.org/livekit/livekit-server:v1.12.0@sha256:" + "a" * 64
EGRESS_IMAGE = "example.org/livekit/egress:v1.13.0@sha256:" + "b" * 64
IMAGE_IDS = {SERVER_IMAGE: "sha256:" + "1" * 64, EGRESS_IMAGE: "sha256:" + "2" * 64}
HOST = "livekit.example.invalid"
WEBHOOK = "https://recorder.example.invalid/api/livekit/webhook"
NODE_IP = "192.0.2.10"

SECRET_VALUES = {
    "api_key": "APIfixtureKey0123",
    "api_secret": "fixture-api-secret-0123456789abcdef",
    "redis_password": "fixture-redis-password-0123",
    "s3_access_key": "fixture-s3-access",
    "s3_secret_key": "fixture-s3-secret-0123456789",
}


def livekit_config(**changes: Any) -> LivekitConfig:
    values: dict[str, Any] = {
        "secrets": SecretRef("secrets/prod/livekit.yml"),
        "server_image": SERVER_IMAGE,
        "egress_image": EGRESS_IMAGE,
        "node_ip": NODE_IP,
        "webhook_url": WEBHOOK,
        "traefik_host": HOST,
    }
    values.update(changes)
    return LivekitConfig(**values)


def values(cfg: LivekitConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


def configs(cfg: LivekitConfig, secrets: SecretValues) -> dict[str, str]:
    return {str(c.path): render_config(c, secrets)[0] for c in cfg.compose_app().config_files}


def stamp_document(cfg: LivekitConfig, secrets: SecretValues) -> str:
    """``applied.json`` as the stamp step writes it (no host ids: no env file needs one)."""

    app = cfg.compose_app()
    stamp = desired_stamp(app, render_compose(app), {}, configs(cfg, secrets))
    stamp["ids"] = {}
    return json.dumps(stamp, sort_keys=True)


def running(cfg: LivekitConfig, **status: str) -> list[str]:
    """``docker inspect`` lines of the project's containers (``status``: service -> state, "" to drop one)."""

    lines = []
    for service in cfg.compose_app().services:
        state = status.get(service.name, "running")
        if state:
            lines.append(f"{service.name} {state} {IMAGE_IDS.get(service.image, 'sha256:' + '9' * 64)} False")
    return lines


def _host(cfg: LivekitConfig) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **docker_converged(),
        "cat /etc/passwd | cut": ["root:x:0:0:root:/root:/usr/bin/fish|root|root||!"],
        "docker inspect --format": running(cfg),
        "docker image inspect": [f"{ref} {image}" for ref, image in IMAGE_IDS.items()],
        "systemctl show -p ActiveState": ["ActiveState=active", "NeedDaemonReload=no"],
    }
    for path in (SITE, "/etc/livekit", "/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.service("livekit.service"))
    if cfg.traefik_host is not None:
        responses.update(fakehost.file(ROUTE, render_route(cfg)))
    return responses


def converged(cfg: LivekitConfig, secrets: SecretValues, **overrides: Any) -> dict[str, Any]:
    """Facts of a host where ``cfg`` was applied and nothing changed since; ``overrides`` by fact substring."""

    app = cfg.compose_app()
    responses = _host(cfg)
    responses[f"cat {STATE}/applied.json"] = [stamp_document(cfg, secrets)]
    responses.update(fakehost.file(COMPOSE, render_compose(app)))
    responses.update(fakehost.file(UNIT, render_unit(app)))
    texts = configs(cfg, secrets)
    responses.update(fakehost.file(SERVER_YAML, texts[SERVER_YAML], mode="-rw-------"))
    responses.update(fakehost.file(EGRESS_YAML, texts[EGRESS_YAML], mode="-rw-r-----"))
    responses.update(overrides)
    return responses


def role_vars(cfg: LivekitConfig, secrets: SecretValues) -> dict[str, Any]:
    """The playbook's role vars for these inputs (the role's defaults for the rest)."""

    server, _, server_tag = cfg.server_image.partition("@")[0].rpartition(":")
    egress, _, egress_tag = cfg.egress_image.partition("@")[0].rpartition(":")
    return {
        "livekit_service_name": cfg.service_name,
        "livekit_server_image": server,
        "livekit_server_tag": server_tag,
        "livekit_egress_image": egress,
        "livekit_egress_tag": egress_tag,
        "livekit_site_dir": str(cfg.site_path),
        "livekit_config_dir": str(cfg.config_dir),
        "livekit_http_port": cfg.http_port,
        "livekit_rtc_tcp_port": cfg.rtc_tcp_port,
        "livekit_rtc_port_range_start": cfg.rtc_port_range_start,
        "livekit_rtc_port_range_end": cfg.rtc_port_range_end,
        "livekit_node_ip": cfg.node_ip,
        "livekit_api_key": secrets["api_key"],
        "livekit_api_secret": secrets["api_secret"],
        "livekit_webhook_url": cfg.webhook_url,
        "livekit_s3_access_key": secrets["s3_access_key"],
        "livekit_s3_secret_key": secrets["s3_secret_key"],
        "livekit_s3_endpoint": cfg.s3_endpoint,
        "livekit_s3_bucket": cfg.s3_bucket,
        "livekit_traefik_host": cfg.traefik_host or "",
        "livekit_redis_password": secrets["redis_password"],
    }


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    """A vendored ``livekit_deploy`` template, rendered like Ansible's ``template`` module."""

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(f"livekit_deploy__{template}").render(**variables)


def ansible_deployed(cfg: LivekitConfig, secrets: SecretValues, **overrides: Any) -> dict[str, Any]:
    """Facts of a host the role deployed with these inputs: its files, running containers, no stamp.

    ``egress.yaml`` is ``0644``, as roles before the 0640 tightening left it.
    """

    variables = role_vars(cfg, secrets)
    responses = _host(cfg)
    responses.update(fakehost.file(COMPOSE, render_ansible("livekit-compose.yml.j2", variables)))
    responses.update(fakehost.file(UNIT, render_ansible("livekit.service.j2", variables)))
    responses.update(fakehost.file(SERVER_YAML, render_ansible("livekit.yaml.j2", variables), mode="-rw-------"))
    responses.update(fakehost.file(EGRESS_YAML, render_ansible("egress.yaml.j2", variables)))
    responses.update(overrides)
    return responses
