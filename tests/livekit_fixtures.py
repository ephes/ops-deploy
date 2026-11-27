"""A livekit config (made-up values) and the facts of hosts running it.

Two hosts: one where ops-deploy applied ``cfg`` and nothing changed since
(:func:`converged`), and one running the containers on the same images
without the compose file, the unit, the config files or an applied stamp
(:func:`unstamped`).
"""

from __future__ import annotations

import json
from typing import Any

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.compose_app.render import render_compose, render_config, render_unit
from ops_deploy.services.compose_app.state import desired_stamp
from ops_deploy.services.livekit import LivekitConfig, render_route
from ops_deploy.services.livekit.deploy import render_reserved_ports
from tests import fakehost
from tests.test_infra_docker_vector import docker_converged

SITE = "/opt/livekit"
COMPOSE = f"{SITE}/docker-compose.yml"
SERVER_YAML = "/etc/livekit/livekit.yaml"
EGRESS_YAML = "/etc/livekit/egress.yaml"
STATE = "/var/lib/ops-deploy/livekit"
UNIT = "/etc/systemd/system/livekit.service"
ROUTE = "/etc/traefik/dynamic/livekit.yml"
SERVER_IMAGE = "example.org/livekit/livekit-server:v1.12.0@sha256:" + "a" * 64
# The oldest server TURN accepts (turn_domain refuses older tags).
TURN_SERVER_IMAGE = "example.org/livekit/livekit-server:v1.13.10@sha256:" + "d" * 64
TURN_DOMAIN = "turn.example.invalid"
RESERVED = "/etc/sysctl.d/60-livekit-reserved-ports.conf"
EGRESS_IMAGE = "example.org/livekit/egress:v1.13.0@sha256:" + "b" * 64
IMAGE_IDS = {
    SERVER_IMAGE: "sha256:" + "1" * 64,
    EGRESS_IMAGE: "sha256:" + "2" * 64,
    TURN_SERVER_IMAGE: "sha256:" + "3" * 64,
}
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


def turn_config(**changes: Any) -> LivekitConfig:
    """``livekit_config`` with TURN on (and a server new enough for it)."""

    return livekit_config(**{"server_image": TURN_SERVER_IMAGE, "turn_domain": TURN_DOMAIN, **changes})


def reservation(cfg: LivekitConfig, *, running: str = "50000-50100", sockets: tuple[str, ...] = ()) -> dict[str, Any]:
    """The media port reservation's facts: the running value, ``ss`` with ``sockets``, the sysctl file."""

    responses: dict[str, Any] = {
        "cat /proc/sys/net/ipv4/ip_local_reserved_ports": [running, "read"],
        "test -x /usr/bin/ss": ["present"],
        "/usr/bin/ss -Hnlup": [*sockets, "checked"],
        **fakehost.directory("/etc/sysctl.d"),
    }
    if running:
        responses.update(fakehost.file(RESERVED, render_reserved_ports(cfg)))
    return responses


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
    if cfg.turn_domain is not None:
        responses.update(reservation(cfg))
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


def unstamped(cfg: LivekitConfig, **overrides: Any) -> dict[str, Any]:
    """Facts of a host running the containers (and the route) but none of the other files, and no stamp."""

    responses = _host(cfg)
    responses.update(overrides)
    return responses
