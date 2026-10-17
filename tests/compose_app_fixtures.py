"""A compose_app config in the torrent stack's shape (made-up values), and the facts of a host running it.

The shape is ops-control's torrent stack: a VPN container that owns the network
namespace, a torrent client and an indexer inside it, two env files (the VPN
secrets reach only the VPN container), a host secret for the VPN control
server, the client's and the indexer's UI on loopback, a dual route, the
indexer key copied into the client's search plugin and the client's
preferences reconciled through its WebUI.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.compose_app import (
    AppUser,
    Bind,
    ComposeAppConfig,
    ComposeService,
    Directory,
    EnvEntry,
    EnvFile,
    Healthcheck,
    HostId,
    HostSecret,
    JsonKeyCopy,
    PublishedPort,
    QbittorrentPreferences,
    RequiredPath,
    Route,
    Secret,
    Sysctl,
)
from ops_deploy.services.compose_app.deploy import route_config, route_without_http
from ops_deploy.services.compose_app.render import render_compose, render_env, render_unit
from ops_deploy.services.compose_app.state import desired_stamp
from tests import fakehost
from tests.test_infra_docker_vector import docker_converged

SITE = "/home/vpnstack/site"
DATA = "/srv/crypt/vpnstack"
DOWNLOADS = "/srv/crypt/media/downloads/torrents"
STATE = "/var/lib/ops-deploy/vpnstack"
UNIT = "/etc/systemd/system/vpnstack.service"
ROUTE = "/etc/traefik/dynamic/vpnstack.yml"
COMPOSE = f"{SITE}/compose.yml"
VPN_ENV = f"{SITE}/vpn.env"
APPS_ENV = f"{SITE}/apps.env"
APIKEY = f"{SITE}/vpn-control-apikey"
JACKETT_JSON = f"{DATA}/client/config/qBittorrent/nova3/engines/jackett.json"
VPN_IMAGE = "example.org/vpn/gate:v3@sha256:" + "a" * 64
CLIENT_IMAGE = "example.org/apps/client:latest@sha256:" + "b" * 64
INDEXER_IMAGE = "example.org/apps/indexer:latest@sha256:" + "c" * 64
IMAGE_IDS = {VPN_IMAGE: "sha256:" + "1" * 64, CLIENT_IMAGE: "sha256:" + "2" * 64, INDEXER_IMAGE: "sha256:" + "3" * 64}
UID, GID = 990, 965
# Fact keys of the host-side probes (the mode follows the quoted script).
RENDER_PROBE = "' render-probe )"
COPY_PROBE = "' copy-probe )"
QBT_PROBE = "' probe )"

SECRET_VALUES = {
    "tz": "Europe/Berlin",
    "vpn_private_key": "fixture-private-key+/0123456789abcdefghij=",
    "vpn_preshared_key": "fixture-preshared-key+/0123456789abcdefg=",
    "vpn_addresses": "10.66.0.2/32, fd00:66::2/128",
    "vpn_forwarded_port": "40000",
    "client_username": "fixture-user",
    "client_password": "fixture-client-password-0123",
    "basic_auth_user": "fixture-admin",
    "basic_auth_password": "fixture-basic-auth-pw-0123",
}


def stack_config(**changes: Any) -> ComposeAppConfig:
    vpn = ComposeService(
        name="vpn",
        image=VPN_IMAGE,
        cap_add=("NET_ADMIN",),
        devices=("/dev/net/tun",),
        sysctls=(
            Sysctl(key="net.ipv6.conf.all.disable_ipv6", value="1"),
            Sysctl(key="net.ipv6.conf.default.disable_ipv6", value="1"),
        ),
        env_files=("vpn.env",),
        binds=(Bind(source=f"{SITE}/vpn", target="/gluetun"),),
        ports=(PublishedPort(published=18080, target=8080), PublishedPort(published=19117, target=9117)),
        healthcheck=Healthcheck(
            test=("CMD-SHELL", "wget -qO- http://127.0.0.1:9999 >/dev/null 2>&1"),
            interval="30s",
            timeout="10s",
            retries=5,
            start_period="20s",
        ),
    )
    client = ComposeService(
        name="client",
        image=CLIENT_IMAGE,
        network_mode="service:vpn",
        env_files=("apps.env",),
        binds=(Bind(source=f"{DATA}/client/config", target="/config"), Bind(source=DOWNLOADS)),
    )
    indexer = ComposeService(
        name="indexer",
        image=INDEXER_IMAGE,
        network_mode="service:vpn",
        env_files=("apps.env",),
        binds=(Bind(source=f"{DATA}/indexer/config", target="/config"),),
        healthcheck=Healthcheck(
            test=("CMD-SHELL", "curl -fsS -o /dev/null http://127.0.0.1:9117/UI/Login"),
            interval="30s",
            timeout="10s",
            retries=5,
            start_period="20s",
        ),
    )
    values: dict[str, Any] = {
        "service_name": "vpnstack",
        "title": "VPN stack (vpn + client + indexer)",
        "project": "vpnstack",
        "user": "vpnstack",
        "site_path": SITE,
        "secrets": SecretRef("secrets/prod/vpnstack.yml"),
        "groups": ("media",),
        "users": (AppUser(name="vpnstack", groups=("media",), home="/home/vpnstack"),),
        "mounts_required": ("/srv/crypt",),
        "paths_required": (RequiredPath(path="/srv/crypt/media/downloads", hint="deploy the media tree first"),),
        "directories": (
            Directory(path=DATA, owner="vpnstack", group="media", mode="0750"),
            Directory(path=f"{DATA}/client/config", owner="vpnstack", group="media", mode="0750"),
            Directory(path=f"{DATA}/client/config/qBittorrent", owner="vpnstack", group="media", mode="0750"),
            Directory(path=f"{DATA}/client/config/qBittorrent/nova3", owner="vpnstack", group="media", mode="0755"),
            Directory(
                path=f"{DATA}/client/config/qBittorrent/nova3/engines", owner="vpnstack", group="media", mode="0750"
            ),
            Directory(path=f"{DATA}/indexer/config", owner="vpnstack", group="media", mode="0750"),
            Directory(path=DOWNLOADS, owner="vpnstack", group="media", mode="2775"),
            Directory(path=f"{DOWNLOADS}/incomplete", owner="vpnstack", group="media", mode="2775"),
            Directory(path=SITE, mode="0755"),
            Directory(path=f"{SITE}/vpn", mode="0700"),
        ),
        "env_files": (
            EnvFile(
                name="vpn.env",
                mode="0600",
                entries=(
                    EnvEntry(key="TZ", value=Secret(secret="tz")),
                    EnvEntry(key="VPN_SERVICE_PROVIDER", value="examplevpn"),
                    EnvEntry(key="VPN_TYPE", value="wireguard"),
                    EnvEntry(key="WIREGUARD_PRIVATE_KEY", value=Secret(secret="vpn_private_key")),
                    EnvEntry(key="WIREGUARD_PRESHARED_KEY", value=Secret(secret="vpn_preshared_key")),
                    EnvEntry(key="WIREGUARD_ADDRESSES", value=Secret(secret="vpn_addresses", form="first_ipv4")),
                    EnvEntry(key="SERVER_COUNTRIES", value="Netherlands,Sweden"),
                    EnvEntry(key="FIREWALL_VPN_INPUT_PORTS", value=Secret(secret="vpn_forwarded_port", form="int")),
                    EnvEntry(
                        key="HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE",
                        value=('{"auth":"apikey","apikey":"', HostSecret(host_secret=APIKEY), '"}'),
                    ),
                ),
            ),
            EnvFile(
                name="apps.env",
                mode="0644",
                entries=(
                    EnvEntry(key="TZ", value=Secret(secret="tz")),
                    EnvEntry(key="PUID", value=HostId(user="vpnstack")),
                    EnvEntry(key="PGID", value=HostId(group="media")),
                    EnvEntry(key="UMASK", value="002"),
                    EnvEntry(key="WEBUI_PORT", value="8080"),
                    EnvEntry(key="TORRENTING_PORT", value=Secret(secret="vpn_forwarded_port", form="int")),
                ),
            ),
        ),
        "services": (vpn, client, indexer),
        "route": Route(
            host="vpnstack.example.org",
            port=18080,
            access="internal_or_basic_auth",
            basic_auth_user=Secret(secret="basic_auth_user"),
            basic_auth_password=Secret(secret="basic_auth_password"),
        ),
        "steps": (
            JsonKeyCopy(
                name="Copy the indexer API key into the client search plugin",
                source=f"{DATA}/indexer/config/Jackett/ServerConfig.json",
                keys=("APIKey", "ApiKey", "api_key", "apikey"),
                dest=JACKETT_JSON,
                template={
                    "api_key": "{value}",
                    "url": "http://127.0.0.1:9117",
                    "tracker_first": False,
                    "thread_count": 20,
                },
                owner="vpnstack",
                group="media",
                mode="0640",
            ),
            QbittorrentPreferences(
                service="client",
                port=18080,
                username=Secret(secret="client_username"),
                password=Secret(secret="client_password"),
                preferences={
                    "save_path": f"{DOWNLOADS}/manual",
                    "temp_path": f"{DOWNLOADS}/incomplete",
                    "listen_port": Secret(secret="vpn_forwarded_port", form="int"),
                    "random_port": False,
                    "upnp": False,
                    "current_network_interface": "tun0",
                    "bypass_local_auth": False,
                },
            ),
        ),
        "legacy_dirs": (f"{DATA}/incomplete", f"{DATA}/watch"),
        "legacy_files": (f"{SITE}/.env",),
    }
    values.update(changes)
    return ComposeAppConfig(**values)


def values(cfg: ComposeAppConfig, **changes: str) -> SecretValues:
    assert cfg.secrets is not None
    return SecretValues(cfg.secrets, {**SECRET_VALUES, **changes})


def stamp_document(cfg: ComposeAppConfig, secrets: SecretValues, ids: dict[str, int] | None = None) -> str:
    """``applied.json`` as the stamp step writes it after a successful run."""

    envs = {env.name: render_env(cfg, env, secrets) for env in cfg.env_files}
    stamp = desired_stamp(cfg, render_compose(cfg), envs, {})
    stamp["ids"] = ids if ids is not None else {"group:media": GID, "user:vpnstack": UID}
    return json.dumps(stamp, sort_keys=True)


def running(cfg: ComposeAppConfig, **status: str) -> list[str]:
    """``docker inspect`` lines of the project's containers (``status``: service -> state, "" to drop one)."""

    lines = []
    for service in cfg.services:
        state = status.get(service.name, "running")
        if state:
            lines.append(f"{service.name} {state} {IMAGE_IDS.get(service.image, 'sha256:' + '9' * 64)} False")
    return lines


def converged(cfg: ComposeAppConfig, secrets: SecretValues, **overrides: Any) -> dict[str, Any]:
    """Facts of a host where ``cfg`` was applied and nothing changed since; ``overrides`` by fact substring."""

    envs = {env.name: render_env(cfg, env, secrets) for env in cfg.env_files}
    responses: dict[str, Any] = {
        **docker_converged(),
        "cat /etc/group": ["root:x:0:", "docker:x:800:", f"media:x:{GID}:vpnstack", f"vpnstack:x:{UID}:"],
        "cat /etc/passwd | cut": [
            "root:x:0:0:root:/root:/bin/bash|root|root||!",
            f"vpnstack:x:{UID}:{UID}::/home/vpnstack:/usr/sbin/nologin|vpnstack|vpnstack media||!",
        ],
        f"cat {STATE}/applied.json": [stamp_document(cfg, secrets)],
        "docker inspect --format": running(cfg),
        "docker image inspect": [f"{ref} {image}" for ref, image in IMAGE_IDS.items()],
        "systemctl show -p ActiveState": ["ActiveState=active", "NeedDaemonReload=no"],
        RENDER_PROBE: [
            f"id group:media {GID}",
            f"id user:vpnstack {UID}",
            f"file {VPN_ENV} same",
            f"file {APPS_ENV} same",
        ],
        COPY_PROBE: ["same"],
        QBT_PROBE: ["current"],
        "docker network inspect": ["present"],
    }
    for directory in cfg.directories:
        mode = (
            "drwxrwsr-x"
            if directory.mode == "2775"
            else {"0750": "drwxr-x---", "0700": "drwx------"}.get(directory.mode, "drwxr-xr-x")
        )
        responses.update(fakehost.stat(str(directory.path), user=directory.owner, group=directory.group, mode=mode))
    for path in ("/etc/systemd/system", "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.service("vpnstack.service"))
    responses.update(fakehost.file(COMPOSE, render_compose(cfg)))
    responses.update(fakehost.file(UNIT, render_unit(cfg)))
    route = route_config(cfg, secrets)
    if route is not None:
        auth = None if route.basic_auth is None else hash_password(route.basic_auth.password.get_secret_value())
        responses.update(fakehost.file(ROUTE, route_without_http(route, auth)))
    for env in envs.values():
        if env.content is not None:
            text = env.content.reveal().decode()
            mode = "-rw-------" if env.mode == "0600" else "-rw-r--r--"
            responses.update(fakehost.file(str(env.path), text, mode=mode))
    responses.update(overrides)
    return responses


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
