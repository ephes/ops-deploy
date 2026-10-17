"""compose_app on the smoke target: a namespace provider with two dependents, end to end.

The app has the torrent stack's shape with stand-ins: the provider is a small
image built on the VM (busybox; its health endpoint answers only while
``SMOKE_HEALTHY=1`` in its env file), the dependents are busybox web servers in
its network namespace. All images come from a registry on the VM, pinned by
digest, so the first run pulls what is missing and later runs never pull.
No VPN, no real credentials.

The runs, in order (each followed by a rerun that must change nothing):

1. first deploy: users, directories, host secret, env files, pulls, start, route, key copy, stamp;
2. an env change read by one service: only that container is recreated;
3. a config file change: only its reader restarts (same container);
4. a unit-only change (``ExecStop``): ``daemon-reload``, no container touched;
5. a failed apply (``ExecReload`` broken by a runtime drop-in) after a config
   change: ``pending`` stays; once fixed, the next run applies again, with the
   dependents stopped first (a pending run may have replaced the provider);
6. a failed apply of an env change, then a revert: the file is written back;
7. a stopped container is started again;
8. the provider never becomes healthy: the deploy fails with the dependents
   stopped (never running outside the new namespace); the revert brings
   everything back, the dependents in the new provider's namespace;
9. the port preflight stops a run before any change when a port is taken;
10. remove: unit, containers, route and files go, data and the host secret stay.

Traefik is never restarted.
"""

from __future__ import annotations

import json
import secrets
import shlex
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.infra import DockerInstallConfig, deploy_docker_install
from ops_deploy.services.compose_app import (
    AppUser,
    Bind,
    ComposeAppConfig,
    ComposeAppRemoveConfig,
    ComposeService,
    ConfigFile,
    Directory,
    EnvEntry,
    EnvFile,
    Healthcheck,
    HostId,
    HostSecret,
    JsonKeyCopy,
    PublishedPort,
    RequiredPath,
    Route,
    Secret,
    Sysctl,
    deploy_compose_app,
    remove_compose_app,
)
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

APP = "casmoke"
ROOT = "/srv/casmoke"
SITE = f"/home/{APP}/site"
STATE = f"/var/lib/ops-deploy/{APP}"
REGISTRY = "127.0.0.1:5000"
APIKEY = f"{SITE}/vpn-control-apikey"
CONFIG = f"{ROOT}/client/conf.yml"
FQDN = "casmoke.example.invalid"
PREFIX = f"Deploy {APP} | "
PROVIDER_ENTRY = """#!/bin/sh
mkdir -p /www && echo ok > /www/index.html
if [ "${SMOKE_HEALTHY:-1}" = 1 ]; then httpd -p 127.0.0.1:9999 -h /www; fi
trap 'exit 0' TERM INT
while :; do sleep 1; done
"""


@dataclass
class Images:
    provider: str
    box: str


@dataclass
class Smoke:
    host: SmokeHost
    images: Images
    values: SecretValues
    runs: dict[str, SshRun] = field(default_factory=dict)

    def deploy(self, label: str, cfg: ComposeAppConfig, *, succeed: bool = True) -> SshRun:
        run = run_deploy_ssh(
            deploy_compose_app, cfg, self.values, host_name=self.host.name, host_data=self.host.host_data
        )
        TIMINGS[f"compose_app: {label}"] = run.seconds
        self.runs[label] = run
        if succeed:
            assert run.succeeded, (label, run.error, [op.name for op in run.ops if not op.succeeded])
        return run

    def converged(self, label: str, cfg: ComposeAppConfig) -> None:
        run = self.deploy(f"{label} (rerun)", cfg)
        assert run.mutating_changed_ops == [], label

    def containers(self) -> dict[str, tuple[str, str, str]]:
        """service -> (id, StartedAt, status)."""

        fmt = '{{index .Config.Labels "com.docker.compose.service"}} {{.Id}} {{.State.StartedAt}} {{.State.Status}}'
        out = self.host.out(
            f"ids=$(docker ps -aq --filter label=com.docker.compose.project={APP}); "
            f'[ -z "$ids" ] || docker inspect --format {shlex.quote(fmt)} $ids'
        )
        result = {}
        for line in out.splitlines():
            name, cid, started, status = line.split()
            result[name] = (cid, started, status)
        return result


def app_config(images: Images, **changes: Any) -> ComposeAppConfig:
    check = Healthcheck(
        test=("CMD-SHELL", "wget -qO- http://127.0.0.1:9999 >/dev/null 2>&1"),
        interval="2s",
        timeout="2s",
        retries=3,
        start_period="1s",
    )
    vpn = ComposeService(
        name="vpn",
        image=images.provider,
        cap_add=("NET_ADMIN",),
        devices=("/dev/net/tun",),
        sysctls=(
            Sysctl(key="net.ipv6.conf.all.disable_ipv6", value="1"),
            Sysctl(key="net.ipv6.conf.default.disable_ipv6", value="1"),
        ),
        env_files=("vpn.env",),
        binds=(Bind(source=f"{SITE}/vpn", target="/gluetun"),),
        ports=(PublishedPort(published=18480, target=8080), PublishedPort(published=18481, target=9117)),
        healthcheck=check,
    )
    client = ComposeService(
        name="client",
        image=images.box,
        network_mode="service:vpn",
        command=("sh", "-c", "mkdir -p /www && echo client > /www/index.html && exec httpd -f -p 8080 -h /www"),
        env_files=("client.env",),
        binds=(
            Bind(source=f"{ROOT}/client", target="/config"),
            Bind(source=f"{ROOT}/downloads"),
            Bind(source=CONFIG, target="/conf.yml", read_only=True),
        ),
    )
    indexer = ComposeService(
        name="indexer",
        image=images.box,
        network_mode="service:vpn",
        command=("sh", "-c", "mkdir -p /www && echo indexer > /www/index.html && exec httpd -f -p 9117 -h /www"),
        env_files=("indexer.env",),
        binds=(Bind(source=f"{ROOT}/indexer", target="/config"),),
        healthcheck=Healthcheck(
            test=("CMD-SHELL", "wget -qO- http://127.0.0.1:9117 >/dev/null 2>&1"),
            interval="2s",
            timeout="2s",
            retries=3,
            start_period="1s",
        ),
    )
    values: dict[str, Any] = {
        "service_name": APP,
        "title": "compose_app smoke (vpn + client + indexer)",
        "project": APP,
        "user": APP,
        "site_path": SITE,
        "secrets": SecretRef("secrets/smoke/casmoke.yml"),
        "groups": ("casmedia",),
        "users": (AppUser(name=APP, groups=("casmedia",), home=f"/home/{APP}"),),
        "mounts_required": (ROOT,),
        "paths_required": (RequiredPath(path=ROOT, hint="the smoke fixture mounts it"),),
        "directories": (
            Directory(path=f"{ROOT}/client", owner=APP, group="casmedia", mode="0750"),
            Directory(path=f"{ROOT}/indexer", owner=APP, group="casmedia", mode="0750"),
            Directory(path=f"{ROOT}/downloads", owner=APP, group="casmedia", mode="2775"),
            Directory(path=SITE, mode="0755"),
            Directory(path=f"{SITE}/vpn", mode="0700"),
        ),
        "env_files": (
            EnvFile(
                name="vpn.env",
                entries=(
                    EnvEntry(key="SMOKE_HEALTHY", value="1"),
                    EnvEntry(key="VPN_KEY", value=Secret(secret="vpn_key")),
                    EnvEntry(
                        key="HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE",
                        value=('{"auth":"apikey","apikey":"', HostSecret(host_secret=APIKEY), '"}'),
                    ),
                ),
            ),
            EnvFile(
                name="client.env",
                mode="0644",
                entries=(
                    EnvEntry(key="PUID", value=HostId(user=APP)),
                    EnvEntry(key="PGID", value=HostId(group="casmedia")),
                    EnvEntry(key="UMASK", value="002"),
                ),
            ),
            EnvFile(name="indexer.env", mode="0644", entries=(EnvEntry(key="INDEXER_MODE", value="one"),)),
        ),
        "config_files": (
            ConfigFile(
                path=CONFIG,
                format="yaml",
                data={"greeting": "hello", "token": {"secret": "smoke_token"}},
                mode="0640",
                owner=APP,
                group="casmedia",
                restarts=("client",),
            ),
        ),
        "services": (vpn, client, indexer),
        "route": Route(
            host=FQDN,
            port=18480,
            access="internal_or_basic_auth",
            basic_auth_user="smoke",
            basic_auth_password=Secret(secret="basic_auth_password"),
        ),
        "steps": (
            JsonKeyCopy(
                name="Copy the indexer key",
                source=f"{ROOT}/indexer/ServerConfig.json",
                keys=("APIKey",),
                dest=f"{ROOT}/client/jackett.json",
                template={"api_key": "{value}", "url": "http://127.0.0.1:9117"},
                owner=APP,
                group="casmedia",
            ),
        ),
        "legacy_dirs": (f"{ROOT}/old-empty", f"{ROOT}/old-full"),
    }
    values.update(changes)
    return ComposeAppConfig(**values)


def _with_env(cfg: ComposeAppConfig, name: str, *entries: EnvEntry) -> ComposeAppConfig:
    files = tuple(env.model_copy(update={"entries": entries}) if env.name == name else env for env in cfg.env_files)
    return cfg.model_copy(update={"env_files": files})


def _with_greeting(cfg: ComposeAppConfig, greeting: str) -> ComposeAppConfig:
    config = cfg.config_files[0]
    data = dict(config.data, greeting=greeting)
    return cfg.model_copy(update={"config_files": (config.model_copy(update={"data": data}),)})


def _prepare(host: SmokeHost) -> Images:
    """Docker, a registry, the images (pushed, then the provider dropped locally), the mount, the source file."""

    run = run_deploy_ssh(deploy_docker_install, DockerInstallConfig(), host_name=host.name, host_data=host.host_data)
    assert run.succeeded, run.error
    host.run(
        f"systemctl disable --now {APP} 2>/dev/null; "
        f"ids=$(docker ps -aq --filter label=com.docker.compose.project={APP}); "
        '[ -z "$ids" ] || docker rm -f $ids; '
        f"rm -f /etc/systemd/system/{APP}.service /etc/traefik/dynamic/{APP}.yml; systemctl daemon-reload; "
        f"rm -rf {STATE} /home/{APP}; userdel {APP} 2>/dev/null; groupdel {APP} 2>/dev/null; true"
    )
    host.run(
        f"mkdir -p {ROOT} && (findmnt --mountpoint {ROOT} >/dev/null || mount -t tmpfs -o size=64m tmpfs {ROOT}) && "
        f"rm -rf {ROOT}/* && mkdir -p {ROOT}/old-empty/sub {ROOT}/old-full {ROOT}/indexer && "
        f"echo keep > {ROOT}/old-full/file && "
        f'echo \'{{"APIKey": "smoke-indexer-key"}}\' > {ROOT}/indexer/ServerConfig.json'
    )
    host.run(
        "docker inspect smoke-registry >/dev/null 2>&1 || "
        "docker run -d --restart=always -p 127.0.0.1:5000:5000 --name smoke-registry registry:2.8.3; "
        "for i in $(seq 1 30); do wget -qO- http://127.0.0.1:5000/v2/ >/dev/null 2>&1 && break; sleep 1; done; "
        f"docker pull -q busybox:1.36.1 >/dev/null && docker tag busybox:1.36.1 {REGISTRY}/{APP}/box:1 && "
        f"docker push -q {REGISTRY}/{APP}/box:1 >/dev/null"
    )
    build = f"/root/{APP}-provider"
    host.run(f"mkdir -p {build} && cat > {build}/entry.sh", input=PROVIDER_ENTRY)
    host.run(
        f'printf \'FROM {REGISTRY}/{APP}/box:1\\nCOPY entry.sh /entry.sh\\nENTRYPOINT ["/bin/sh", "/entry.sh"]\\n\' '
        f"> {build}/Dockerfile && docker build -q -t {REGISTRY}/{APP}/vpn:v1 {build} >/dev/null && "
        f"docker push -q {REGISTRY}/{APP}/vpn:v1 >/dev/null"
    )

    def pin(ref: str) -> str:
        digest = host.out(f"docker image inspect --format '{{{{index .RepoDigests 0}}}}' {ref}").split("@")[-1]
        return f"{ref}@{digest}"

    images = Images(provider=pin(f"{REGISTRY}/{APP}/vpn:v1"), box=pin(f"{REGISTRY}/{APP}/box:1"))
    # The first deploy pulls the provider.
    host.run(f"docker image rm {REGISTRY}/{APP}/vpn:v1 {images.provider} >/dev/null 2>&1; true")
    return images


@pytest.fixture(scope="module")
def smoke(smoke_host: SmokeHost) -> Iterator[Smoke]:
    images = _prepare(smoke_host)
    values = SecretValues(
        SecretRef("secrets/smoke/casmoke.yml"),
        {
            "vpn_key": f"smoke-vpn-{secrets.token_hex(12)}",
            "smoke_token": f"smoke-token-{secrets.token_hex(8)}",
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(8)}",
        },
    )
    yield Smoke(smoke_host, images, values)
    smoke_host.run(f"rm -rf /run/systemd/system/{APP}.service.d; systemctl daemon-reload; true")


def _traefik_restarts(host: SmokeHost) -> str:
    return host.out(
        "systemctl show -p NRestarts --value traefik; systemctl show -p ExecMainStartTimestamp --value traefik"
    )


def _break_reload(host: SmokeHost, broken: bool) -> None:
    dropin = f"/run/systemd/system/{APP}.service.d"
    if broken:
        host.run(f"mkdir -p {dropin} && printf '[Service]\\nExecReload=\\nExecReload=/bin/false\\n' > {dropin}/x.conf")
    else:
        host.run(f"rm -rf {dropin}")
    host.run("systemctl daemon-reload")


def test_compose_app_lifecycle(smoke: Smoke) -> None:
    host = smoke.host
    cfg = app_config(smoke.images)
    traefik = _traefik_restarts(host)

    # 1. first deploy
    first = smoke.deploy("first", cfg)
    assert f"{PREFIX}Pull {smoke.images.provider}" in first.mutating_changed_ops
    assert f"{PREFIX}Pull {smoke.images.box}" not in first.mutating_changed_ops
    states = smoke.containers()
    assert {name: state[2] for name, state in states.items()} == {
        "vpn": "running",
        "client": "running",
        "indexer": "running",
    }
    vpn_id = states["vpn"][0]
    for dependent in ("client", "indexer"):
        mode = host.out(f"docker inspect --format '{{{{.HostConfig.NetworkMode}}}}' {states[dependent][0]}")
        assert mode == f"container:{vpn_id}"
    assert host.out(f"stat -c '%U %G %a' {APIKEY}") == "root root 600"
    apikey = host.out(f"cat {APIKEY}")
    env = host.out(f"docker inspect --format '{{{{json .Config.Env}}}}' {vpn_id}")
    assert f'HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={{"auth":"apikey","apikey":"{apikey}"}}' in json.loads(env)
    uid, gid = host.out(f"id -u {APP}"), host.out("getent group casmedia | cut -d: -f3")
    client_env = json.loads(host.out(f"docker inspect --format '{{{{json .Config.Env}}}}' {states['client'][0]}"))
    assert f"PUID={uid}" in client_env
    assert f"PGID={gid}" in client_env
    assert host.out(f"docker exec {vpn_id} cat /proc/sys/net/ipv6/conf/all/disable_ipv6") == "1"
    listen = host.out("ss -Hltn 'sport = :18480' | awk '{print $4}'")
    assert listen == "127.0.0.1:18480"
    assert host.out("wget -qO- http://127.0.0.1:18480/") == "client"
    assert json.loads(host.out(f"cat {ROOT}/client/jackett.json"))["api_key"] == "smoke-indexer-key"
    assert host.out(f"test -e {ROOT}/old-empty && echo yes || echo no") == "no"
    assert host.out(f"cat {ROOT}/old-full/file") == "keep"
    assert host.out(f"test -e {STATE}/pending && echo yes || echo no") == "no"
    assert json.loads(host.out(f"cat {STATE}/applied.json"))["ids"] == {
        "group:casmedia": int(gid),
        f"user:{APP}": int(uid),
    }
    assert host.out(f"stat -c '%a' {STATE}") == "700"
    # The route: internal clients pass, the rest needs Basic Auth.
    lan_ip = host.out("ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1")
    curl = f"curl -sk -o /dev/null -w '%{{http_code}}' -H 'Host: {FQDN}'"
    for _ in range(20):
        if host.out(f"{curl} https://{lan_ip}/") == "200":
            break
        time.sleep(1)
    assert host.out(f"{curl} https://{lan_ip}/") == "200"
    assert host.out(f"{curl} https://127.0.0.1/") == "401"
    smoke.converged("first", cfg)

    # 2. an env change read by one service: only that container is recreated
    before = smoke.containers()
    one = _with_env(cfg, "indexer.env", EnvEntry(key="INDEXER_MODE", value="two"))
    run = smoke.deploy("indexer env", one)
    assert f"{PREFIX}Reload {APP}.service" in run.mutating_changed_ops
    after = smoke.containers()
    assert after["indexer"][0] != before["indexer"][0]
    assert after["vpn"] == before["vpn"]
    assert after["client"] == before["client"]
    smoke.converged("indexer env", one)

    # 3. a config file change: only its reader restarts, in place
    greeted = _with_greeting(one, "hi")
    before = smoke.containers()
    run = smoke.deploy("config file", greeted)
    assert f"{PREFIX}Restart client for their config files" in run.mutating_changed_ops
    after = smoke.containers()
    assert after["client"][0] == before["client"][0]
    assert after["client"][1] != before["client"][1]
    assert after["vpn"] == before["vpn"]
    assert after["indexer"] == before["indexer"]
    assert "greeting: hi" in host.out(f"docker exec {after['client'][0]} cat /conf.yml")
    smoke.converged("config file", greeted)

    # 4. a unit-only change touches no container
    retitled = greeted.model_copy(update={"stop": "stop"})
    before = smoke.containers()
    run = smoke.deploy("unit only", retitled)
    assert run.mutating_changed_ops == [
        f"{PREFIX}Install systemd unit {APP}.service",
        f"{PREFIX}Reload systemd for {APP}.service",
    ]
    assert smoke.containers() == before
    smoke.converged("unit only", retitled)

    # 5. a failed apply after a config change, then the fixed rerun
    _break_reload(host, True)
    hello = _with_greeting(retitled, "hello again")
    before = smoke.containers()
    failed = smoke.deploy("failed apply", hello, succeed=False)
    assert not failed.succeeded
    assert host.out(f"test -e {STATE}/pending && echo yes") == "yes"
    assert "greeting: hello again" in host.out(f"cat {CONFIG}")
    _break_reload(host, False)
    run = smoke.deploy("after the failed apply", hello)
    # pending: every provider counts as replaced, so its dependents (the reader too) stop and start again.
    assert f"{PREFIX}Stop client, indexer before their network namespace is replaced" in run.mutating_changed_ops
    assert host.out(f"test -e {STATE}/pending && echo yes || echo no") == "no"
    assert smoke.containers()["client"][1] != before["client"][1]
    smoke.converged("after the failed apply", hello)

    # 6. a failed apply of an env change, then a revert to the applied state
    _break_reload(host, True)
    changed = _with_env(hello, "indexer.env", EnvEntry(key="INDEXER_MODE", value="three"))
    assert not smoke.deploy("failed env change", changed, succeed=False).succeeded
    assert "three" in host.out(f"cat {SITE}/indexer.env")
    _break_reload(host, False)
    smoke.deploy("revert", hello)
    assert "INDEXER_MODE='two'" in host.out(f"cat {SITE}/indexer.env")
    assert host.out(f"test -e {STATE}/pending && echo yes || echo no") == "no"
    smoke.converged("revert", hello)

    # 7. a stopped container is started again
    host.run(f"docker stop {smoke.containers()['client'][0]} >/dev/null")
    run = smoke.deploy("stopped container", hello)
    assert f"{PREFIX}Reload {APP}.service" in run.mutating_changed_ops
    assert smoke.containers()["client"][2] == "running"
    smoke.converged("stopped container", hello)

    # 8. the provider never becomes healthy
    unhealthy = _with_env(
        hello,
        "vpn.env",
        EnvEntry(key="SMOKE_HEALTHY", value="0"),
        *[e for e in hello.env_files[0].entries if e.key != "SMOKE_HEALTHY"],
    )
    failed = smoke.deploy("unhealthy provider", unhealthy, succeed=False)
    assert not failed.succeeded
    assert failed.op(f"{PREFIX}Stop client, indexer before their network namespace is replaced").succeeded
    states = smoke.containers()
    assert states["vpn"][2] == "running"
    assert states["client"][2] != "running"
    assert states["indexer"][2] != "running"
    assert host.out(f"test -e {STATE}/pending && echo yes") == "yes"
    run = smoke.deploy("healthy again", hello)
    states = smoke.containers()
    assert all(state[2] == "running" for state in states.values())
    for dependent in ("client", "indexer"):
        mode = host.out(f"docker inspect --format '{{{{.HostConfig.NetworkMode}}}}' {states[dependent][0]}")
        assert mode == f"container:{states['vpn'][0]}"
    smoke.converged("healthy again", hello)

    # 9. the port preflight
    host.run("nohup python3 -m http.server 18482 --bind 127.0.0.1 >/dev/null 2>&1 & sleep 1")
    try:
        vpn = hello.services[0]
        ports = (*vpn.ports, PublishedPort(published=18482, target=8081))
        taken = hello.model_copy(update={"services": (vpn.model_copy(update={"ports": ports}), *hello.services[1:])})
        failed = smoke.deploy("port taken", taken, succeed=False)
        assert not failed.succeeded
        assert failed.mutating_changed_ops == []
        assert not failed.op(f"{PREFIX}Port preflight").succeeded
    finally:
        host.run("pkill -f 'http.server 18482'; true")
    smoke.converged("port free again", hello)

    assert _traefik_restarts(host) == traefik

    # 10. remove keeps the data
    removed = run_deploy_ssh(
        remove_compose_app,
        ComposeAppRemoveConfig(app=hello, confirm=True),
        host_name=host.name,
        host_data=host.host_data,
    )
    assert removed.succeeded, removed.error
    assert smoke.containers() == {}
    for path in (f"/etc/systemd/system/{APP}.service", f"/etc/traefik/dynamic/{APP}.yml", f"{SITE}/compose.yml", STATE):
        assert host.out(f"test -e {path} && echo yes || echo no") == "no", path
    for path in (APIKEY, f"{ROOT}/client/jackett.json", f"{ROOT}/downloads", f"{SITE}/vpn"):
        assert host.out(f"test -e {path} && echo yes || echo no") == "yes", path
