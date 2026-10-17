"""The step sequence every Compose app shares (2.10 of the design), and its removal.

1. Render everything and check every value (no operation before that).
2. Read-only: required mounts and paths, the port preflight; Docker (the
   ``docker_install`` steps) and ``docker compose version``.
3. Groups, users, directories; external networks.
4. Read the host (:mod:`.state`) and decide. When the run applies, it marks
   itself pending before the first input write, then writes the compose,
   env and config files and pulls the pinned images that are missing.
5. The unit (``daemon-reload`` only when it changed or systemd says so), then
   the apply: ``systemctl reload`` (``ExecReload`` = ``up -d
   --remove-orphans``), or ``start`` when the unit is not active. When a
   namespace provider (a service others join with ``network_mode:
   service:X``) may be recreated, its dependents are stopped first; Compose
   starts them again only once the provider is healthy. Then the readers of
   changed config files restart.
6. The route (never a Traefik restart), the API steps, the read-only checks,
   the stamp, and the legacy directories.

A routine deploy never runs ``systemctl restart`` (``down`` + ``up``).
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from io import StringIO
from typing import cast

from pydantic import SecretStr
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Users
from pyinfra.operations import files, server, systemd

from ops_deploy.base._common import RoleConfig, output
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import BasicAuth, TraefikRoute, mark_read_only, systemd_unit, traefik_route
from ops_deploy.helpers.systemd import UNIT_DIR
from ops_deploy.helpers.traefik import DYNAMIC_DIR, render_route
from ops_deploy.infra import docker_steps
from ops_deploy.ops import secret_file, secret_stdin
from ops_deploy.services._lifecycle import exists, remove_path, stop_disable
from ops_deploy.services.compose_app import checks
from ops_deploy.services.compose_app.config import AppUser, ComposeAppConfig, Directory, Secret
from ops_deploy.services.compose_app.render import (
    RenderedEnv,
    check_secrets,
    host_refs,
    render_compose,
    render_config,
    render_env,
    render_unit,
    resolve,
)
from ops_deploy.services.compose_app.state import (
    COMPOSE_HOST,
    PENDING,
    Plan,
    host_specs,
    payload,
    plan,
    script,
)
from ops_deploy.services.compose_app.steps import api_steps


def deploy_compose_app(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    """Deploy one app; the operations are named ``Deploy <service_name> | ...``."""

    named = cast(Callable[[ComposeAppConfig, SecretValues], None], deploy(f"Deploy {cfg.service_name}")(_deploy))
    named(cfg, secrets)


def route_config(cfg: ComposeAppConfig, secrets: SecretValues) -> TraefikRoute | None:
    route = cfg.route
    if route is None:
        return None
    auth = None
    if route.access == "internal_or_basic_auth" and route.basic_auth_password is not None:
        user = route.basic_auth_user
        auth = BasicAuth(
            user=resolve(user, secrets) if isinstance(user, Secret) else user or "",
            password=SecretStr(resolve(route.basic_auth_password, secrets)),
        )
    return TraefikRoute(
        name=route.name or cfg.service_name.replace("_", "-"),
        host=route.host,
        app_port=route.port,
        # A YAML comment: the title without the characters the helper refuses there.
        title=re.sub(r"[^A-Za-z0-9 ._()-]", "", cfg.title),
        basic_auth=auth,
        internal_only=route.access == "internal",
        internal_ip_ranges=route.internal_ip_ranges,
        frame_options=route.frame_options,
    )


def route_without_http(route: TraefikRoute, auth_hash: str | None) -> str:
    """The helper's route without its ``-http`` router: nothing on the HTTP entrypoint.

    The static config redirects that entrypoint to HTTPS before any router;
    without a router there, the backend cannot be served over HTTP even if
    the redirect went away.
    """

    text = render_route(route, auth_hash)
    stripped = re.sub(r"\n\n    # Plain HTTP;.*?(?=\n\n  middlewares:)", "", text, count=1, flags=re.S)
    if stripped == text or re.search(rf"^    {re.escape(route.name)}-http:$", stripped, re.M):
        raise ValueError(f"route {route.name}: the helper's -http router was not found")
    return stripped


def _preconditions(cfg: ComposeAppConfig) -> None:
    for mount in cfg.mounts_required:
        quoted = shlex.quote(str(mount))
        mark_read_only(
            server.shell(
                name=f"Require the mount {mount}",
                commands=[
                    f"findmnt --mountpoint {quoted} >/dev/null || {{ echo {quoted}' is not mounted' >&2; exit 1; }}"
                ],
            )
        )
    for required in cfg.paths_required:
        quoted = shlex.quote(str(required.path))
        message = shlex.quote(f"missing {required.path}: {required.hint}")
        mark_read_only(
            server.shell(
                name=f"Require {required.path}",
                commands=[f"test -e {quoted} || {{ echo {message} >&2; exit 1; }}"],
            )
        )
    checks.port_preflight(cfg)


def _users(cfg: ComposeAppConfig) -> None:
    for group in cfg.groups:
        server.group(name=f"Ensure group {group}", group=group, system=True)
    existing = host.get_fact(Users)
    for user in cfg.users:
        _user(user, existing.get(user.name))


def _user(user: AppUser, existing: dict[str, object] | None) -> None:
    """Create a missing user; an existing one only gets its missing groups (like the playbooks' ``append``)."""

    server.group(name=f"Ensure group {user.primary_group}", group=user.primary_group, system=True)
    if existing is None:
        server.user(
            name=f"Ensure user {user.name}",
            user=user.name,
            group=user.primary_group,
            groups=list(user.groups),
            home=str(user.home),
            shell=user.shell,
            system=True,
            create_home=True,
        )
        return
    for key, wanted in (("home", str(user.home)), ("shell", user.shell), ("group", user.primary_group)):
        if existing.get(key) != wanted:
            logger.warning(f"{host.name}: existing user {user.name} has {key} {existing.get(key)!r}, left unchanged")
    groups = cast(list[str], existing.get("groups") or [])
    missing = [g for g in user.groups if g not in groups and g != existing.get("group")]
    if missing:
        server.user(
            name=f"Add {user.name} to {', '.join(missing)}",
            user=user.name,
            groups=missing,
            append=True,
            ensure_home=False,
        )


def _directory(directory: Directory) -> None:
    mode = directory.mode.rjust(4, "0")
    if directory.owner.isdigit():
        # Numeric ids (a container's user without a name here): compared with stat,
        # as files.directory would compare names and chown every run.
        path = shlex.quote(str(directory.path))
        wanted = f"{directory.owner} {directory.group} {int(mode, 8):o}"
        current = output(f"stat -c '%u %g %a' {path}").strip()
        files.directory(name=f"Ensure directory {directory.path}", path=str(directory.path))
        if current != wanted:
            server.shell(
                name=f"Set owner and mode of {directory.path}",
                commands=[f"chown {directory.owner}:{directory.group} {path} && chmod {mode} {path}"],
            )
        return
    files.directory(
        name=f"Ensure directory {directory.path}",
        path=str(directory.path),
        user=directory.owner,
        group=directory.group,
        mode=mode,
    )


def _networks(cfg: ComposeAppConfig) -> None:
    for network in cfg.external_networks:
        quoted = shlex.quote(network)
        if output(f"docker network inspect {quoted} >/dev/null && echo present").strip() != "present":
            server.shell(name=f"Create the Docker network {network}", commands=[f"docker network create {quoted}"])


def _compose(cfg: ComposeAppConfig, *args: str) -> str:
    return shlex.join(["docker", "compose", "-p", cfg.project, "-f", str(cfg.compose_path), *args])


def _inputs(
    cfg: ComposeAppConfig,
    decided: Plan,
    compose: str,
    envs: dict[str, RenderedEnv],
    configs: dict[str, tuple[str, bool]],
) -> None:
    """The pending marker (when applying), then the compose, env and config files and the pulls."""

    state = shlex.quote(str(cfg.state_dir))
    if decided.apply:
        server.shell(
            name=f"Mark {cfg.service_name} pending",
            commands=[f"install -d -o root -g root -m 0700 {state} && touch {state}/{PENDING}"],
        )
        for path in decided.legacy_files:
            files.file(name=f"Remove the former {path}", path=path, present=False)
    files.put(
        name=f"Write {cfg.compose_file}",
        src=StringIO(compose),
        dest=str(cfg.compose_path),
        user="root",
        group="root",
        mode="0644",
    )
    for env in envs.values():
        if env.content is not None:
            secret_file(
                name=f"Write {env.path.name}",
                path=env.path,
                content=env.content,
                mode=env.mode,
                user="root",
                group="root",
            )
    hosted = host_specs(envs)
    if hosted and (decided.host_probe_failed or any(spec["path"] in decided.differs for spec in hosted)):
        secret_stdin(
            name="Write the env files with host values",
            command=script(COMPOSE_HOST, "render-apply"),
            content=SecretContent(payload({"ids": host_refs(cfg), "files": hosted})),
        )
    for config in cfg.config_files:
        text, private = configs[str(config.path)]
        mode = config.mode.rjust(4, "0")
        if private:
            secret_file(
                name=f"Write {config.path}",
                path=config.path,
                content=SecretContent(text),
                mode=mode,
                user=config.owner,
                group=config.group,
            )
        else:
            files.put(
                name=f"Write {config.path}",
                src=StringIO(text),
                dest=str(config.path),
                user=config.owner,
                group=config.group,
                mode=mode,
            )
    for ref in decided.missing_images:
        server.shell(name=f"Pull {ref}", commands=[shlex.join(["docker", "pull", "--quiet", ref])])


def _rollout(cfg: ComposeAppConfig, decided: Plan, unit_text: str) -> None:
    unit = f"{cfg.unit_name}.service"
    unit_op = systemd_unit(cfg.unit_name, unit_text)
    if unit_op.will_change or decided.unit_stale:
        systemd.daemon_reload(name=f"Reload systemd for {unit}")
    systemd.service(name=f"Enable {unit}", service=unit, running=None, enabled=True)
    if not decided.apply:
        return
    dependents = [d for p in cfg.providers if decided.service_changed(cfg, p) for d in cfg.dependents(p)]
    if dependents:
        server.shell(
            name=f"Stop {', '.join(dependents)} before their network namespace is replaced",
            commands=[_compose(cfg, "stop", *dependents)],
        )
    verb = "reload" if decided.unit_active else "start"
    server.shell(name=f"{verb.capitalize()} {unit}", commands=[f"systemctl {verb} {shlex.quote(unit)}"])
    readers = sorted(
        {s for c in cfg.config_files if decided.file_changed(str(c.path)) for s in c.restarts if s not in dependents}
    )
    if readers:
        server.shell(
            name=f"Restart {', '.join(readers)} for their config files", commands=[_compose(cfg, "restart", *readers)]
        )


def _legacy_dirs(cfg: ComposeAppConfig) -> None:
    for path in cfg.legacy_dirs:
        quoted = shlex.quote(str(path))
        if output(f"test -d {quoted} && echo yes").strip() != "yes":
            continue
        if output(f"find {quoted} ! -type d -print -quit").strip():
            logger.warning(f"{host.name}: legacy directory {path} is not empty; kept")
            continue
        server.shell(
            name=f"Remove the empty legacy directory {path}", commands=[f"find {quoted} -depth -type d -empty -delete"]
        )


def _deploy(cfg: ComposeAppConfig, secrets: SecretValues) -> None:
    # Everything is rendered (and every value checked) before any operation.
    check_secrets(cfg, secrets)
    compose = render_compose(cfg)
    envs = {env.name: render_env(cfg, env, secrets) for env in cfg.env_files}
    configs = {str(c.path): render_config(c, secrets) for c in cfg.config_files}
    unit_text = render_unit(cfg)
    route = route_config(cfg, secrets)

    _preconditions(cfg)
    docker_steps(cfg.docker)
    mark_read_only(server.shell(name="Check Docker Compose", commands=["docker compose version >/dev/null"]))
    _users(cfg)
    for directory in cfg.directories:
        _directory(directory)
    _networks(cfg)

    decided = plan(cfg, compose, envs, {path: text for path, (text, _) in configs.items()})
    _inputs(cfg, decided, compose, envs, configs)
    _rollout(cfg, decided, unit_text)
    if route is not None:
        traefik_route(route, renderer=route_without_http, restart="none")
    api_steps(cfg, secrets, recreated=decided.apply)
    checks.rollout_checks(cfg)
    if decided.apply:
        # Last: only a run that came up healthy records what it applied.
        secret_stdin(
            name=f"Record the applied {cfg.service_name} state",
            command=script(COMPOSE_HOST, "stamp"),
            content=SecretContent(
                payload({"state_dir": str(cfg.state_dir), "stamp": decided.desired, "ids": host_refs(cfg)})
            ),
        )
    _legacy_dirs(cfg)


class ComposeAppRemoveConfig(RoleConfig):
    """What :func:`remove_compose_app` takes down; nothing happens without ``confirm``."""

    app: ComposeAppConfig
    confirm: bool = False


def remove_compose_app(cfg: ComposeAppRemoveConfig) -> None:
    """Stop and remove the app: unit, containers, route, compose, env and config files, stamp.

    Directories, data, host secrets, images and external networks stay.
    """

    named = cast(Callable[[ComposeAppConfig, bool], None], deploy(f"Remove {cfg.app.service_name}")(_remove))
    named(cfg.app, cfg.confirm)


def _remove(cfg: ComposeAppConfig, confirm: bool) -> None:
    if not confirm:
        raise DeployError(
            f"{cfg.service_name}: removal not confirmed; this stops the app and removes its unit, "
            "containers, route and files (data stays). Set confirm to proceed."
        )
    unit = f"{cfg.unit_name}.service"
    stop_disable([unit])
    project = shlex.quote(f"label=com.docker.compose.project={cfg.project}")
    if output(f"docker ps -aq --filter {project}").strip():
        if exists(str(cfg.compose_path)):
            server.shell(
                name=f"Remove the {cfg.project} containers", commands=[_compose(cfg, "down", "--remove-orphans")]
            )
        else:
            server.shell(
                name=f"Remove the {cfg.project} containers",
                commands=[f"docker ps -aq --filter {project} | xargs -r docker rm -f"],
            )
    reload = remove_path(str(UNIT_DIR / unit))
    if cfg.route is not None:
        remove_path(str(DYNAMIC_DIR / f"{cfg.route.name or cfg.service_name.replace('_', '-')}.yml"))
    for env in cfg.env_files:
        remove_path(str(cfg.env_path(env)))
    for config in cfg.config_files:
        remove_path(str(config.path))
    remove_path(str(cfg.compose_path))
    remove_path(str(cfg.state_dir))
    if reload:
        systemd.daemon_reload(name="Reload systemd")
