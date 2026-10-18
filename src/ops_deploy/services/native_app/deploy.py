"""Plan read-only; mark before writes; clear only after rollout and health succeed."""

from __future__ import annotations

import json
import shlex
from importlib.resources import files as resources
from io import StringIO
from typing import Any

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import files, server, systemd

from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers import http_check, service_rollout, system_user, systemd_unit, traefik_route
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.traefik import DYNAMIC_DIR, BasicAuth, TraefikRoute
from ops_deploy.services.compose_app.config import Secret
from ops_deploy.services.native_app.config import NativeAppConfig
from ops_deploy.services.native_app.render import render_route, render_toml, render_unit


def _fact(script: str) -> str:
    wrapped = f'out=$( {script} ) || exit $?; printf "%s\\n__native_ok__\\n" "$out"'
    result = str(host.get_fact(Command, command=shlex.join(["sh", "-c", wrapped])) or "")
    if not result.endswith("__native_ok__"):
        raise ValueError("native read-only preflight failed")
    return result.removesuffix("__native_ok__").strip()


def _source_command(cfg: NativeAppConfig, mode: str, arch: str) -> str:
    source: dict[str, Any] | None = None
    if cfg.source is not None:
        source = cfg.source.model_dump(mode="json", exclude={"checksums", "insecure_reason"})
        source["checksum"] = cfg.source.checksums[arch]  # type: ignore[index]
        source["url"] = cfg.source.url.replace("{arch}", {"x86_64": "amd64", "aarch64": "arm64"}[arch])
    code = resources("ops_deploy.services.native_app").joinpath("files/release_host.py").read_text()
    return shlex.join(
        ["python3", "-I", "-c", code, mode, json.dumps({"source": source, "state_dir": str(cfg.state_dir)})]
    )


def _port_command(cfg: NativeAppConfig, *, required: bool) -> str:
    code = resources("ops_deploy.services.native_app").joinpath("files/port_host.py").read_text()
    assert cfg.unit is not None
    return shlex.join(
        [
            "python3",
            "-I",
            "-c",
            code,
            json.dumps(
                {
                    "port": cfg.listen_port,
                    "unit": cfg.unit.name,
                    "required": required,
                }
            ),
        ]
    )


def deploy_native_app(cfg: NativeAppConfig, secrets: SecretValues) -> None:
    """Deploy one release/custom unit, or only a route. This subset never invokes apt."""

    # All controller-side rendering and secret validation precede operations.
    config_texts = [(part, render_toml(part.data)) for part in cfg.configs]
    unit_text = render_unit(cfg) if cfg.unit else None
    route = None
    if cfg.route is not None:
        part = cfg.route
        auth = None
        if part.basic_auth_user is not None and part.basic_auth_password is not None:
            user = part.basic_auth_user
            auth = BasicAuth(
                user=secrets[user.secret] if isinstance(user, Secret) else user,
                password=SecretStr(secrets[part.basic_auth_password.secret]),
            )
        route = TraefikRoute(
            name=part.name or cfg.service_name.replace("_", "-"),
            host=part.host,
            app_port=part.port,
            app_host=part.backend_host,
            title=cfg.title,
            basic_auth=auth,
            internal_only=part.access == "internal",
            internal_ip_ranges=part.internal_ip_ranges,
            frame_options=part.frame_options,
        )
        render_route(route, "validation-only" if auth else None)
    if _fact("uname -s") != "Linux" or _fact("cat /proc/1/comm") != "systemd":
        raise ValueError("native_app requires Linux with systemd")
    arch = _fact("uname -m")
    if cfg.source and arch not in cfg.source.checksums:
        raise ValueError("release has no checksum for the target architecture")
    for path in cfg.mounts_required:
        if (
            _fact(
                f"if findmnt --mountpoint {shlex.quote(str(path))} >/dev/null; then echo present; else echo missing; fi"
            )
            != "present"
        ):
            raise ValueError("required mount is absent")
    for path in cfg.paths_required:
        if _fact(f"if test -d {shlex.quote(str(path))}; then echo present; else echo missing; fi") != "present":
            raise ValueError("required external directory is absent")
    for path in cfg.executables_required:
        if _fact(f"if test -x {shlex.quote(str(path))}; then echo present; else echo missing; fi") != "present":
            raise ValueError("runtime prerequisite is absent; provision it separately")
    if cfg.listen_port is not None and _fact(_port_command(cfg, required=False)) != "ready":
        raise ValueError("native port preflight failed")
    source_state = _fact(_source_command(cfg, "probe", arch))
    if source_state not in ("current", "adopt", "install"):
        raise ValueError("release probe returned an invalid state")
    state = shlex.quote(str(cfg.state_dir))
    pending = _fact(f"if test -e {state}/pending; then echo pending; fi") == "pending"
    restart_path = f"{state}/restart"
    restart_left = _fact(f"if test -e {restart_path}; then echo restart; fi") == "restart"
    all_ops: list[OperationMeta] = []
    inputs: list[OperationMeta] = []

    def mutation_needed() -> bool:
        return source_state != "current" or pending or restart_left or any(op.will_change for op in all_ops)

    def restart_needed() -> bool:
        return restart_left or any(op.will_change for op in inputs)

    server.shell(
        name="Mark native apply pending",
        commands=[f"install -d -o root -g root -m 0700 {state} && touch {state}/pending"],
        _if=mutation_needed,
    )
    if cfg.unit is not None:
        server.shell(name="Mark native restart owed", commands=[f"touch {restart_path}"], _if=restart_needed)
    if cfg.account is not None:
        account = cfg.account
        user_ops = system_user(
            account.name, group=account.group, home=account.home, shell=str(account.shell), mode="0750"
        )
        all_ops += [user_ops.group, *user_ops.directories]
        if user_ops.user is not None:
            all_ops.append(user_ops.user)
            inputs.append(user_ops.user)
    for directory in cfg.directories:
        all_ops.append(
            files.directory(
                name=f"Ensure native directory {directory.path}",
                path=str(directory.path),
                user=directory.owner,
                group=directory.group,
                mode=directory.mode,
            )
        )
    if cfg.source:
        if source_state == "install":
            inputs.append(
                server.shell(
                    name="Install pinned native release",
                    commands=[_source_command(cfg, "install", arch)],
                )
            )
        if cfg.binary_link:
            all_ops.append(
                files.link(name="Link native binary", path=str(cfg.binary_link), target=str(cfg.source.dest))
            )
    for config, text in config_texts:
        inputs.append(
            files.put(
                name=f"Write native config {config.path}",
                src=StringIO(text),
                dest=str(config.path),
                user="root",
                group="root",
                mode=config.mode,
            )
        )
    if cfg.unit is not None and unit_text is not None:
        unit_op = systemd_unit(cfg.unit.name, unit_text)
        inputs.append(unit_op)
        reload_owed = (
            _fact(f"systemctl show -p NeedDaemonReload --value {cfg.unit.name}.service 2>/dev/null || true") == "yes"
        )
        # A resumed run must reload even if the unit write already completed.
        if reload_owed or restart_left:
            server.shell(name="Resume native unit reload", commands=["systemctl daemon-reload"])
        rollout = service_rollout(cfg.unit.name, units=[unit_op], restart_when=inputs, always_restart=False)
        # A marker from a failed earlier run is a restart trigger even when files now match.
        systemd.service(
            name="Resume native restart",
            service=f"{cfg.unit.name}.service",
            running=None,
            restarted=True,
            _if=lambda: restart_left and not rollout.start.did_change() and not rollout.restart.did_change(),
        )
        all_ops += [rollout.enable, rollout.start]
        mark_read_only(
            server.shell(
                name="Check native unit active", commands=[f"systemctl is-active --quiet {cfg.unit.name}.service"]
            )
        )
    if route is not None:
        # Track the helper's directory input as well as the route file so its
        # metadata repair is covered by the pending marker before it happens.
        all_ops.append(
            files.directory(
                name="Ensure native route directory",
                path=str(DYNAMIC_DIR),
                user="root",
                group="root",
                mode="0755",
            )
        )
        all_ops.append(traefik_route(route, renderer=render_route, restart="none"))
    if cfg.listen_port is not None:
        mark_read_only(server.shell(name="Check native listener", commands=[_port_command(cfg, required=True)]))
    if cfg.health_url:
        http_check(cfg.health_url, status=cfg.health_statuses)
    all_ops.extend(inputs)
    server.shell(
        name="Commit native applied state", commands=[_source_command(cfg, "commit", arch)], _if=mutation_needed
    )
    server.shell(
        name="Clear native pending markers", commands=[f"rm -f {state}/pending {restart_path}"], _if=mutation_needed
    )
