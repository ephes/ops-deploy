"""Full original API backend, including genuine management and explicit service state."""

from __future__ import annotations

import base64
import json
import shlex
from importlib.resources import files as resources
from io import StringIO
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import require_linux
from ops_deploy.base.uv_install import UvInstallConfig, deploy_uv_install
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import http_check, mark_read_only, systemd_unit
from ops_deploy.helpers.python import _as_user
from ops_deploy.infra.postgres_install import DatabaseSpec, deploy_postgres_install
from ops_deploy.ops import secret_file, secret_stdin, sync_tree

from .config import OperationsApiConfig, OperationsApiPins
from .git import checkout as git_checkout
from .render import render_config, render_route, render_unit

SOURCE_EXCLUDES = (".git", ".venv*", ".env*", "__pycache__", "site", ".cache", "experiments")


def operations_api_port_preflight(cfg: OperationsApiConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but daybook-operations may listen on the app port.

    Like ``common/preflight_ports.yml`` with ``bind: loopback``: a TCP listener
    on the port at a loopback or wildcard address fails the deploy unless every
    process behind it runs in ``daybook-operations.service``. Read-only; runs before
    any change. ``SKIP_PREFLIGHT_PORTS`` has no effect on the pyinfra path.
    """

    unit = "daybook-operations.service"
    script = (
        f"out=$(ss -Hltnp 'sport = :{cfg.port}') || exit 1; "
        "printf '%s\\n' \"$out\" | { bad=0; "
        "while read -r _state _recv _send local _peer users; do "
        'case "${local%:*}" in 127.0.0.1|0.0.0.0|"[::1]"|"[::]"|"*"|"[::ffff:127.0.0.1]") ;; *) continue ;; esac; '
        "pids=$(printf '%s' \"$users\" | grep -o 'pid=[0-9]*' | cut -d= -f2); "
        '[ -n "$pids" ] || bad=1; '
        "for pid in $pids; do "
        f"grep -qx '0::/system.slice/{unit}' /proc/$pid/cgroup 2>/dev/null || bad=1; done; "
        '[ "$bad" = 0 ] || echo "port in use: $local $users" >&2; '
        'done; [ "$bad" = 0 ]; }'
    )
    return mark_read_only(
        server.shell(name=f"Port preflight tcp/{cfg.port}", commands=[f"sh -c {shlex.quote(script)}"])
    )


def source_ownership_command(cfg: OperationsApiConfig, *, check: bool) -> str:
    path = shlex.quote(str(cfg.site_path))
    owner = shlex.quote(cfg.user)
    selected = f"find -P {path} \\( ! -user {owner} -o ! -group {owner} \\)"
    if check:
        return (
            f"if ! id -u {owner} >/dev/null 2>&1 || ! getent group {owner} >/dev/null 2>&1; then echo pending; "
            f"elif test ! -d {path}; then echo current; else "
            f"out=$({selected} -print -quit) || exit 1; "
            'if test -z "$out"; then echo current; else echo pending; fi; fi'
        )
    return selected + " -exec chown -h " + shlex.quote(cfg.user + ":" + cfg.user) + " -- {} +"


def management_command() -> str:
    source = base64.b64encode(resources(__package__).joinpath("files/management_host.py").read_bytes()).decode()
    script = (
        f"import base64;exec(compile(base64.b64decode('{source}'),"
        "'<operations-management>','exec'),{'__name__':'__main__'})"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", script])


def management_payload(cfg: OperationsApiConfig, action: str) -> SecretContent:
    if action not in {"migrate", "provision"}:
        raise ValueError("Unsupported Operations API management action")
    return SecretContent(
        json.dumps(
            {
                "user": cfg.user,
                "site": str(cfg.site_path),
                "venv": str(cfg.venv_path),
                "config_dir": cfg.config_dir,
                "action": action,
            }
        )
        + "\n"
    )


def dependency_command(cfg: OperationsApiConfig, *, check: bool) -> str:
    argv = [cfg.uv, "sync", "--frozen", "--no-dev", "--group", "operations-api", "--python", "3.14"]
    if check:
        argv += ["--check", "--offline", "--no-cache", "--no-python-downloads"]
    return (
        "cd "
        + shlex.quote(str(cfg.site_path))
        + " && "
        + _as_user(cfg.user, PurePosixPath(cfg.home), {"UV_PROJECT_ENVIRONMENT": str(cfg.venv_path)}, argv)
    )


@deploy("Deploy Daybook Operations API")
def deploy_daybook_operations_api(
    cfg: OperationsApiConfig, pins: OperationsApiPins, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    protected = render_config(cfg, pins)
    require_linux("daybook_operations_api")
    deploy_postgres_install(
        cfg=cfg.postgres,
        databases=(DatabaseSpec(name=cfg.database, owner=cfg.database_user, password=pins.database_password),),
    )
    server.group(name="Ensure Operations API group", group=cfg.user, system=True)
    server.user(
        name="Ensure Operations API account",
        user=cfg.user,
        group=cfg.user,
        home=cfg.home,
        shell="/usr/sbin/nologin",
        system=True,
        ensure_home=True,
        create_home=True,
    )
    site = files.directory(
        name="Ensure Operations API site", path=str(cfg.site_path), user=cfg.user, group=cfg.user, mode="0750"
    )
    files.directory(
        name="Ensure Operations API configuration", path=cfg.config_dir, user=cfg.user, group=cfg.user, mode="0750"
    )
    files.directory(
        name="Ensure Operations API backups", path=cfg.backup_root, user=cfg.user, group=cfg.user, mode="0700"
    )
    deploy_uv_install(cfg=UvInstallConfig(install_dir=str(PurePosixPath(cfg.uv).parent)))
    if cfg.deploy_method == "rsync":
        assert cfg.source_path is not None
        code = sync_tree(
            name="Sync exact Operations API source",
            src=cfg.source_path,
            dest=cfg.site_path,
            excludes=SOURCE_EXCLUDES,
            runner=rsync,
            user=cfg.user,
            group=cfg.user,
            prepared_by=site,
            rsync_path="/usr/bin/rsync",
        )
    else:
        code = git_checkout(cfg)
    # The SDK's recursive directory operation checks only the parent owner.
    # The original role also repairs descendant ownership; inspect metadata only
    # and chown only mismatches, avoiding ctime churn on a converged repeat.
    ownership = host.get_fact(Command, command=source_ownership_command(cfg, check=True))
    if ownership not in {"current", "pending"}:
        raise DeployError("Operations API source ownership inspection failed")
    server.shell(
        name="Set original source ownership",
        commands=[source_ownership_command(cfg, check=False)],
        _if=lambda: ownership == "pending",
    )
    # Read-only dependency check avoids an invented restart on every successful
    # managed repeat. The real frozen sync still runs after source change/drift.
    check = dependency_command(cfg, check=True)
    dependency_state = host.get_fact(
        Command, command=f"if {check} >/dev/null 2>&1; then echo current; else echo pending; fi"
    )
    deps = server.shell(
        name="Sync Operations API frozen dependencies",
        commands=[dependency_command(cfg, check=False)],
        _if=lambda: dependency_state != "current" or code.did_change(),
    )
    configs = [
        secret_file(
            name=f"Write Operations API {name}",
            path=PurePosixPath(cfg.config_dir) / name,
            content=value,
            mode="0600",
            user=cfg.user,
            group=cfg.user,
        )
        for name, value in protected.items()
    ]
    # These are genuine original management executions, never fact gathering.
    # Provision may write unchanged enabled values; it never edits source rows.
    for action in ("migrate", "provision"):
        secret_stdin(
            name=f"Operations API {action}", command=management_command(), content=management_payload(cfg, action)
        )
    units = [
        systemd_unit("daybook-operations" + ("-reconcile" if kind == "reconcile" else ""), render_unit(cfg, kind))
        for kind in ("api", "reconcile")
    ]
    files.put(
        name="Write Operations API private router",
        src=StringIO(render_route(cfg)),
        dest=cfg.traefik_path,
        user="root",
        group="root",
        mode="0644",
    )
    systemd.daemon_reload(name="Reload Operations API unit definitions", _if=any_changed(*units))
    for name in ("daybook-operations", "daybook-operations-reconcile"):
        state = systemd.service(
            name=f"Set explicit {name} state", service=name, enabled=cfg.enabled, running=cfg.enabled
        )
        if cfg.enabled:

            def should_restart(state: OperationMeta = state) -> bool:
                return not state.did_change() and any_changed(code, deps, *configs, *units)()

            systemd.service(
                name=f"Restart changed {name}",
                service=name,
                restarted=True,
                _if=should_restart,
            )
    if cfg.enabled:
        http_check(
            f"http://127.0.0.1:{cfg.port}/healthz",
            retries=10,
            delay=2,
            timeout=10,
            name="Verify Operations API database readiness",
        )
