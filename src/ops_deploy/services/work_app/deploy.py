"""work_app: the work ledger, a Django app on SQLite served by gunicorn.

Port of the ``work_app_deploy`` Ansible role (rsync method) and of the
operations wiring in ops-control's ``deploy-work-app.yml`` (port preflight,
Echoport backup target, Nyxmon health check). The files it writes are
byte-identical to the role's (``tests/test_work_app_parity.py``), so Ansible
and ops-deploy can take turns on one host without churn. The SQLite database
lives in the site directory next to the synced trees and is never part of a
sync; this deploy only runs ``migrate`` against it, as the role does.
"""

from __future__ import annotations

import json
import re
import shlex
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar

import jinja2
from pydantic import Field, SecretStr, field_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    http_check,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
)
from ops_deploy.helpers.python import DEFAULT_UV, _as_user
from ops_deploy.helpers.traefik import _MIDDLEWARE, Hostname
from ops_deploy.ops import secret_file, sync_tree

TEMPLATE_PACKAGE = "ops_deploy.services.work_app"
FILES = Path(__file__).parent / "files"

# The role's ``work_app_source_dirs`` / ``work_app_source_files``.
SOURCE_DIRS = ("src", "ledger")
SOURCE_FILES = ("manage.py", "pyproject.toml", "uv.lock")
# The role's ``work_app_rsync_excludes``: never shipped, and protected from --delete.
SOURCE_EXCLUDES = (
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".coverage",
    "htmlcov",
    ".env",
    ".vault_password",
    "*.sqlite3",
    "*.sqlite3-*",
)
# The role's ``work_app_internal_ip_ranges``.
INTERNAL_IP_RANGES = (
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
    "fd50:3e45:c454:0::/64",
)
# Values the role puts unquoted into ``.env``, which its tasks then source
# with a shell: nothing a shell would interpret.
PlainValue = Annotated[str, Field(pattern=r"^[A-Za-z0-9._:/@%+~*-]+$")]
PathValue = Annotated[PurePosixPath, Field()]
UV_SYNC_ARGS = ("--frozen", "--no-dev", "--no-install-project")
_SECRET_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


class WorkAppConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("django_secret_key", "basic_auth_password")

    service_name: ServiceName = "work-app"
    user: UnixUser = "work"
    group: UnixUser = "work"
    home: PathValue = PurePosixPath("/home/work")
    site_path: PathValue = PurePosixPath("/home/work/site")
    database_path: PathValue = PurePosixPath("/home/work/site/db.sqlite3")
    # A work-ledger checkout: ``src/`` and ``ledger/`` are synced into the site
    # directory, ``manage.py``, ``pyproject.toml`` and ``uv.lock`` copied.
    source_path: Path
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    app_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    app_port: int = Field(default=10011, ge=1024, le=65535)
    workers: int = Field(default=2, ge=1, le=64)
    wsgi_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:]+$")] = "src.config.wsgi:application"
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    django_debug: bool = False
    django_allowed_hosts: tuple[PlainValue, ...] = ("127.0.0.1",)
    django_csrf_trusted_origins: tuple[PlainValue, ...] = ()
    django_admin_url: PlainValue = "admin/"
    evidence_base_url: PlainValue = "https://github.com/ephes/work-ledger/blob/main/"
    healthcheck_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")] = "/accounts/login/"
    health_retries: int = Field(default=20, ge=1)
    health_delay: int = Field(default=3, ge=0)
    traefik_host: Hostname = "work.home.example.com"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    internal_ip_ranges: tuple[str, ...] = INTERNAL_IP_RANGES
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"
    # Operations wiring from the playbook; off by default (the role has none).
    echoport_target: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")] | None = None
    echoport_schedule: Annotated[str, Field(pattern=r"^[0-9*/,\- ]+$")] = "10 2 * * *"
    nyxmon_check: bool = False

    @field_validator("django_allowed_hosts")
    @classmethod
    def _hosts_not_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("django_allowed_hosts must not be empty")
        return value

    @field_validator("source_path")
    @classmethod
    def _source_is_a_work_ledger_checkout(cls, value: Path) -> Path:
        missing = [d for d in SOURCE_DIRS if not (value / d).is_dir()]
        missing += [f for f in SOURCE_FILES if not (value / f).is_file()]
        if missing:
            raise ValueError(f"source_path is not a work-ledger checkout (missing {', '.join(missing)})")
        return value

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv"

    @property
    def venv_bin(self) -> PurePosixPath:
        return self.venv_path / "bin"

    @property
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env"

    @property
    def static_root(self) -> PurePosixPath:
        return self.site_path / "staticfiles"

    @property
    def unit(self) -> str:
        return f"{self.service_name}.service"

    @property
    def health_url(self) -> str:
        return f"http://{self.app_host}:{self.app_port}{self.healthcheck_path}"

    @property
    def nyxmon_url(self) -> str:
        return f"http://{self.app_host}:{self.app_port}/healthz"


@cache
def _templates() -> jinja2.Environment:
    # Rendered like Ansible's template module (trim_blocks), for byte parity.
    return jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def render(template: str, **context: object) -> str:
    return _templates().get_template(template).render(**context)


def check_secrets(secrets: SecretValues) -> None:
    """The role's and the playbook's input assertions; errors never quote values."""

    key = secrets.get("django_secret_key", "")
    if len(key) < 50 or "CHANGEME" in key or not _SECRET_KEY.match(key):
        raise ValueError("django_secret_key must be at least 50 characters from [A-Za-z0-9_-] and not a placeholder")
    password = secrets.get("basic_auth_password", "")
    if not password or "CHANGEME" in password:
        raise ValueError("basic_auth_password must be set and not a placeholder")
    if any(c in value for value in secrets.values() for c in "\r\n"):
        raise ValueError("secret values must be single lines")


def render_env(cfg: WorkAppConfig, secrets: SecretValues) -> SecretContent:
    """The role's ``env.j2``."""

    return SecretContent(render("work-app.env.j2", cfg=cfg, secret_key=secrets["django_secret_key"]))


def traefik_config(cfg: WorkAppConfig, secrets: SecretValues) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        title="Work app",
        host=cfg.traefik_host,
        app_port=cfg.app_port,
        app_host=cfg.app_host,
        basic_auth=BasicAuth(
            user=secrets.get("basic_auth_user") or cfg.basic_auth_user,
            password=SecretStr(secrets["basic_auth_password"]),
        ),
        internal_ip_ranges=cfg.internal_ip_ranges,
        middlewares=cfg.traefik_middlewares,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def render_route(route: TraefikRoute, auth_hash: str | None) -> str:
    """The role's own route template (dual routers, HTTP redirect middleware)."""

    return render("work-app.traefik.yml.j2", route=route, auth_hash=auth_hash)


def site_shell(cfg: WorkAppConfig, script: str) -> str:
    """``script`` run in the site directory as the service user."""

    shell = _as_user(cfg.user, cfg.home, {}, ["sh", "-c", script])
    return f"cd {shlex.quote(str(cfg.site_path))} && {shell}"


def manage_script(cfg: WorkAppConfig, *args: str) -> str:
    """The role's ``. .env; python manage.py ...``: secrets are read on the host."""

    command = shlex.join([str(cfg.venv_bin / "python"), "manage.py", *args])
    return f"set -a; . {shlex.quote(str(cfg.env_path))}; set +a; exec {command}"


def _port_preflight(cfg: WorkAppConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but work-app may listen on the app port.

    Like ``common/preflight_ports.yml`` with ``bind: loopback``: a TCP listener
    on the port at a loopback or wildcard address fails the deploy unless every
    process behind it runs in ``work-app.service``. Read-only; runs before any
    change. ``SKIP_PREFLIGHT_PORTS`` has no effect on the pyinfra path.
    """

    script = (
        f"out=$(ss -Hltnp 'sport = :{cfg.app_port}') || exit 1; "
        "printf '%s\\n' \"$out\" | { bad=0; "
        "while read -r _state _recv _send local _peer users; do "
        'case "${local%:*}" in 127.0.0.1|0.0.0.0|"[::1]"|"[::]"|"*"|"[::ffff:127.0.0.1]") ;; *) continue ;; esac; '
        "pids=$(printf '%s' \"$users\" | grep -o 'pid=[0-9]*' | cut -d= -f2); "
        '[ -n "$pids" ] || bad=1; '
        "for pid in $pids; do "
        f"grep -qx '0::/system.slice/{cfg.unit}' /proc/$pid/cgroup 2>/dev/null || bad=1; done; "
        '[ "$bad" = 0 ] || echo "port in use: $local $users" >&2; '
        'done; [ "$bad" = 0 ]; }'
    )
    return mark_read_only(
        server.shell(
            name=f"Port preflight tcp/{cfg.app_port}",
            commands=[f"sh -c {shlex.quote(script)}"],
        )
    )


def _stale_venv(cfg: WorkAppConfig) -> OperationMeta | None:
    """The role's "Remove broken or outdated venv": a venv of another Python is removed.

    A venv whose interpreter is missing or broken needs no removal here:
    ``uv sync`` recreates it (the helper forces the sync while the interpreter
    is not executable).
    """

    probe = _as_user(cfg.user, cfg.home, {}, [str(cfg.venv_bin / "python"), "--version"])
    version = host.get_fact(Command, command=f"{probe} 2>&1 || true") or ""
    match = re.match(r"^Python (\d+\.\d+)", version.strip())
    if match is None or match.group(1) == cfg.python_version:
        return None
    return files.directory(name=f"Remove outdated venv {cfg.venv_path}", path=str(cfg.venv_path), present=False)


def _migrations_current(cfg: WorkAppConfig) -> bool:
    """``migrate --check`` (read-only), only against an existing database.

    Django would create an empty SQLite file when asked on a host without one,
    so a missing database or ``.env`` counts as "not current" without asking.
    """

    check = site_shell(cfg, manage_script(cfg, "migrate", "--check"))
    db, env = shlex.quote(str(cfg.database_path)), shlex.quote(str(cfg.env_path))
    probe = f"test -f {db} && test -f {env} && {check} >/dev/null 2>&1 && echo current || true"
    return host.get_fact(Command, command=probe) == "current"


def _deps_current(cfg: WorkAppConfig) -> bool:
    """``uv sync --check`` (read-only): the venv matches the lock file as deployed.

    Catches a sync that failed after the sources were copied: the next run sees
    unchanged sources but a venv that is not up to date.
    """

    python = shlex.quote(str(cfg.venv_bin / "python"))
    argv = [str(DEFAULT_UV), "sync", *UV_SYNC_ARGS, "--check"]
    env = {"UV_PROJECT_ENVIRONMENT": str(cfg.venv_path)}
    check = f"cd {shlex.quote(str(cfg.site_path))} && {_as_user(cfg.user, cfg.home, env, argv)}"
    return (
        host.get_fact(Command, command=f"test -x {python} && {check} >/dev/null 2>&1 && echo current || true")
        == "current"
    )


def _code_newer_than_service(cfg: WorkAppConfig) -> bool:
    """Deployed files written after the service last started (a run that failed before its restart).

    The app's own ``__pycache__`` output is ignored.
    """

    paths = " ".join(shlex.quote(p) for p in (*SOURCE_DIRS, *SOURCE_FILES, ".env"))
    # The timestamp has second resolution (and is truncated): allow two seconds.
    script = (
        f"ts=$(systemctl show -p ExecMainStartTimestamp --value {shlex.quote(cfg.unit)} 2>/dev/null); "
        '[ -n "$ts" ] || exit 0; start=$(date -d "$ts" +%s) || exit 0; '
        f"cd {shlex.quote(str(cfg.site_path))} || exit 0; "
        f'[ -n "$(find {paths} -type f -not -path "*/__pycache__/*" '
        '-newermt "@$((start + 2))" -print -quit 2>/dev/null)" ] '
        "&& echo stale"
    )
    probe = f"sh -c {shlex.quote(script)} || true"
    return host.get_fact(Command, command=probe) == "stale"


def _static_present(cfg: WorkAppConfig) -> bool:
    root = shlex.quote(str(cfg.static_root))
    probe = f'test -n "$(find {root} -mindepth 1 -print -quit 2>/dev/null)" && echo present || true'
    return host.get_fact(Command, command=probe) == "present"


def _manage_shell(owner: str, script: str, params: dict[str, object], *, env_file: bool) -> str:
    """``manage.py shell -c`` in ``/home/<owner>/site`` as ``owner``."""

    site = PurePosixPath("/home") / owner / "site"
    code = f"PARAMS = {json.dumps(params)!r}\nimport json as _j\nPARAMS = _j.loads(PARAMS)\n{script}"
    run = 'exec .venv/bin/python manage.py shell -c "$1"'
    if env_file:
        run = f"set -a; . ./.env; set +a; {run}"
    shell = _as_user(owner, site.parent, {}, ["sh", "-c", run, "sh", code])
    return f"cd {shlex.quote(str(site))} && {shell}"


def _wiring(name: str, owner: str, script: str, params: dict[str, object], *, env_file: bool) -> None:
    """Probe in check mode; apply only when the probe does not say ``unchanged``."""

    manage = shlex.quote(f"/home/{owner}/site/manage.py")
    probe = _manage_shell(owner, script, {**params, "mode": "check"}, env_file=env_file)
    state = host.get_fact(Command, command=f"{{ test -f {manage} && {probe}; }} 2>/dev/null | tail -n1 || true")
    if (state or "").strip() == "unchanged":
        return
    missing = f"{owner.capitalize()} must be deployed on this host before the work app can be wired to it"
    server.shell(
        name=name,
        commands=[
            f"test -f {manage} || {{ echo {shlex.quote(missing)} >&2; exit 1; }}",
            _manage_shell(owner, script, {**params, "mode": "apply"}, env_file=env_file),
        ],
    )


def _operations_wiring(cfg: WorkAppConfig) -> None:
    if cfg.echoport_target is not None:
        _wiring(
            "Upsert Echoport backup target",
            "echoport",
            (FILES / "echoport_target.py").read_text(),
            {
                "name": cfg.echoport_target,
                "description": "Work app SQLite database backups via echoport-backup",
                "icon": "clipboard",
                "service_name": cfg.unit,
                "restore_owner": f"{cfg.user}:{cfg.group}",
                "db_path": str(cfg.database_path),
                "schedule": cfg.echoport_schedule,
            },
            env_file=False,
        )
    if cfg.nyxmon_check:
        _wiring(
            "Upsert Nyxmon health check",
            "nyxmon",
            (FILES / "nyxmon_check.py").read_text(),
            {
                "service": "Work app",
                "name": "Work app health",
                "legacy_name": "Work app login page",
                "url": cfg.nyxmon_url,
            },
            env_file=True,
        )


@deploy("Deploy work_app")
def deploy_work_app(cfg: WorkAppConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    secrets.require(cfg.required_secret_keys)
    check_secrets(secrets)
    env_content = render_env(cfg, secrets)
    route = traefik_config(cfg, secrets)

    _port_preflight(cfg)
    system_user(
        cfg.user,
        group=cfg.group,
        home=cfg.home,
        shell="/usr/sbin/nologin",
        directories=[cfg.site_path, cfg.static_root],
        mode="0750",
    )
    # The role's synchronize per directory (--delete inside it) and copy of the top-level files.
    synced: list[OperationMeta] = [
        sync_tree(
            name=f"Sync work_app {name}/",
            src=cfg.source_path / name,
            dest=cfg.site_path / name,
            excludes=SOURCE_EXCLUDES,
            runner=rsync,
            user=cfg.user,
            group=cfg.group,
        )
        for name in SOURCE_DIRS
    ]
    synced += [
        files.put(
            name=f"Copy {name}",
            src=str(cfg.source_path / name),
            dest=str(cfg.site_path / name),
            user=cfg.user,
            group=cfg.group,
            mode="0644",
        )
        for name in SOURCE_FILES
    ]
    stale = _stale_venv(cfg)
    deps_stale = not _deps_current(cfg)
    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        python=cfg.python_version,
        # --no-install-project: the server only needs the locked dependencies.
        args=UV_SYNC_ARGS,
        # Also while the venv is out of step with the lock file (a failed earlier run).
        when_changed=None if deps_stale else [*synced, *([stale] if stale else [])],
    )
    env = secret_file(
        name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user, group=cfg.group
    )

    # Migrations also run while any are unapplied (after a failed run whose sync already happened).
    pending = not _migrations_current(cfg)
    code_changed = [*synced, deps, env]
    migrate = server.shell(
        name="Run work_app migrations",
        commands=[site_shell(cfg, manage_script(cfg, "migrate", "--noinput"))],
        _if=lambda: pending or any(meta.did_change() for meta in code_changed),
    )
    files.file(
        name="Restrict database permissions",
        path=str(cfg.database_path),
        user=cfg.user,
        group=cfg.group,
        mode="0600",
    )
    no_static = not _static_present(cfg)
    collect = server.shell(
        name="Collect static files",
        commands=[site_shell(cfg, manage_script(cfg, "collectstatic", "--noinput"))],
        _if=lambda: no_static or any(meta.did_change() for meta in code_changed),
    )

    unit = systemd_unit(cfg.unit, render("work-app.service.j2", cfg=cfg))
    # A failed earlier run may have written files without restarting the service.
    behind = _code_newer_than_service(cfg)
    running_old = server.shell(name="Service started before the deployed files", commands=["true"], _if=lambda: behind)
    service_rollout(cfg.service_name, units=[unit], restart_when=[*synced, deps, env, migrate, collect, running_old])
    # The role's Traefik task has no restart handler: the file provider watches the directory.
    traefik_route(route, renderer=render_route, restart="none")

    http_check(cfg.health_url, retries=cfg.health_retries, delay=cfg.health_delay)
    _operations_wiring(cfg)
