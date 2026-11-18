"""haushalt: daybook's ``services/haushalt`` (Django + SQLite, gunicorn) behind a Traefik allowlist.

The family finance dashboard. Until 2026-11-18 it had its own pyinfra deploy
in its own repository, shaped after ``opaq_app``; this service takes it over
with the same host layout, so the first run on a host deployed the old way
changes no path, port, user or database:

- ``/home/haushalt`` (0700) with ``site/web`` (the Django project, synced from
  ``services/haushalt/web``), ``site/pyproject.toml``, ``site/uv.lock`` and
  ``site/.python-version`` (from ``services/haushalt``, its own uv project),
  ``venv/`` (only the ``web`` dependency group), ``data/db.sqlite3`` (outside
  the synced tree, so no sync can remove it), ``static/`` and
  ``haushalt.env``;
- gunicorn on ``127.0.0.1:10067`` under ``haushalt.service``;
- the Traefik route ``/etc/traefik/dynamic/haushalt.yml`` (tailnet
  allowlist, then the Django login).

Differences to the old deploy: the route gets the shared edge-header deletion
(``_edge.j2``) and gunicorn ``--forwarder-headers=``, like every route and
gunicorn unit ops-deploy renders; the header comments name ops-deploy.

The Echoport backup target of the database is not part of this deploy:
ops-control registers it separately (``haushalt_backup``, generic runner).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self, cast

from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File
from pyinfra.facts.server import Command
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import (
    TraefikRoute,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    wait_port,
)
from ops_deploy.helpers.probes import probe, uv_sync_state, verify_probe, when_present
from ops_deploy.helpers.python import _as_user, _gate
from ops_deploy.helpers.traefik import Hostname
from ops_deploy.ops import secret_file, sync_tree
from ops_deploy.services._gunicorn import require_gunicorn_forwarder_headers
from ops_deploy.services._login_app import (
    Fetcher,
    RouteChecks,
    controller_login_check,
    health_check,
    port_preflight,
    refused_check,
    urllib_fetch,
)

TEMPLATE_PACKAGE = "ops_deploy.services.haushalt"
# The app inside a daybook checkout: its own uv project.
APP_SOURCE = "services/haushalt"
PROJECT_FILES = ("pyproject.toml", "uv.lock", ".python-version")

SECRET_KEY = re.compile(r"^[A-Za-z0-9_-]{50,}$")
# Root's directory for deploy state (as django_site's), one per service.
STATE_ROOT = PurePosixPath("/var/lib/ops-deploy")
# ``python3 -I -c RESTRICT_DATABASE <path> <user>`` as root: hand the database
# to the service user, mode 0600, through file descriptors only. Every
# directory on the way is opened with O_NOFOLLOW, the file too (and
# O_NONBLOCK, so a FIFO cannot block); only a regular file is changed, so no
# link the service user plants in its home can redirect the change.
RESTRICT_DATABASE = (
    "import os, pwd, stat, sys\n"
    "path, user = sys.argv[1], sys.argv[2]\n"
    "account = pwd.getpwnam(user)\n"
    "parts = path.strip('/').split('/')\n"
    "fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)\n"
    "for part in parts[:-1]:\n"
    "    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n"
    "    os.close(fd)\n"
    "    fd = nxt\n"
    "f = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)\n"
    "if not stat.S_ISREG(os.fstat(f).st_mode):\n"
    "    sys.exit(path + ' is not a regular file')\n"
    "os.fchown(f, account.pw_uid, account.pw_gid)\n"
    "os.fchmod(f, 0o600)\n"
)


class HaushaltConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("django_secret_key", "upload_token")

    service_name: ServiceName = "haushalt"
    user: UnixUser = "haushalt"
    # Inside the user's home (checked): the old deploy's layout.
    site_path: PurePosixPath = PurePosixPath("/home/haushalt/site")
    # A daybook checkout.
    source_path: Path
    # Never shipped, and kept on the host across --delete.
    rsync_excludes: tuple[str, ...] = (
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        "*.sqlite3",
        "*.sqlite3-*",
        "staticfiles",
        ".env",
        ".DS_Store",
    )
    app_host: Literal["127.0.0.1"] = "127.0.0.1"
    app_port: int = Field(default=10067, ge=1024, le=65535)
    workers: int = Field(default=2, ge=1, le=64)
    # Must equal services/haushalt/.python-version (checked).
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    dependency_group: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")] = "web"
    traefik_enabled: bool = True
    traefik_host: Hostname | None = None
    traefik_entrypoint: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")] = "web-secure"
    traefik_http_entrypoint: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")] = "web"
    allowed_networks: tuple[str, ...] = ()
    route_checks: RouteChecks = RouteChecks()

    @field_validator("source_path")
    @classmethod
    def _source_is_a_checkout(cls, value: Path) -> Path:
        needed = (f"{APP_SOURCE}/web/manage.py", *(f"{APP_SOURCE}/{name}" for name in PROJECT_FILES))
        missing = [p for p in needed if not (value / p).is_file()]
        if missing:
            raise ValueError(f"source_path is not a daybook checkout with haushalt (missing {', '.join(missing)})")
        return value

    @field_validator("allowed_networks")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("allowed_networks must contain CIDR ranges") from None
            if "/" not in item:
                raise ValueError("allowed_networks must contain CIDR ranges")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.traefik_enabled and (self.traefik_host is None or not self.allowed_networks):
            raise ValueError("Traefik needs traefik_host and a non-empty allowed_networks")
        if self.route_checks != RouteChecks() and not self.traefik_enabled:
            raise ValueError("route_checks need Traefik")
        if self.site_path.parent != self.home:
            raise ValueError("site_path must be a directory directly in the user's home")
        pinned = (self.source_path / APP_SOURCE / ".python-version").read_text().strip()
        if pinned != self.python_version:
            raise ValueError(f"python_version {self.python_version} differs from the project's .python-version")
        return self

    @property
    def home(self) -> PurePosixPath:
        return PurePosixPath("/home") / self.user

    @property
    def app_dir(self) -> PurePosixPath:
        return self.site_path / "web"

    @property
    def data_path(self) -> PurePosixPath:
        return self.home / "data"

    @property
    def database_path(self) -> PurePosixPath:
        return self.data_path / "db.sqlite3"

    @property
    def static_root(self) -> PurePosixPath:
        return self.home / "static"

    @property
    def env_path(self) -> PurePosixPath:
        return self.home / f"{self.service_name}.env"

    @property
    def venv_path(self) -> PurePosixPath:
        return self.home / "venv"

    @property
    def identity_record(self) -> PurePosixPath:
        """The database's device and inode while a migrate step runs (root's state directory)."""

        return STATE_ROOT / self.service_name / "database-identity"

    @property
    def rollout_marker(self) -> PurePosixPath:
        """Exists from before the first change of a run until the restarted service passed its checks."""

        return STATE_ROOT / self.service_name / ".ops-deploy-pending"


def check_secrets(secrets: SecretValues) -> None:
    """Shape checks naming keys only (the old deploy created both with ``token_urlsafe``)."""

    secrets.require(HaushaltConfig.required_secret_keys)
    if not SECRET_KEY.match(secrets["django_secret_key"]):
        raise ValueError("django_secret_key needs 50 or more characters of [A-Za-z0-9_-]")
    if len(secrets["upload_token"]) < 32:
        raise ValueError("upload_token needs 32 or more characters")


def upload_token_sha256(secrets: SecretValues) -> str:
    """The digest that reaches the host; the token itself never does."""

    return hashlib.sha256(secrets["upload_token"].encode()).hexdigest()


def traefik_config(cfg: HaushaltConfig) -> TraefikRoute:
    assert cfg.traefik_host is not None
    return TraefikRoute(name=cfg.service_name, host=cfg.traefik_host, app_port=cfg.app_port, app_host=cfg.app_host)


def render_route(cfg: HaushaltConfig) -> str:
    return render(
        TEMPLATE_PACKAGE, "haushalt.traefik.yml.j2", cfg=cfg, allowed_networks_json=json.dumps(cfg.allowed_networks)
    )


def render_unit(cfg: HaushaltConfig) -> str:
    return render(TEMPLATE_PACKAGE, "haushalt.service.j2", cfg=cfg)


def render_env(cfg: HaushaltConfig, secrets: SecretValues) -> SecretContent:
    """The environment file (systemd ``EnvironmentFile`` and shell-sourceable); host name first."""

    names = [cfg.traefik_host] if cfg.traefik_host else []
    return SecretContent(
        render(
            TEMPLATE_PACKAGE,
            "haushalt.env.j2",
            cfg=cfg,
            secret_key=secrets["django_secret_key"],
            upload_token_sha256=upload_token_sha256(secrets),
            allowed_hosts=",".join([*names, "127.0.0.1"]),
            csrf_trusted_origins=f"https://{cfg.traefik_host}" if cfg.traefik_host else "",
        )
    )


def _as(user: str, home: PurePosixPath, cwd: PurePosixPath, script: str, env: dict[str, str] | None = None) -> str:
    return f"cd {shlex.quote(str(cwd))} && {_as_user(user, home, env or {}, ['bash', '-c', script])}"


def _probe(command: str) -> str:
    """Stdout of an absence probe (a missing file is its answer, not an error)."""

    return str(host.get_fact(Command, command=f"{command} 2>/dev/null || true") or "")


@deploy("Deploy haushalt service")
def deploy_haushalt(
    cfg: HaushaltConfig,
    secrets: SecretValues,
    rsync: RsyncRunner = subprocess_rsync_runner,
    fetch: Fetcher = urllib_fetch,
) -> None:
    check_secrets(secrets)
    env_content = render_env(cfg, secrets)

    port_preflight(cfg.service_name, cfg.app_port)
    user, home, site = cfg.user, cfg.home, cfg.site_path
    database, env_file = shlex.quote(str(cfg.database_path)), shlex.quote(str(cfg.env_path))
    identity = shlex.quote(str(cfg.identity_record))
    # An installed host (its environment file exists) without its database is
    # a host whose data is gone or being restored: never initialize an empty
    # one there. Only a fresh host gets a new database.
    # The database must be a regular file in rollback-journal mode (header
    # bytes 18 and 19 are 1; Django's default and the app's), the one any
    # unfinished migrate step recorded, and present on an installed host.
    # Root reads only a bounded header of a file checked to be regular, and
    # the identity record from root's own state directory.
    guard = (
        f"test ! -L {database} || {{ echo '{cfg.database_path} is a symbolic link' >&2; exit 1; }}; "
        f"test ! -e {database} || test -f {database} || "
        f"{{ echo '{cfg.database_path} is not a regular file' >&2; exit 1; }}; "
        f"if test -f {database}; then size=$(stat -c %s {database}) || exit 1; "
        f'if [ "$size" -gt 0 ]; then '
        f"header=$(timeout 10 od -A n -t u1 -j 18 -N 2 {database}) || exit 1; set -- $header; "
        f'[ "$size" -ge 100 ] && [ "${{1:-}} ${{2:-}}" = "1 1" ] || '
        f"{{ echo '{cfg.database_path} is not a rollback-journal database' >&2; exit 1; }}; fi; fi; "
        f"if test -e {identity}; then "
        f'[ "$(stat -c %d:%i {database} 2>/dev/null)" = "$(head -c 64 {identity})" ] || '
        f"{{ echo '{cfg.database_path} is not the file the migrate step of an earlier run started with: "
        f"check the database, then remove {cfg.identity_record}' >&2; exit 1; }}; fi; "
        f"test -e {database} || test ! -e {env_file} || "
        f"{{ echo '{cfg.database_path} is missing on an installed host: restore it first' >&2; exit 1; }}"
    )
    mark_read_only(server.shell(name="Refuse to replace a missing database", commands=[f"sh -c {shlex.quote(guard)}"]))
    installed = host.get_fact(File, path=str(cfg.env_path)) is not None
    database_fact = host.get_fact(File, path=str(cfg.database_path))
    database_missing = database_fact is None

    # Written before the changes it stands for (``will_change`` of the watched
    # operations is known once planning is done) and removed only after the
    # restarted service passed every check: a run that died in between leaves
    # it, and the next run finishes the rollout although its files match.
    # Root's directory, so the service user cannot plant a link a root
    # ``touch`` would follow.
    marker = shlex.quote(str(cfg.rollout_marker))
    state_dir = shlex.quote(str(cfg.rollout_marker.parent))
    rollout_pending = _probe(f"test -e {marker} && echo pending").strip() == "pending"
    watched: list[OperationMeta] = []
    owed: list[bool] = []
    pending = server.shell(
        name="Mark the rollout pending",
        commands=[f"install -d -o root -g root -m 0700 {state_dir} && touch {marker}"],
        _if=lambda: rollout_pending or any(owed) or any(meta.will_change for meta in watched),
    )

    # Private figures live here: nothing is readable by others.
    system_user(
        user,
        home=home,
        shell="/usr/sbin/nologin",
        mode="0700",
        directories=[site, cfg.data_path, cfg.static_root],
    )
    # A fresh host's database exists before its environment file, so a first
    # run that dies in between is still a fresh host to the guard. Created by
    # the service user, exclusively (noclobber): never over an existing file.
    server.shell(
        name="Create the database of a fresh host",
        commands=[_as_user(user, home, {}, ["bash", "-c", f"umask 077; set -C; : > {database}"])],
        _if=lambda: not installed and database_missing,
    )

    source = cfg.source_path / APP_SOURCE
    synced: list[OperationMeta] = [
        sync_tree(
            name="Sync web",
            src=source / "web",
            dest=cfg.app_dir,
            excludes=cfg.rsync_excludes,
            runner=rsync,
            user=user,
            group=user,
        )
    ]
    project_files = [
        files.put(
            name=f"Copy {name}",
            src=str(source / name),
            dest=str(site / name),
            user=user,
            group=user,
            mode="0600",
        )
        for name in PROJECT_FILES
    ]
    code = [*synced, *project_files]
    watched += code
    tree, owner = shlex.quote(str(site)), f"{user}:{user}"
    # Mode bits of symbolic links grant nothing and chmod leaves them: not checked.
    exposed = f"find {tree} \\( ! -user {user} -o ! -group {user} -o \\( ! -type l -perm /077 \\) \\) -print -quit"
    pending_privacy = _probe(exposed).strip()
    owed.append(bool(pending_privacy))
    private = server.shell(
        name="Own and privatize the synced tree",
        commands=[f"chown -R {owner} {tree} && chmod -R u+rwX,go-rwx {tree}"],
        _if=lambda: bool(pending_privacy) or any(meta.did_change() for meta in synced),
    )

    # Only the web group: the collector and its private moneymoney-snapshot
    # package stay on the Macs, so the host never contacts GitHub.
    interpreter = shlex.quote(str(cfg.venv_path / "bin" / "python"))
    venv_missing = _probe(f"test -x {interpreter} && echo present").strip() != "present"
    running = _probe(
        _as(user, home, site, f"exec {interpreter} -c 'import sys; print(\"%d.%d\" % sys.version_info[:2])'")
    ).strip()
    stale_python = bool(running) and running != cfg.python_version
    uv_args = [
        "sync",
        "--frozen",
        "--only-group",
        cfg.dependency_group,
        "--no-install-project",
        "--python",
        cfg.python_version,
    ]
    uv_env = {"UV_PROJECT_ENVIRONMENT": str(cfg.venv_path), "UV_PYTHON_INSTALL_DIR": str(home / "python")}

    def uv(*extra: str) -> str:
        return f"cd {tree} && " + _as_user(user, home, uv_env, ["/usr/local/bin/uv", *uv_args, *extra])

    # A venv that is not in sync with the lock (an earlier run died after the
    # files were copied) is as pending as new files.
    deps_check = when_present(
        [cfg.venv_path / "bin" / "python", site], uv_sync_state(uv("--check")), otherwise="pending"
    )
    deps_state = probe(deps_check, name="haushalt dependencies")
    out_of_sync = venv_missing or deps_state != "current"
    owed.append(out_of_sync or stale_python)
    deps = server.shell(
        name=f"uv sync {site} ({cfg.dependency_group})",
        commands=[uv()],
        _if=_gate(project_files, force=out_of_sync or stale_python),
    )
    if deps_state is None:
        verify_probe(deps_check, name="haushalt dependencies", expect="current")

    env = secret_file(
        name="Write environment file", path=cfg.env_path, content=env_content, mode="0600", user=user, group=user
    )
    watched.append(env)

    python = shlex.quote(str(cfg.venv_path / "bin" / "python"))
    # Before any management command: a database restored as root would make
    # the probe and migrate fail as the service user. Never creates the file,
    # never follows a link (``RESTRICT_DATABASE``).
    expected = {"user": user, "group": user, "mode": 600}
    restrict = bool(database_fact) and any(
        cast(dict[str, object], database_fact).get(key) != value for key, value in expected.items()
    )
    server.shell(
        name="Restrict the database",
        commands=[shlex.join(["python3", "-I", "-c", RESTRICT_DATABASE, str(cfg.database_path), user])],
        _if=lambda: restrict,
    )
    # Migrate must not run against another database than the one planned:
    # root records its device and inode in its own state directory before the
    # step and compares them after it. A mismatch (a restore moved the file
    # while migrate ran, and SQLite may have created a new one) fails the run
    # before the restart and keeps the record, so the guard refuses every
    # later run until an operator checked the database.
    script = (
        f"umask 077; set -euo pipefail; "
        f"test -f {database} && test ! -L {database} || {{ echo 'the database is missing' >&2; exit 1; }}; "
        f"set -a; . {env_file}; set +a; "
        f"{python} manage.py migrate --noinput; {python} manage.py collectstatic --noinput --clear"
    )
    triggers = [*code, private, deps, env]
    # No migration probe: it would open the live database (read-write, with
    # SQLite's journal recovery) while planning, before the guard ran. As with
    # the old deploy script, migrate runs when the code, dependencies or
    # environment changed, the database or venv is new, or a rollout is
    # pending (an interrupted run); after restoring an older database, run
    # migrate by hand (docs/services/haushalt.md).
    unmigrated = database_missing or venv_missing
    owed.append(unmigrated)

    def needs_manage() -> bool:
        return unmigrated or rollout_pending or any(meta.did_change() for meta in triggers)

    server.shell(
        name="Record the database identity",
        commands=[
            # Resolved first, published atomically: never an empty or partial record.
            f"install -d -o root -g root -m 0700 {state_dir} && id=$(stat -c %d:%i {database}) && "
            f"(umask 077; printf '%s\\n' \"$id\" > {identity}.new) && mv -f {identity}.new {identity}"
        ],
        _if=needs_manage,
    )
    manage = server.shell(
        name="manage.py migrate and collectstatic",
        commands=[_as(user, home, cfg.app_dir, script)],
        _if=needs_manage,
    )
    server.shell(
        name="Check the database identity",
        commands=[
            f'[ "$(stat -c %d:%i {database} 2>/dev/null)" = "$(head -c 64 {identity})" ] || '
            "{ echo 'the database was replaced while migrate ran' >&2; exit 1; }; "
            f"rm -f {identity}"
        ],
        _if=needs_manage,
    )

    # The unit passes --forwarder-headers=.
    require_gunicorn_forwarder_headers(cfg.venv_path)
    unit = systemd_unit(cfg.service_name, render_unit(cfg))
    watched.append(unit)
    # The unit may have been written by the run that died, before its reload.
    server.shell(
        name="Reload systemd to finish a pending rollout",
        commands=["systemctl daemon-reload"],
        _if=lambda: rollout_pending,
    )
    if cfg.traefik_enabled:
        # Written without restarting Traefik: its file provider watches the directory.
        traefik_route(traefik_config(cfg), renderer=lambda _route, _hash: render_route(cfg), restart="none")
    service_rollout(cfg.service_name, units=[unit], restart_when=[*triggers, manage])

    wait_port(cfg.app_port, host=cfg.app_host)
    health_check(cfg.app_host, cfg.app_port)
    if cfg.route_checks.controller_login:
        assert cfg.traefik_host is not None
        controller_login_check(cfg.traefik_host, cfg.route_checks, fetch)
    if cfg.route_checks.refused_address is not None:
        assert cfg.traefik_host is not None
        refused_check(cfg.traefik_host, cfg.route_checks)
    # Only now, after the restart and every check: the rollout is complete.
    server.shell(
        name="Clear the pending rollout",
        commands=[f"rm -f {marker}"],
        _if=lambda: rollout_pending or pending.did_change(),
    )
