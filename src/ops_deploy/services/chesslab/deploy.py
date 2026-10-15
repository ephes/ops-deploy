"""chesslab: the Chesslab trainer, a Django app served by granian.

Port of the ``chesslab_deploy`` Ansible role (rsync method) and of the
operations wiring in ops-control's ``deploy-chesslab.yml`` (Echoport backup
target, Nyxmon health check). The files it writes are byte-identical to the
role's (``tests/test_chesslab_parity.py``), so Ansible and ops-deploy can take
turns on one host without churn. The SQLite database lives outside the synced
site directory and is never created here: like the role, the deploy stops
before any change to the site when it is missing or not read/writable by the
service user.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import shlex
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar

import jinja2
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import apt, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
)
from ops_deploy.helpers.probes import last_line, migrations_state, probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.traefik import _MIDDLEWARE, Hostname
from ops_deploy.ops import secret_file, secret_stdin, sync_tree

TEMPLATE_PACKAGE = "ops_deploy.services.chesslab"
FILES = Path(__file__).parent / "files"

# The role's rsync excludes: never shipped, and protected from --delete.
SOURCE_EXCLUDES = (
    ".git",
    ".venv",
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".env",
    "chess.db",
    "*.db",
    "*.db-*",
)
# The role's chesslab_internal_ip_ranges (not the helper's default list).
INTERNAL_IP_RANGES = ("127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
PACKAGES = ("python3", "python3-venv", "sqlite3", "rsync")
# Records which app users were last ensured (an HMAC, never the passwords).
USERS_STAMP = ".ops-deploy-users"

PlainValue = Annotated[str, Field(pattern=r"^[^\s\"'\\$`]*$")]
PathValue = Annotated[PurePosixPath, Field()]


class ChesslabUser(BaseModel):
    """One entry of the secret ``users`` list: a Django admin and trainer owner."""

    model_config = ConfigDict(extra="ignore", frozen=True, hide_input_in_errors=True)

    username: Annotated[str, Field(min_length=1, pattern=r"^[^\r\n]+$")]
    password: SecretStr
    owner: Annotated[str, Field(min_length=1, pattern=r"^[^\r\n]+$")]

    @field_validator("password")
    @classmethod
    def _non_empty(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if not secret or "\n" in secret or "\r" in secret:
            raise ValueError("chesslab user passwords must be single, non-empty lines")
        return value


class ChesslabConfig(BaseServiceConfig):
    # secret_key or session_secret is checked by check_secrets.
    required_secret_keys: ClassVar[tuple[str, ...]] = ("users", "basic_auth_password")

    service_name: ServiceName = "chesslab"
    user: UnixUser = "chesslab"
    group: UnixUser = "chesslab"
    home: PathValue = PurePosixPath("/home/chesslab")
    site_path: PathValue = PurePosixPath("/home/chesslab/site")
    data_path: PathValue = PurePosixPath("/home/chesslab/data")
    db_path: PathValue = PurePosixPath("/home/chesslab/data/chess.db")
    # A chess (chesslab) checkout; synced as the site root.
    source_path: Path
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    app_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    app_port: int = Field(default=10019, ge=1024, le=65535)
    workers: int = Field(default=2, ge=1, le=64)
    limit: Annotated[str, Field(pattern=r"^[0-9]*$")] = ""
    wsgi_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:]+$")] = "chesslab.djangoapp.wsgi:application"
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "chesslab.djangoapp.settings"
    django_debug: bool = False
    django_allowed_hosts: tuple[PlainValue, ...] = ("127.0.0.1", "localhost")
    django_csrf_trusted_origins: tuple[PlainValue, ...] = ()
    secure_cookies: bool = True
    run_migrations: bool = True
    traefik_host: Hostname = "chess.example.com"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    internal_ip_ranges: tuple[str, ...] = INTERNAL_IP_RANGES
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"
    health_retries: int = Field(default=20, ge=1)
    health_delay: int = Field(default=3, ge=0)
    # Operations wiring from the playbook; off by default (the role has none).
    echoport_target: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")] | None = None
    echoport_schedule: Annotated[str, Field(pattern=r"^[0-9*/,\- ]+$")] = "50 2 * * *"
    echoport_update_schedule: bool = False
    nyxmon_check: bool = False

    @field_validator("source_path")
    @classmethod
    def _source_is_a_chesslab_checkout(cls, value: Path) -> Path:
        missing = [p for p in ("pyproject.toml", "uv.lock", "src/chesslab") if not (value / p).exists()]
        if missing:
            raise ValueError(f"source_path is not a chesslab checkout (missing {', '.join(missing)})")
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
    def health_url(self) -> str:
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


def secret_key(secrets: SecretValues) -> str:
    """The playbook's ``secret_key | default(session_secret)``."""

    return secrets.get("secret_key") or secrets.get("session_secret") or ""


def app_users(secrets: SecretValues) -> tuple[ChesslabUser, ...]:
    """The secret ``users`` list (JSON); errors never quote values."""

    try:
        raw = json.loads(secrets.get("users", ""))
    except json.JSONDecodeError:
        raise ValueError("secret users must be a list of mappings") from None
    if not isinstance(raw, list) or not raw or not all(isinstance(item, dict) for item in raw):
        raise ValueError("secret users must be a non-empty list of mappings")
    users = []
    for item in raw:
        # The role's ``owner | default(lichess_username)``.
        owner = item["owner"] if "owner" in item else item.get("lichess_username")
        try:
            users.append(ChesslabUser.model_validate({**item, "owner": owner}))
        except Exception:
            raise ValueError("each chesslab user requires username, password, and owner or lichess_username") from None
    return tuple(users)


def check_secrets(secrets: SecretValues) -> tuple[ChesslabUser, ...]:
    key = secret_key(secrets)
    if len(key) <= 20 or "CHANGEME" in key:
        raise ValueError("secret_key (or session_secret) must be longer than 20 characters and not a placeholder")
    password = secrets.get("basic_auth_password", "")
    if not password or "CHANGEME" in password:
        raise ValueError("basic_auth_password must be set and not a placeholder")
    if any(c in value for value in secrets.values() for c in "\r\n"):
        raise ValueError("secret values must be single lines")
    return app_users(secrets)


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def django_environment(cfg: ChesslabConfig, secrets: SecretValues) -> dict[str, str]:
    """The variables of the role's ``.env`` and Django task ``environment``."""

    env = {
        "DJANGO_SETTINGS_MODULE": cfg.django_settings_module,
        "CHESSLAB_SECRET_KEY": secret_key(secrets),
        "CHESSLAB_DEBUG": str(cfg.django_debug).lower(),
        "CHESSLAB_DB_PATH": str(cfg.db_path),
        "CHESSLAB_ALLOWED_HOSTS": ",".join(cfg.django_allowed_hosts),
        "CHESSLAB_CSRF_TRUSTED_ORIGINS": ",".join(cfg.django_csrf_trusted_origins),
        "CHESSLAB_SECURE_COOKIES": str(cfg.secure_cookies).lower(),
    }
    if cfg.limit:
        env["CHESSLAB_TRAINER_LIMIT"] = cfg.limit
    return env


def render_env(cfg: ChesslabConfig, secrets: SecretValues) -> SecretContent:
    """The role's ``chesslab.env.j2``: every value double-quoted, ``\\`` and ``"`` escaped."""

    lines = [f'{key}="{_quote(value)}"\n' for key, value in django_environment(cfg, secrets).items()]
    return SecretContent("".join(lines))


def traefik_config(cfg: ChesslabConfig, secrets: SecretValues) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        title="Chesslab",
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
    """The role's own route template (redirect router, ``X-Forwarded-Host``)."""

    return render("chesslab.traefik.yml.j2", route=route, auth_hash=auth_hash)


def _stdin_env(env: dict[str, str]) -> SecretContent:
    # One ``KEY=value`` per line; read back with ``export "$line"`` (no expansion).
    return SecretContent("".join(f"{key}={value}\n" for key, value in env.items()))


_READ_ENV = 'while IFS= read -r line && [ -n "$line" ]; do export "$line"; done'


def _site_shell(cfg: ChesslabConfig, script: str) -> str:
    shell = _as_user(cfg.user, cfg.home, {}, ["sh", "-c", script])
    return f"cd {shlex.quote(str(cfg.site_path))} && {shell}"


def _database_check(cfg: ChesslabConfig) -> OperationMeta:
    """The role's "Verify chesslab database is available to service user"."""

    db = shlex.quote(str(cfg.db_path))
    test = _as_user(
        cfg.user,
        cfg.home,
        {},
        ["test", "-f", str(cfg.db_path), "-a", "-r", str(cfg.db_path), "-a", "-w", str(cfg.db_path)],
    )
    return mark_read_only(
        server.shell(
            name="Check chesslab database",
            commands=[f"{test} || {{ echo {db}' is missing or not read/writable by {cfg.user}' >&2; exit 1; }}"],
        )
    )


def _port_preflight(cfg: ChesslabConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but chesslab may listen on the app port.

    Like ``common/preflight_ports.yml`` with ``bind: loopback``: a TCP listener
    on the port at a loopback or wildcard address fails the deploy unless every
    process behind it runs in ``chesslab.service``. Read-only; runs before any
    change. ``SKIP_PREFLIGHT_PORTS`` has no effect on the pyinfra path.
    """

    unit = f"{cfg.service_name}.service"
    script = (
        f"out=$(ss -Hltnp 'sport = :{cfg.app_port}') || exit 1; "
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
        server.shell(
            name=f"Port preflight tcp/{cfg.app_port}",
            commands=[f"sh -c {shlex.quote(script)}"],
        )
    )


def _users_stamp(cfg: ChesslabConfig, secrets: SecretValues, users: tuple[ChesslabUser, ...]) -> str:
    material = json.dumps([[u.username, u.owner, u.password.get_secret_value()] for u in users], separators=(",", ":"))
    return hmac.new(secret_key(secrets).encode(), material.encode(), hashlib.sha256).hexdigest() + "\n"


def _row_digest(username: str, owner: str) -> str:
    return hashlib.sha256(f"{username.lower()}|1|1|1|{owner.strip().lower()}|1".encode()).hexdigest()


def _users_probe(cfg: ChesslabConfig) -> str:
    """Every app user exists as an active superuser with its trainer profile.

    Read from the database (SQLite, read-only) as digests, so user names never
    reach the controller's output.
    """

    sql = (
        "select lower(u.username), u.is_staff, u.is_superuser, u.is_active, "
        "coalesce(p.lichess_username, ''), coalesce(p.is_trainer_admin, 0) "
        "from auth_user u left join accounts_profile p on p.user_id = u.id"
    )

    def sqlite(statement: str) -> str:
        return shlex.join(["sqlite3", "-readonly", "-separator", "|", str(cfg.db_path), statement])

    tables = "select count(*) from sqlite_master where type = 'table' and name in ('auth_user', 'accounts_profile')"
    digest = 'while IFS= read -r row; do printf %s "$row" | sha256sum | cut -c1-64; done'
    rows = (
        # Before a first deploy: no sqlite3 yet (installed by this deploy) or a
        # database not migrated yet. Both mean no users; other errors fail.
        "command -v sqlite3 >/dev/null || { echo none; exit 0; }; "
        f't=$( {sqlite(tables)} ) || exit 1; [ "$t" = 2 ] || {{ echo none; exit 0; }}; '
        f'rows=$( {sqlite(sql)} ) || exit 1; [ -z "$rows" ] || printf \'%s\\n\' "$rows" | {digest}'
    )
    # No database yet (the check before the sync fails the run then): no users.
    return when_present([cfg.db_path], rows, otherwise="none")


def _users_in_place(rows: str | None, users: tuple[ChesslabUser, ...]) -> bool:
    return rows is not None and {_row_digest(u.username, u.owner) for u in users} <= set(rows.split())


def _ensure_users(cfg: ChesslabConfig, secrets: SecretValues, users: tuple[ChesslabUser, ...]) -> None:
    """The role's ``ensure_admin`` loop, only when something may need it.

    ``ensure_admin`` reports created/updated/unchanged; pyinfra cannot report
    from command output, so it runs when a user or profile is missing or
    differs, or the users secret changed since the last run (stamp file).
    """

    stamp_path = cfg.home / USERS_STAMP
    stamp = _users_stamp(cfg, secrets, users)
    current = host.get_fact(Command, command=f"cat {shlex.quote(str(stamp_path))} 2>/dev/null || true") or ""
    check = _users_probe(cfg)
    rows = probe(check, name="chesslab app users")
    if current.strip() == stamp.strip() and _users_in_place(rows, users):
        return
    env = django_environment(cfg, secrets)
    # User names travel on stdin with the password and are handed to the
    # command in-process, so they never appear in a process's arguments.
    call = (
        "import os, django; django.setup(); "
        "from django.core.management import call_command; "
        "call_command('ensure_admin', username=os.environ['CHESSLAB_DEPLOY_USERNAME'], "
        "lichess_username=os.environ['CHESSLAB_DEPLOY_OWNER'], stdout=open(os.devnull, 'w'))"
    )
    argv = shlex.join([str(cfg.venv_bin / "python"), "-c", call])
    for user in users:
        secret_stdin(
            name="Ensure chesslab app user",
            command=_site_shell(cfg, f"{_READ_ENV}; exec {argv}"),
            content=_stdin_env(
                {
                    **env,
                    "CHESSLAB_ADMIN_PASSWORD": user.password.get_secret_value(),
                    "CHESSLAB_DEPLOY_USERNAME": user.username,
                    "CHESSLAB_DEPLOY_OWNER": user.owner,
                }
            ),
        )
    secret_file(
        name="Record chesslab app users", path=stamp_path, content=SecretContent(stamp), user="root", group="root"
    )
    if rows is None:
        verify_probe(check, name="chesslab app users")


def _migrations_probe(cfg: ChesslabConfig) -> str:
    """``migrate --check`` (read-only), with Django's debug key instead of the secret one."""

    env = {
        "DJANGO_SETTINGS_MODULE": cfg.django_settings_module,
        "CHESSLAB_DEBUG": "true",
        "CHESSLAB_DB_PATH": str(cfg.db_path),
    }
    argv = [str(cfg.venv_bin / "python"), "-m", "django", "migrate", "--check", "--plan"]
    plan = f"cd {shlex.quote(str(cfg.site_path))} && {_as_user(cfg.user, cfg.home, env, argv)}"
    return when_present([cfg.venv_bin / "python", cfg.db_path], migrations_state(plan), otherwise="pending")


def _migrate(cfg: ChesslabConfig, secrets: SecretValues, when_changed: list[OperationMeta]) -> OperationMeta:
    """Run migrations after a code or dependency change, or while any are unapplied
    (also after a failed run whose sync already happened)."""

    check = _migrations_probe(cfg)
    state = probe(check, name="chesslab migrations")
    argv = [str(cfg.venv_bin / "python"), "-m", "django", "migrate", "--noinput"]
    migrate = secret_stdin(
        name="Run chesslab migrations",
        command=_site_shell(cfg, f"{_READ_ENV}; exec {shlex.join(argv)}"),
        content=_stdin_env(django_environment(cfg, secrets)),
        _if=lambda: state != "current" or any(meta.did_change() for meta in when_changed),
    )
    if state is None:
        verify_probe(check, name="chesslab migrations", expect="current")
    return migrate


def _health_check(cfg: ChesslabConfig) -> OperationMeta:
    """The role's ``/healthz`` check: status 200 and ``{"ok": true}``."""

    curl = shlex.join(["curl", "-sS", "--max-time", "5", "-w", "\\n%{http_code}", cfg.health_url])
    script = (
        f"for i in $(seq 1 {cfg.health_retries}); do "
        f"out=$({curl} 2>/dev/null); "
        'if [ "$(printf \'%s\' "$out" | tail -n1)" = 200 ] && '
        "printf '%s' \"$out\" | grep -Eq '\"ok\": *true'; then exit 0; fi; "
        f"sleep {cfg.health_delay}; done; "
        f"echo '{cfg.health_url} is not healthy' >&2; exit 1"
    )
    return mark_read_only(server.shell(name=f"Check {cfg.health_url}", commands=[f"sh -c {shlex.quote(script)}"]))


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
    run_check = _manage_shell(owner, script, {**params, "mode": "check"}, env_file=env_file)
    # Without the service the step below fails the run with a message.
    check = when_present([f"/home/{owner}/site/manage.py"], last_line(run_check), otherwise="missing")
    state = probe(check, name=name)
    if (state or "").strip() == "unchanged":
        return
    missing = f"{owner.capitalize()} must be deployed on this host before chesslab can be wired to it"
    server.shell(
        name=name,
        commands=[
            f"test -f {manage} || {{ echo {shlex.quote(missing)} >&2; exit 1; }}",
            _manage_shell(owner, script, {**params, "mode": "apply"}, env_file=env_file),
        ],
    )
    if state is None:
        verify_probe(check, name=name, expect="unchanged")


def _operations_wiring(cfg: ChesslabConfig) -> None:
    if cfg.echoport_target is not None:
        _wiring(
            "Upsert Echoport backup target",
            "echoport",
            (FILES / "echoport_target.py").read_text(),
            {
                "name": cfg.echoport_target,
                "description": "Chesslab SQLite trainer database backups via echoport-backup",
                "icon": "chess",
                "service_name": f"{cfg.service_name}.service",
                "restore_owner": f"{cfg.user}:{cfg.group}",
                "db_path": str(cfg.db_path),
                "schedule": cfg.echoport_schedule,
                "update_schedule": cfg.echoport_update_schedule,
            },
            env_file=False,
        )
    if cfg.nyxmon_check:
        _wiring(
            "Upsert Nyxmon health check",
            "nyxmon",
            (FILES / "nyxmon_check.py").read_text(),
            {"service": "Chesslab", "name": "Chesslab trainer health", "url": cfg.health_url},
            env_file=True,
        )


@deploy("Deploy chesslab")
def deploy_chesslab(cfg: ChesslabConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    secrets.require(cfg.required_secret_keys)
    users = check_secrets(secrets)
    env_content = render_env(cfg, secrets)
    route = traefik_config(cfg, secrets)

    _port_preflight(cfg)
    system_user(
        cfg.user,
        group=cfg.group,
        home=cfg.home,
        shell="/usr/sbin/nologin",
        directories=[cfg.site_path, cfg.data_path],
    )
    _database_check(cfg)
    code = sync_tree(
        name="Sync chesslab source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=SOURCE_EXCLUDES,
        runner=rsync,
        user=cfg.user,
        group=cfg.group,
    )
    apt.packages(name="Install chesslab runtime packages", packages=list(PACKAGES))
    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        python=cfg.python_version,
        args=("--frozen", "--no-dev"),
        when_changed=[code],
    )
    env = secret_file(
        name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user, group=cfg.group
    )
    migrated = [_migrate(cfg, secrets, [code, deps])] if cfg.run_migrations else []
    _ensure_users(cfg, secrets, users)

    unit = systemd_unit(cfg.service_name, render("chesslab.service.j2", cfg=cfg))
    service_rollout(cfg.service_name, units=[unit], restart_when=[code, deps, env, *migrated])
    traefik_route(route, renderer=render_route)

    _health_check(cfg)
    _operations_wiring(cfg)
