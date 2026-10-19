"""weeknotes.home: the daybook steering inbox, a Django app behind gunicorn on PostgreSQL.

Port of the ``weeknotes_home_deploy`` Ansible role (rsync method) and of the
operations wiring in ops-control's ``deploy-weeknotes-home.yml`` (FastDeploy
service row, Echoport backup target with its FastDeploy service token, Nyxmon
checks). The env file, unit and Traefik route are byte-identical to the
role's (``tests/test_weeknotes_home_parity.py``), so Ansible and ops-deploy can
take turns on one host without churn. The PostgreSQL database, the cache
directory and the collected static files survive every deploy.

Not ported: the role's ``git`` deploy method, ``traefik_enabled``,
``basic_auth_enabled`` and ``service_restart_on_change`` switches and the
precomputed password hash (the playbook uses none of them), and the
``uv_install`` and ``postgres_install`` role dependencies (``uv`` must be at
``/usr/local/bin/uv`` and PostgreSQL installed, as on every host that has run
the role).
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal
from urllib.parse import quote

import jinja2
from pydantic import Field, SecretStr, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    http_check,
    mark_read_only,
    postgres_database,
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
from ops_deploy.services._echoport import target_shell

TEMPLATE_PACKAGE = "ops_deploy.services.weeknotes_home"
FILES = Path(__file__).parent / "files"

# The role's rsync excludes: never shipped, and protected from --delete.
SOURCE_EXCLUDES = (
    ".git",
    ".venv",
    "/.venv-weeknotes-home",
    ".envrc",
    "/.env.weeknotes-home",
    ".cache",
    "/cache",
    "/static",
    "/site",
    "services/weeknotes_home/db.sqlite3",
    "services/weeknotes_home/staticfiles",
    "__pycache__",
    "*.pyc",
    # Not in the role's list: ``uv sync`` builds the project and leaves this
    # behind, so syncing with --delete would remove it, rebuild it and restart
    # the service on every run (the role does exactly that).
    "/src/daybook.egg-info",
)
SOURCE_FILES = ("pyproject.toml", "uv.lock", "services/weeknotes_home/manage.py", "src/daybook/cli.py")
# The role's validate_auth.yml: trusted client ranges must lie inside these.
APPROVED_NETWORKS = (
    "192.168.0.0/16",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "100.64.0.0/10",
    "fd7a:115c:a1e0::/48",
)
DEFAULT_ECHOPORT_HEALTH_URL = "http://127.0.0.1:10018/api/health/"
ECHOPORT_SITE = PurePosixPath("/home/echoport/site")
NYXMON_DB = PurePosixPath("/home/nyxmon/site/db.sqlite3")
FASTDEPLOY_DB = "fastdeploy"

PlainValue = Annotated[str, Field(pattern=r"^[^\s\"'\\$`]*$")]
Line = Annotated[str, Field(pattern=r"^[^\r\n]*$")]
Identifier = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]
TargetName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")]
Url = Annotated[str, Field(pattern=r"^https?://[^\s\"'\\$`]+$")]


class WeeknotesHomeConfig(BaseServiceConfig):
    """The role's variables without the ``weeknotes_home_`` prefix (defaults from its defaults/main.yml)."""

    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "django_secret_key",
        "postgres_password",
        "api_token",
        "basic_auth_password",
    )

    service_name: ServiceName = "weeknotes-home"
    user: UnixUser = "weeknotes-home"
    group: UnixUser = "weeknotes-home"
    home: PurePosixPath = PurePosixPath("/home/weeknotes-home")
    site_path: PurePosixPath = PurePosixPath("/home/weeknotes-home/site")
    # A daybook checkout; synced as the site root.
    source_path: Path
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    app_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    app_port: int = Field(default=10062, ge=1024, le=65535)
    workers: int = Field(default=2, ge=1, le=64)
    timeout: int = Field(default=120, ge=1)
    wsgi_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:]+$")] = "weeknotes_home.wsgi:application"
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "weeknotes_home.settings"
    django_debug: bool = False
    django_allowed_hosts: tuple[PlainValue, ...] = ("127.0.0.1", "localhost")
    django_csrf_trusted_origins: tuple[PlainValue, ...] = ()
    db_conn_max_age: int = Field(default=60, ge=0)
    cast_base_url: Line = ""
    run_migrations: bool = True
    collectstatic: bool = True
    postgres_database: Identifier = "weeknotes_home"
    postgres_user: Identifier = "weeknotes_home"
    # The deploy manages the database through the local cluster's socket, so
    # DATABASE_URL must point at that same cluster.
    postgres_host: Literal["localhost", "127.0.0.1"] = "localhost"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    traefik_host: Hostname = "weeknotes.home.example.com"
    traefik_entrypoints: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")], ...] = ("web-secure",)
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    internal_ip_ranges: tuple[str, ...] = APPROVED_NETWORKS
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")] = "admin"
    health_retries: int = Field(default=20, ge=1)
    health_delay: int = Field(default=3, ge=0)
    # Operations wiring from the playbook's post tasks; off by default (the role has none).
    operations_wiring: bool = False
    fastdeploy_site_root: PurePosixPath = PurePosixPath("/home/fastdeploy/site")
    echoport_target_name: TargetName = "weeknotes_home"
    echoport_legacy_target_name: TargetName = "weeknotes-home"
    echoport_fastdeploy_service: TargetName = "weeknotes-home-backup"
    echoport_target_schedule: Annotated[str, Field(pattern=r"^[0-9*/,\- ]+$")] = "10 4 * * *"
    echoport_health_url: Url = DEFAULT_ECHOPORT_HEALTH_URL
    fastdeploy_token_days: int = Field(default=90, ge=1, le=90)
    fastdeploy_token_rotate_days: int = Field(default=30, ge=1)
    fastdeploy_token_force_rotate: bool = False
    nyxmon_service_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$")] = "weeknotes-home"
    nyxmon_check_interval: int = Field(default=300, ge=1)
    backup_window_grace_hours: float = Field(default=0.5, ge=0)
    backup_window_suppression_reason: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")] = (
        "echoport_backup_window_active"
    )

    @field_validator("source_path")
    @classmethod
    def _source_is_a_daybook_checkout(cls, value: Path) -> Path:
        missing = [name for name in SOURCE_FILES if not (value / name).exists()]
        if missing:
            raise ValueError(f"source_path is not a daybook checkout (missing {', '.join(missing)})")
        return value

    @field_validator("home", "fastdeploy_site_root")
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/"):
            raise ValueError("paths must be absolute, without '..', and not '/'")
        return value

    @field_validator("internal_ip_ranges")
    @classmethod
    def _inside_approved_networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        """The role's trusted-network check: canonical CIDRs inside the private/Tailnet ranges."""

        if not value:
            raise ValueError("internal_ip_ranges must not be empty")
        approved = [ipaddress.ip_network(item) for item in APPROVED_NETWORKS]
        for item in value:
            try:
                network = ipaddress.ip_network(item, strict=True)
            except ValueError:
                raise ValueError("internal_ip_ranges must be canonical CIDR networks") from None
            if str(network) != item:
                raise ValueError("internal_ip_ranges must be canonical CIDR networks")
            if not any(
                network.network_address in parent and network.broadcast_address in parent for parent in approved
            ):
                raise ValueError("internal_ip_ranges must lie inside the approved private/Tailnet networks")
        return value

    @model_validator(mode="after")
    def _rules(self) -> WeeknotesHomeConfig:
        if self.fastdeploy_token_rotate_days >= self.fastdeploy_token_days:
            raise ValueError("fastdeploy_token_rotate_days must be shorter than fastdeploy_token_days")
        if self.echoport_target_name == self.echoport_legacy_target_name:
            raise ValueError("echoport_legacy_target_name must differ from echoport_target_name")
        if not self.traefik_entrypoints:
            raise ValueError("traefik_entrypoints must not be empty")
        return self

    @property
    def service_path(self) -> PurePosixPath:
        return self.site_path / "services" / "weeknotes_home"

    @property
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env.weeknotes-home"

    @property
    def env_exec_path(self) -> PurePosixPath:
        """files/env_exec.py on the host: runs a program with the env file loaded."""

        return self.home / "env-exec.py"

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv-weeknotes-home"

    @property
    def venv_bin(self) -> PurePosixPath:
        return self.venv_path / "bin"

    @property
    def cache_dir(self) -> PurePosixPath:
        return self.site_path / "cache" / "weeknotes-home"

    @property
    def static_root(self) -> PurePosixPath:
        return self.site_path / "static" / "weeknotes-home"

    @property
    def health_url(self) -> str:
        return f"http://{self.app_host}:{self.app_port}/healthz"

    @property
    def fastdeploy_service_config(self) -> PurePosixPath:
        return self.fastdeploy_site_root / "services" / self.echoport_fastdeploy_service / "config.json"


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
    """The playbook's and role's secret asserts, plus single-line values (they land in an env file)."""

    secrets.require(WeeknotesHomeConfig.required_secret_keys)
    if any(c in value for value in secrets.values() for c in "\r\n"):
        raise ValueError("secret values must be single lines")
    secret_key = secrets["django_secret_key"]
    if len(secret_key) <= 20 or "CHANGEME" in secret_key:
        raise ValueError("django_secret_key must be longer than 20 characters and not a placeholder")
    if "CHANGEME" in secrets["postgres_password"] or not secrets["postgres_password"].isascii():
        raise ValueError("postgres_password must be ASCII and not a placeholder")
    if "CHANGEME" in secrets["api_token"] or not re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", secrets["api_token"]):
        raise ValueError("api_token must be 32 to 256 URL-safe characters (letters, digits, . _ ~ -)")
    password = secrets["basic_auth_password"]
    if not re.fullmatch(r"[\x20-\x7e]+", password) or "CHANGEME" in password:
        raise ValueError("basic_auth_password must be printable ASCII and not a placeholder")


def _urlencode(value: str) -> str:
    # Jinja's ``urlencode`` plus the role's ``replace('/', '%2F')``.
    return quote(value, safe="")


def database_url(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> str:
    """The role's ``weeknotes_home_database_url``."""

    return (
        f"postgres://{_urlencode(cfg.postgres_user)}:{_urlencode(secrets['postgres_password'])}"
        f"@{cfg.postgres_host}:{cfg.postgres_port}/{_urlencode(cfg.postgres_database)}"
    )


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def env_lines(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> list[tuple[str, str]]:
    """``.env.weeknotes-home`` as (name, value) pairs, in the role template's order."""

    return [
        ("DJANGO_SETTINGS_MODULE", cfg.django_settings_module),
        ("DJANGO_SECRET_KEY", secrets["django_secret_key"]),
        ("DJANGO_DEBUG", str(cfg.django_debug).lower()),
        ("DJANGO_ALLOWED_HOSTS", ",".join(cfg.django_allowed_hosts)),
        ("DJANGO_CSRF_TRUSTED_ORIGINS", ",".join(cfg.django_csrf_trusted_origins)),
        ("DJANGO_STATIC_ROOT", str(cfg.static_root)),
        ("DJANGO_DB_CONN_MAX_AGE", str(cfg.db_conn_max_age)),
        ("WEEKNOTES_HOME_CAST_BASE_URL", cfg.cast_base_url),
        ("WEEKNOTES_HOME_API_TOKEN", secrets["api_token"]),
        ("DATABASE_URL", database_url(cfg, secrets)),
    ]


def render_env(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> SecretContent:
    """The role's ``weeknotes-home.env.j2``: every value double-quoted, ``\\`` and ``"`` escaped."""

    lines = ["# Managed by Ansible - weeknotes.home environment\n"]
    lines += [f'{key}="{_escape(value)}"\n' for key, value in env_lines(cfg, secrets)]
    return SecretContent("".join(lines))


def traefik_config(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        title="weeknotes.home",
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


def render_route(cfg: WeeknotesHomeConfig, route: TraefikRoute, auth_hash: str | None) -> str:
    """The role's own route template (``X-Forwarded-Host``, ``customFrameOptionsValue: DENY``)."""

    return render(
        "weeknotes-home.traefik.yml.j2", route=route, auth_hash=auth_hash, entrypoints=cfg.traefik_entrypoints
    )


def nyxmon_checks(cfg: WeeknotesHomeConfig) -> list[dict[str, Any]]:
    """The playbook's ``NYXMON_CHECKS_JSON``."""

    health = cfg.echoport_health_url
    status_path = f"$.targets_by_name.{cfg.echoport_target_name}"
    return [
        {
            "name": "weeknotes.home local health",
            "check_type": "http",
            "url": cfg.health_url,
            "check_interval": cfg.nyxmon_check_interval,
            "data": {"timeout": 5, "retries": 2, "retry_delay": 2},
        },
        {
            "name": "weeknotes.home backup freshness",
            "check_type": "json-metrics",
            "url": health,
            "check_interval": cfg.nyxmon_check_interval,
            "data": {
                "url": health,
                "timeout": 10,
                "retries": 1,
                "retry_delay": 2,
                "checks": [
                    {"path": f"{status_path}.status", "op": "==", "value": "ok", "severity": "critical"},
                    {"path": f"{status_path}.next_scheduled", "op": "!=", "value": None, "severity": "critical"},
                ],
                "notification_suppression": {
                    "url": health,
                    "timeout": 3.0,
                    "status_path": f"{status_path}.status",
                    "active_statuses": [],
                    "active_if": [
                        {
                            "path": f"{status_path}.overdue_hours",
                            "op": "<=",
                            "value": cfg.backup_window_grace_hours,
                        },
                    ],
                    "reason": cfg.backup_window_suppression_reason,
                },
            },
        },
    ]


# -- command building ------------------------------------------------------------


def _stdin_lines(*lines: str) -> SecretContent:
    return SecretContent("".join(f"{line}\n" for line in lines))


def _site_manage(cfg: WeeknotesHomeConfig, *argv: str) -> str:
    """``manage.py <argv>`` in the service directory as the service user, with the env file loaded."""

    python = str(cfg.venv_bin / "python")
    # ``-I``: the helper imports only the standard library, never from its directory.
    command = [python, "-I", str(cfg.env_exec_path), str(cfg.env_path), str(cfg.service_path / "manage.py"), *argv]
    return f"cd {shlex.quote(str(cfg.service_path))} && {_as_user(cfg.user, cfg.home, {}, command)}"


def _site_probe(cfg: WeeknotesHomeConfig, command: str) -> str:
    """``command`` (a ``manage.py`` probe) once the site can run it, else ``pending`` (before a first deploy)."""

    needed = (cfg.venv_bin / "python", cfg.service_path / "manage.py", cfg.env_path, cfg.env_exec_path)
    return when_present(needed, command, otherwise="pending")


def _port_preflight(cfg: WeeknotesHomeConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but weeknotes-home may listen on the app port.

    Like ``common/preflight_ports.yml`` with ``bind: loopback``: a TCP listener
    on the port at a loopback or wildcard address fails the deploy unless every
    process behind it runs in ``weeknotes-home.service``. Read-only; runs before
    any change. ``SKIP_PREFLIGHT_PORTS`` has no effect on the pyinfra path.
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
        server.shell(name=f"Port preflight tcp/{cfg.app_port}", commands=[f"sh -c {shlex.quote(script)}"])
    )


def _migrations_probe(cfg: WeeknotesHomeConfig) -> str:
    """``migrate --check`` (read-only), with the settings the service itself runs with."""

    return _site_probe(cfg, migrations_state(_site_manage(cfg, "migrate", "--check", "--plan")))


def _static_probe(cfg: WeeknotesHomeConfig) -> str:
    """``collectstatic --dry-run`` (read-only) copies nothing: the role's own "changed" test."""

    dry_run = _site_manage(cfg, "collectstatic", "--noinput", "--dry-run")
    check = (
        f"out=$( {dry_run} ) || exit 1; "
        "if printf '%s\\n' \"$out\" | grep -q '^0 static files copied'; then echo current; else echo pending; fi"
    )
    return _site_probe(cfg, check)


def _django(cfg: WeeknotesHomeConfig, triggers: list[OperationMeta]) -> list[OperationMeta]:
    """The role's migrate and collectstatic, run after a change that can need them.

    The role runs both on every deploy and reports a change unless Django says
    nothing was to do. Here they run when the code, dependencies or env file
    changed, while migrations are pending, or while ``collectstatic`` has files to copy
    (also after a failed run whose sync already happened). Returns the migration
    step, which restarts the service when it runs: a retry after a failed run
    must not leave the old code running on the new schema.
    """

    migrated: list[OperationMeta] = []
    if cfg.run_migrations:
        migrations_check = _migrations_probe(cfg)
        migrations = probe(migrations_check, name="weeknotes-home migrations")
        migrate = server.shell(
            name="Run weeknotes-home migrations",
            commands=[_site_manage(cfg, "migrate", "--noinput")],
            _if=lambda: migrations != "current" or any(meta.did_change() for meta in triggers),
        )
        migrated.append(migrate)
        if migrations is None:
            verify_probe(migrations_check, name="weeknotes-home migrations", expect="current")
    if cfg.collectstatic:
        static_check = _static_probe(cfg)
        static = probe(static_check, name="weeknotes-home static files")
        server.shell(
            name="Collect weeknotes-home static files",
            commands=[_site_manage(cfg, "collectstatic", "--noinput")],
            _if=lambda: static != "current" or any(meta.did_change() for meta in triggers),
        )
        if static is None:
            verify_probe(static_check, name="weeknotes-home static files", expect="current")
    return migrated


# -- operations wiring (the playbook's post tasks) -------------------------------


def _guard(name: str, path: PurePosixPath, message: str) -> OperationMeta:
    return mark_read_only(
        server.shell(
            name=name,
            commands=[f"test -f {shlex.quote(str(path))} || {{ echo {shlex.quote(message)} >&2; exit 1; }}"],
        )
    )


def _sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _psql(database: str) -> str:
    return shlex.join(["runuser", "-u", "postgres", "--", "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-d", database])


def _fastdeploy_service_row(cfg: WeeknotesHomeConfig) -> None:
    """The playbook's "Sync FastDeploy service row": the row mirrors the service's config.json."""

    lines = host.get_fact(FileContents, path=str(cfg.fastdeploy_service_config))
    if not lines:
        return  # the guard before this step fails the run
    config_json = "\n".join(lines)
    try:
        wanted = json.loads(config_json)
    except json.JSONDecodeError:
        raise ValueError(f"{cfg.fastdeploy_service_config} is not valid JSON") from None
    name = cfg.echoport_fastdeploy_service
    query = f"select data::text from service where name = {_sql_literal(name)}"
    query_row = shlex.join(["runuser", "-u", "postgres", "--", "psql", "-XAtq", "-d", FASTDEPLOY_DB, "-c", query])
    stored = probe(query_row, name="FastDeploy service row")
    try:
        if stored and json.loads(stored) == wanted:
            return
    except json.JSONDecodeError:
        pass
    sql = (
        "INSERT INTO service (name, data) "
        f"VALUES ({_sql_literal(name)}, {_sql_literal(config_json)}::json) "
        "ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data "
        "WHERE service.data::jsonb IS DISTINCT FROM EXCLUDED.data::jsonb;\n"
    )
    secret_stdin(
        name="Sync FastDeploy service row for the backup service",
        command=_psql(FASTDEPLOY_DB),
        content=SecretContent(sql),
    )
    if stored is None:
        verify_probe(query_row, name="FastDeploy service row")


def _echoport_shell(cfg: WeeknotesHomeConfig, mode: Literal["check", "apply"]) -> str:
    # Like the playbook, every deploy sets the schedule.
    params = {
        "name": cfg.echoport_target_name,
        "legacy_name": cfg.echoport_legacy_target_name,
        "description": "weeknotes.home PostgreSQL backups via service-owned FastDeploy runner",
        "icon": "notebook",
        "target_mode": "service_owned",
        "fastdeploy_service": cfg.echoport_fastdeploy_service,
        "service_name": cfg.service_name,
        "restore_owner": f"{cfg.user}:{cfg.group}",
        "schedule": cfg.echoport_target_schedule,
        "schedule_policy": "set",
        "service_token": {
            "renewal_days": cfg.fastdeploy_token_rotate_days,
            "force_rotate": cfg.fastdeploy_token_force_rotate,
        },
    }
    return target_shell(params, mode, site=ECHOPORT_SITE)


def _token_and_target(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    """The playbook's FastDeploy token and Echoport target steps, as one remote script.

    A new token is issued only when the target's stored one is missing,
    undecodable, scoped to another service, a legacy token without ``jti`` or
    within the rotate window (or when forced). It goes from ``issueservicetoken``
    to the Echoport upsert through a pipe: never to the controller, a file or
    a command line. The FastDeploy user name arrives on stdin.
    """

    # Without Echoport the guard before this step fails the run.
    check = when_present([ECHOPORT_SITE / "manage.py"], last_line(_echoport_shell(cfg, "check")), otherwise="missing")
    state = probe(check, name="Echoport backup target")
    if (state or "").strip() == "unchanged":
        return
    # FastDeploy's own CLI is called in-process with the user read from stdin,
    # so the name is in no process's arguments (``commands.py --user`` would put it there).
    call = (
        "import sys; sys.argv = ['commands.py', 'issueservicetoken', "
        f"'--service', {cfg.echoport_fastdeploy_service!r}, '--user', sys.stdin.readline().strip(), "
        f"'--days', '{cfg.fastdeploy_token_days}', '--origin', 'echoport']; "
        "import commands; commands.cli()"
    )
    issue = _as_user("fastdeploy", PurePosixPath("/home/fastdeploy"), {}, [".venv/bin/python", "-c", call])
    jwt = "^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$"
    script = "\n".join(
        [
            "IFS= read -r fd_user",
            f"out=$( {_echoport_shell(cfg, 'apply')} </dev/null) || exit 1",
            'out=$(printf "%s\\n" "$out" | tail -n 1)',
            'if [ "$out" = need-token ]; then',
            f"  token=$(cd {shlex.quote(str(cfg.fastdeploy_site_root))} && "
            f"printf '%s\\n' \"$fd_user\" | {issue} 2>/dev/null) "
            "|| { echo 'issueservicetoken failed (output withheld)' >&2; exit 1; }",
            f"  printf '%s\\n' \"$token\" | grep -Eq '{jwt}' "
            "|| { echo 'issueservicetoken did not print exactly one JWT (output withheld)' >&2; exit 1; }",
            f"  printf '%s\\n' \"$token\" | {_echoport_shell(cfg, 'apply')} >/dev/null || exit 1",
            "fi",
        ]
    )
    secret_stdin(
        name="Issue or reuse the FastDeploy token and upsert the Echoport backup target",
        command=f"sh -c {shlex.quote(script)}",
        content=_stdin_lines(secrets["fastdeploy_token_user"]),
    )
    if state is None:
        verify_probe(check, name="Echoport backup target", expect="unchanged")


def _nyxmon(cfg: WeeknotesHomeConfig, mode: str) -> str:
    env = {
        "NYXMON_DB_PATH": str(NYXMON_DB),
        "NYXMON_SERVICE_NAME": cfg.nyxmon_service_name,
        "NYXMON_CHECKS_JSON": json.dumps(nyxmon_checks(cfg)),
        "NYXMON_MODE": mode,
    }
    script = (FILES / "nyxmon_checks.py").read_text()
    return _as_user("nyxmon", PurePosixPath("/home/nyxmon"), env, ["python3", "-c", script])


def _nyxmon_checks(cfg: WeeknotesHomeConfig) -> None:
    # Without Nyxmon the guard before this step fails the run.
    check = when_present([NYXMON_DB], last_line(_nyxmon(cfg, "check")), otherwise="missing")
    state = probe(check, name="Nyxmon checks")
    if (state or "").strip() == "changed=false":
        return
    server.shell(name="Upsert Nyxmon checks", commands=[_nyxmon(cfg, "apply")])
    if state is None:
        verify_probe(check, name="Nyxmon checks", expect="changed=false")


def _operations_wiring(cfg: WeeknotesHomeConfig, secrets: SecretValues) -> None:
    secrets.require(("fastdeploy_token_user",))
    _guard(
        "Check Echoport installation",
        ECHOPORT_SITE / "manage.py",
        "Echoport must be deployed before weeknotes.home backup integration can be configured.",
    )
    _guard(
        "Check FastDeploy backup service registration",
        cfg.fastdeploy_service_config,
        "Run just register-weeknotes-home-backup before deploying the weeknotes.home Echoport target.",
    )
    _fastdeploy_service_row(cfg)
    _token_and_target(cfg, secrets)
    _guard(
        "Check Nyxmon installation",
        NYXMON_DB,
        "Nyxmon must be deployed before weeknotes.home monitoring can be configured.",
    )
    _nyxmon_checks(cfg)


@deploy("Deploy weeknotes-home")
def deploy_weeknotes_home(
    cfg: WeeknotesHomeConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    check_secrets(secrets)
    env_content = render_env(cfg, secrets)
    route = traefik_config(cfg, secrets)

    _port_preflight(cfg)
    postgres_database(
        cfg.postgres_database,
        owner=cfg.postgres_user,
        password=SecretStr(secrets["postgres_password"]),
        port=cfg.postgres_port,
    )
    system_user(cfg.user, group=cfg.group, home=cfg.home, shell="/bin/bash", directories=[cfg.site_path])
    code = sync_tree(
        name="Sync daybook source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=SOURCE_EXCLUDES,
        runner=rsync,
        user=cfg.user,
        group=cfg.group,
    )
    for path in (cfg.cache_dir, cfg.static_root):
        files.directory(name=f"Ensure directory {path}", path=str(path), user=cfg.user, group=cfg.group, mode="0755")
    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        python=cfg.python_version,
        args=("--frozen", "--group", "weeknotes-home"),
        when_changed=[code],
    )
    env = secret_file(
        name="Write .env.weeknotes-home",
        path=cfg.env_path,
        content=env_content,
        mode="0600",
        user=cfg.user,
        group=cfg.group,
    )
    files.put(
        name=f"Install {cfg.env_exec_path}",
        src=str(FILES / "env_exec.py"),
        dest=str(cfg.env_exec_path),
        user="root",
        group="root",
        mode="0644",
    )
    migrated = _django(cfg, [code, deps, env])

    unit = systemd_unit(cfg.service_name, render("weeknotes-home.service.j2", cfg=cfg))
    service_rollout(cfg.service_name, units=[unit], restart_when=[code, deps, env, *migrated])
    traefik_route(route, renderer=lambda r, auth_hash: render_route(cfg, r, auth_hash))

    http_check(
        cfg.health_url, retries=cfg.health_retries, delay=cfg.health_delay, timeout=10, name=f"Check {cfg.health_url}"
    )
    if cfg.operations_wiring:
        _operations_wiring(cfg, secrets)
