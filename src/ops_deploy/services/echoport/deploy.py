"""echoport: the Echoport backup orchestrator (Django + SQLite, granian) behind Traefik.

Port of the ``echoport_deploy`` Ansible role (rsync method, uv) together with
the steps ops-control's ``deploy-echoport.yml`` runs around it: the loopback
listener check and the Nyxmon health check upsert. The role's templates are
shipped unchanged and rendered the way Ansible renders them, so the env file,
unit, Traefik route and staging refresh script are byte-identical
(``tests/test_echoport_parity.py``) and Ansible and ops-deploy can take turns
on one host without churn. The crontab entries use Ansible's own format
(``#Ansible: <name>`` header), so neither tool adds a second copy of a job.

Unlike the role, steps that would change nothing are skipped: migrate and
collectstatic run when code, dependencies or the env file changed (or while a
migration is pending), and the admin account, the scoped MinIO account, the
cleanup user's ``mc`` alias, the crontab and the Nyxmon check are probed first
(read-only) and written only when they differ from what this deploy would set.
``db.sqlite3*`` is never touched. Credentials reach the host on stdin only; the
MinIO root credentials never do (the account is managed through root's MinIO
admin alias on the host).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar

import jinja2
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from pyinfra import host, logger
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
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
)
from ops_deploy.helpers.probes import migrations_state, probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.traefik import _MIDDLEWARE, Hostname
from ops_deploy.ops import secret_file, secret_stdin, sync_tree

# The MinIO account scripts live with the MinIO deploy, which manages such accounts too.
from ops_deploy.services.minio.deploy import MC_ALIAS_PROBE, MINIO_ACCOUNT

FILES = Path(__file__).parent / "files"
ADMIN_PROBE = (FILES / "admin_probe.py").read_text()
CRON_EDIT = (FILES / "cron_edit.py").read_text()
NYXMON_CHECK = (FILES / "nyxmon_check.py").read_text()

# Never transferred, and protected from --delete (the role's rsync options).
SOURCE_EXCLUDES = (
    ".git",
    ".venv",
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    ".coverage",
    "htmlcov",
    ".tox",
    ".mypy_cache",
    "node_modules",
    "cache",
)
# Excluded from the Django tree only: package sources are synced separately,
# and the database and generated trees are state.
DJANGO_EXCLUDES = ("src/", "db.sqlite3", "db.sqlite3-*", "media/", "staticfiles/")
# Site-root files the deploy writes itself; without these excludes ``--delete``
# would remove them on every run.
SITE_MANAGED = ("/.env", "/venv", "/uv.lock", "/staging-db-refresh.sh", "/pyproject.toml")
DEV_SECRET_KEY = "development-secret-key-change-in-production"  # pragma: allowlist secret

# Rendered unquoted into the env file and units: no whitespace, quotes, ``$``,
# backticks or backslashes.
_PLAIN = r"^[^\s'\"$`\\]*$"
Plain = Annotated[str, Field(pattern=_PLAIN)]
Entry = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")]
TargetName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")]


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NyxmonCheck(_Part):
    """The playbook's Nyxmon ``json-metrics`` check on Echoport's health endpoint.

    Written into Nyxmon's SQLite database as the ``nyxmon`` user; skipped (with
    a warning) when that database does not exist on the host.
    """

    health_url: Annotated[str, Field(pattern=r"^https?://[^\s'\"$`\\]+$")] = "http://127.0.0.1:10018/api/health/"
    interval: int = Field(default=300, ge=1)
    # ``echoport_backup_window_grace_hours`` and ``..._suppression_reason`` of
    # the inventory's group vars.
    grace_hours: float = Field(default=0.5, ge=0)
    suppression_reason: Plain = "echoport_backup_window_active"
    # Echoport targets whose freshness the check asserts.
    targets: tuple[TargetName, ...] = (
        "homepage-production-db",
        "python-podcast-production-db",
        "homepage-media",
        "python-podcast-media",
    )
    service_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ._-]+$")] = "echoport"
    user: UnixUser = "nyxmon"
    db_path: PurePosixPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")


class MinioAccount(_Part):
    """The playbook's scoped MinIO account for the cleanup user's ``mc`` alias.

    Port of ``minio_deploy``'s ``tasks_from: backup_account`` as
    ``deploy-echoport.yml`` includes it: a user that may list, read and delete
    in the whole bucket, never write or use the admin API, with the policy
    ``backup-<name>``. It is created or updated through root's MinIO admin
    alias on the host; the MinIO root credentials are never needed. The secret
    is ``minio_secret_key``; the user name is derived from ``name`` (MinIO
    allows 20 characters), as the playbook's ``backup_minio_account_user``.
    """

    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")] = "echoport-retention"
    bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,62}$")] = "backups"
    allow_put: bool = False
    allow_delete: bool = True
    # ``minio_host_alias`` of the MinIO deploy (root's mc configuration).
    admin_alias: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$")] = "local"
    policy_dir: PurePosixPath = PurePosixPath("/etc/minio/policies")

    @property
    def user(self) -> str:
        return "bk-" + hashlib.sha256(self.name.encode()).hexdigest()[:17]

    @property
    def policy(self) -> str:
        return f"backup-{self.name}"

    @property
    def policy_path(self) -> PurePosixPath:
        return self.policy_dir / f"{self.policy}.json"


class EchoportConfig(BaseServiceConfig):
    """The role's variables without the ``echoport_`` prefix (defaults from its defaults/main.yml)."""

    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "django_secret_key",
        "fastdeploy_base_url",
        "fastdeploy_service_token",
        "admin_username",
        "admin_password",
    )

    service_name: ServiceName = "echoport"
    user: UnixUser = "echoport"
    group: UnixUser = "echoport"
    home: PurePosixPath = PurePosixPath("/home/echoport")
    site_path: PurePosixPath = PurePosixPath("/home/echoport/site")
    # An echoport checkout: src/django becomes the site root, the other paths
    # follow below the site, pyproject.toml and uv.lock are copied next to it.
    source_path: Path
    rsync_additional_paths: tuple[Annotated[str, Field(pattern=r"^src(/[A-Za-z0-9_-][A-Za-z0-9_.-]*)+/?$")], ...] = (
        "src/backups/",
    )
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.13"

    app_host: Annotated[str, Field(pattern=r"^127\.0\.0\.1$")] = "127.0.0.1"
    app_port: int = Field(default=10018, ge=1024, le=65535)
    workers: int = Field(default=2, ge=1, le=64)
    allowed_path_prefixes: tuple[Annotated[str, Field(pattern=r"^/[^\s,'\"$`\\]+$")], ...] = (
        "/home/",
        "/opt/",
        "/var/lib/",
        "/mnt/cryptdata/",
    )
    # None leaves the variable out of the env file (Echoport's own default
    # applies: 900, 86400 and 60).
    stale_run_grace_seconds: int | None = Field(default=None, ge=0)
    late_result_window_seconds: int | None = Field(default=None, ge=0)
    health_overdue_grace_minutes: int | None = Field(default=None, ge=0)

    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    django_allowed_hosts: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9.:*\[\]-]+$")], ...] = ("127.0.0.1",)
    django_debug: bool = False

    traefik_enabled: bool = True
    traefik_host: Hostname = "echoport.example.com"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    basic_auth_enabled: bool = True
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"
    internal_ip_ranges: tuple[str, ...] = (
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
    )

    scheduler_enabled: bool = True
    # The minute field of the crontab entry.
    scheduler_interval: Annotated[str, Field(pattern=r"^[0-9*/,-]+$")] = "*/5"
    cleanup_enabled: bool = True
    cleanup_hour: Annotated[str, Field(pattern=r"^[0-9*/,-]+$")] = "3"
    # The cleanup cron job deletes expired archives through ``mc`` as the
    # service user, so that user needs its own alias (credentials: the
    # ``minio_account`` user and the secret ``minio_secret_key``, or without an
    # account the secrets ``minio_access_key`` and ``minio_secret_key``).
    minio_mc_path: PurePosixPath = PurePosixPath("/usr/local/bin/mc")
    minio_alias: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$")] = "minio"
    minio_url: Annotated[str, Field(pattern=r"^(https?://[^\s'\"$`\\]+)?$")] = ""
    minio_verify_bucket: Annotated[str, Field(pattern=r"^[a-z0-9.-]*$")] = "backups"
    minio_account: MinioAccount | None = None

    staging_db_refresh_enabled: bool = False
    staging_db_refresh_hour: Annotated[str, Field(pattern=r"^[0-9*/,-]+$")] = "2"
    staging_db_refresh_minute: Annotated[str, Field(pattern=r"^[0-9*/,-]+$")] = "20"
    staging_db_refresh_targets: tuple[TargetName, ...] = ()
    staging_db_refresh_triggered_by: Plain = "staging-refresh-scheduler"

    # The playbook's loopback check and Nyxmon wiring; off by default (the role has neither).
    nyxmon: NyxmonCheck | None = None

    @field_validator("source_path")
    @classmethod
    def _source_is_an_echoport_checkout(cls, value: Path) -> Path:
        missing = [p for p in ("src/django/manage.py", "pyproject.toml", "uv.lock") if not (value / p).exists()]
        if missing:
            raise ValueError(f"source_path is not an echoport checkout (missing {', '.join(missing)})")
        return value

    @model_validator(mode="after")
    def _role_rules(self) -> EchoportConfig:
        if not self.site_path.is_relative_to(self.home) or self.site_path == self.home:
            raise ValueError("site_path must be below home")
        if self.cleanup_enabled and not (self.minio_alias and self.minio_url):
            raise ValueError("cleanup_enabled requires minio_url")
        if self.minio_account is not None and not self.cleanup_enabled:
            raise ValueError("minio_account is the cleanup alias's account; it requires cleanup_enabled")
        for extra in self.rsync_additional_paths:
            if not (self.source_path / extra).is_dir():
                raise ValueError(f"missing path for rsync deployment: {extra}")
        return self

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv"

    @property
    def venv_bin(self) -> PurePosixPath:
        return self.venv_path / "bin"

    @property
    def cache_dir(self) -> PurePosixPath:
        return self.site_path / "cache"

    @property
    def logs_dir(self) -> PurePosixPath:
        return self.home / "logs"

    @property
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env"

    @property
    def staging_refresh_active(self) -> bool:
        return self.staging_db_refresh_enabled and bool(self.staging_db_refresh_targets)


def check_secrets(cfg: EchoportConfig, secrets: SecretValues) -> None:
    """The role's asserts and the playbook's required keys, naming keys only."""

    secrets.require(cfg.required_secret_keys)
    if cfg.basic_auth_enabled and cfg.traefik_enabled:
        secrets.require(("basic_auth_password",))
    if cfg.minio_account is not None:
        secrets.require(("minio_secret_key",))
        if "minio_access_key" in secrets:
            raise ValueError("minio_access_key is the minio_account user, derived from its name; do not pass it")
    elif cfg.cleanup_enabled:
        secrets.require(("minio_access_key", "minio_secret_key"))
    if any("\n" in value or "\r" in value for value in secrets.values()):
        raise ValueError("secret values must be single lines")
    # The role's backup_account input check (the value is never printed).
    if cfg.minio_account is not None and not 32 <= len(secrets["minio_secret_key"]) <= 40:
        raise ValueError("minio_secret_key must be 32 to 40 characters for the MinIO account")
    placeholders = {"CHANGEME", DEV_SECRET_KEY}
    watched = ["django_secret_key"]
    if cfg.cleanup_enabled or cfg.minio_account is not None:
        watched.append("minio_secret_key")
    if cfg.basic_auth_enabled and cfg.traefik_enabled:
        watched.append("basic_auth_password")
    weak = [key for key in watched if secrets[key] in placeholders]
    if weak:
        raise ValueError(f"secrets are placeholders: {', '.join(weak)}")


@cache
def _templates() -> jinja2.Environment:
    # The role's own templates, rendered with the options and the ``quote``
    # filter of Ansible's template module.
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.echoport", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["quote"] = shlex.quote
    # Ansible's filters in the policy template of ``minio_deploy``.
    env.filters["to_json"] = json.dumps
    env.filters["bool"] = bool
    return env


def role_vars(cfg: EchoportConfig, secrets: SecretValues, *, auth_hash: str | None = None) -> dict[str, Any]:
    """The role's variables, as ``deploy-echoport.yml`` sets them."""

    def optional(value: int | None) -> int | str:
        return "" if value is None else value

    return {
        "echoport_user": cfg.user,
        "echoport_group": cfg.group,
        "echoport_home": str(cfg.home),
        "echoport_site_path": str(cfg.site_path),
        "echoport_venv_bin": str(cfg.venv_bin),
        "echoport_cache_dir": str(cfg.cache_dir),
        "echoport_app_host": cfg.app_host,
        "echoport_app_port": cfg.app_port,
        "echoport_workers": cfg.workers,
        "echoport_allowed_path_prefixes": list(cfg.allowed_path_prefixes),
        "echoport_stale_run_grace_seconds": optional(cfg.stale_run_grace_seconds),
        "echoport_late_result_window_seconds": optional(cfg.late_result_window_seconds),
        "echoport_health_overdue_grace_minutes": optional(cfg.health_overdue_grace_minutes),
        "echoport_django_settings_module": cfg.django_settings_module,
        "echoport_django_allowed_hosts": ",".join(cfg.django_allowed_hosts),
        "echoport_django_secret_key": secrets.get("django_secret_key", ""),
        "echoport_django_debug": cfg.django_debug,
        "echoport_fastdeploy_base_url": secrets.get("fastdeploy_base_url", ""),
        "echoport_fastdeploy_service_token": secrets.get("fastdeploy_service_token", ""),
        "echoport_minio_mc_path": str(cfg.minio_mc_path),
        "echoport_minio_alias": cfg.minio_alias,
        "echoport_traefik_host": cfg.traefik_host,
        "echoport_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "echoport_traefik_middlewares": list(cfg.traefik_middlewares),
        "echoport_basic_auth_enabled": cfg.basic_auth_enabled,
        "echoport_basic_auth_user": secrets.get("basic_auth_user") or cfg.basic_auth_user,
        "echoport_basic_auth_password_hash": auth_hash or "",
        "echoport_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "echoport_staging_db_refresh_targets": list(cfg.staging_db_refresh_targets),
        "echoport_staging_db_refresh_triggered_by": cfg.staging_db_refresh_triggered_by,
    }


def render_role(template: str, cfg: EchoportConfig, secrets: SecretValues, **extra: Any) -> str:
    return _templates().get_template(template).render(**{**role_vars(cfg, secrets), **extra})


def render_env(cfg: EchoportConfig, secrets: SecretValues) -> SecretContent:
    """``.env`` (the role's ``echoport.env.j2``)."""

    return SecretContent(render_role("echoport.env.j2", cfg, secrets))


def render_policy(account: MinioAccount) -> str:
    """The account's policy (``minio_deploy``'s ``backup-account-policy.json.j2``, whole bucket)."""

    return (
        _templates()
        .get_template("backup-account-policy.json.j2")
        .render(
            minio_backup_account_bucket=account.bucket,
            minio_backup_account_prefixes=[account.name],
            minio_backup_account_whole_bucket=True,
            minio_backup_account_allow_put=account.allow_put,
            minio_backup_account_allow_delete=account.allow_delete,
        )
    )


def traefik_config(cfg: EchoportConfig, secrets: SecretValues) -> TraefikRoute:
    auth = None
    if cfg.basic_auth_enabled:
        auth = BasicAuth(
            user=secrets.get("basic_auth_user") or cfg.basic_auth_user,
            password=SecretStr(secrets["basic_auth_password"]),
        )
    return TraefikRoute(
        name="echoport",
        host=cfg.traefik_host,
        app_port=cfg.app_port,
        app_host=cfg.app_host,
        basic_auth=auth,
        internal_ip_ranges=cfg.internal_ip_ranges,
        middlewares=cfg.traefik_middlewares,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def render_route(cfg: EchoportConfig, secrets: SecretValues, route: TraefikRoute, auth_hash: str | None) -> str:
    """The role's ``traefik-echoport.yml.j2``, with the password hash the helper resolved."""

    return render_role("traefik-echoport.yml.j2", cfg, secrets, echoport_basic_auth_password_hash=auth_hash or "")


# -- host commands -------------------------------------------------------------


def _probe(command: str) -> str:
    return str(host.get_fact(Command, command=f"{command} 2>/dev/null || true") or "")


def _as(cfg: EchoportConfig, script: str, env: dict[str, str] | None = None, *, user: str | None = None) -> str:
    """``script`` in ``site_path`` as the service user (``HOME`` and ``env`` set), via ``sh -c``."""

    who = user or cfg.user
    home = cfg.home if who == cfg.user else PurePosixPath("/home") / who
    return f"cd {shlex.quote(str(cfg.site_path))} && {_as_user(who, home, env or {}, ['sh', '-c', script])}"


def _manage(cfg: EchoportConfig, args: str) -> str:
    """``python manage.py <args>``; settings read ``.env`` from the site root."""

    return f"exec {shlex.quote(str(cfg.venv_bin / 'python'))} manage.py {args}"


def _django_env(cfg: EchoportConfig) -> dict[str, str]:
    return {"DJANGO_SETTINGS_MODULE": cfg.django_settings_module}


def _venv_stale(cfg: EchoportConfig) -> OperationMeta:
    """Remove a venv whose Python does not run or is not ``python_version`` (rebuilt by ``uv sync``)."""

    version = _as_user(cfg.user, cfg.home, {}, [str(cfg.venv_bin / "python"), "--version"])
    venv = shlex.quote(str(cfg.venv_path))
    current = _probe(f'if [ -e {venv} ]; then v=$({version} 2>/dev/null) && echo "$v" || echo broken; fi').strip()
    matched = re.match(r"^Python (\d+\.\d+)", current)
    stale = bool(current) and (matched is None or matched.group(1) != cfg.python_version)
    return server.shell(
        name=f"Remove {cfg.venv_path} unless it runs Python {cfg.python_version}",
        commands=[f"rm -rf {venv}"],
        _if=lambda: stale,
    )


def _ownership(cfg: EchoportConfig) -> OperationMeta:
    """The role's recursive ``chown`` of the site, run only when a file has another owner.

    Only the owner is checked: processes run as the service user by ``runuser``
    or cron have the user's primary group (``users`` on macmini), so group
    drift appears again after every run and would make every deploy a change.
    """

    site = shlex.quote(str(cfg.site_path))
    owner = f"{cfg.user}:{cfg.group}"
    wrong = _probe(f"find {site} ! -user {cfg.user} -print -quit")
    return server.shell(
        name=f"Set ownership of {cfg.site_path}",
        commands=[f"chown -R {owner} {site}"],
        _if=lambda: bool(wrong.strip()),
    )


# -- the role: Django ------------------------------------------------------------


def _site_probe(cfg: EchoportConfig, command: str, *, otherwise: str) -> str:
    """``command`` once the site can run ``manage.py``, else ``otherwise`` (before a first deploy)."""

    needed = (cfg.venv_bin / "python", cfg.site_path / "manage.py", cfg.env_path)
    return when_present(needed, command, otherwise=otherwise)


def _migrations_probe(cfg: EchoportConfig) -> str:
    plan = _as(cfg, _manage(cfg, "migrate --check --plan"), _django_env(cfg))
    return _site_probe(cfg, migrations_state(plan), otherwise="pending")


def _static_missing(cfg: EchoportConfig) -> bool:
    manifest = shlex.quote(str(cfg.site_path / "staticfiles/staticfiles.json"))
    return _probe(f"test -f {manifest} && echo present") != "present"


def _django_hash(password: str, encoded: str) -> str | None:
    """``encoded`` (``algorithm$iterations$salt``) rehashed with ``password``, as Django stores it."""

    algorithm, iterations, salt = [*encoded.split("$"), "", ""][:3]
    if algorithm != "pbkdf2_sha256" or not iterations.isdigit() or not salt:
        return None
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
    return f"{algorithm}${iterations}${salt}${base64.b64encode(raw).decode()}"


def admin_current(probe: str, username: str, email: str, password: str) -> bool:
    """True if the probe shows the admin as ``ensure_superuser`` would leave it.

    An empty ``email`` is not enforced, as in the command.
    """

    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    for line in probe.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0] != digest(username):
            continue
        rehashed = _django_hash(password, fields[3])
        return (
            (not email or fields[1] == digest(email))
            and fields[2] == "11"
            and rehashed is not None
            and digest(rehashed) == fields[4]
        )
    return False


def _admin(cfg: EchoportConfig, secrets: SecretValues) -> OperationMeta:
    username, email = secrets["admin_username"], secrets.get("admin_email", "")
    run = _as(cfg, _manage(cfg, f"shell -c {shlex.quote(ADMIN_PROBE)}"), _django_env(cfg))
    check = _site_probe(cfg, run, otherwise="none")
    rows = probe(check, name="Echoport admin user")
    current = rows is not None and admin_current(rows, username, email, secrets["admin_password"])
    ensure_run = (
        "IFS= read -r ADMIN_USERNAME; IFS= read -r ADMIN_EMAIL; IFS= read -r ADMIN_PASSWORD; "
        "export ADMIN_USERNAME ADMIN_EMAIL ADMIN_PASSWORD; " + _manage(cfg, "ensure_superuser >/dev/null")
        # Its success line names the user; failures still reach stderr.
    )
    ensure = secret_stdin(
        name="Ensure Echoport admin user",
        command=_as(cfg, ensure_run, _django_env(cfg)),
        content=SecretContent(f"{username}\n{email}\n{secrets['admin_password']}\n"),
        _if=lambda: not current,
    )
    if rows is None:
        verify_probe(check, name="Echoport admin user")
    return ensure


# -- the role: scheduler -----------------------------------------------------------


def cron_job(cfg: EchoportConfig, name: str, minute: str, hour: str, job: str, *, present: bool) -> OperationMeta:
    """One crontab entry of the service user, in Ansible's ``cron`` module format."""

    params = {
        "user": cfg.user,
        "name": name,
        "state": "present" if present else "absent",
        "minute": minute,
        "hour": hour,
        "job": job,
    }

    def command(apply: bool) -> str:
        arg = json.dumps({**params, "apply": apply}, separators=(",", ":"))
        return shlex.join(["python3", "-I", "-c", CRON_EDIT, arg])

    # Before the user exists there is no crontab to read.
    check = when_present([cfg.home], command(apply=False), otherwise="pending")
    state = probe(check, name=f"cron job {name}")
    edit = server.shell(
        name=f"Cron job {name}: {params['state']}",
        commands=[command(apply=True)],
        _if=lambda: (state or "").strip() != "unchanged",
    )
    if state is None:
        verify_probe(check, name=f"cron job {name}", expect="unchanged")
    return edit


def _log_file(cfg: EchoportConfig, name: str) -> OperationMeta:
    return files.file(
        name=f"Ensure log file {name}",
        path=str(cfg.logs_dir / name),
        present=True,
        touch=False,
        user=cfg.user,
        group=cfg.group,
        mode="0640",
    )


def _mc(cfg: EchoportConfig, *args: str) -> str:
    return _as_user(cfg.user, cfg.home, {}, [str(cfg.minio_mc_path), *args])


def _alias_wanted(cfg: EchoportConfig, secrets: SecretValues) -> dict[str, str]:
    """The cleanup user's alias as ``mc alias import`` reads it."""

    access = cfg.minio_account.user if cfg.minio_account is not None else secrets["minio_access_key"]
    return {
        "url": cfg.minio_url,
        "accessKey": access,
        "secretKey": secrets["minio_secret_key"],
        "api": "s3v4",
        "path": "auto",
    }


def _alias_digest(wanted: dict[str, str]) -> str:
    return hashlib.sha256("\n".join((wanted["url"], wanted["accessKey"], wanted["secretKey"])).encode()).hexdigest()


def _alias_check(cfg: EchoportConfig) -> str:
    """Strict probe: a digest of the cleanup user's stored alias, or ``none``."""

    # mc reports a missing alias as JSON, which the probe reads as "none"; any
    # other failure of mc fails the probe.
    listing = (
        f"out=$( {_mc(cfg, '--json', 'alias', 'list', cfg.minio_alias)} ); rc=$?; "
        f'printf \'%s\\n\' "$out" | python3 -I -c {shlex.quote(MC_ALIAS_PROBE)} "$rc"'
    )
    return when_present([cfg.home], listing, otherwise="none")


def _minio_account(cfg: EchoportConfig, secrets: SecretValues) -> None:
    """The playbook's ``backup_account`` include: the cleanup alias's own MinIO account.

    Like the role, everything goes through root's admin alias and the secret
    reaches ``mc`` on stdin. Unlike it, the policy is created and the user
    upserted only when the probe finds them missing or different: the secret
    counts as current when the cleanup user's alias already holds it and lists
    the bucket with it.
    """

    account = cfg.minio_account
    assert account is not None
    mc, admin = str(cfg.minio_mc_path), account.admin_alias
    document = render_policy(account)

    def script(mode: str) -> str:
        args = [mode, mc, admin, account.policy, account.user, document]
        return shlex.join(["python3", "-I", "-c", MINIO_ACCOUNT, *args])

    state = probe(script("probe"), name=f"MinIO account {account.name}")
    found = dict(part.partition("=")[::2] for part in (state or "").split())
    stored = (probe(_alias_check(cfg), name="mc alias of the cleanup user") or "").strip()
    listing = f"{_mc(cfg, 'ls', f'{cfg.minio_alias}/{account.bucket}')} >/dev/null && echo ok"
    login = _probe(when_present([cfg.home], listing, otherwise="no")).strip()
    current = found.get("user") in ("attached", "unattached") and stored == _alias_digest(_alias_wanted(cfg, secrets))
    current = current and login == "ok"

    missing = shlex.quote(
        f"mc admin info {admin} failed: the admin alias is not configured for root on this host "
        "or MinIO is unreachable. Deploy MinIO with minio_bootstrap_with_mc first."
    )
    mark_read_only(
        server.shell(
            name=f"Require the MinIO admin alias {admin} of root",
            commands=[f"{shlex.join([mc, 'admin', 'info', admin])} >/dev/null || {{ echo {missing} >&2; exit 1; }}"],
        )
    )
    files.directory(
        name="Create MinIO policy directory", path=str(account.policy_dir), user="root", group="root", mode="0750"
    )
    policy_file = files.put(
        name=f"Install MinIO policy {account.policy}",
        src=StringIO(document),
        dest=str(account.policy_path),
        user="root",
        group="root",
        mode="0640",
    )
    server.shell(
        name=f"Create or update MinIO policy {account.policy}",
        commands=[shlex.join([mc, "admin", "policy", "create", admin, account.policy, str(account.policy_path)])],
        _if=lambda: policy_file.did_change() or found.get("policy") != "ok",
    )
    failed = shlex.quote(
        f"mc admin user add for {account.user} failed; mc output is withheld (it can quote the secret)"
    )
    add = shlex.join([mc, "admin", "user", "add", admin])
    secret_stdin(
        name=f"Create or update MinIO user of {account.name}",
        # ``mc admin user add`` is an upsert; it reads the user and the secret from stdin.
        command=f"{add} >/dev/null 2>&1 || {{ echo {failed} >&2; exit 1; }}",
        content=SecretContent(f"{account.user}\n{secrets['minio_secret_key']}\n"),
        _if=lambda: not current,
    )
    server.shell(
        name=f"Attach MinIO policy {account.policy}",
        commands=[shlex.join([mc, "admin", "policy", "attach", admin, account.policy, "--user", account.user])],
        _if=lambda: found.get("user") != "attached",
    )
    mark_read_only(server.shell(name=f"Verify MinIO account {account.name}", commands=[script("verify")]))


def _mc_alias(cfg: EchoportConfig, secrets: SecretValues) -> None:
    """The cleanup user's ``mc`` alias: set when it differs, then prove the bucket is reachable."""

    wanted = _alias_wanted(cfg, secrets)
    check = _alias_check(cfg)
    found = probe(check, name="mc alias of the cleanup user")
    stored = (found or "").strip()
    # ``alias import`` opens its file itself; the user cannot reopen the
    # root-owned pipe on stdin, so the JSON goes through a private file, removed
    # right after.
    script = (
        "set -e; d=$(mktemp -d); trap 'rm -rf \"$d\"' EXIT; "
        # The directory stays root-owned (the user can enter it, not change it), so
        # nothing in it can be swapped for a link before root writes the file.
        'chmod 0711 "$d"; umask 077; '
        f'cat > "$d/alias.json"; chown {cfg.user} "$d/alias.json"; '
        + f'{_mc(cfg, "alias", "import", cfg.minio_alias)} "$d/alias.json"'
    )
    secret_stdin(
        name="Configure mc alias for the cleanup user",
        # Not ``alias set``, which would put the credentials in the host's process list.
        command=script,
        content=SecretContent(json.dumps(wanted)),
        _if=lambda: stored != _alias_digest(wanted),
    )
    if found is None:
        verify_probe(check, name="mc alias of the cleanup user")
    if cfg.minio_verify_bucket:
        mark_read_only(
            server.shell(
                name="Verify the cleanup user can reach the MinIO bucket",
                commands=[f"{_mc(cfg, 'ls', f'{cfg.minio_alias}/{cfg.minio_verify_bucket}')} >/dev/null"],
            )
        )


def _scheduler(cfg: EchoportConfig, secrets: SecretValues) -> None:
    run = f"cd {cfg.site_path} && DJANGO_SETTINGS_MODULE={cfg.django_settings_module} {cfg.venv_bin}/python manage.py"
    cron_job(
        cfg,
        "Echoport scheduled backups",
        cfg.scheduler_interval,
        "*",
        f"{run} run_scheduled_backups >> {cfg.logs_dir}/scheduler.log 2>&1",
        present=cfg.scheduler_enabled,
    )
    if cfg.scheduler_enabled:
        _log_file(cfg, "scheduler.log")
    if cfg.cleanup_enabled:
        _mc_alias(cfg, secrets)
    cron_job(
        cfg,
        "Echoport cleanup old backups",
        "0",
        cfg.cleanup_hour,
        f"{run} cleanup_old_backups >> {cfg.logs_dir}/cleanup.log 2>&1",
        present=cfg.cleanup_enabled,
    )
    if cfg.cleanup_enabled:
        _log_file(cfg, "cleanup.log")
    if cfg.staging_refresh_active:
        files.put(
            name="Install staging DB refresh helper script",
            src=StringIO(render_role("staging-db-refresh.sh.j2", cfg, secrets)),
            dest=str(cfg.site_path / "staging-db-refresh.sh"),
            user=cfg.user,
            group=cfg.group,
            mode="0750",
        )
    cron_job(
        cfg,
        "Echoport staging DB refresh",
        cfg.staging_db_refresh_minute,
        cfg.staging_db_refresh_hour,
        f"cd {cfg.site_path} && {cfg.site_path}/staging-db-refresh.sh >> {cfg.logs_dir}/staging-db-refresh.log 2>&1",
        present=cfg.staging_refresh_active,
    )
    if cfg.staging_refresh_active:
        _log_file(cfg, "staging-db-refresh.log")


# -- the playbook's post tasks ---------------------------------------------------


def _listener_check(cfg: EchoportConfig) -> OperationMeta:
    """Echoport listens on the app port, and only on IPv4 loopback (the playbook's post task)."""

    port = cfg.app_port
    script = (
        f'for i in $(seq 1 15); do out=$(ss -H -ltn "sport = :{port}"); [ -n "$out" ] && break; sleep 2; done; '
        f'[ -n "$out" ] || {{ echo "nothing listens on port {port}" >&2; exit 1; }}; '
        f"if printf '%s\\n' \"$out\" | grep -Ev '127\\.0\\.0\\.1:{port}[[:space:]]' >/dev/null; then "
        f'echo "Echoport must listen only on 127.0.0.1:{port}" >&2; exit 1; fi'
    )
    return mark_read_only(
        server.shell(name=f"Check Echoport listens only on 127.0.0.1:{port}", commands=[f"sh -c {shlex.quote(script)}"])
    )


def nyxmon_checks(nyxmon: NyxmonCheck) -> list[dict[str, Any]]:
    """The playbook's ``NYXMON_CHECKS_JSON``."""

    grace = nyxmon.grace_hours
    return [
        {
            "name": "Echoport backup freshness (homepage/python-podcast)",
            "check_type": "json-metrics",
            "url": nyxmon.health_url,
            "check_interval": nyxmon.interval,
            "data": {
                "url": nyxmon.health_url,
                "timeout": 10.0,
                "retries": 1,
                "retry_delay": 2.0,
                "checks": [
                    {
                        "path": f"$.targets_by_name.{target}.status",
                        "op": "==",
                        "value": "ok",
                        "severity": "critical",
                    }
                    for target in nyxmon.targets
                ],
                "notification_suppression": {
                    "url": nyxmon.health_url,
                    "timeout": 3.0,
                    "status_path": "$.status",
                    "active_statuses": [],
                    "active_if": [
                        {"path": f"$.targets_by_name.{target}.overdue_hours", "op": "<=", "value": grace}
                        for target in nyxmon.targets
                    ],
                    "reason": nyxmon.suppression_reason,
                },
            },
        }
    ]


def _nyxmon(nyxmon: NyxmonCheck) -> None:
    db = shlex.quote(str(nyxmon.db_path))
    if _probe(f"test -f {db} && echo present") != "present":
        logger.warning(f"{host.name}: Nyxmon database {nyxmon.db_path} not found; skipping the Echoport Nyxmon check")
        return
    env = {
        "NYXMON_DB_PATH": str(nyxmon.db_path),
        "NYXMON_SERVICE_NAME": nyxmon.service_name,
        "NYXMON_CHECKS_JSON": json.dumps(nyxmon_checks(nyxmon), separators=(",", ":")),
    }
    home = PurePosixPath("/home") / nyxmon.user

    def command(apply: bool) -> str:
        return _as_user(
            nyxmon.user,
            home,
            {**env, "NYXMON_APPLY": "1" if apply else "0"},
            ["python3", "-I", "-c", NYXMON_CHECK],
        )

    state = probe(command(apply=False), name="Nyxmon Echoport check")
    server.shell(
        name="Upsert Nyxmon Echoport json-metrics check",
        commands=[command(apply=True)],
        _if=lambda: (state or "").strip() != "changed=false",
    )
    if state is None:
        verify_probe(command(apply=False), name="Nyxmon Echoport check", expect="changed=false")


@deploy("Deploy echoport")
def deploy_echoport(cfg: EchoportConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    check_secrets(cfg, secrets)
    env_content = render_env(cfg, secrets)
    route = traefik_config(cfg, secrets) if cfg.traefik_enabled else None
    if cfg.minio_account is not None:
        _minio_account(cfg, secrets)

    system_user(cfg.user, group=cfg.group, home=cfg.home, directories=[cfg.site_path, cfg.cache_dir, cfg.logs_dir])

    code = sync_tree(
        name="Sync echoport source",
        src=cfg.source_path / "src/django",
        dest=cfg.site_path,
        excludes=(*SOURCE_EXCLUDES, *DJANGO_EXCLUDES, *SITE_MANAGED),
        runner=rsync,
        user=cfg.user,
        group=cfg.group,
    )
    synced = [code]
    for extra in cfg.rsync_additional_paths:
        target = cfg.site_path / extra.rstrip("/")
        for path in dict.fromkeys((target.parent, target)):
            files.directory(
                name=f"Ensure directory {path}", path=str(path), user=cfg.user, group=cfg.group, mode="0755"
            )
        synced.append(
            sync_tree(
                name=f"Sync echoport {extra}",
                src=cfg.source_path / extra,
                dest=target,
                excludes=SOURCE_EXCLUDES,
                runner=rsync,
                user=cfg.user,
                group=cfg.group,
            )
        )
    for name in ("pyproject.toml", "uv.lock"):
        synced.append(
            files.put(
                name=f"Copy {name} from source",
                src=str(cfg.source_path / name),
                dest=str(cfg.site_path / name),
                user=cfg.user,
                group=cfg.group,
                mode="0644",
            )
        )
    _ownership(cfg)

    stale = _venv_stale(cfg)
    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        python=cfg.python_version,
        when_changed=[*synced, stale],
    )
    files.link(
        name="Link venv to .venv",
        path=str(cfg.site_path / "venv"),
        target=str(cfg.venv_path),
        user=cfg.user,
        group=cfg.group,
        force=True,
    )

    env = secret_file(
        name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user, group=cfg.group
    )
    changed = [*synced, deps, env]
    migrations_check = _migrations_probe(cfg)
    migrations = probe(migrations_check, name="Echoport migrations")
    migrate = server.shell(
        name="manage.py migrate --noinput",
        commands=[_as(cfg, _manage(cfg, "migrate --noinput"), _django_env(cfg))],
        _if=lambda: migrations != "current" or any(meta.did_change() for meta in changed),
    )
    if migrations is None:
        verify_probe(migrations_check, name="Echoport migrations", expect="current")
    collect_static = _static_missing(cfg)
    server.shell(
        name="manage.py collectstatic --noinput",
        commands=[_as(cfg, _manage(cfg, "collectstatic --noinput"), _django_env(cfg))],
        _if=lambda: collect_static or any(meta.did_change() for meta in [*changed, migrate]),
    )
    _admin(cfg, secrets)

    unit = systemd_unit(cfg.service_name, render_role("echoport.service.j2", cfg, secrets))
    service_rollout(cfg.service_name, units=[unit], restart_when=[*changed, stale, migrate])
    if route is not None:
        traefik_route(route, renderer=lambda r, auth_hash: render_route(cfg, secrets, r, auth_hash))
    _scheduler(cfg, secrets)

    _listener_check(cfg)
    if cfg.nyxmon is not None:
        _nyxmon(cfg.nyxmon)
