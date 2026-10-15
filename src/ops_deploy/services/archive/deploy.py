"""archive: Django app (``archive``) plus its enrichment worker (``archive-metadata-worker``).

Port of the ``archive_deploy`` Ansible role (rsync method) together with the
playbook steps around it in ops-control's ``deploy-archive.yml``: the MinIO
media bucket and service account (through root's MinIO admin alias on the
host, never the MinIO root credentials), the one-time move of a local media tree
into MinIO, and the Echoport backup target. The role's templates are shipped
unchanged and rendered the way Ansible renders them, so env files, units and
the Traefik route are byte-identical (``tests/test_archive_parity.py``) and
Ansible and ops-deploy can take turns on one host without churn.

Unlike the role, steps that would change nothing are skipped: migrate and
collectstatic run when code, dependencies or the env changed; the admin
account, the MinIO setup and the Echoport target are probed first (read-only)
and only written when they differ from what this deploy would set.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal

import jinja2
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import apt, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import (
    TraefikRoute,
    http_check,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
    wait_port,
)
from ops_deploy.helpers.probes import last_line, probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.traefik import _MIDDLEWARE, Hostname
from ops_deploy.ops import secret_file, secret_stdin, sync_tree

FILES = Path(__file__).parent / "files"
MINIO_BOOTSTRAP = (FILES / "minio_bootstrap.sh").read_text()
MINIO_PROBE = (FILES / "minio_probe.sh").read_text()
MEDIA_MIGRATE = (FILES / "media_migrate.sh").read_text()
ECHOPORT_TARGET = (FILES / "echoport_target.py").read_text()
ADMIN_PROBE = (FILES / "admin_probe.py").read_text()

S3 = "storages.backends.s3.S3Storage"
RETIRED_UNITS = ("archive-quote-classifier.timer", "archive-quote-classifier.service")
UNIT_DIR = PurePosixPath("/etc/systemd/system")

# Rendered unquoted into .env: no whitespace, quotes, ``$``, backticks or backslashes.
_PLAIN = r"^[^\s'\"$`\\]*$"
Plain = Annotated[str, Field(pattern=_PLAIN)]
Url = Annotated[str, Field(pattern=r"^(https?://[^\s'\"$`\\]+)?$")]
Seconds = Annotated[int, Field(ge=1, le=86400)]

# Keys of the archive secrets file that override the config (the playbook
# reads them with a default); they are settings, not credentials.
SETTING_KEYS = (
    "summary_api_base",
    "summary_model",
    "transcription_api_base",
    "transcription_model",
    "media_storage_backend",
    "media_storage_location",
    "media_storage_bucket_name",
    "media_storage_endpoint_url",
    "media_storage_region_name",
    "media_storage_access_key_id",
    "media_storage_addressing_style",
)


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MinioBootstrap(_Part):
    """The playbook's MinIO bucket/service-account step (S3 backend only).

    Bucket, policy and user are managed through ``admin_alias``, root's MinIO
    admin alias on the host (``minio_host_alias`` of the MinIO deploy), as
    ``deploy-archive.yml`` does: the MinIO root credentials are never needed.
    """

    policy_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")] = "archive-media-rw"
    mc: PurePosixPath = PurePosixPath("/usr/local/bin/mc")
    admin_alias: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$")] = "local"


class EchoportTarget(_Part):
    """The playbook's Echoport backup target upsert (needs Echoport on the host)."""

    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")] = "archive"
    # A schedule set in the Echoport UI is kept unless ``update_schedule``.
    schedule: Annotated[str, Field(pattern=r"^\S+( \S+){4}$")] = "40 2 * * *"
    update_schedule: bool = False
    user: UnixUser = "echoport"
    site_path: PurePosixPath = PurePosixPath("/home/echoport/site")


class ArchiveConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "django_secret_key",
        "api_token",
        "summary_api_key",
        "admin_username",
        "admin_password",
    )

    service_name: ServiceName = "archive"
    worker_service_name: ServiceName = "archive-metadata-worker"
    user: UnixUser = "archive"
    site_path: PurePosixPath = PurePosixPath("/home/archive/site")
    # An archive checkout; its root becomes the site root.
    source_path: Path
    # The role's rsync excludes; the host-side ones keep state alive across --delete.
    source_excludes: tuple[str, ...] = (
        ".git",
        ".venv",
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".env",
        "/.env.shell",
        "db.sqlite3*",
        "archive-media/",
        "staticfiles/",
        "src/django/gunicorn.ctl",
    )
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.12"
    app_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    app_port: int = Field(default=10041, ge=1024, le=65535)
    workers: int = Field(default=2, ge=1, le=64)
    metadata_worker_interval: Seconds = 10
    metadata_worker_limit: int = Field(default=10, ge=1, le=1000)
    metadata_request_timeout: Seconds = 15
    summary_request_timeout: Seconds = 60
    transcription_request_timeout: Seconds = 300
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    django_debug: bool = False
    django_allowed_hosts: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9.:*\[\]-]+$")], ...] = ("127.0.0.1",)
    django_csrf_trusted_origins: tuple[Url, ...] = ()
    summary_api_base: Url = "https://api.openai.com/v1"
    summary_model: Plain = "gpt-4o-mini"
    transcription_api_base: Url | None = None  # None: the summary base
    transcription_model: Plain = "gpt-4o-mini-transcribe"
    media_storage_backend: Literal["django.core.files.storage.FileSystemStorage", "storages.backends.s3.S3Storage"] = (
        "django.core.files.storage.FileSystemStorage"
    )
    # Literal path characters only: it also becomes an rsync exclude pattern.
    media_storage_location: Annotated[str, Field(pattern=r"^(/[A-Za-z0-9._/-]*)?$")] = ""  # empty: <site>/archive-media
    media_storage_base_url: Url = ""
    media_storage_bucket_name: Annotated[str, Field(pattern=r"^([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])?$")] = ""
    media_storage_endpoint_url: Url = ""
    media_storage_region_name: Plain = ""
    media_storage_access_key_id: Plain = ""
    media_storage_addressing_style: Literal["path", "virtual", "auto"] = "path"
    traefik_host: Hostname = "archive.example.com"
    traefik_entrypoints: tuple[Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")], ...] = ("web-secure",)
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    minio: MinioBootstrap | None = None
    echoport: EchoportTarget | None = None

    @field_validator("media_storage_location")
    @classmethod
    def _media_location_normalized(cls, value: str) -> str:
        if value and any(part in ("", ".", "..") for part in value.split("/")[1:]):
            raise ValueError("media_storage_location must be a normalized absolute path")
        return value

    @field_validator("source_path")
    @classmethod
    def _source_is_an_archive_checkout(cls, value: Path) -> Path:
        missing = [p for p in ("src/django/manage.py", "pyproject.toml", "uv.lock") if not (value / p).exists()]
        if missing:
            raise ValueError(f"source_path is not an archive checkout (missing {', '.join(missing)})")
        return value

    @property
    def home(self) -> PurePosixPath:
        return PurePosixPath("/home") / self.user

    @property
    def django_path(self) -> PurePosixPath:
        return self.site_path / "src/django"

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv"

    @property
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env"

    @property
    def static_root(self) -> PurePosixPath:
        return self.site_path / "staticfiles"

    @property
    def media_location(self) -> str:
        return self.media_storage_location or str(self.site_path / "archive-media")

    @property
    def s3(self) -> bool:
        return self.media_storage_backend == S3


def resolve(cfg: ArchiveConfig, secrets: SecretValues) -> ArchiveConfig:
    """``cfg`` with the settings the secrets file sets, validated (the playbook's ``_resolved`` vars)."""

    overrides = {key: secrets[key] for key in SETTING_KEYS if key in secrets}
    resolved = cfg.model_validate({**cfg.model_dump(), **overrides}) if overrides else cfg
    if resolved.s3:
        missing = [
            name
            for name in ("media_storage_bucket_name", "media_storage_endpoint_url", "media_storage_access_key_id")
            if not getattr(resolved, name)
        ]
        if not secrets.get("media_storage_secret_access_key"):
            missing.append("media_storage_secret_access_key")
        if missing:
            raise ValueError(f"S3 media storage needs {', '.join(missing)}")
    return resolved


def check_secrets(secrets: SecretValues) -> None:
    """The role's asserts, naming keys only."""

    secrets.require(ArchiveConfig.required_secret_keys)
    # The media secret reaches the MinIO scripts as one line on stdin (the
    # playbook's CR/LF assert); every other value is held to the same rule.
    if any("\n" in value or "\r" in value for value in secrets.values()):
        raise ValueError("secret values must be single lines")
    # The MinIO step uses root's admin alias on the host; the root credentials
    # must never travel from the controller.
    shipped = [key for key in ("minio_root_user", "minio_root_password") if key in secrets]
    if shipped:
        raise ValueError(f"the MinIO root credentials are not used, do not pass them: {', '.join(shipped)}")
    weak = [
        key
        for key in ("django_secret_key", "api_token", "summary_api_key")
        if len(secrets[key]) <= 20 or secrets[key] == "CHANGEME"
    ]
    if not secrets["admin_username"] or not secrets["admin_password"] or secrets["admin_password"] == "CHANGEME":
        weak.append("admin_username/admin_password")
    if weak:
        raise ValueError(f"secrets are missing, too short or placeholders: {', '.join(weak)}")


@cache
def _templates() -> jinja2.Environment:
    # The role's own templates, rendered with the options of Ansible's template module.
    return jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.archive", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def role_vars(cfg: ArchiveConfig, secrets: SecretValues) -> dict[str, Any]:
    """The role's variables, as ``deploy-archive.yml`` sets them."""

    site = str(cfg.site_path)
    summary_base = cfg.summary_api_base
    return {
        "archive_user": cfg.user,
        "archive_group": cfg.user,
        "archive_home": str(cfg.home),
        "archive_site_path": site,
        "archive_django_path": str(cfg.django_path),
        "archive_venv_bin": f"{cfg.venv_path}/bin",
        "archive_env_path": str(cfg.env_path),
        "archive_db_path": f"{site}/db.sqlite3",
        "archive_static_root": str(cfg.static_root),
        "archive_app_host": cfg.app_host,
        "archive_app_port": cfg.app_port,
        "archive_workers": cfg.workers,
        "archive_metadata_worker_interval": cfg.metadata_worker_interval,
        "archive_metadata_worker_limit": cfg.metadata_worker_limit,
        "archive_metadata_request_timeout": cfg.metadata_request_timeout,
        "archive_summary_request_timeout": cfg.summary_request_timeout,
        "archive_transcription_request_timeout": cfg.transcription_request_timeout,
        "archive_django_settings_module": cfg.django_settings_module,
        "archive_django_debug": cfg.django_debug,
        "archive_django_secret_key": secrets.get("django_secret_key", ""),
        "archive_django_allowed_hosts": list(cfg.django_allowed_hosts),
        "archive_django_csrf_trusted_origins": list(cfg.django_csrf_trusted_origins),
        "archive_api_token": secrets.get("api_token", ""),
        "archive_summary_api_key": secrets.get("summary_api_key", ""),
        "archive_summary_api_base": summary_base,
        "archive_summary_model": cfg.summary_model,
        "archive_transcription_api_key": secrets.get("transcription_api_key", secrets.get("summary_api_key", "")),
        "archive_transcription_api_base": summary_base
        if cfg.transcription_api_base is None
        else cfg.transcription_api_base,
        "archive_transcription_model": cfg.transcription_model,
        "archive_media_storage_backend": cfg.media_storage_backend,
        "archive_media_storage_location": cfg.media_location,
        "archive_media_storage_base_url": cfg.media_storage_base_url,
        "archive_media_storage_bucket_name": cfg.media_storage_bucket_name,
        "archive_media_storage_endpoint_url": cfg.media_storage_endpoint_url,
        "archive_media_storage_region_name": cfg.media_storage_region_name,
        "archive_media_storage_access_key_id": cfg.media_storage_access_key_id,
        "archive_media_storage_secret_access_key": secrets.get("media_storage_secret_access_key", ""),
        "archive_media_storage_addressing_style": cfg.media_storage_addressing_style,
        "archive_traefik_host": cfg.traefik_host,
        "archive_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "archive_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "archive_traefik_middlewares": list(cfg.traefik_middlewares),
    }


def render_role(template: str, cfg: ArchiveConfig, secrets: SecretValues, **extra: Any) -> str:
    return _templates().get_template(template).render(**role_vars(cfg, secrets), **extra)


def render_env(cfg: ArchiveConfig, secrets: SecretValues, *, shell: bool) -> SecretContent:
    """``.env`` (systemd ``EnvironmentFile``) or, with ``shell``, the quoted ``.env.shell``."""

    return SecretContent(render_role("archive.env.j2", cfg, secrets, task_shell_environment=shell))


def traefik_config(cfg: ArchiveConfig) -> TraefikRoute:
    return TraefikRoute(name=cfg.service_name, host=cfg.traefik_host, app_port=cfg.app_port, app_host=cfg.app_host)


def _as(user: str, home: PurePosixPath, cwd: PurePosixPath, script: str, env: dict[str, str] | None = None) -> str:
    return f"cd {shlex.quote(str(cwd))} && {_as_user(user, home, env or {}, ['sh', '-c', script])}"


def _manage(cfg: ArchiveConfig, args: str) -> str:
    """``python manage.py <args>`` as the role runs it: env from ``.env.shell``, in ``src/django``."""

    shell_env = shlex.quote(f"{cfg.env_path}.shell")
    python = shlex.quote(str(cfg.venv_path / "bin/python"))
    return f"set -a; . {shell_env}; set +a; exec {python} manage.py {args}"


def _bash(script: str, label: str, *args: object) -> str:
    return shlex.join(["bash", "-c", script, label, *(str(a) for a in args)])


def _probe(command: str) -> str:
    """Stdout of an absence probe (a missing file is its answer, not an error)."""

    return str(host.get_fact(Command, command=f"{command} 2>/dev/null || true") or "")


def _python_changed(cfg: ArchiveConfig) -> OperationMeta:
    """A no-op marker that counts as changed when the venv runs another Python than configured."""

    # As the service user: the venv belongs to it, root never runs its interpreter.
    python = shlex.quote(str(cfg.venv_path / "bin/python"))
    script = f"exec {python} -c 'import sys; print(\"%d.%d\" % sys.version_info[:2])'"
    # No venv yet: nothing to replace. A venv whose Python fails is replaced too.
    check = when_present([cfg.venv_path / "bin/python"], _as(cfg.user, cfg.home, cfg.site_path, script), otherwise="")
    current = probe(check, name="archive venv Python")
    stale = current is None or (bool(current.strip()) and current.strip() != cfg.python_version)
    return server.shell(
        name=f"Python {cfg.python_version} wanted in the venv",
        commands=["true"],
        _if=lambda: stale,
    )


# -- playbook pre_tasks: MinIO --------------------------------------------------


def _app_alias(cfg: ArchiveConfig, secrets: SecretValues) -> str:
    """The app's ``mc`` alias as one line of JSON (the playbook's ``archive_media_app_alias``)."""

    alias = {
        "url": cfg.media_storage_endpoint_url,
        "accessKey": cfg.media_storage_access_key_id,
        "secretKey": secrets["media_storage_secret_access_key"],
        "api": "s3v4",
        "path": "auto",
    }
    return json.dumps(alias)


def _minio(cfg: ArchiveConfig, secrets: SecretValues, env: OperationMeta) -> None:
    assert cfg.minio is not None
    minio = cfg.minio
    mc, admin, bucket = minio.mc, minio.admin_alias, cfg.media_storage_bucket_name
    # The script answers "ok" or "bootstrap:<reason>"; only a crash is a failure.
    args = (mc, admin, cfg.media_storage_endpoint_url, bucket, minio.policy_name, cfg.env_path)
    check = _bash(MINIO_PROBE, "minio-probe", *args)
    state = probe(check, name="MinIO media bucket and service account")
    missing = shlex.quote(
        f"mc admin info {admin} failed: the admin alias is not configured for root on this host "
        "or MinIO is unreachable. Run the MinIO deploy (minio_bootstrap_with_mc) first."
    )
    mark_read_only(
        server.shell(
            name=f"Require the MinIO admin alias {admin} of root",
            commands=[
                f"{shlex.join([str(mc), 'admin', 'info', admin])} >/dev/null || {{ echo {missing} >&2; exit 1; }}"
            ],
        )
    )
    secret_stdin(
        name="Ensure MinIO media bucket and service account",
        command=_bash(
            MINIO_BOOTSTRAP, "minio-bootstrap", mc, admin, bucket, cfg.media_storage_access_key_id, minio.policy_name
        ),
        content=SecretContent(f"{secrets['media_storage_secret_access_key']}\n{_app_alias(cfg, secrets)}\n"),
        # New app credentials in .env: the account may need them too.
        _if=lambda: (state or "").strip() != "ok" or env.did_change(),
    )
    if state is None:
        verify_probe(check, name="MinIO media bucket and service account", expect="ok")


def _media_migration(cfg: ArchiveConfig, secrets: SecretValues) -> None:
    mc = cfg.minio.mc if cfg.minio is not None else PurePosixPath("/usr/local/bin/mc")
    common = (mc, cfg.media_storage_bucket_name, cfg.media_location)
    check = _bash(MEDIA_MIGRATE, "media-migrate", *common, "probe")
    state = probe(check, name="local archive-media migration")
    if state is not None and state.strip() != "archive_media_pending":
        return
    secret_stdin(
        name="Migrate local archive-media into MinIO",
        command=_bash(MEDIA_MIGRATE, "media-migrate", *common),
        content=SecretContent(f"{_app_alias(cfg, secrets)}\n"),
    )
    if state is None:
        verify_probe(check, name="local archive-media migration")


# -- role: admin account --------------------------------------------------------


def _django_hash(password: str, encoded: str) -> str | None:
    """``encoded`` (``algorithm$iterations$salt``) rehashed with ``password``, as Django stores it."""

    algorithm, iterations, salt = [*encoded.split("$"), "", ""][:3]
    if algorithm != "pbkdf2_sha256" or not iterations.isdigit() or not salt:
        return None
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
    return f"{algorithm}${iterations}${salt}${base64.b64encode(raw).decode()}"


def admin_current(probe: str, username: str, email: str, password: str) -> bool:
    """True if the probe shows the admin exactly as ``ensure_admin_user`` would leave it."""

    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    for line in probe.splitlines():
        fields = line.split()
        if len(fields) != 5 or fields[0] != digest(username):
            continue
        rehashed = _django_hash(password, fields[3])
        return (
            fields[1] == digest(email) and fields[2] == "11" and rehashed is not None and digest(rehashed) == fields[4]
        )
    return False


def _admin(cfg: ArchiveConfig, secrets: SecretValues) -> None:
    username, email = secrets["admin_username"].strip(), secrets.get("admin_email", "").strip()
    run_probe = _as(cfg.user, cfg.home, cfg.django_path, _manage(cfg, f"shell -c {shlex.quote(ADMIN_PROBE)}"))
    needed = (cfg.venv_path / "bin/python", cfg.django_path / "manage.py", f"{cfg.env_path}.shell")
    check = when_present(needed, run_probe, otherwise="none")
    rows = probe(check, name="archive admin user")
    current = rows is not None and admin_current(rows, username, email, secrets["admin_password"])
    run = (
        "IFS= read -r ARCHIVE_ADMIN_USER; IFS= read -r ARCHIVE_ADMIN_EMAIL; "
        + _manage(
            cfg, 'ensure_admin_user --username "$ARCHIVE_ADMIN_USER" --email "$ARCHIVE_ADMIN_EMAIL" --password-stdin'
        )
        # Its success line names the user; failures still reach stderr.
        + " >/dev/null"
    )
    secret_stdin(
        name="Ensure archive admin user",
        command=_as(cfg.user, cfg.home, cfg.django_path, run),
        content=SecretContent(f"{username}\n{email}\n{secrets['admin_password']}\n"),
        _if=lambda: not current,
    )
    if rows is None:
        verify_probe(check, name="archive admin user")


# -- role: retired units, playbook post_tasks: Echoport ------------------------------


def _retired_units() -> None:
    paths = " ".join(str(UNIT_DIR / unit) for unit in RETIRED_UNITS)
    present = _probe(f"ls {paths}")
    units = " ".join(RETIRED_UNITS)
    server.shell(
        name="Remove retired archive quote classifier units",
        commands=[
            f"systemctl disable --now {units} >/dev/null 2>&1 || true",
            f"rm -f {paths}",
            "systemctl daemon-reload",
        ],
        _if=lambda: bool(present.strip()),
    )


def _echoport(cfg: ArchiveConfig) -> None:
    assert cfg.echoport is not None
    target = cfg.echoport
    site = target.site_path
    manage = shlex.quote(str(site / "manage.py"))
    params = {
        "name": target.name,
        "schedule": target.schedule,
        "update_schedule": target.update_schedule,
        "db_path": f"{cfg.site_path}/db.sqlite3",
    }

    def command(apply: bool) -> str:
        env = {"ARCHIVE_ECHOPORT": json.dumps({**params, "apply": apply}, separators=(",", ":"))}
        python = shlex.quote(str(site / ".venv/bin/python"))
        script = f"exec {python} {manage} shell -c {shlex.quote(ECHOPORT_TARGET)}"
        return _as(target.user, PurePosixPath("/home") / target.user, site, script, env)

    installed = _probe(f"test -f {manage} && echo installed")
    check = when_present([site / "manage.py"], last_line(command(apply=False)), otherwise="missing")
    state = probe(check, name=f"Echoport backup target {target.name}")
    server.shell(
        name="Require Echoport for the archive backup target",
        commands=[f"test -f {manage} || {{ echo 'Echoport must be deployed before archive' >&2; exit 1; }}"],
        _if=lambda: installed.strip() != "installed",
    )
    server.shell(
        name=f"Upsert Echoport backup target {target.name}",
        commands=[command(apply=True)],
        _if=lambda: (state or "").strip() != "unchanged",
    )
    if state is None:
        verify_probe(check, name=f"Echoport backup target {target.name}", expect="unchanged")


@deploy("Deploy archive")
def deploy_archive(cfg: ArchiveConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    check_secrets(secrets)
    cfg = resolve(cfg, secrets)
    env_content, shell_env = render_env(cfg, secrets, shell=False), render_env(cfg, secrets, shell=True)

    system_user(cfg.user, home=cfg.home, directories=[cfg.site_path, cfg.static_root])
    # Before the MinIO scripts, which use python3 too.
    apt.packages(name="Install runtime packages", packages=["python3", "python3-venv", "sqlite3", "rsync"])
    env = secret_file(
        name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user, group=cfg.user
    )
    shell_env_op = secret_file(
        name="Write .env.shell",
        path=PurePosixPath(f"{cfg.env_path}.shell"),
        content=shell_env,
        mode="0600",
        user=cfg.user,
        group=cfg.user,
    )
    if cfg.s3:
        if cfg.minio is not None:
            _minio(cfg, secrets, env)
        _media_migration(cfg, secrets)

    excludes = cfg.source_excludes
    media = PurePosixPath(cfg.media_location)
    if media.is_relative_to(cfg.site_path) and media != cfg.site_path:
        # Media kept inside the site under another name must survive --delete too.
        excludes = (*excludes, f"/{media.relative_to(cfg.site_path)}/")
    code = sync_tree(
        name="Sync archive source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=excludes,
        runner=rsync,
        user=cfg.user,
        group=cfg.user,
    )
    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        python=cfg.python_version,
        args=("--no-dev",),
        when_changed=[code, _python_changed(cfg)],
    )
    changed = [code, deps, env, shell_env_op]
    for args in ("migrate --noinput", "collectstatic --noinput"):
        server.shell(
            name=f"manage.py {args}",
            commands=[_as(cfg.user, cfg.home, cfg.django_path, _manage(cfg, args))],
            _if=lambda: any(meta.did_change() for meta in changed),
        )
    _admin(cfg, secrets)

    for name, template in (
        (cfg.service_name, "archive.service.j2"),
        (cfg.worker_service_name, "archive-metadata-worker.service.j2"),
    ):
        unit = systemd_unit(name, render_role(template, cfg, secrets))
        service_rollout(name, units=[unit], restart_when=[deps, env, code])
    _retired_units()
    traefik_route(
        traefik_config(cfg),
        renderer=lambda _route, _hash: render_role("archive.traefik.yml.j2", cfg, secrets),
    )

    wait_port(cfg.app_port, host=cfg.app_host)
    http_check(f"http://{cfg.app_host}:{cfg.app_port}/", status=200, retries=20, delay=3)
    if cfg.echoport is not None:
        _echoport(cfg)
