"""heis: the Heis Wagtail site, a Django app served by gunicorn.

Port of the ``heis_deploy`` Ansible role (rsync method, uv). The files it
writes are byte-identical to the role's (``tests/test_heis_parity.py``), so
Ansible and ops-deploy can take turns on one host without churn. The SQLite
database, the uploaded media and the other host-side state in the site
directory are never touched: the source sync does not delete, and the
production content switches (``setup_default_pages``, ``seed_content``) are
honoured exactly like the role's.
"""

from __future__ import annotations

import hashlib
import hmac
import shlex
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar

import jinja2
from pydantic import Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory
from pyinfra.facts.server import Command
from pyinfra.operations import apt, files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.git_source import CommitSha
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import (
    TraefikRoute,
    http_check,
    record_source,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
    wait_port,
)
from ops_deploy.helpers.probes import migrations_state, probe, verify_probe, when_present
from ops_deploy.helpers.python import DEFAULT_UV, _as_user
from ops_deploy.helpers.traefik import DYNAMIC_DIR, Hostname
from ops_deploy.ops import secret_file, secret_stdin, sync_tree

TEMPLATE_PACKAGE = "ops_deploy.services.heis"

# The role's heis_rsync_excludes (database, media and backups stay on the
# host), plus the host-written files the role would copy over from a developer
# checkout: ``.env`` (the deploy writes it), collectstatic output and the cache.
SOURCE_EXCLUDES = (
    ".vault_password",
    "db.sqlite3",
    "db.sqlite3-wal",
    "db.sqlite3-shm",
    "*.sqlite3",
    "*.sqlite3-wal",
    "*.sqlite3-shm",
    "media",
    "backups",
    ".venv",
    "venv",
    ".git",
    "__pycache__",
    "*.pyc",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    "heis-buehne-bilder.zip",
    "/.env",
    "/staticfiles",
    "/cache",
)
# Records which admin account was last ensured (an HMAC, never the password).
ADMIN_STAMP = ".ops-deploy-admin"
# Present while the content reconcilers have not all succeeded (root-owned).
CONTENT_PENDING = ".ops-deploy-content-pending"
# The role's heis_prerequisite_packages.
PACKAGES = ("fish", "rsync", "sqlite3")
# Placeholders the role's asserts refuse.
PLACEHOLDERS = frozenset({"", "CHANGEME", "CHANGE_ME"})
# A Traefik rule; lands in double quotes in the route file.
TraefikRule = Annotated[str, Field(min_length=1, pattern=r'^[^"\\\r\n]+$')]
# Lands in single quotes in the route file.
RedirectPart = Annotated[str, Field(pattern=r"^[^'\r\n]*$")]

# Admin account probe (stdlib only, no secrets in it): one digest per row for
# "active staff superuser" and one for "has this email", so user names and
# addresses never reach the controller's output.
ADMIN_PROBE = """\
import hashlib, sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
try:
    rows = db.execute("select username, email, is_staff, is_superuser, is_active from auth_user").fetchall()
except sqlite3.OperationalError as exc:
    # Not migrated yet: no accounts. Any other database error fails the probe.
    if "no such table" not in str(exc):
        raise
    rows = []
digest = lambda *parts: hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()
for username, email, staff, superuser, active in rows:
    print("A", digest(username, staff, superuser, active))
    print("B", digest(username, email))
"""


class HeisRoute(TraefikRoute):
    """The role writes ``<user>.traefik.yml``, not the helper's ``<name>.yml``."""

    @property
    def path(self) -> PurePosixPath:
        return DYNAMIC_DIR / f"{self.name}.traefik.yml"


class HeisConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "django_secret_key",
        "django_admin_url",
        "admin_username",
        "admin_email",
        "admin_password",
    )

    service_name: ServiceName = "heis"
    # The role names the systemd unit and the Traefik file after the user.
    user: UnixUser = "heis"
    group: UnixUser = "heis"
    home: PurePosixPath = PurePosixPath("/home/heis")
    site_path: PurePosixPath = PurePosixPath("/home/heis/site")
    # A heis checkout; synced as the site root.
    source_path: Path
    # The commit ``source_path`` was checked out at (a git source), recorded on
    # the host; None: a local working tree, and the host's record is removed.
    source_commit: CommitSha | None = None
    source_excludes: tuple[str, ...] = SOURCE_EXCLUDES
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.13"
    app_port: int = Field(default=10020, ge=1024, le=65535)
    gunicorn_workers: int = Field(default=4, ge=1, le=64)
    gunicorn_timeout: int = Field(default=3600, ge=1)
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    # None: ``<fqdn>,localhost`` (the role's default).
    django_allowed_hosts: Annotated[str, Field(pattern=r"^[A-Za-z0-9.,:*\[\]-]+$")] | None = None
    fqdn: Hostname
    # A Traefik rule such as ``Host(`a.example`) || Host(`www.a.example`)``.
    traefik_host_rule: TraefikRule
    # The HTTPS router's rule; None: ``traefik_host_rule`` (the role's default).
    traefik_tls_host_rule: TraefikRule | None = None
    # Both set: a permanent redirect to the canonical host on the HTTPS router.
    traefik_canonical_redirect_regex: RedirectPart = ""
    traefik_canonical_redirect_replacement: RedirectPart = ""
    # None: ``https://<fqdn>`` (the role's default).
    wagtailadmin_base_url: Annotated[str, Field(pattern=r"^https?://[^\s'\"]+$")] | None = None
    # DJANGO_SERVE_MEDIA; the inventory turns it on for staging and heis.
    serve_media: bool = False
    # The role's content reconcilers; production turns both off.
    setup_default_pages: bool = True
    seed_content: bool = True
    health_retries: int = Field(default=30, ge=1)

    @field_validator("source_path")
    @classmethod
    def _source_is_a_heis_checkout(cls, value: Path) -> Path:
        missing = [p for p in ("manage.py", "pyproject.toml", "uv.lock", "config/wsgi.py") if not (value / p).exists()]
        if missing:
            raise ValueError(f"source_path is not a heis checkout (missing {', '.join(missing)})")
        return value

    @model_validator(mode="after")
    def _redirect_is_complete(self) -> HeisConfig:
        if bool(self.traefik_canonical_redirect_regex) != bool(self.traefik_canonical_redirect_replacement):
            raise ValueError("traefik_canonical_redirect_regex and _replacement go together")
        return self

    @property
    def tls_host_rule(self) -> str:
        return self.traefik_tls_host_rule or self.traefik_host_rule

    @property
    def admin_base_url(self) -> str:
        return self.wagtailadmin_base_url or f"https://{self.fqdn}"

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
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env"

    @property
    def db_path(self) -> PurePosixPath:
        return self.site_path / "db.sqlite3"

    @property
    def allowed_hosts(self) -> str:
        return self.django_allowed_hosts or f"{self.fqdn},localhost"


@cache
def _templates() -> jinja2.Environment:
    # Rendered like Ansible's template module (trim_blocks), for byte parity.
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    # Ansible's ``quote`` filter is ``shlex.quote``.
    env.filters["quote"] = lambda value: shlex.quote(str(value))
    return env


def render(template: str, **context: object) -> str:
    return _templates().get_template(template).render(**context)


def check_secrets(secrets: SecretValues) -> None:
    """The role's asserts, plus single-line values. Errors name keys only."""

    if secrets.get("django_secret_key", "") in ("", "CHANGEME"):
        raise ValueError("django_secret_key must be set and not a placeholder")
    if secrets.get("django_admin_url", "") in ("", "CHANGEME"):
        raise ValueError("django_admin_url must be set and not a placeholder")
    for name in ("admin_username", "admin_password"):
        if secrets.get(name, "") in PLACEHOLDERS:
            raise ValueError(f"{name} must be set and not a placeholder")
    if any(c in value for value in secrets.values() for c in "\r\n"):
        raise ValueError("secret values must be single lines")


def render_env(cfg: HeisConfig, secrets: SecretValues) -> SecretContent:
    check_secrets(secrets)
    return SecretContent(
        render("heis.env.j2", cfg=cfg, secret_key=secrets["django_secret_key"], admin_url=secrets["django_admin_url"])
    )


def traefik_config(cfg: HeisConfig) -> HeisRoute:
    return HeisRoute(
        name=cfg.user,
        title="Heis",
        host=cfg.fqdn,
        app_port=cfg.app_port,
        # The role's backend URL says ``localhost``.
        app_host="localhost",
    )


def render_route(cfg: HeisConfig) -> str:
    """The role's own route template (TLS rule, canonical redirect), not the shared dual-router one."""

    return render("heis.traefik.yml.j2", cfg=cfg)


def _stdin_env(env: dict[str, str]) -> SecretContent:
    # One ``KEY=value`` per line; read back with ``export "$line"`` (no expansion).
    return SecretContent("".join(f"{key}={value}\n" for key, value in env.items()))


_READ_ENV = 'while IFS= read -r line && [ -n "$line" ]; do export "$line"; done'


def _site_shell(cfg: HeisConfig, script: str) -> str:
    """``script`` run by ``sh`` in the site directory as the service user."""

    shell = _as_user(cfg.user, cfg.home, {}, ["sh", "-c", script])
    return f"cd {shlex.quote(str(cfg.site_path))} && {shell}"


def _manage_script(cfg: HeisConfig, *command: str, stdin_env: bool = False) -> str:
    """The role's ``set -a; . .env; set +a; python manage.py ...`` with its settings module."""

    lines = [
        "set -a",
        f". {shlex.quote(str(cfg.env_path))}",
        "set +a",
        f"export DJANGO_SETTINGS_MODULE={shlex.quote(cfg.django_settings_module)}",
    ]
    if stdin_env:
        lines.append(_READ_ENV)
    lines.append(f"exec {shlex.join([str(cfg.venv_bin / 'python'), 'manage.py', *command])}")
    return "; ".join(lines)


def _fact(command: str) -> str:
    return (host.get_fact(Command, command=command) or "").strip()


def _site_owned(cfg: HeisConfig) -> OperationMeta:
    """The role's recursive ``file: owner/group`` on the site, only when something is off."""

    site = shlex.quote(str(cfg.site_path))
    wrong = f"find {site} \\( ! -user {cfg.user} -o ! -group {cfg.group} \\) -print -quit"
    pending = _fact(f"{wrong} 2>/dev/null || true")
    return server.shell(
        name="Set ownership of the site tree",
        commands=[f"chown -hR {cfg.user}:{cfg.group} {site}"],
        _if=lambda: bool(pending),
    )


def _migrations_probe(cfg: HeisConfig) -> str:
    """``migrate --check`` (read-only), only against an existing database (Django would create one)."""

    plan = _site_shell(cfg, _manage_script(cfg, "migrate", "--check", "--plan"))
    needed = (cfg.db_path, cfg.env_path, cfg.venv_bin / "python")
    return when_present(needed, migrations_state(plan), otherwise="pending")


UV_SYNC_ARGS = ("--frozen", "--no-dev")


def _deps_probe(cfg: HeisConfig) -> str:
    """``uv sync --dry-run`` (read-only) finds nothing to install, remove or recreate.

    Catches an earlier run that stopped after the source sync and a changed
    ``python_version``, neither of which the sync's own change shows.
    """

    argv = [str(DEFAULT_UV), "sync", *UV_SYNC_ARGS, "--python", cfg.python_version, "--dry-run"]
    env = {"UV_PROJECT_ENVIRONMENT": str(cfg.venv_path)}
    sync = f"cd {shlex.quote(str(cfg.site_path))} && {_as_user(cfg.user, cfg.home, env, argv)}"
    check = (
        f"out=$( {sync} 2>&1 ) || {{ printf '%s\\n' \"$out\" >&2; exit 1; }}; "
        "if printf '%s\\n' \"$out\" | grep -qx 'Would make no changes'; then echo current; else echo pending; fi"
    )
    # Nothing synced yet: the sync installs everything.
    return when_present([cfg.site_path / "uv.lock"], check, otherwise="pending")


def _static_collected(cfg: HeisConfig) -> bool:
    manifest = shlex.quote(str(cfg.site_path / "staticfiles" / "staticfiles.json"))
    return _fact(f"test -f {manifest} && echo present || true") == "present"


def _manage(
    cfg: HeisConfig, name: str, command: tuple[str, ...], *, when_changed: list[OperationMeta], force: bool
) -> OperationMeta:
    return server.shell(
        name=name,
        commands=[_site_shell(cfg, _manage_script(cfg, *command))],
        _if=lambda: force or any(meta.did_change() for meta in when_changed),
    )


def _reconcile_content(cfg: HeisConfig, *, when_changed: list[OperationMeta]) -> None:
    """The role's Wagtail content reconcilers, when the inventory enables them.

    The role runs them on every deploy and reads "changed" from their output.
    They write to the database, so here they run only when the code, the
    dependencies or the schema changed (always on a first deploy): content
    removed by hand between deploys of unchanged code is not put back.
    A marker file is set before they run and removed only after all of them
    succeeded, so a run that failed half-way is retried by the next deploy.
    Production disables both switches and is never touched.
    """

    commands: list[tuple[str, tuple[str, ...]]] = []
    if cfg.setup_default_pages:
        commands.append(
            ("Ensure default Wagtail pages exist", ("setup_default_pages", "--hostname", cfg.fqdn, "--port", "443"))
        )
    if cfg.seed_content:
        commands.append(("Seed homepage content", ("seed_home_content",)))
        commands.append(("Seed subpage content and chrome defaults", ("seed_subpages_content",)))
    if not commands:
        return
    marker = shlex.quote(str(cfg.home / CONTENT_PENDING))
    pending = _fact(f"test -e {marker} && echo pending || true") == "pending"
    needed = lambda: pending or any(meta.did_change() for meta in when_changed)  # noqa: E731
    server.shell(name="Mark content reconciliation pending", commands=[f"touch {marker}"], _if=needed)
    for name, command in commands:
        server.shell(name=name, commands=[_site_shell(cfg, _manage_script(cfg, *command))], _if=needed)
    server.shell(name="Clear content reconciliation marker", commands=[f"rm -f {marker}"], _if=needed)


def _admin_stamp(cfg: HeisConfig, secrets: SecretValues) -> str:
    material = "\0".join(secrets[k] for k in ("admin_username", "admin_email", "admin_password"))
    return hmac.new(secrets["django_secret_key"].encode(), material.encode(), hashlib.sha256).hexdigest() + "\n"


def _digest(*parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


def _admin_probe(cfg: HeisConfig) -> str:
    """The account exists as an active staff superuser with the configured email."""

    argv = shlex.join(["python3", "-I", "-c", ADMIN_PROBE, str(cfg.db_path)])
    return when_present([cfg.db_path], argv, otherwise="none")


def _admin_in_place(rows: str | None, secrets: SecretValues) -> bool:
    username, email = secrets["admin_username"], secrets["admin_email"]
    return rows is not None and {f"A {_digest(username, 1, 1, 1)}", f"B {_digest(username, email)}"} <= set(
        rows.splitlines()
    )


def _ensure_superuser(cfg: HeisConfig, secrets: SecretValues) -> None:
    """The role's ``ensure_superuser`` task, only when it may have something to do.

    The command is idempotent but reports nothing pyinfra can read, so it runs
    when the account is missing, inactive or lost its staff/superuser flags, or
    the admin secrets changed since the last run (stamp file). Like the role it
    fails on an inactive account. A password changed by hand stays until the
    secret changes (the role resets it on every deploy).
    """

    stamp_path = cfg.home / ADMIN_STAMP
    stamp = _admin_stamp(cfg, secrets)
    check = _admin_probe(cfg)
    rows = probe(check, name=f"{cfg.user} admin user")
    if _fact(f"cat {shlex.quote(str(stamp_path))} 2>/dev/null || true") == stamp.strip() and _admin_in_place(
        rows, secrets
    ):
        return
    # Name, email and password travel on stdin: never in a process's arguments.
    secret_stdin(
        name="Ensure heis admin user",
        command=_site_shell(cfg, _manage_script(cfg, "ensure_superuser", stdin_env=True)),
        content=_stdin_env(
            {
                "ADMIN_USERNAME": secrets["admin_username"],
                "ADMIN_EMAIL": secrets["admin_email"],
                "ADMIN_PASSWORD": secrets["admin_password"],
            }
        ),
    )
    secret_file(name="Record heis admin user", path=stamp_path, content=SecretContent(stamp), user="root", group="root")
    if rows is None:
        verify_probe(check, name=f"{cfg.user} admin user")


def _http_checks(cfg: HeisConfig) -> None:
    wait_port(cfg.app_port, host="127.0.0.1", retries=cfg.health_retries)
    # Production settings redirect plain HTTP to HTTPS (301).
    http_check(f"http://127.0.0.1:{cfg.app_port}/", status=(200, 301, 302), host_header=cfg.fqdn)


@deploy("Deploy heis")
def deploy_heis(cfg: HeisConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    secrets.require(cfg.required_secret_keys)
    env_content = render_env(cfg, secrets)
    route = traefik_config(cfg)

    # The role's prerequisites (``package: state=present``, no cache update);
    # fish must be there before the user gets it as login shell.
    apt.packages(name="Install heis prerequisites", packages=list(PACKAGES))
    system_user(
        cfg.user,
        group=cfg.group,
        home=cfg.home,
        shell="/usr/bin/fish",
        directories=[cfg.site_path, cfg.cache_dir],
    )
    # The role's ``file`` creates a missing ``~/.config`` as the service user
    # and never touches an existing one (live hosts have it ``heis:root``).
    if not host.get_fact(Directory, path=str(cfg.home / ".config")):
        files.directory(
            name=f"Ensure directory {cfg.home / '.config'}",
            path=str(cfg.home / ".config"),
            user=cfg.user,
            group=cfg.group,
            mode="0755",
        )
    fish_dir = cfg.home / ".config" / "fish"
    files.directory(
        name=f"Ensure directory {fish_dir}", path=str(fish_dir), user=cfg.user, group=cfg.group, mode="0755"
    )
    files.put(
        name="Write fish config",
        src=StringIO(render("user_config.fish.j2", cfg=cfg)),
        dest=str(cfg.home / ".config" / "fish" / "config.fish"),
        user=cfg.user,
        group=cfg.group,
        mode="0644",
    )

    code = sync_tree(
        name="Sync heis source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=cfg.source_excludes,
        # The role passes delete: false; stale files stay, host state is safe.
        delete=False,
        runner=rsync,
        user=cfg.user,
        group=cfg.group,
    )
    _site_owned(cfg)

    deps_check = _deps_probe(cfg)
    deps_state = probe(deps_check, name=f"{cfg.user} dependencies")
    deps = uv_sync(
        cfg.site_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        python=cfg.python_version,
        args=UV_SYNC_ARGS,
        # None: run whatever the source did, when the environment is not as locked.
        when_changed=[code] if deps_state == "current" else None,
    )
    if deps_state is None:
        verify_probe(deps_check, name=f"{cfg.user} dependencies", expect="current")
    files.link(
        name="Link venv to .venv",
        path=str(cfg.site_path / "venv"),
        target=str(cfg.venv_path),
        user=cfg.user,
        group=cfg.group,
    )

    env = secret_file(
        name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user, group=cfg.group
    )
    migrations_check = _migrations_probe(cfg)
    migrations = probe(migrations_check, name=f"{cfg.user} migrations")
    migrate = _manage(
        cfg,
        "Run heis migrations",
        ("migrate",),
        when_changed=[code, deps],
        force=migrations != "current",
    )
    if migrations is None:
        verify_probe(migrations_check, name=f"{cfg.user} migrations", expect="current")
    _reconcile_content(cfg, when_changed=[code, deps, migrate])
    _manage(
        cfg,
        "Collect static files",
        ("collectstatic", "--noinput"),
        when_changed=[code, deps],
        force=not _static_collected(cfg),
    )
    _ensure_superuser(cfg, secrets)

    launcher = files.put(
        name="Write gunicorn.sh",
        src=StringIO(render("gunicorn.sh.j2", cfg=cfg)),
        dest=str(cfg.site_path / "gunicorn.sh"),
        user=cfg.user,
        group=cfg.group,
        mode="0755",
    )
    unit = systemd_unit(cfg.user, render("heis.service.j2", cfg=cfg))
    service_rollout(cfg.user, units=[unit], restart_when=[code, deps, env, launcher])
    # The role never reloads Traefik: its file provider watches the directory.
    traefik_route(route, renderer=lambda _route, _hash: render_route(cfg), restart="none")

    _http_checks(cfg)
    # Last: only a deploy that came up healthy records its commit.
    record_source(cfg.site_path, cfg.source_commit, user=cfg.user, group=cfg.group)
