"""The split-site module that ran before django_site, kept as the reference for the equivalence test.

Vendored unchanged from its last version (an unmerged ops-deploy branch), with
made-up names in place of the site's: it is not part of the package and
nothing deploys with it. ``tests/test_django_site_split_equivalence.py`` runs
its scenarios through it and through django_site and compares them. It goes
with that test.

Its own description: a Django/Wagtail site plus a standalone Next.js server.
gunicorn serves Django/Wagtail on SQLite, a standalone Next.js build serves
the paths listed in ``next_path_prefixes``, and one Traefik route splits the
traffic between them. Persistent state lives in ``~/data``. Markers in the
site, written before the changes they stand for and removed when a run
completed, make the next run repeat what a failed one left undone.
"""

from __future__ import annotations

import shlex
from collections.abc import Iterable
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self

import jinja2
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, FileContents
from pyinfra.facts.server import Command
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.git_source import CommitSha
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import (
    TraefikRoute,
    http_check,
    mark_read_only,
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

TEMPLATE_PACKAGE = "tests.legacy_split_site"

# Never synced: build output and environments the host makes itself.
BASE_EXCLUDES = ("/.git", "node_modules", ".venv", ".next")
# Written into the site by the deploy; must survive the sync's ``--delete``.
DEPLOY_WRITTEN = ("/.env", "/gunicorn.sh", "/next.sh", "/cache", "/django/staticfiles")
EMAIL_BACKEND = "anymail.backends.mailgun.EmailBackend"
# Markers next to the synced tree (``sync_tree`` never touches ``.ops-deploy-*``).
# Each is written before the change it stands for and removed once a run
# completed, so a run that fails halfway leaves the work to the next one.
PENDING = ".ops-deploy-pending"  # source changed: every source step and both restarts
RESTART = ".ops-deploy-restart-{unit}"  # something the unit reads changed: restart it
STATIC = ".ops-deploy-collectstatic"  # dependencies changed: collect static files again
BUILD_STAMP = ".ops-deploy-next-build"
STANDALONE = "nextjs/.next/standalone/nextjs"
UV_SYNC_ARGS = ("--locked", "--no-dev")

UrlPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/%-]*$")]
# A route prefix: at least one segment, no trailing slash (``/cms``, not ``/cms/``).
PathPrefix = Annotated[str, Field(pattern=r"^(/[A-Za-z0-9_~%-][A-Za-z0-9._~%-]*)+$")]
# Path segments and grep/find arguments: no quotes, spaces or shell syntax, and
# never ``.`` or ``..`` (a segment may start with one dot, as ``.next`` does).
Name = Annotated[str, Field(pattern=r"^\.?[A-Za-z0-9_-][A-Za-z0-9._-]*$")]
FindPattern = Annotated[str, Field(pattern=r"^\.?[A-Za-z0-9_*-][A-Za-z0-9._*-]*(/\.?[A-Za-z0-9_*-][A-Za-z0-9._*-]*)*$")]
Token = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]

# ``createsuperuser`` probe (stdlib only): does the bootstrap account exist?
ADMIN_PROBE = """\
import sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
try:
    found = db.execute("select count(*) from auth_user where username = ?", (sys.argv[2],)).fetchone()[0]
except sqlite3.OperationalError as exc:
    # Not migrated yet: no accounts. Any other database error fails the probe.
    if "no such table" not in str(exc):
        raise
    found = 0
print("present" if found else "absent")
"""
# Creates or updates the bootstrap superuser from the environment, one line.
SET_BOOTSTRAP_PASSWORD = (
    "import os; from django.contrib.auth import get_user_model; U = get_user_model(); "
    "u, _ = U.objects.get_or_create(username=os.environ['BOOTSTRAP_ADMIN_USERNAME'], "
    "defaults={'email': os.environ['BOOTSTRAP_ADMIN_EMAIL'], 'is_staff': True, 'is_superuser': True}); "
    "u.is_staff = True; u.is_superuser = True; u.email = os.environ['BOOTSTRAP_ADMIN_EMAIL']; "
    "u.set_password(os.environ['BOOTSTRAP_ADMIN_PASSWORD']); u.save()"
)
# Moves a media directory into private storage without losing anything (see
# ``media_move_script``): check, copy what is missing, verify, then remove.
MEDIA_MOVE = """\
import filecmp, os, shutil, stat, sys
src, dst = sys.argv[1], sys.argv[2]
def walk():
    for root, dirs, files in os.walk(src):
        for name in dirs + files:
            yield os.path.relpath(os.path.join(root, name), src)
def kind(path):
    mode = os.lstat(path).st_mode
    return "dir" if stat.S_ISDIR(mode) else "file" if stat.S_ISREG(mode) else "other"
problems = []
for rel in walk():
    s, d = os.path.join(src, rel), os.path.join(dst, rel)
    if kind(s) == "other":
        problems.append(rel + ": not a regular file or directory")
    elif os.path.lexists(d) and (kind(d) != kind(s) or kind(s) == "file" and not filecmp.cmp(s, d, shallow=False)):
        problems.append(rel + ": differs from the private copy")
if os.path.lexists(dst) and kind(dst) != "dir":
    problems.append(dst + ": not a directory")
if problems:
    sys.exit("not moving " + src + ":\\n" + "\\n".join(problems))
os.makedirs(dst, exist_ok=True)
for rel in walk():
    s, d = os.path.join(src, rel), os.path.join(dst, rel)
    if kind(s) == "dir":
        os.makedirs(d, exist_ok=True)
    elif not os.path.lexists(d):
        shutil.copy2(s, d)
verified = []
for rel in walk():
    s, d = os.path.join(src, rel), os.path.join(dst, rel)
    if kind(s) != kind(d) or kind(s) == "file" and not filecmp.cmp(s, d, shallow=False):
        sys.exit("copy of " + rel + " does not match; " + src + " kept")
    verified.append(rel)
# Only what was verified goes; a file that appeared meanwhile keeps the source
# directory, so the next deploy moves it.
for rel in sorted(verified, key=lambda r: r.count(os.sep), reverse=True):
    s = os.path.join(src, rel)
    try:
        os.rmdir(s) if kind(s) == "dir" else os.remove(s)
    except OSError:
        pass
try:
    os.rmdir(src)
except OSError:
    pass
"""
# A POST with the session's CSRF token and the site's Origin must reach the
# view (400 for the empty body) instead of being refused (403). ``$base`` is
# the site, ``$path`` the session endpoint.
CSRF_CHECK = """\
set -e
jar=$(mktemp); body=$(mktemp); trap 'rm -f "$jar" "$body"' EXIT
session=$(curl -fsS -c "$jar" "$base$path")
token=$(printf '%s' "$session" | python3 -c 'import json, sys; print(json.load(sys.stdin)["csrfToken"])')
[ -n "$token" ] || { echo "No CSRF token from $base$path" >&2; exit 1; }
status=$(curl -sS -o "$body" -w '%{http_code}' -b "$jar" -H 'Content-Type: application/json' \
-H "Origin: $base" -H "X-CSRFToken: $token" --data '{}' "$base$path")
[ "$status" = 400 ] || { echo "Expected CSRF-accepted validation failure (400) for $base, got $status" >&2; exit 1; }
"""


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class UrlCheck(_Part):
    """One smoke check through Traefik, run with curl on the host for every public host."""

    path: UrlPath
    status: int = Field(default=200, ge=100, le=599)
    # Follow redirects (Ansible's ``uri`` default); off to check a redirect itself.
    follow: bool = True
    # Every string must occur in the body (fixed strings).
    contains: tuple[Annotated[str, Field(pattern=r"^[^'\\\r\n]+$")], ...] = ()
    retries: int = Field(default=1, ge=1)
    delay: int = Field(default=5, ge=0)


class LegacyGuard(_Part):
    """Code that must never be served: fails the deploy before any restart.

    ``tokens`` are searched in the standalone output and the app directories
    (``node_modules`` excluded), ``dirs`` are ``find -path`` patterns.
    """

    tokens: tuple[Token, ...] = ()
    dirs: tuple[FindPattern, ...] = ()
    search: tuple[FindPattern, ...] = ("nextjs/.next/standalone",)


class LegacySplitRoute(TraefikRoute):
    """The playbook writes ``<user>.traefik.yml``, not the helper's ``<name>.yml``."""

    @property
    def path(self) -> PurePosixPath:
        return DYNAMIC_DIR / f"{self.name}.traefik.yml"


class LegacySplitConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "django_secret_key",
        "bootstrap_admin_password",
        "django_admin_url_path",
        "wagtail_admin_url_path",
        "django_mailgun_api_key",
        "mailgun_api_url",
        "mailgun_sender_domain",
        "django_default_from_email",
        "django_server_email",
        "django_email_subject_prefix",
    )

    service_name: ServiceName = "splitsite"
    # Units, the Traefik file and the paths are named after the user.
    user: UnixUser = "splitsite"
    home: PurePosixPath = PurePosixPath("/home/splitsite")
    site_path: PurePosixPath = PurePosixPath("/home/splitsite/site")
    # The application tree (git source or checkout); synced as the site root.
    source_path: Path
    # The commit ``source_path`` was checked out at (a git source), recorded on
    # the host; None: a local working tree, and the host's record is removed.
    source_commit: CommitSha | None = None
    extra_source_excludes: tuple[str, ...] = ()
    fqdn: Hostname
    # None: ``Host(`<fqdn>`)``. Lands in double quotes.
    traefik_host_rule: Annotated[str, Field(min_length=1, pattern=r'^[^"\\\r\n]+$')] | None = None
    # Paths routed to Next.js (each as ``Path(p) || PathPrefix(p/)``), in this order.
    next_path_prefixes: Annotated[tuple[PathPrefix, ...], Field(min_length=1)] = ("/_next",)
    deploy_environment: Literal["staging", "production"] = "staging"
    django_port: int = Field(default=10025, ge=1024, le=65535)
    next_port: int = Field(default=10026, ge=1024, le=65535)
    gunicorn_workers: int = Field(default=3, ge=1, le=64)
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    # The secrets' Mailgun API URL must be exactly this one.
    mailgun_api_url: Annotated[str, Field(pattern=r"^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._/-]*)?$")]
    extra_django_allowed_hosts: tuple[Hostname, ...] = ()
    extra_django_csrf_trusted_origins: tuple[Annotated[str, Field(pattern=r"^https?://[A-Za-z0-9.:-]+$")], ...] = ()
    # Admin URL paths the secrets must not use: these, and anything under a
    # Next.js prefix or ``reserved_admin_url_paths``.
    refused_admin_url_paths: tuple[UrlPath, ...] = ()
    reserved_admin_url_paths: tuple[UrlPath, ...] = ()
    bootstrap_admin_username: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@+-]{1,150}$")] = "admin"
    bootstrap_admin_email: Annotated[str, Field(pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$")]
    # A file under ``nextjs/`` installed as ``nextjs/middleware.ts`` after each sync.
    middleware_from: Name | None = None
    # A management command that loads content shipped with the source.
    content_import_command: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")] | None = None
    # ``media/<name>`` directories moved into ``private_media/<name>`` once.
    private_media_moves: tuple[Name, ...] = ()
    # ``nextjs/public/<name>`` directories whose files are never served.
    purged_public_dirs: tuple[Name, ...] = ()
    legacy_guard: LegacyGuard = LegacyGuard()
    next_check_path: UrlPath = "/"
    csrf_check_path: UrlPath | None = None
    public_checks: tuple[UrlCheck, ...] = (UrlCheck(path="/"),)
    skip_public_smoke_checks: bool = False

    @field_validator("source_path")
    @classmethod
    def _source_has_both_apps(cls, value: Path) -> Path:
        needed = ("package.json", "package-lock.json", "django/manage.py", "django/pyproject.toml", "django/uv.lock")
        missing = [p for p in needed if not (value / p).is_file()]
        if missing:
            raise ValueError(f"source_path is not a Django plus Next.js tree (missing {', '.join(missing)})")
        return value

    @model_validator(mode="after")
    def _middleware_exists(self) -> Self:
        if self.middleware_from and not (self.source_path / "nextjs" / self.middleware_from).is_file():
            raise ValueError("middleware_from must name a file in the source's nextjs/ directory")
        return self

    @property
    def source_excludes(self) -> tuple[str, ...]:
        middleware = ("/nextjs/middleware.ts",) if self.middleware_from else ()
        # Never shipped, so the purge does not fight the sync.
        purged = tuple(f"/nextjs/public/{name}/***" for name in self.purged_public_dirs)
        return tuple(
            dict.fromkeys((*BASE_EXCLUDES, *self.extra_source_excludes, *DEPLOY_WRITTEN, *middleware, *purged))
        )

    @property
    def data_path(self) -> PurePosixPath:
        return self.home / "data"

    @property
    def media_root(self) -> PurePosixPath:
        return self.data_path / "media"

    @property
    def private_media_root(self) -> PurePosixPath:
        return self.data_path / "private_media"

    @property
    def sqlite_path(self) -> PurePosixPath:
        return self.data_path / "db.sqlite3"

    @property
    def bootstrap_marker(self) -> PurePosixPath:
        return self.data_path / ".bootstrap-admin-password-applied"

    @property
    def healthcheck_force_failure_file(self) -> PurePosixPath:
        return self.data_path / "healthcheck.force_fail"

    @property
    def cache_dir(self) -> PurePosixPath:
        return self.site_path / "cache"

    @property
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env"

    @property
    def django_path(self) -> PurePosixPath:
        return self.site_path / "django"

    @property
    def venv_path(self) -> PurePosixPath:
        return self.django_path / ".venv"

    @property
    def venv_bin(self) -> PurePosixPath:
        return self.venv_path / "bin"

    @property
    def django_unit(self) -> str:
        return f"{self.user}-django"

    @property
    def next_unit(self) -> str:
        return f"{self.user}-next"

    @property
    def django_url(self) -> str:
        return f"http://127.0.0.1:{self.django_port}"

    @property
    def host_rule(self) -> str:
        return self.traefik_host_rule or f"Host(`{self.fqdn}`)"

    @property
    def host_rule_grouped(self) -> str:
        """``host_rule`` for ``<rule> && (<paths>)``: parenthesized when it has ``||``."""

        return f"({self.host_rule})" if "||" in self.host_rule else self.host_rule

    @property
    def next_paths_rule(self) -> str:
        return " || ".join(f"Path(`{p}`) || PathPrefix(`{p}/`)" for p in self.next_path_prefixes)

    @property
    def public_hosts(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.fqdn, *self.extra_django_allowed_hosts)))

    @property
    def allowed_hosts(self) -> str:
        return ",".join(dict.fromkeys((self.fqdn, "localhost", "127.0.0.1", *self.extra_django_allowed_hosts)))

    @property
    def csrf_trusted_origins(self) -> str:
        return ",".join(dict.fromkeys((f"https://{self.fqdn}", *self.extra_django_csrf_trusted_origins)))

    @property
    def build_stamp(self) -> str:
        """The ``next build`` environment; a different one needs a rebuild (it bakes URLs in)."""

        return f"NODE_ENV=production WAGTAIL_BASE_URL={self.django_url} NEXT_PUBLIC_FQDN={self.fqdn}"


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


def _single_quoted(value: str) -> str:
    # ``'...'`` with ``'`` as ``'\''``: ``source`` reads the value literally.
    return "'" + value.replace("'", "'\\''") + "'"


def _normalized_path(value: str) -> str:
    return "/" + value.strip("/") + "/"


def check_secrets(cfg: LegacySplitConfig, secrets: SecretValues) -> None:
    """The playbook's asserts for protected deploys (all keys set: ``SecretValues.require``).

    Errors name keys only.
    """

    secrets.require(cfg.required_secret_keys)
    if any(c in value for value in secrets.values() for c in "\r\n"):
        raise ValueError("secret values must be single lines")
    if len(secrets["django_secret_key"]) < 50:
        raise ValueError("django_secret_key must have at least 50 characters")
    for key in ("bootstrap_admin_password", "django_mailgun_api_key"):
        if "CHANGEME" in secrets[key]:
            raise ValueError(f"{key} must not be a placeholder")
    if secrets["mailgun_api_url"] != cfg.mailgun_api_url:
        raise ValueError("mailgun_api_url must be the configured Mailgun relay URL")
    refused = {_normalized_path(p) for p in cfg.refused_admin_url_paths}
    reserved = tuple(_normalized_path(p) for p in (*cfg.next_path_prefixes, *cfg.reserved_admin_url_paths))
    paths: dict[str, str] = {}
    for key in ("django_admin_url_path", "wagtail_admin_url_path"):
        value = secrets[key]
        # Lands unescaped in WAGTAILADMIN_BASE_URL.
        if not value.strip("/") or not all(c.isascii() and (c.isalnum() or c in "._~/-") for c in value):
            raise ValueError(f"{key} must be a URL path (letters, digits and . _ ~ / -)")
        paths[key] = _normalized_path(value)
        if paths[key] in refused:
            raise ValueError(f"{key} must not be the default admin path")
        if paths[key].startswith(reserved):
            raise ValueError(f"{key} must not be under a reserved prefix")
    if paths["django_admin_url_path"] == paths["wagtail_admin_url_path"]:
        raise ValueError("django_admin_url_path and wagtail_admin_url_path must differ")


def render_env(cfg: LegacySplitConfig, secrets: SecretValues) -> SecretContent:
    check_secrets(cfg, secrets)
    return SecretContent(render("env.j2", cfg=cfg, s=secrets, q=_single_quoted, email_backend=EMAIL_BACKEND))


def render_route(cfg: LegacySplitConfig) -> str:
    return render("traefik.yml.j2", cfg=cfg)


def code_lines(lines: Iterable[str]) -> list[str]:
    """``lines`` without comment and blank lines (the shebang counts as code)."""

    return [line for line in lines if line.strip() and (line.startswith("#!") or not line.lstrip().startswith("#"))]


def _fact(command: str) -> str:
    return str(host.get_fact(Command, command=command) or "").strip()


def _as_service_user(cfg: LegacySplitConfig, script: str, cwd: PurePosixPath) -> str:
    """``script`` run by ``sh`` in ``cwd`` as the service user."""

    return f"cd {shlex.quote(str(cwd))} && {_as_user(cfg.user, cfg.home, {}, ['sh', '-c', script])}"


_READ_ENV = 'while IFS= read -r line && [ -n "$line" ]; do export "$line"; done'


def _stdin_env(env: dict[str, str]) -> SecretContent:
    # One ``KEY=value`` per line; read back with ``export "$line"`` (no expansion).
    return SecretContent("".join(f"{key}={value}\n" for key, value in env.items()))


def _manage_script(cfg: LegacySplitConfig, *command: str, stdin_env: bool = False, then: str = "") -> str:
    """``manage.py <command>`` with ``.env`` loaded (the playbook passes the same values as environment)."""

    lines = ["set -a", f". {shlex.quote(str(cfg.env_path))}", "set +a"]
    if stdin_env:
        lines.append(_READ_ENV)
    run = shlex.join([str(cfg.venv_bin / "python"), "manage.py", *command])
    lines.append(f"{run} && {then}" if then else f"exec {run}")
    return "; ".join(lines)


def _manage(
    cfg: LegacySplitConfig,
    name: str,
    *command: str,
    when_changed: list[OperationMeta],
    force: bool = False,
    restart: str = "",
) -> OperationMeta:
    """``manage.py <command>``; with ``restart`` the unit's restart marker is written first."""

    shell = _as_service_user(cfg, _manage_script(cfg, *command), cfg.django_path)
    return server.shell(
        name=name,
        commands=[f"touch {_marker(cfg, restart)} && {shell}" if restart else shell],
        _if=lambda: force or any(meta.did_change() for meta in when_changed),
    )


def _mark(cfg: LegacySplitConfig, name: str, unit: str, left: bool, changes: list[OperationMeta]) -> OperationMeta:
    """Write a marker when one is left over or one of ``changes`` (filled in later) will change."""

    return server.shell(
        name=name,
        commands=[f"touch {_marker(cfg, unit)}"],
        _if=lambda: left or any(op.will_change for op in changes),
    )


def _marker(cfg: LegacySplitConfig, unit: str = "") -> str:
    name = RESTART.format(unit=unit) if unit else PENDING
    return shlex.quote(str(cfg.site_path / name))


def _deps_probe(cfg: LegacySplitConfig) -> str:
    """``uv sync --dry-run`` (read-only) finds nothing to install, remove or recreate."""

    argv = [str(DEFAULT_UV), "sync", *UV_SYNC_ARGS, "--dry-run"]
    env = {"UV_PROJECT_ENVIRONMENT": str(cfg.venv_path)}
    sync = f"cd {shlex.quote(str(cfg.django_path))} && {_as_user(cfg.user, cfg.home, env, argv)}"
    check = (
        f"out=$( {sync} 2>&1 ) || {{ printf '%s\\n' \"$out\" >&2; exit 1; }}; "
        "if printf '%s\\n' \"$out\" | grep -qx 'Would make no changes'; then echo current; else echo pending; fi"
    )
    return when_present([cfg.django_path / "uv.lock"], check, otherwise="pending")


def _migrations_probe(cfg: LegacySplitConfig) -> str:
    """``migrate --check`` (read-only), only against an existing database (Django would create one)."""

    plan = _as_service_user(cfg, _manage_script(cfg, "migrate", "--check", "--plan"), cfg.django_path)
    needed = (cfg.sqlite_path, cfg.env_path, cfg.venv_bin / "python")
    return when_present(needed, migrations_state(plan), otherwise="pending")


def _admin_probe(cfg: LegacySplitConfig) -> str:
    argv = shlex.join(["python3", "-I", "-c", ADMIN_PROBE, str(cfg.sqlite_path), cfg.bootstrap_admin_username])
    return when_present([cfg.sqlite_path], argv, otherwise="absent")


def _bootstrap_admin(cfg: LegacySplitConfig, secrets: SecretValues) -> None:
    """The playbook's ``createsuperuser`` and first-deploy password, only when they have work.

    ``createsuperuser`` runs when the account is missing (the playbook runs it
    on every deploy and ignores "already exists"). The password is set once,
    recorded by a marker in ``~/data``; a password changed in the admin stays.
    Name and email are config, the password reaches the host only on stdin.
    """

    check = _admin_probe(cfg)
    state = probe(check, name=f"{cfg.user} bootstrap admin")
    if state != "present":
        args = ("createsuperuser", "--noinput", "--username", cfg.bootstrap_admin_username)
        secret_stdin(
            name="Create the bootstrap admin",
            command=_as_service_user(
                cfg,
                _manage_script(cfg, *args, "--email", cfg.bootstrap_admin_email, stdin_env=True),
                cfg.django_path,
            ),
            content=_stdin_env({"DJANGO_SUPERUSER_PASSWORD": secrets["bootstrap_admin_password"]}),
        )
        if state is None:
            verify_probe(check, name=f"{cfg.user} bootstrap admin", expect="present")
    marker = shlex.quote(str(cfg.bootstrap_marker))
    if _fact(f"test -e {marker} && echo present || true") != "present":
        secret_stdin(
            name="Set the bootstrap admin password (first deploy only)",
            command=_as_service_user(
                cfg,
                _manage_script(cfg, "shell", "-c", SET_BOOTSTRAP_PASSWORD, stdin_env=True, then=f"touch {marker}"),
                cfg.django_path,
            ),
            content=_stdin_env(
                {
                    "BOOTSTRAP_ADMIN_USERNAME": cfg.bootstrap_admin_username,
                    "BOOTSTRAP_ADMIN_EMAIL": cfg.bootstrap_admin_email,
                    "BOOTSTRAP_ADMIN_PASSWORD": secrets["bootstrap_admin_password"],
                }
            ),
        )


def _private_media_moves(cfg: LegacySplitConfig) -> None:
    """Move ``media/<name>`` (served as is) into ``private_media/<name>`` once, when pending.

    Both units are stopped while files move (uploads must not land in a file
    being moved) and started again if they ran, also when the move fails.
    """

    units = (f"{cfg.next_unit}.service", f"{cfg.django_unit}.service")
    for name in cfg.private_media_moves:
        src = shlex.quote(str(cfg.media_root / name))
        marker = shlex.quote(str(cfg.private_media_root / f".legacy-{name}-migrated"))
        if _fact(f"if [ -d {src} ] || [ ! -f {marker} ]; then echo pending; fi") != "pending":
            continue
        script = media_move_script(str(cfg.media_root / name), str(cfg.private_media_root / name), marker)
        move = _as_service_user(cfg, script, cfg.home)
        quiet = quiesced_script(units, move)
        server.shell(name=f"Move media/{name} into private storage", commands=[quiet])


def quiesced_script(units: Iterable[str], command: str) -> str:
    """Run ``command`` with ``units`` stopped; start the ones that ran (or were starting) again.

    A failed ``stop`` runs nothing. The script exits with ``command``'s status.
    """

    names = " ".join(units)
    return (
        # Running, starting or waiting to restart: start it again afterwards.
        f"running=$(for u in {names}; do case $(systemctl is-active $u) in "
        "(active|activating|reloading) echo $u ;; esac; done); "
        # Only units that do not exist (a first deploy) are left out; masked or
        # broken ones that may still run are stopped like any other.
        f"loaded=$(for u in {names}; do case $(systemctl show -p LoadState --value $u) in "
        "(not-found) ;; (*) echo $u ;; esac; done); "
        # ``stop`` also cancels a pending automatic restart.
        'if [ -n "$loaded" ] && ! systemctl stop $loaded; then [ -z "$running" ] || systemctl start $running; '
        "echo 'could not stop the units; nothing moved' >&2; exit 1; fi; "
        f"rc=0; ( {command} ) || rc=$?; "
        # A unit that ran and cannot start again (masked meanwhile, say) fails the step.
        'if [ -n "$running" ] && ! systemctl start $running; then '
        "echo 'could not start the units again' >&2; [ $rc -ne 0 ] || rc=1; fi; exit $rc"
    )


def media_move_script(src: str, dst: str, marker: str) -> str:
    """Move ``src`` into ``dst`` (both directories), then write ``marker``.

    Files already in ``dst`` stay. Everything is checked before anything is
    copied or removed: only directories and regular files (no symlinks) in
    ``src``, and a path in both must be a regular file with the same content
    in ``dst``; otherwise the move fails and ``src`` stays as it is. Only
    verified copies are removed from ``src``; the marker is written once
    ``src`` is gone (a file written meanwhile waits for the next deploy).
    """

    argv = shlex.join(["python3", "-I", "-c", MEDIA_MOVE, src, dst])
    return (
        f"set -eu; if [ -d {shlex.quote(src)} ]; then {argv}; "
        f"if [ ! -d {shlex.quote(src)} ]; then date -u +%FT%TZ > {marker}; fi; "
        f"elif [ ! -f {marker} ]; then date -u +%FT%TZ > {marker}; fi"
    )


def _build_next(cfg: LegacySplitConfig, source: OperationMeta) -> OperationMeta:
    """``npm ci`` and ``next build`` (standalone) when the source or the build environment changed.

    The stamp records the build environment of the last complete build; it is
    removed first, so a build that fails runs again on the next deploy. The
    Next.js restart marker is written before anything else.
    """

    site = shlex.quote(str(cfg.site_path))
    current = _fact(
        f"cat {site}/{BUILD_STAMP} 2>/dev/null; test -f {site}/{STANDALONE}/server.js && echo built || true"
    )
    stale = current != f"{cfg.build_stamp}\nbuilt"
    env = shlex.join(["env", *cfg.build_stamp.split()])
    script = "; ".join(
        [
            "set -e",
            f"rm -f {BUILD_STAMP}",
            "npm ci --no-audit --no-fund",
            f"{env} npm run build",
            # ``next build`` leaves these out of the standalone output.
            f"[ -e {STANDALONE}/.next/static ] || cp -r nextjs/.next/static {STANDALONE}/.next/static",
            f"[ -e {STANDALONE}/public ] || cp -r nextjs/public {STANDALONE}/public",
            f"echo {shlex.quote(cfg.build_stamp)} > {BUILD_STAMP}",
        ]
    )
    return server.shell(
        name="Build the Next.js app (npm ci, next build)",
        commands=[f"touch {_marker(cfg, cfg.next_unit)} && {_as_service_user(cfg, script, cfg.site_path)}"],
        _if=lambda: stale or source.did_change(),
    )


def _purge_public_dirs(cfg: LegacySplitConfig, *, after: list[OperationMeta]) -> None:
    """Files in ``purged_public_dirs`` are never served: removed when present, then checked (read-only).

    The removal also runs when one of ``after`` (the sync, the build) changed:
    they may bring such files that no fact saw while planning.
    """

    dirs = [d for name in cfg.purged_public_dirs for d in (f"nextjs/public/{name}", f"{STANDALONE}/public/{name}")]
    if not dirs:
        return
    find = purge_script(dirs, "-print -quit")
    site = shlex.quote(str(cfg.site_path))
    # Nothing synced yet on a new host: nothing to remove.
    found = bool(_fact(f"if cd {site} 2>/dev/null; then {find}; fi"))
    delete = purge_script(dirs, "-delete")
    server.shell(
        name="Remove purged public files",
        commands=[_as_service_user(cfg, delete, cfg.site_path)],
        _if=lambda: found or any(op.did_change() for op in after),
    )
    check = f'cd {site} && out=$( {find} ); [ -z "$out" ] || {{ echo "purged files still served: $out" >&2; exit 1; }}'
    mark_read_only(server.shell(name="Check purged public files are absent", commands=[check]))


def purge_script(dirs: Iterable[str], action: str) -> str:
    """``find <dir> <symlinks and files but a regular .gitkeep> <action>`` for each of ``dirs`` that exists.

    Symlinks count, a symlinked ``dir`` itself included: ``find`` does not
    follow it, so a link to private files is removed instead of served.
    """

    return "; ".join(
        f"if [ -e {d} ] || [ -L {d} ]; then find {d} \\( -type l -o -type f ! -name .gitkeep \\) {action}; fi"
        for d in dirs
    )


def legacy_guard_script(guard: LegacyGuard) -> str:
    """Fails when a ``guard.tokens`` string or a ``guard.dirs`` directory is in the served code."""

    lines = []
    if guard.tokens:
        grep = " ".join(f"-e {t}" for t in guard.tokens)
        targets = " ".join(guard.search)
        include = " ".join(f"--include='*.{ext}'" for ext in ("js", "ts", "tsx", "mjs", "cjs"))
        lines.append(f"tokens=$(grep -rInF --exclude-dir=node_modules {grep} {targets} {include} 2>/dev/null || true)")
    else:
        lines.append("tokens=")
    if guard.dirs:
        paths = " -o ".join(f"-path '{d}'" for d in guard.dirs)
        roots = " ".join(guard.search)
        prune = "-name node_modules -prune -o"
        lines.append(f"dirs=$(find {roots} {prune} -type d \\( {paths} \\) -print 2>/dev/null || true)")
    else:
        lines.append("dirs=")
    lines.append(
        'if [ -n "$tokens" ] || [ -n "$dirs" ]; then echo "Legacy code found in the served tree" >&2; '
        '[ -z "$tokens" ] || echo "$tokens" >&2; [ -z "$dirs" ] || echo "Directories: $dirs" >&2; exit 1; fi'
    )
    return "\n".join(lines) + "\n"


def url_check_script(url: str, check: UrlCheck) -> str:
    """curl ``url`` until it answers ``check.status`` (and its body has ``check.contains``)."""

    curl = ["curl", "-sS", "-o", '"$body"', "-w", "'%{http_code}'", "--max-time", "10"]
    if check.follow:
        curl.append("-L")
    contains = "".join(f' && grep -qF -e {shlex.quote(s)} "$body"' for s in check.contains)
    expected = f"{check.status} with the expected content" if check.contains else str(check.status)
    return (
        "body=$(mktemp); trap 'rm -f \"$body\"' EXIT; "
        f"for i in $(seq 1 {check.retries}); do "
        # A transfer curl did not complete (timeout, truncation) never counts.
        f"if code=$({' '.join(curl)} {shlex.quote(url)} 2>/dev/null) && "
        f'[ "$code" = {check.status} ]{contains}; then exit 0; fi; sleep {check.delay}; done; '
        f'echo "{url} answered ${{code:-nothing}}, expected {expected}" >&2; exit 1'
    )


def _public_checks(cfg: LegacySplitConfig) -> None:
    """The playbook's smoke checks through Traefik, from the host, for every public host."""

    for name in cfg.public_hosts:
        base = f"https://{name}"
        for check in cfg.public_checks:
            url = f"{base}{check.path}"
            script = url_check_script(url, check)
            mark_read_only(server.shell(name=f"Check {url}", commands=[f"sh -c {shlex.quote(script)}"]))
        if cfg.csrf_check_path:
            csrf = f"base={shlex.quote(base)}; path={shlex.quote(cfg.csrf_check_path)}; {CSRF_CHECK}"
            mark_read_only(server.shell(name=f"Check the CSRF origin of {base}", commands=[csrf]))


@deploy("Deploy splitsite")
def deploy_legacy_split_site(
    cfg: LegacySplitConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    env_content = render_env(cfg, secrets)
    site = shlex.quote(str(cfg.site_path))

    # Node.js and uv are host-level; the host's own deploys install them.
    mark_read_only(
        server.shell(
            name="Require Node.js and uv",
            commands=[
                f"test -x /usr/bin/node && test -x {DEFAULT_UV} || "
                "{ echo 'this deploy needs /usr/bin/node and /usr/local/bin/uv' >&2; exit 1; }"
            ],
        )
    )
    system_user(cfg.user, home=cfg.home, shell="/usr/bin/fish", directories=[cfg.site_path])
    for path in (cfg.data_path, cfg.media_root, cfg.private_media_root):
        files.directory(name=f"Ensure directory {path}", path=str(path), user=cfg.user, group=cfg.user, mode="0750")
    _private_media_moves(cfg)

    # Markers left by an earlier run that stopped before its end.
    left = _fact(
        f"cd {site} 2>/dev/null && ls -1A | grep -x -e {PENDING} -e {STATIC} -e '.ops-deploy-restart-.*' || true"
    ).split()
    # Written before the changes they stand for: the operations are filled in
    # below, and ``will_change`` is known once planning is done.
    source_changes: list[OperationMeta] = []
    source = _mark(cfg, "Mark the source change pending", "", PENDING in left, source_changes)
    reads: dict[str, list[OperationMeta]] = {cfg.django_unit: [], cfg.next_unit: []}
    restart_marks = {
        unit: _mark(cfg, f"Mark {unit} for a restart", unit, RESTART.format(unit=unit) in left, reads[unit])
        for unit in reads
    }
    code = sync_tree(
        name="Sync the source",
        src=cfg.source_path,
        dest=cfg.site_path,
        excludes=cfg.source_excludes,
        delete=True,
        runner=rsync,
        user=cfg.user,
        group=cfg.user,
    )
    source_changes.append(code)
    if cfg.middleware_from:
        source_changes.append(
            files.put(
                name=f"Install nextjs/{cfg.middleware_from} as nextjs/middleware.ts",
                src=str(cfg.source_path / "nextjs" / cfg.middleware_from),
                dest=str(cfg.site_path / "nextjs" / "middleware.ts"),
                user=cfg.user,
                group=cfg.user,
                mode="0644",
            )
        )

    env = secret_file(name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user)
    config_dir = cfg.home / ".config"
    # Owner only, like the playbook's ``file``: the group stays root.
    if not host.get_fact(Directory, path=str(config_dir)):
        files.directory(name=f"Ensure directory {config_dir}", path=str(config_dir), user=cfg.user)
    files.directory(name=f"Ensure directory {config_dir / 'fish'}", path=str(config_dir / "fish"), user=cfg.user)
    files.put(
        name="Write fish config",
        src=StringIO(render("user_config.fish.j2", cfg=cfg)),
        dest=str(config_dir / "fish" / "config.fish"),
        user=cfg.user,
        mode="0644",
    )

    deps_check = _deps_probe(cfg)
    deps_state = probe(deps_check, name=f"{cfg.user} dependencies")
    venv = shlex.quote(str(cfg.venv_bin / "python"))
    venv_missing = _fact(f"test -x {venv} && echo present || true") != "present"
    # uv_sync's own gate, so the markers precede the sync. New packages may
    # bring new static files: collectstatic is owed until a run completes.
    deps_mark = server.shell(
        name=f"Mark {cfg.django_unit} for a restart and collectstatic (dependencies)",
        commands=[f"touch {_marker(cfg, cfg.django_unit)} {shlex.quote(str(cfg.site_path / STATIC))}"],
        _if=lambda: deps_state != "current" or venv_missing or source.did_change(),
    )
    deps = uv_sync(
        cfg.django_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        args=UV_SYNC_ARGS,
        when_changed=[source] if deps_state == "current" else None,
    )
    if deps_state is None:
        verify_probe(deps_check, name=f"{cfg.user} dependencies", expect="current")
    gunicorn = files.put(
        name="Write gunicorn.sh",
        src=StringIO(render("gunicorn.sh.j2", cfg=cfg)),
        dest=str(cfg.site_path / "gunicorn.sh"),
        user=cfg.user,
        mode="0755",
    )
    files.directory(name=f"Ensure directory {cfg.cache_dir}", path=str(cfg.cache_dir), user=cfg.user)

    migrations_check = _migrations_probe(cfg)
    migrations = probe(migrations_check, name=f"{cfg.user} migrations")
    _manage(cfg, "Run migrations", "migrate", "--noinput", when_changed=[source, deps], force=migrations != "current")
    if migrations is None:
        verify_probe(migrations_check, name=f"{cfg.user} migrations", expect="current")
    manifest = shlex.quote(str(cfg.django_path / "staticfiles" / "staticfiles.json"))
    static = _manage(
        cfg,
        "Collect static files",
        "collectstatic",
        "--noinput",
        "--clear",
        when_changed=[source, deps],
        force=STATIC in left or _fact(f"test -f {manifest} && echo present || true") != "present",
        restart=cfg.django_unit,
    )
    if cfg.content_import_command:
        # Converges the content to what the source ships; the playbook runs it on every deploy.
        _manage(cfg, "Import content", cfg.content_import_command, when_changed=[source])
    _bootstrap_admin(cfg, secrets)

    build = _build_next(cfg, source)
    _purge_public_dirs(cfg, after=[source, build])
    if cfg.legacy_guard.tokens or cfg.legacy_guard.dirs:
        mark_read_only(
            server.shell(
                name="Check no legacy code is served",
                commands=[f"cd {site} && {legacy_guard_script(cfg.legacy_guard)}"],
            )
        )
    next_sh_path = cfg.site_path / "next.sh"
    next_sh_text = render("next.sh.j2", cfg=cfg)
    next_sh = files.put(
        name="Write next.sh", src=StringIO(next_sh_text), dest=str(next_sh_path), user=cfg.user, mode="0755"
    )
    # A launcher that differs only in comments is rewritten without a restart.
    deployed = host.get_fact(FileContents, path=str(next_sh_path))
    launcher_changed = deployed is None or code_lines(deployed) != code_lines(next_sh_text.splitlines())

    # Traefik's file provider watches the directory: no reload, like the playbook.
    route = LegacySplitRoute(name=cfg.user, host=cfg.fqdn, app_port=cfg.django_port)
    traefik_route(route, renderer=lambda _route, _hash: render_route(cfg), restart="none")
    django_unit = systemd_unit(cfg.django_unit, render("django.service.j2", cfg=cfg))
    next_unit = systemd_unit(cfg.next_unit, render("next.service.j2", cfg=cfg))
    reads[cfg.django_unit] += [env, gunicorn, django_unit]
    reads[cfg.next_unit] += [next_unit, *([next_sh] if launcher_changed else [])]
    marks = [source, deps_mark, static, build, *restart_marks.values()]
    # A restart marker also reloads systemd: the unit file may be what an
    # earlier run installed and never loaded.
    service_rollout(
        cfg.django_unit,
        units=[django_unit, restart_marks[cfg.django_unit]],
        restart_when=[source, deps_mark, static],
    )
    service_rollout(cfg.next_unit, units=[next_unit, restart_marks[cfg.next_unit]], restart_when=[build])

    wait_port(cfg.django_port, retries=30)
    # Production settings redirect plain HTTP to HTTPS.
    http_check(f"{cfg.django_url}/", status=(200, 301, 302), retries=6, delay=5)
    wait_port(cfg.next_port, retries=30)
    http_check(
        f"http://127.0.0.1:{cfg.next_port}{cfg.next_check_path}", status=(200, 301, 302, 307), retries=6, delay=5
    )
    if not cfg.skip_public_smoke_checks:
        _public_checks(cfg)
    # Everything is in place and answering: record the commit, clear the markers.
    record_source(cfg.site_path, cfg.source_commit, user=cfg.user, group=cfg.user)
    server.shell(
        name="Clear the pending markers",
        commands=[
            f"cd {site} && rm -f {PENDING} {STATIC} {RESTART.format(unit=cfg.django_unit)} "
            f"{RESTART.format(unit=cfg.next_unit)}"
        ],
        _if=lambda: any(op.did_change() for op in marks),
    )
