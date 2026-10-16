"""Typed configuration of one Django/Wagtail site (the parts, then :class:`DjangoSiteConfig`).

Everything specific to a site is a value here; the deploy code never branches
on the site's name. Values that come from the site's secrets file are
:class:`Secret` references, so the keys a site needs follow from its config
(:attr:`DjangoSiteConfig.required_secret_keys`) instead of a separate list.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.git_source import CommitSha
from ops_deploy.helpers.traefik import Hostname

# A Traefik rule; lands in double quotes in the route file.
TraefikRule = Annotated[str, Field(min_length=1, pattern=r'^[^"\\\r\n]+$')]
# Lands in single quotes in the route file.
RedirectPart = Annotated[str, Field(pattern=r"^[^'\r\n]*$")]
# Lands in a comment (route, unit) or a systemd ``Description=``: one plain line.
Label = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9 .,:;()/_+-]+$")]
EnvKey = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]*$")]
SecretKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
DottedName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*(:[A-Za-z_][A-Za-z0-9_]*)?$")]
ManageArg = Annotated[str, Field(min_length=1, pattern=r"^[A-Za-z0-9_.,:/=@+-]+$")]
# A relative directory inside the synced tree ("" is the tree itself).
RelDir = Annotated[str, Field(pattern=r"^([A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*)?$")]
# A marker file name (in the site's root-only state directory).
MarkerName = Annotated[str, Field(pattern=r"^\.ops-deploy-[a-z0-9-]+$")]

# The deploy's own files in the home directory (and the site): not step-group markers.
RESERVED_MARKERS = frozenset({".ops-deploy-pending", ".ops-deploy-admin", ".ops-deploy-source", ".ops-deploy-regroup"})
UNIT_PATTERN = r"^[a-z][a-z0-9-]{0,62}$"
# The keys django_site writes itself; ``env.extra`` may not repeat them.
BASE_ENV_KEYS = (
    "DJANGO_SETTINGS_MODULE",
    "DJANGO_SECRET_KEY",
    "DJANGO_ADMIN_URL",
    "DJANGO_ALLOWED_HOSTS",
    "DJANGO_CACHE_LOCATION",
)
DEFAULT_UV_ARGS = ("--frozen", "--no-dev")


def env_value_problem(value: str) -> str | None:
    r"""Why ``value`` cannot be one line ``KEY='value'`` of ``.env``, or ``None``.

    The file is read by ``sh`` (``set -a; . .env``), by systemd's
    ``EnvironmentFile=``, by django-environ's ``read_env`` and by
    python-dotenv. Inside single quotes ``sh`` and systemd take every
    character as it is but ``'`` and a line break. The other two need more:
    django-environ strips a second pair of double quotes and resolves a
    leading ``$`` as a reference to another variable; python-dotenv expands
    ``${NAME}`` and reads ``\\`` as one backslash (and a final ``\`` as an
    escaped quote). Such values are refused, so all four read the same value.
    """

    if "'" in value:
        return "contains a single quote"
    if any(c in value for c in "\r\n\0"):
        return "is not a single line"
    if value.startswith("$"):
        return "starts with $"
    if "${" in value:
        return "contains ${"
    if "\\\\" in value or value.endswith("\\"):
        return "contains a double backslash or ends with a backslash"
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return "is wrapped in double quotes"
    return None


def plain_path(value: PurePosixPath) -> PurePosixPath:
    """An absolute path below ``/`` that templates and shell lines can carry unquoted."""

    if not re.fullmatch(r"(/[A-Za-z0-9_.-]+)+", str(value)) or ".." in value.parts:
        raise ValueError("must be an absolute path of letters, digits and _ . -")
    return value


class Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Secret(Part):
    """A value taken from the site's secrets file by key."""

    secret: SecretKey


EnvValue = str | Secret


class EnvEntry(Part):
    key: EnvKey
    value: EnvValue


class SourceSpec(Part):
    """The tree synced to ``site_path`` and how."""

    path: Path
    # The commit ``path`` was checked out at (a git source), recorded on the
    # host; None: a local working tree, and the host's record is removed.
    commit: CommitSha | None = None
    excludes: tuple[str, ...] = ()
    # Remove files the source no longer has (host state must then be excluded).
    delete: bool = False
    # Files (relative to the app directory) a checkout of this site must have.
    required_files: tuple[str, ...] = ("manage.py", "pyproject.toml", "uv.lock")
    # Repair the owner of anything in the site tree that is not the service user's.
    repair_ownership: bool = True


class AppSpec(Part):
    app_dir: RelDir = ""
    settings_module: DottedName
    wsgi_app: DottedName = "config.wsgi"
    port: int = Field(ge=1024, le=65535)
    workers: int = Field(default=4, ge=1, le=64)
    timeout: int = Field(default=3600, ge=1)
    python: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}(\.[0-9]{1,2})?$")] | None = None
    uv_args: tuple[Annotated[str, Field(pattern=r"^--[a-z-]+$")], ...] = DEFAULT_UV_ARGS


class SqliteDb(Part):
    kind: Literal["sqlite"] = "sqlite"
    # Default: ``<app dir>/db.sqlite3``.
    path: PurePosixPath | None = None

    @field_validator("path")
    @classmethod
    def _plain(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        return None if value is None else plain_path(value)


class LocalMedia(Part):
    kind: Literal["local"] = "local"
    # Default: ``<app dir>/media``. Never synced or deleted by the deploy.
    root: PurePosixPath | None = None

    @field_validator("root")
    @classmethod
    def _plain(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        return None if value is None else plain_path(value)


class EnvSpec(Part):
    secret_key: Secret = Secret(secret="django_secret_key")
    admin_url: EnvValue | None = None
    # None: ``<fqdn>,localhost``.
    allowed_hosts: Annotated[str, Field(pattern=r"^[A-Za-z0-9.,:*\[\]-]+$")] | None = None
    extra: tuple[EnvEntry, ...] = ()


class ManageStep(Part):
    name: Label
    argv: tuple[ManageArg, ...] = Field(min_length=1)


Trigger = Literal["source", "deps", "migrate"]


class StepGroup(Part):
    """Management commands run as one group, in order.

    ``when="changes"`` runs the group when one of ``triggers`` happened in this
    run (the source or the dependencies changed, migrations ran);
    ``"always"`` on every deploy. With ``marker`` (a file in the service
    user's home) the group is marked pending before it runs and the marker is
    removed only after every step succeeded; while it is there, the next
    deploy runs the group again. ``after`` places the group right after the
    migrations or after ``collectstatic`` (the default).
    """

    name: Label
    steps: tuple[ManageStep, ...] = Field(min_length=1)
    when: Literal["changes", "always"] = "changes"
    triggers: frozenset[Trigger] = frozenset({"source", "deps", "migrate"})
    marker: MarkerName | None = None
    after: Literal["migrate", "collectstatic"] = "collectstatic"


class Steps(Part):
    collectstatic_args: tuple[ManageArg, ...] = ("--noinput",)
    # collectstatic also restarts the main unit (a manifest the process caches).
    restart_after_collectstatic: bool = False
    extra: tuple[StepGroup, ...] = ()


class EnsureSuperuser(Part):
    """The site's own idempotent ``manage.py <command>`` reading ``ADMIN_*`` from its environment."""

    kind: Literal["ensure"] = "ensure"
    command: ManageArg = "ensure_superuser"
    username: Secret = Secret(secret="admin_username")
    email: Secret = Secret(secret="admin_email")
    password: Secret = Secret(secret="admin_password")


class Route(Part):
    """``<unit>.traefik.yml``: HTTP and HTTPS routers for a public website."""

    fqdn: Hostname
    host_rule: TraefikRule
    # The HTTPS router's rule; None: ``host_rule``.
    tls_host_rule: TraefikRule | None = None
    cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")] = "letsencrypt"
    # Both set: a permanent redirect to the canonical host on the HTTPS router
    # (regex and replacement land in single quotes).
    canonical_redirect_regex: RedirectPart = ""
    canonical_redirect_replacement: RedirectPart = ""
    # Why this route has no Basic Auth (docs/TRAEFIK_SECURITY.md in the private repo).
    public_reason: Label

    @model_validator(mode="after")
    def _redirect_is_complete(self) -> Self:
        if bool(self.canonical_redirect_regex) != bool(self.canonical_redirect_replacement):
            raise ValueError("canonical_redirect_regex and canonical_redirect_replacement go together")
        return self


class Checks(Part):
    """Read-only checks after the rollout: the port opens, the site answers locally."""

    port_retries: int = Field(default=30, ge=1)
    path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9/_.-]*$")] = "/"
    # Production settings redirect plain HTTP to HTTPS.
    statuses: tuple[Annotated[int, Field(ge=100, le=599)], ...] = Field(default=(200, 301, 302), min_length=1)


class DjangoSiteConfig(BaseServiceConfig):
    service_name: ServiceName
    # systemd ``Description=<title> web application``.
    title: Label
    # The unit and the Traefik file; None: ``service_name``.
    unit: Annotated[str, Field(pattern=UNIT_PATTERN)] | None = None
    user: UnixUser
    group: UnixUser | None = None
    home: PurePosixPath
    site_path: PurePosixPath
    shell: Literal["/usr/bin/fish", "/bin/bash"] = "/bin/bash"
    # Debian packages the site needs on the host, installed first (no cache update).
    apt_packages: tuple[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.+-]+$")], ...] = ()
    # ``~/.config/fish/config.fish`` (venv on PATH, cd to the site) and the ``venv`` link.
    fish: bool = False
    source: SourceSpec
    app: AppSpec
    database: SqliteDb = SqliteDb()
    media: LocalMedia = LocalMedia()
    env: EnvSpec = EnvSpec()
    steps: Steps = Steps()
    admin: EnsureSuperuser | None = None
    route: Route
    checks: Checks = Checks()
    # The systemd sandboxing options (ProtectSystem=strict and friends).
    hardening: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        missing = [p for p in self.source.required_files if not (self.source.path / self.app.app_dir / p).exists()]
        if missing:
            raise ValueError(f"source.path is not a {self.service_name} checkout (missing {', '.join(missing)})")
        keys = [entry.key for entry in self.env.extra]
        repeated = sorted({k for k in keys if keys.count(k) > 1 or k in BASE_ENV_KEYS})
        if repeated:
            raise ValueError(f"env.extra repeats {', '.join(repeated)}")
        for key, value in self.env_entries_unresolved():
            problem = None if isinstance(value, Secret) else env_value_problem(value)
            if problem:
                raise ValueError(f"env value of {key} {problem}")
        markers = [g.marker for g in self.steps.extra if g.marker]
        if len(markers) != len(set(markers)):
            raise ValueError("steps.extra markers must differ")
        reserved = [m for m in markers if m in RESERVED_MARKERS or m.startswith(".ops-deploy-restart-")]
        if reserved:
            raise ValueError(f"steps.extra markers {', '.join(reserved)} are the deploy's own files")
        return self

    @field_validator("home", "site_path")
    @classmethod
    def _plain_paths(cls, value: PurePosixPath) -> PurePosixPath:
        return plain_path(value)

    # -- derived names and paths ------------------------------------------

    @property
    def unit_name(self) -> str:
        return self.unit or self.service_name.replace("_", "-")

    @property
    def group_name(self) -> str:
        return self.group or self.user

    @property
    def app_path(self) -> PurePosixPath:
        return self.site_path / self.app.app_dir if self.app.app_dir else self.site_path

    @property
    def venv_path(self) -> PurePosixPath:
        return self.app_path / ".venv"

    @property
    def venv_bin(self) -> PurePosixPath:
        return self.venv_path / "bin"

    @property
    def cache_dir(self) -> PurePosixPath:
        return self.app_path / "cache"

    @property
    def env_path(self) -> PurePosixPath:
        return self.app_path / ".env"

    @property
    def db_path(self) -> PurePosixPath:
        return self.database.path or self.app_path / "db.sqlite3"

    @property
    def media_root(self) -> PurePosixPath:
        return self.media.root or self.app_path / "media"

    @property
    def sync_excludes(self) -> tuple[str, ...]:
        """``source.excludes`` plus what the host writes inside the site, which no sync may touch.

        ``.env``, the cache, the collected static files, the SQLite database
        with everything SQLite keeps next to it (``-wal``, ``-shm``,
        ``-journal``: ``<db>*``) and the media, each anchored at the site root.
        rsync neither overwrites nor deletes an excluded path.
        """

        host_files = (self.env_path, self.cache_dir, self.app_path / "staticfiles", self.media_root)
        anchored = [f"/{p.relative_to(self.site_path)}" for p in host_files if p.is_relative_to(self.site_path)]
        if self.db_path.is_relative_to(self.site_path):
            anchored.append(f"/{self.db_path.relative_to(self.site_path)}*")
        return tuple(dict.fromkeys((*self.source.excludes, *anchored)))

    @property
    def allowed_hosts(self) -> str:
        return self.env.allowed_hosts or f"{self.route.fqdn},localhost"

    @property
    def required_secret_keys(self) -> tuple[str, ...]:  # type: ignore[override]
        """Every secret key the config refers to, in order of first use."""

        return tuple(dict.fromkeys(secret.secret for secret in _secrets(self)))

    def env_entries_unresolved(self) -> list[tuple[str, EnvValue]]:
        """``.env`` in file order, secrets still as references."""

        entries: list[tuple[str, EnvValue]] = [
            ("DJANGO_SETTINGS_MODULE", self.app.settings_module),
            ("DJANGO_SECRET_KEY", self.env.secret_key),
        ]
        if self.env.admin_url is not None:
            entries.append(("DJANGO_ADMIN_URL", self.env.admin_url))
        entries += [
            ("DJANGO_ALLOWED_HOSTS", self.allowed_hosts),
            ("DJANGO_CACHE_LOCATION", str(self.cache_dir)),
        ]
        entries += [(entry.key, entry.value) for entry in self.env.extra]
        return entries


def _secrets(value: Any) -> Iterator[Secret]:
    if isinstance(value, Secret):
        yield value
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from _secrets(getattr(value, name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _secrets(item)
