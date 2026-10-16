"""nyxmon: Django dashboard (``nyxmon``) plus monitoring agent (``nyxmon-monitor``).

Port of the ``nyxmon_deploy`` Ansible role, rsync method only. The files it
writes are byte-identical to the role's (``tests/test_nyxmon_parity.py``), so
Ansible and ops-deploy can take turns on one host without churn. The SQLite
database and the other host-side state in the site directory survive every
sync (``persistent_excludes``).
"""

from __future__ import annotations

import re
import shlex
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import (
    BasicAuth,
    TraefikRoute,
    django_manage,
    http_check,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    uv_sync,
    wait_port,
)
from ops_deploy.helpers.probes import probe, when_present
from ops_deploy.helpers.traefik import _MIDDLEWARE, DEFAULT_INTERNAL_IP_RANGES, Hostname
from ops_deploy.ops import secret_file, sync_tree
from ops_deploy.services.nyxmon.agent import check_agent, install_agent, prune_agents, select_agent

TEMPLATE_PACKAGE = "ops_deploy.services.nyxmon"

Count = Annotated[int, Field(ge=1, le=100)]
Interval = Annotated[int, Field(ge=60, le=2592000)]
# No whitespace, quotes, ``$``, backticks or backslashes: rendered unquoted into .env.
Url = Annotated[str, Field(pattern=r"^(https?://[^\s'\"$`\\]+)?$")]

# Source directories synced next to the Django tree, and single files copied from the source root.
EXTRA_DIRS = ("src/nyxmon", "src/nyxboard")
SOURCE_FILES = ("pyproject.toml", "uv.lock", "README.md")
SQLITE_PRIVACY = "[Service]\nUMask=0077\n"
# The role's nyxmon_agent_rust_release_url, with {version} for the version.
RELEASE_URL = (
    "https://github.com/ephes/nyxmon/releases/download/agent-rs-v{version}/"
    "nyxmon-agent-{version}-x86_64-unknown-linux-gnu.tar.gz"
)
# Development values the role refuses (CHANGEME is refused everywhere).
PLACEHOLDERS = {
    "django_secret_key": "development-secret-key-change-in-production",
    "telegram_bot_token": "development-token",
    "telegram_chat_id": "-1001234567890",
}


class NyxmonConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "django_secret_key",
        "telegram_bot_token",
        "telegram_chat_id",
        "basic_auth_password",
    )

    service_name: ServiceName = "nyxmon"
    monitor_service_name: ServiceName = "nyxmon-monitor"
    user: UnixUser = "nyxmon"
    site_path: PurePosixPath = PurePosixPath("/home/nyxmon/site")
    # A nyxmon checkout; src/django/ becomes the site root.
    source_path: Path
    # Never shipped (the role's nyxmon_rsync_excludes minus host state).
    source_excludes: tuple[str, ...] = (
        ".vault_password",
        "*.pyc",
        ".pytest_cache",
        ".coverage",
        "htmlcov",
        ".tox",
        ".mypy_cache",
        "node_modules",
    )
    # Host-side state in the site tree that --delete must never remove: the
    # database and its sidecars, cache, rendered env files, media and static
    # files, and the site-root files this deploy writes after the sync.
    persistent_excludes: tuple[str, ...] = (
        "cache",
        ".env*",
        "db.sqlite3*",
        "*.sqlite3",
        "media/",
        "staticfiles/",
        "/src/",
        "/venv",
        "/.env.shell",
        *(f"/{name}" for name in SOURCE_FILES),
    )
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.13"
    app_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    app_port: int = Field(default=10017, ge=1024, le=65535)
    workers: int = Field(default=4, ge=1, le=64)
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    django_allowed_hosts: Annotated[str, Field(pattern=r"^[A-Za-z0-9.,:*\[\]-]+$")] = "127.0.0.1"
    django_admin_url: Annotated[str, Field(pattern=r"^[A-Za-z0-9_/-]+$")] = "admin/"
    django_debug: bool = False
    require_login: bool = False
    notify_consecutive_failures: Count = 2
    notify_repeat_interval_seconds: Interval = 21600
    notify_warning_repeat_interval_seconds: Interval = 86400
    processing_lease_seconds: int = Field(default=900, ge=30)
    check_batch_size: Count = 5
    # The role's nyxmon_agent_impl and nyxmon_agent_rust_*: which agent
    # nyxmon-monitor runs, and the pinned Rust release installed (with either
    # implementation) below the install root. Empty version: nothing installed.
    agent_impl: Literal["python", "rust"] = "python"
    agent_rust_version: Annotated[str, Field(pattern=r"^([0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?)?$")] = ""
    # sha256 of the release archive; required with a version unless a local archive is set.
    agent_rust_sha256: Annotated[str, Field(pattern=r"^([0-9a-f]{64})?$")] = ""
    agent_rust_release_url: str = RELEASE_URL
    # A controller-side archive with the release layout replaces the download.
    agent_rust_local_archive: Path | None = None
    agent_rust_install_root: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/+-]*[A-Za-z0-9._+-]$")] = "/opt/nyxmon-agent"
    agent_rust_keep_versions: Annotated[int, Field(ge=1)] = 3
    # Empty disables the OpsGate producer; otherwise the secret opsgate_submit_token is required.
    opsgate_submit_base_url: Url = ""
    opsgate_approval_base_url: Url = ""  # empty: same as the submit URL
    opsgate_ticket_expires_seconds: int = Field(default=14400, ge=0)
    opsgate_submit_timeout_seconds: int = Field(default=10, ge=0)
    opsgate_submit_include_warnings: bool = False
    traefik_host: Hostname = "nyxmon.example.com"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    traefik_middlewares: tuple[Annotated[str, Field(pattern=_MIDDLEWARE)], ...] = ()
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"

    @field_validator("source_path")
    @classmethod
    def _source_is_a_nyxmon_checkout(cls, value: Path) -> Path:
        missing = [p for p in ("src/django", *EXTRA_DIRS, *SOURCE_FILES) if not (value / p).exists()]
        if missing:
            raise ValueError(f"source_path is not a nyxmon checkout (missing {', '.join(missing)})")
        return value

    @field_validator("agent_rust_release_url")
    @classmethod
    def _release_url_takes_the_version(cls, value: str) -> str:
        try:
            url = value.format(version="0.0.0")
        except (IndexError, KeyError, ValueError):
            raise ValueError("agent_rust_release_url may hold no placeholder but {version}") from None
        if not re.fullmatch(r"https?://[^\s'\"$`\\{}]+", url):
            raise ValueError("agent_rust_release_url must be an http(s) URL without whitespace, quotes, $, ` or \\")
        return value

    @field_validator("agent_rust_keep_versions", mode="before")
    @classmethod
    def _keep_versions_is_a_whole_number(cls, value: object) -> object:
        # The role refuses booleans and anything but digits; pydantic would take True or 1.0 as 1.
        if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
            raise ValueError("agent_rust_keep_versions must be a whole number")
        return value

    @model_validator(mode="after")
    def _lease_covers_a_batch(self) -> Self:
        if self.processing_lease_seconds < (self.check_batch_size + 5) * 60:
            raise ValueError("processing_lease_seconds must be at least five minutes plus one per claimed check")
        return self

    @model_validator(mode="after")
    def _agent_settings(self) -> Self:
        """The role's "Validate monitoring agent implementation settings"."""

        version, local = self.agent_rust_version, self.agent_rust_local_archive
        if self.agent_impl == "rust" and not version:
            raise ValueError("agent_impl rust needs agent_rust_version")
        if version and not self.agent_rust_sha256 and local is None:
            raise ValueError("agent_rust_version needs agent_rust_sha256 (or agent_rust_local_archive)")
        if (self.agent_rust_sha256 or local is not None) and not version:
            raise ValueError("agent_rust_sha256 and agent_rust_local_archive need agent_rust_version")
        if local is not None and not local.is_file():
            raise ValueError("agent_rust_local_archive is not a file")
        return self

    @property
    def home(self) -> PurePosixPath:
        return PurePosixPath("/home") / self.user

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / ".venv"

    @property
    def env_path(self) -> PurePosixPath:
        return self.site_path / ".env"

    @property
    def cache_dir(self) -> PurePosixPath:
        return self.site_path / "cache"

    @property
    def agent_rust_binary(self) -> str:
        return f"{self.agent_rust_install_root}/{self.agent_rust_version}/nyxmon-agent"

    @property
    def agent_rust_url(self) -> str:
        return self.agent_rust_release_url.format(version=self.agent_rust_version)

    @property
    def opsgate_enabled(self) -> bool:
        return bool(self.opsgate_submit_base_url)

    @property
    def opsgate_approval_url(self) -> str:
        return self.opsgate_approval_base_url or self.opsgate_submit_base_url


def traefik_config(cfg: NyxmonConfig, secrets: SecretValues) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        title="Nyxmon",
        host=cfg.traefik_host,
        app_port=cfg.app_port,
        app_host=cfg.app_host,
        basic_auth=BasicAuth(
            # The shared Traefik secrets may name the user; the config default applies otherwise.
            user=secrets.get("basic_auth_user") or cfg.basic_auth_user,
            password=SecretStr(secrets["basic_auth_password"]),
        ),
        internal_ip_ranges=cfg.internal_ip_ranges,
        middlewares=cfg.traefik_middlewares,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def render_env(cfg: NyxmonConfig, secrets: SecretValues, *, shell: bool) -> SecretContent:
    """``.env`` (systemd ``EnvironmentFile``) or, with ``shell``, the quoted ``.env.shell``."""

    if cfg.opsgate_enabled and len(secrets.get("opsgate_submit_token", "").strip()) < 20:
        raise ValueError("opsgate_submit_token must have at least 20 characters when OpsGate is enabled")
    if any("\n" in value or "\r" in value for value in secrets.values()):
        raise ValueError("secret values must be single lines")
    placeholders = [k for k, v in secrets.items() if "CHANGEME" in v or PLACEHOLDERS.get(k) == v]
    if placeholders:
        raise ValueError(f"secrets still hold placeholder values: {', '.join(sorted(placeholders))}")
    return SecretContent(render(TEMPLATE_PACKAGE, "nyxmon.env.j2", cfg=cfg, secrets=secrets, shell=shell))


def _sqlite_private(cfg: NyxmonConfig) -> OperationMeta:
    """Database and sidecars ``0600 user:user`` (the role's sqlite_privacy.yml)."""

    site, owner = shlex.quote(str(cfg.site_path)), f"{cfg.user}:{cfg.user}"
    files_ = f"find {site} -maxdepth 1 -type f -name 'db.sqlite3*'"
    exposed = f"{files_} \\( ! -user {cfg.user} -o ! -group {cfg.user} -o ! -perm 600 \\) -print"
    check = when_present([cfg.site_path], f"test -f {site}/db.sqlite3 || echo missing; {exposed}", otherwise="missing")
    # Planned from what the host looks like now; on a first deploy migrate creates the database later.
    # A failed probe runs the step, whose last command checks the result.
    pending = probe(check, name="nyxmon SQLite privacy")
    return server.shell(
        name="Restrict SQLite database and sidecars",
        commands=[
            f"test -f {site}/db.sqlite3 || {{ echo 'nyxmon database is missing' >&2; exit 1; }}",
            # Only files that need it, one at a time: a journal SQLite removes
            # between find and chown counts as done (the role's recursive
            # chown fails on exactly that race).
            f'{exposed} | while read -r f; do {{ chown -h {owner} "$f" && chmod 0600 "$f"; }} 2>/dev/null '
            '|| ! test -e "$f" || exit 1; done',
            f'test -z "$({exposed} 2>/dev/null)"',
        ],
        _if=lambda: pending is None or bool(pending.strip()),
    )


def _opsgate_check(cfg: NyxmonConfig) -> OperationMeta:
    """The monitor runs with the rendered OpsGate URLs (the role's validate_opsgate_smoke.yml)."""

    unit = shlex.quote(cfg.monitor_service_name)
    wanted = [
        f"OPSGATE_SUBMIT_BASE_URL={cfg.opsgate_submit_base_url}",
        f"OPSGATE_APPROVAL_BASE_URL={cfg.opsgate_approval_url}",
    ]
    greps = " && ".join(f"printf '%s' \"$env\" | grep -qxF {shlex.quote(line)}" for line in wanted)
    script = (
        f"for i in $(seq 1 10); do systemctl is-active -q {unit} && break; sleep 3; done; "
        f"pid=$(systemctl show --property=MainPID --value {unit}); "
        f'[ "${{pid:-0}}" -gt 0 ] || {{ echo "{cfg.monitor_service_name} has no main PID" >&2; exit 1; }}; '
        f"env=$(tr '\\0' '\\n' < /proc/$pid/environ); "
        f'{greps} || {{ echo "{cfg.monitor_service_name} runs with stale OpsGate settings" >&2; exit 1; }}'
    )
    return mark_read_only(
        server.shell(
            name=f"Check {cfg.monitor_service_name} OpsGate settings", commands=[f"sh -c {shlex.quote(script)}"]
        )
    )


@deploy("Deploy nyxmon")
def deploy_nyxmon(cfg: NyxmonConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    secrets.require(cfg.required_secret_keys)
    env_content, shell_env = render_env(cfg, secrets, shell=False), render_env(cfg, secrets, shell=True)

    site_dirs = [cfg.site_path / d for d in ("src", *EXTRA_DIRS)]
    system_user(cfg.user, home=cfg.home, directories=[cfg.site_path, cfg.cache_dir, cfg.home / "logs", *site_dirs])

    excludes = (*cfg.source_excludes, *cfg.persistent_excludes)
    code = [
        sync_tree(
            name="Sync Django source",
            src=cfg.source_path / "src/django",
            dest=cfg.site_path,
            excludes=excludes,
            runner=rsync,
            user=cfg.user,
            group=cfg.user,
        ),
        *(
            sync_tree(
                name=f"Sync {d}",
                src=cfg.source_path / d,
                dest=cfg.site_path / d,
                excludes=excludes,
                runner=rsync,
                user=cfg.user,
                group=cfg.user,
            )
            for d in EXTRA_DIRS
        ),
        *(
            files.put(
                name=f"Copy {f}",
                src=str(cfg.source_path / f),
                dest=str(cfg.site_path / f),
                mode="0644",
                user=cfg.user,
                group=cfg.user,
            )
            for f in SOURCE_FILES
        ),
    ]
    env = secret_file(
        name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user, group=cfg.user
    )
    secret_file(
        name="Write .env.shell",
        path=cfg.site_path / ".env.shell",
        content=shell_env,
        mode="0600",
        user=cfg.user,
        group=cfg.user,
    )

    deps = uv_sync(
        cfg.site_path, user=cfg.user, home=cfg.home, venv=cfg.venv_path, python=cfg.python_version, when_changed=code
    )
    files.link(
        name="Link venv to .venv",
        path=str(cfg.site_path / "venv"),
        target=str(cfg.venv_path),
        user=cfg.user,
        group=cfg.user,
    )
    for command in (("migrate", "--noinput"), ("collectstatic", "--noinput")):
        django_manage(
            cfg.site_path,
            *command,
            user=cfg.user,
            home=cfg.home,
            venv=cfg.venv_path,
            env_file=cfg.site_path / ".env.shell",
            when_changed=[deps, *code],
        )
    # The role's agent_rust.yml: after the migrations, so --check-schema sees the schema the agent runs against.
    installed = install_agent(cfg)
    selected = None

    # Traefik's file provider watches the dynamic directory; like the role
    # (ops-library 2.31.47), no Traefik restart.
    traefik_route(traefik_config(cfg, secrets), restart="none")
    for name, template in (
        (cfg.service_name, "nyxmon.service.j2"),
        (cfg.monitor_service_name, "nyxmon-monitor.service.j2"),
    ):
        unit = systemd_unit(name, render(TEMPLATE_PACKAGE, template, cfg=cfg))
        dropin_dir = f"/etc/systemd/system/{name}.service.d"
        files.directory(name=f"Create {dropin_dir}", path=dropin_dir, user="root", group="root", mode="0755")
        dropin = files.put(
            name=f"SQLite umask for {name}",
            src=StringIO(SQLITE_PRIVACY),
            dest=f"{dropin_dir}/sqlite-privacy.conf",
            user="root",
            group="root",
            mode="0644",
        )
        units = [unit, dropin]
        if name == cfg.monitor_service_name:
            # Every switch and version change rewrites the drop-in: reload and restart.
            selected = select_agent(cfg, dropin_dir)
            units.append(selected)
        service_rollout(name, units=units, restart_when=[deps, env, *code])
    _sqlite_private(cfg)

    wait_port(cfg.app_port, host=cfg.app_host)
    # Production settings redirect plain HTTP (301); with require_login, pages redirect to the login (302).
    http_check(f"http://{cfg.app_host}:{cfg.app_port}/", status=(200, 301, 302), host_header=cfg.traefik_host)
    check_agent(cfg)
    prune_agents(cfg, [installed, selected])
    if cfg.opsgate_enabled:
        _opsgate_check(cfg)
