"""homelab: the home dashboard, a Django app on SQLite served by gunicorn behind Traefik.

Port of the ``homelab_deploy`` Ansible role (with its ``homelab_shared``
defaults) as ops-control's ``deploy-homelab.yml`` runs it. The role's
templates are shipped unchanged and rendered the way Ansible's ``template``
module renders them, so the ``.env``, the unit and the Traefik route are
byte-identical to the role's (``tests/test_homelab_parity.py``) and Ansible and
ops-deploy can take turns on a host without rewriting files or restarting
anything. Like the role (since ops-library 2.49.1), the route keeps the
deployed bcrypt hash while it still matches the password.

Unlike the role, steps that would change nothing are skipped instead of run:
``uv sync``, ``migrate``, ``collectstatic``, ``add_default_services`` and the
recursive ownership fix run when planning finds them needed or a step they
depend on changed. Data is never synced or removed: the source sync has no
``--delete`` and the database, ``media`` uploads, ``staticfiles`` and
``cache`` only get the owner (and the database its mode) the role sets.

The playbook's ``uv_install`` runs only when configured (``uv``, as the
graphyard port): the role pins one uv version and replaces any other.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from collections.abc import Callable, Sequence
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar

import jinja2
from pydantic import Field, SecretStr, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import files, server

from ops_deploy.base import UvInstallConfig, deploy_uv_install
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
)
from ops_deploy.helpers.probes import last_line, migrations_state, probe, uv_sync_state, verify_probe, when_present
from ops_deploy.helpers.python import DEFAULT_UV, _as_user
from ops_deploy.helpers.traefik import DEFAULT_INTERNAL_IP_RANGES, Hostname
from ops_deploy.ops import secret_file, sync_tree

TEMPLATE_PACKAGE = "ops_deploy.services.homelab"
FILES = Path(__file__).parent / "files"
DEFAULT_SERVICES_CHECK = (FILES / "default_services_check.py").read_text()

# The paths source.yml requires in the checkout before it syncs anything.
REQUIRED_SOURCE_PATHS = ("src", "manage.py", "pyproject.toml", "uv.lock")
# source.yml's rsync excludes for ``src`` (no ``--delete``: nothing is removed).
SOURCE_EXCLUDES = ("__pycache__", "*.pyc", ".pytest_cache", ".coverage", "htmlcov", ".mypy_cache")
# The files source.yml copies next to ``src``, with the modes it sets.
SOURCE_FILES = (("manage.py", "0755"), ("pyproject.toml", "0644"), ("uv.lock", "0644"))
MEDIA_EXCLUDES = (".gitkeep",)
PLACEHOLDER = "CHANGEME"
# For the planning probes that run Python as the service user. They must
# leave nothing behind: an existing service user may have another primary
# group than ``group`` (the role only appends ``group``), so a bytecode cache a
# probe writes into the venv or ``src`` would carry that group and the next
# run's ownership probe would find it. The steps that change the host, the
# unit and the service's environment do not get it (the role's end state).
PROBE_ENV = {"PYTHONDONTWRITEBYTECODE": "1"}

# Written unquoted into ``.env``, which systemd reads and bash sources (the
# role's ``set -a; . .env``): a value must mean the same to both, so no
# whitespace, quotes, backslashes, expansions or shell control characters.
_ENV_UNSAFE = re.compile(r"[\s\"'\\$`;&|<>()~]")
EnvValue = Annotated[str, Field(pattern=r"^[!-~]*$")]
MediaDir = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$")]


def _env_safe(value: str) -> bool:
    return value.isascii() and value.isprintable() and not _ENV_UNSAFE.search(value)


class HomelabConfig(BaseServiceConfig):
    """The ``homelab_*`` variables the deploy uses, without the prefix (``homelab_shared`` defaults)."""

    required_secret_keys: ClassVar[tuple[str, ...]] = ("django_secret_key", "basic_auth_password")

    # The role names the unit after ``homelab_service_name`` but enables and
    # restarts ``homelab_user``: both must be the same.
    service_name: ServiceName = "homelab"
    user: UnixUser = "homelab"
    group: UnixUser = "homelab"
    home: PurePosixPath = PurePosixPath("/home/homelab")
    site_path: PurePosixPath = PurePosixPath("/home/homelab/site")
    # A homelab checkout on the controller (``src``, ``manage.py``,
    # ``pyproject.toml``, ``uv.lock``; ``media`` is synced when present).
    source_path: Path
    media_subdirs: tuple[MediaDir, ...] = ("services", "services/logos")
    app_host: Annotated[str, Field(pattern=r"^[0-9.]+$")] = "127.0.0.1"
    app_port: int = Field(default=10010, ge=1, le=65535)
    workers: int = Field(default=4, ge=1, le=64)
    django_settings_module: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.]+$")] = "config.settings.production"
    # One comma-separated string, as the role's variable.
    django_allowed_hosts: EnvValue = "127.0.0.1"
    django_admin_url: EnvValue = "admin/"
    django_debug: bool = False
    uv_path: PurePosixPath = DEFAULT_UV
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    # Pinned uv/uvx convergence, refusing newer installed versions;
    # None: not run, uv must already be at ``uv_path``.
    uv: UvInstallConfig | None = None
    traefik_host: Hostname = "home.example.com"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    basic_auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "admin"
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES

    @field_validator("home", "site_path", "uv_path")
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        if not value.is_absolute() or ".." in value.parts or value == PurePosixPath("/"):
            raise ValueError("paths must be absolute, without '..', and not '/'")
        if not _env_safe(str(value)):
            raise ValueError("paths must not contain whitespace, quotes or shell characters")
        return value

    @field_validator("source_path")
    @classmethod
    def _source_is_a_homelab_checkout(cls, value: Path) -> Path:
        value = value.expanduser().absolute()
        if not value.is_dir():
            raise ValueError("source_path must be a directory on the controller")
        missing = [name for name in REQUIRED_SOURCE_PATHS if not (value / name).exists()]
        if missing:
            raise ValueError(f"source_path is not a homelab checkout (missing {', '.join(missing)})")
        if not (value / "src").is_dir():
            raise ValueError("source_path/src must be a directory")
        return value

    @field_validator("internal_ip_ranges")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("internal_ip_ranges must not be empty")
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("internal_ip_ranges must contain IP networks") from None
            if not re.fullmatch(r"[0-9A-Fa-f:.]+(/[0-9]{1,3})?", item):
                raise ValueError("internal_ip_ranges must contain IP networks")
        return value

    @field_validator("django_allowed_hosts", "django_admin_url")
    @classmethod
    def _env_value(cls, value: str) -> str:
        if not _env_safe(value):
            raise ValueError(".env values must not contain whitespace, quotes or shell characters")
        return value

    @model_validator(mode="after")
    def _role_rules(self) -> HomelabConfig:
        if self.service_name != self.user:
            raise ValueError("service_name must equal user (the role starts the unit named after the user)")
        if self.uv is not None and self.uv.install_dir != str(self.uv_path.parent):
            raise ValueError("uv.install_dir must be the directory of uv_path (the role installs uv there)")
        if self.uv_path.name != "uv":
            raise ValueError("uv_path must name a binary called uv")
        return self

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
    def db_path(self) -> PurePosixPath:
        return self.site_path / "db.sqlite3"

    @property
    def static_root(self) -> PurePosixPath:
        return self.site_path / "staticfiles"

    @property
    def media_root(self) -> PurePosixPath:
        return self.site_path / "media"

    @property
    def cache_dir(self) -> PurePosixPath:
        return self.site_path / "cache"


# -- the role's templates ----------------------------------------------------------


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
    env.filters["dirname"] = lambda value: str(PurePosixPath(value).parent)
    return env


def role_vars(cfg: HomelabConfig, **extra: Any) -> dict[str, Any]:
    """The role's variables the templates read."""

    return {
        "homelab_user": cfg.user,
        "homelab_group": cfg.group,
        "homelab_site_path": str(cfg.site_path),
        "homelab_cache_dir": str(cfg.cache_dir),
        "homelab_database_path": str(cfg.db_path),
        "homelab_static_root": str(cfg.static_root),
        "homelab_media_root": str(cfg.media_root),
        "homelab_app_host": cfg.app_host,
        "homelab_app_port": cfg.app_port,
        "homelab_workers": cfg.workers,
        "homelab_django_settings_module": cfg.django_settings_module,
        "homelab_django_allowed_hosts": cfg.django_allowed_hosts,
        "homelab_django_admin_url": cfg.django_admin_url,
        "homelab_django_debug": cfg.django_debug,
        "homelab_uv_path": str(cfg.uv_path),
        "homelab_traefik_host": cfg.traefik_host,
        "homelab_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "homelab_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "homelab_basic_auth_enabled": True,
        **extra,
    }


def render(template: str, variables: dict[str, Any]) -> str:
    return _templates().get_template(template).render(**variables)


def check_secrets(secrets: SecretValues) -> None:
    """The role's assertions, plus values ``.env`` and the route can carry; errors never quote values."""

    secrets.require(HomelabConfig.required_secret_keys)
    key = secrets["django_secret_key"]
    if not key or PLACEHOLDER in key:
        raise ValueError("django_secret_key must be set and not a placeholder")
    if not _env_safe(key):
        raise ValueError(
            "django_secret_key must be printable ASCII without whitespace, quotes, backslashes or "
            "$ ` ; & | < > ( ) ~ (.env is read by systemd and sourced by bash)"
        )
    password = secrets["basic_auth_password"]
    if not password or PLACEHOLDER in password:
        raise ValueError("basic_auth_password must be set and not a placeholder")
    if any(c in value for value in secrets.values() for c in "\r\n"):
        raise ValueError("secret values must be single lines")


def render_env(cfg: HomelabConfig, secrets: SecretValues) -> SecretContent:
    """The role's ``env.j2``."""

    return SecretContent(render("env.j2", role_vars(cfg, homelab_secret_key=secrets["django_secret_key"])))


def render_unit(cfg: HomelabConfig) -> str:
    return render("systemd.service.j2", role_vars(cfg))


def traefik_config(cfg: HomelabConfig, secrets: SecretValues) -> TraefikRoute:
    return TraefikRoute(
        name=cfg.service_name,
        title="Homelab",
        host=cfg.traefik_host,
        app_port=cfg.app_port,
        app_host=cfg.app_host,
        basic_auth=BasicAuth(
            # The playbook's ``basic_auth_user | default('admin')``.
            user=secrets.get("basic_auth_user") or cfg.basic_auth_user,
            password=SecretStr(secrets["basic_auth_password"]),
        ),
        internal_ip_ranges=cfg.internal_ip_ranges,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def render_route(cfg: HomelabConfig, route: TraefikRoute, auth_hash: str | None) -> str:
    """The role's ``traefik.yml.j2`` (dual router, basic auth outside ``internal_ip_ranges``)."""

    user = route.basic_auth.user if route.basic_auth else cfg.basic_auth_user
    return render(
        "traefik.yml.j2",
        role_vars(cfg, homelab_basic_auth_user=user, homelab_basic_auth_password_hash=auth_hash or ""),
    )


# -- commands -------------------------------------------------------------------------


def _quiet_probe(command: str) -> str:
    """Stdout of a read-only probe whose failure is an answer (missing, broken); empty then."""

    return str(host.get_fact(Command, command=f"{command} 2>/dev/null || true") or "").strip()


def _in_site(cfg: HomelabConfig, argv: Sequence[str], env: dict[str, str] | None = None) -> str:
    """``argv`` in the site directory as the service user (the role's ``become_user``)."""

    return f"cd {shlex.quote(str(cfg.site_path))} && {_as_user(cfg.user, cfg.home, env or {}, argv)}"


def _manage(cfg: HomelabConfig, *args: str, probe: bool = False) -> str:
    """The role's ``set -a; . .env; set +a; .venv/bin/python manage.py ...`` (bash), as the service user.

    ``probe``: a read-only planning probe (no bytecode written, ``PROBE_ENV``).
    """

    script = (
        f"set -a; . {shlex.quote(str(cfg.env_path))}; set +a; "
        f"exec {shlex.join([str(cfg.venv_bin / 'python'), 'manage.py', *args])}"
    )
    env = {"DJANGO_SETTINGS_MODULE": cfg.django_settings_module, **(PROBE_ENV if probe else {})}
    return _in_site(cfg, ["bash", "-c", script], env)


def _manage_shell(cfg: HomelabConfig, code: str) -> str:
    """``manage.py shell -c <code>`` with ``.env`` loaded, as a probe; the code is an argument, not interpolated."""

    script = (
        f"set -a; . {shlex.quote(str(cfg.env_path))}; set +a; "
        f'exec {shlex.quote(str(cfg.venv_bin / "python"))} manage.py shell -c "$1"'
    )
    env = {"DJANGO_SETTINGS_MODULE": cfg.django_settings_module, **PROBE_ENV}
    return _in_site(cfg, ["bash", "-c", script, "bash", code], env)


def _changed(planned: bool, triggers: Sequence[OperationMeta | None]) -> Callable[[], bool]:
    """``_if`` for a step planning found needed, or one to run after a trigger changed."""

    ops = [op for op in triggers if op is not None]
    return lambda: planned or any(op.did_change() for op in ops)


# -- the role's task files --------------------------------------------------------------


def _site_owned(cfg: HomelabConfig, triggers: Sequence[OperationMeta | None]) -> OperationMeta:
    """source.yml's recursive ``file: owner/group`` on the site, only when something is off.

    Probed while planning; also run after a directory was created this run
    (``mkdir -p`` leaves new parents, such as ``media``, owned by root).
    As in the role it comes before the Python steps: files they create (the
    venv, packages, bytecode, collected static files) carry the service
    user's primary group, which the next run sets right. A converged run
    runs none of them, and the planning probes write nothing (``PROBE_ENV``).
    """

    site = shlex.quote(str(cfg.site_path))
    wrong = f"\\( ! -user {cfg.user} -o ! -group {cfg.group} \\)"
    planned = bool(_quiet_probe(f"find {site} {wrong} -print -quit"))
    return server.shell(
        name="Set ownership for synced files",
        commands=[f"find {site} {wrong} -exec chown -h {cfg.user}:{cfg.group} {{}} +"],
        _if=_changed(planned, triggers),
    )


def _uv_present(cfg: HomelabConfig) -> OperationMeta:
    uv = shlex.quote(str(cfg.uv_path))
    message = shlex.quote(f"uv is required at {cfg.uv_path} (the deploy does not install it unless uv is configured)")
    return mark_read_only(
        server.shell(name=f"Require {cfg.uv_path}", commands=[f"test -x {uv} || {{ echo {message} >&2; exit 1; }}"])
    )


def _venv(cfg: HomelabConfig) -> OperationMeta | None:
    """python.yml: a broken venv or one of another Python is removed, then created with ``uv venv``.

    Returns the create step when the venv is (re)created this run.
    """

    version = _quiet_probe(_as_user(cfg.user, cfg.home, PROBE_ENV, [str(cfg.venv_bin / "python"), "--version"]))
    match = re.match(r"^Python (\d+\.\d+)", version)
    if match is not None and match.group(1) == cfg.python_version:
        return None
    venv = shlex.quote(str(cfg.venv_path))
    if _quiet_probe(f"{{ [ -e {venv} ] || [ -L {venv} ]; }} && echo present") == "present":
        server.shell(name=f"Remove broken or outdated venv {cfg.venv_path}", commands=[f"rm -rf -- {venv}"])
    create = [str(cfg.uv_path), "venv", "--python", cfg.python_version, str(cfg.venv_path)]
    return server.shell(name="Create virtual environment using uv", commands=[_in_site(cfg, create)])


def _venv_link(cfg: HomelabConfig) -> None:
    """python.yml's ``venv -> .venv`` link, created only when nothing is at ``venv``."""

    link = cfg.site_path / "venv"
    quoted = shlex.quote(str(link))
    if _quiet_probe(f"{{ [ -e {quoted} ] || [ -L {quoted} ]; }} && echo present") == "present":
        return
    files.link(name="Create venv symlink to .venv", path=str(link), target=".venv", user=cfg.user, group=cfg.group)


def _uv_sync(cfg: HomelabConfig, venv: OperationMeta | None, triggers: Sequence[OperationMeta | None]) -> OperationMeta:
    """python.yml's ``uv sync --frozen`` when a read-only ``--check`` finds work or a trigger changed."""

    env = {"VIRTUAL_ENV": str(cfg.venv_path)}
    sync = [str(cfg.uv_path), "sync", "--frozen"]
    check = when_present(
        [cfg.venv_bin / "python", cfg.site_path / "uv.lock"],
        uv_sync_state(_in_site(cfg, [*sync, "--check"], {**env, **PROBE_ENV})),
        otherwise="pending",
    )
    state = probe(check, name="homelab dependencies")
    deps = server.shell(
        name="Install dependencies with uv sync",
        commands=[_in_site(cfg, sync, env)],
        _if=_changed(venv is not None or state != "current", triggers),
    )
    if state is None:
        verify_probe(check, name="homelab dependencies", expect="current")
    return deps


def _django(
    cfg: HomelabConfig, code: OperationMeta, env: OperationMeta, triggers: Sequence[OperationMeta | None]
) -> OperationMeta:
    """django.yml after the env file: migrate, database owner and mode, collectstatic, default services.

    ``code`` is the source sync, ``triggers`` what else the role's commands
    depend on (copies, venv, dependencies). Returns the migrate step.
    """

    needed = (cfg.env_path, cfg.venv_bin / "python")
    db = shlex.quote(str(cfg.db_path))
    changed = [code, *triggers, env]

    plan = _manage(cfg, "migrate", "--check", "--plan", probe=True)
    migrations_check = when_present((cfg.db_path, *needed), migrations_state(plan), otherwise="pending")
    migrations = probe(migrations_check, name="homelab migrations")
    migrate = server.shell(
        name="Run Django migrations",
        commands=[_manage(cfg, "migrate", "--noinput")],
        _if=_changed(migrations != "current", changed),
    )
    if migrations is None:
        verify_probe(migrations_check, name="homelab migrations", expect="current")

    # "Fix database permissions": the role's 0644 (not tightened here).
    owner = f"{cfg.user}:{cfg.group}"
    current = _quiet_probe(f"stat -c '%U:%G %a' {db}")
    server.shell(
        name="Fix database permissions",
        commands=[f"if [ -e {db} ]; then chown {owner} {db} && chmod 0644 {db}; fi"],
        _if=_changed(bool(current) and current != f"{owner} 644", [] if current else [migrate]),
    )

    # ``--dry-run`` copies nothing; "0 static files copied" means current.
    static_check = when_present(
        needed,
        f"out=$( {_manage(cfg, 'collectstatic', '--noinput', '--dry-run', probe=True)} ) || exit 1; "
        "if printf '%s\\n' \"$out\" | grep -Eq '(^|[^0-9])0 static files copied'; "
        "then echo current; else echo pending; fi",
        otherwise="pending",
    )
    static = probe(static_check, name="homelab static files")
    server.shell(
        name="Collect static files",
        commands=[_manage(cfg, "collectstatic", "--noinput")],
        _if=_changed(static != "current", changed),
    )
    if static is None:
        verify_probe(static_check, name="homelab static files", expect="current")

    # The command's list of services lives in the code: also run it after a
    # code change (the probe ran the code as deployed before this run).
    services_check = when_present(
        (cfg.db_path, *needed), last_line(_manage_shell(cfg, DEFAULT_SERVICES_CHECK)), otherwise="pending"
    )
    services = probe(services_check, name="homelab default services")
    server.shell(
        name="Add default services with logos",
        commands=[_manage(cfg, "add_default_services")],
        _if=_changed(services != "current", [code]),
    )
    if services is None:
        verify_probe(services_check, name="homelab default services", expect="current")
    return migrate


@deploy("Deploy homelab")
def deploy_homelab(cfg: HomelabConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner) -> None:
    check_secrets(secrets)
    env_content = render_env(cfg, secrets)
    route = traefik_config(cfg, secrets)

    # user.yml
    account = system_user(
        cfg.user,
        group=cfg.group,
        home=cfg.home,
        shell="/bin/bash",
        directories=[
            cfg.site_path,
            cfg.static_root,
            cfg.cache_dir,
            *(cfg.media_root / subdir for subdir in cfg.media_subdirs),
        ],
    )

    # source.yml
    code = sync_tree(
        name="Sync homelab src",
        src=cfg.source_path / "src",
        dest=cfg.site_path / "src",
        excludes=SOURCE_EXCLUDES,
        delete=False,
        runner=rsync,
        user=cfg.user,
        group=cfg.group,
    )
    copies = [
        files.put(
            name=f"Copy {name} to site directory",
            src=str(cfg.source_path / name),
            dest=str(cfg.site_path / name),
            user=cfg.user,
            group=cfg.group,
            mode=mode,
        )
        for name, mode in SOURCE_FILES
    ]
    if (cfg.source_path / "media").is_dir():
        sync_tree(
            name="Sync homelab media",
            src=cfg.source_path / "media",
            dest=cfg.media_root,
            excludes=MEDIA_EXCLUDES,
            delete=False,
            runner=rsync,
            user=cfg.user,
            group=cfg.group,
        )
    _site_owned(cfg, account.directories)

    # python.yml
    if cfg.uv is not None:
        deploy_uv_install(cfg=cfg.uv)
    _uv_present(cfg)
    venv = _venv(cfg)
    _venv_link(cfg)
    deps = _uv_sync(cfg, venv, [code, *copies])

    # django.yml
    env = secret_file(
        name="Create environment file for Django",
        path=cfg.env_path,
        content=env_content,
        user=cfg.user,
        group=cfg.group,
        mode="0600",
    )
    migrate = _django(cfg, code, env, [*copies, venv, deps])

    # service.yml; the restart also follows migrate (a retry after a failed
    # run must not leave the old code running on the new schema).
    unit = systemd_unit(cfg.service_name, render_unit(cfg))
    restart = [op for op in (code, *copies, venv, deps, env, migrate) if op is not None]
    service_rollout(cfg.service_name, units=[unit], restart_when=restart)

    # traefik.yml: no Traefik restart, its file provider watches the directory.
    traefik_route(route, renderer=lambda r, auth_hash: render_route(cfg, r, auth_hash), restart="none")
