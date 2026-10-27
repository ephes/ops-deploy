"""open_webui: Open WebUI in a uv-managed virtualenv behind Traefik (the ``open_webui_venv_deploy`` role).

Deploy only (removal stays with the Ansible role). The role's three templates
(environment file, systemd unit, Traefik route) are shipped unchanged and
rendered the way Ansible's ``template`` module renders them, so the files are
byte-identical to the role's and the two tools can take turns without
rewriting them; the deployed bcrypt hash is kept while it still matches the
password.

Unlike the role, the version is pinned (``version``, ``python_version``) and
nothing runs that would change nothing. The interpreter, the virtualenv and
the package are probed while planning: the virtualenv is recreated only when
its interpreter is missing, broken or not ``python_version``, and
``uv pip install open-webui==<version>`` runs only after a recreation or when
the installed distribution has another version. That install takes the
shipped constraint file of the version (the distributions of the environment
it was qualified with, ``files/open-webui-<version>-constraints.txt``), so a
fresh install resolves the same dependency versions instead of the latest
ones. The generated ``.webui_secret_key`` in ``site_dir`` (the key that signs
sessions while no ``WEBUI_SECRET_KEY`` is set) and everything below
``data_dir`` are never written, also when the virtualenv is recreated.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
from functools import cache
from importlib.resources import files as files_of
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Any

import jinja2
from pydantic import Field, TypeAdapter, ValidationError, field_validator, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, File
from pyinfra.facts.server import Users
from pyinfra.operations import files, server

from ops_deploy.base._common import AbsolutePath, RoleConfig, Version, require_linux, require_systemd
from ops_deploy.base.uv_install import UvInstallConfig, deploy_uv_install
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import BasicAuth, TraefikRoute, http_check, mark_read_only, traefik_route, wait_port
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.helpers.python import _as_user
from ops_deploy.helpers.python_security import SECURITY_FLOORS, verify_trust
from ops_deploy.helpers.systemd import service_rollout, systemd_unit
from ops_deploy.helpers.traefik import Hostname
from ops_deploy.ops.secret_file import secret_file

PACKAGE = "ops_deploy.services.open_webui"
ROUTE_NAME = "open-webui"
PLACEHOLDER = "CHANGEME"
DISTRIBUTION = "open-webui"

# open_webui_venv_deploy/defaults/main.yml
ROLE_INTERNAL_IP_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fd7a:115c:a1e0::/48")
# Keys the deploy never writes into the environment file: a WEBUI_SECRET_KEY
# would replace the generated key file (and sign everyone out); API keys are secrets.
REFUSED_ENV = frozenset({"WEBUI_SECRET_KEY", "OPENAI_API_KEY"})

_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_MIDDLEWARE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@_.-]{0,127}$")
_ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
# A value of a ``KEY=value`` line systemd reads unquoted: printable, no quotes or backslashes.
_ENV_VALUE = re.compile(r"^[A-Za-z0-9 !#%&()*+,./:;<=>?@\[\]^_{|}~-]*$")
_URL = re.compile(r"^https?://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._~/-]*)?$")
_ARG = re.compile(r"^[A-Za-z0-9_.=:/,+-]+$")
_PATCH = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

Mode = Annotated[str, Field(pattern=r"^0?[0-7]{3,4}$")]


class OpenWebUIConfig(RoleConfig):
    """The ``open_webui_*`` role variables the deploy uses, without the prefix (role defaults).

    Not ported: ``package_spec`` (``version`` pins it), ``manage_user`` (the
    user is always managed), ``webui_secret_key`` and ``openai_api_key``
    (no secret is ever written into the environment file), ``uv_version``,
    ``uv_update_existing`` and ``uv_force_reinstall`` (``manage_uv`` uses
    ops-deploy's ``UvInstallConfig`` pin), ``basic_auth_password_hash`` (the
    hash is derived from the password, reusing the deployed one),
    ``traefik_config_path`` (always ``/etc/traefik/dynamic/open-webui.yml``)
    and ``systemd_enabled: false``.
    """

    service_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,62}$")] = "open-webui"
    user: UnixUser = "openwebui"
    group: UnixUser = "openwebui"
    # None: the role's ``/home/<user>``. uv keeps the managed interpreter and its cache there.
    home: AbsolutePath | None = None
    site_dir: AbsolutePath = "/opt/open-webui"
    data_dir: AbsolutePath = "/var/lib/open-webui"
    log_dir: AbsolutePath = "/var/log/open-webui"
    # None: ``<site_dir>/open-webui.env`` and ``<site_dir>/.venv``.
    env_path: AbsolutePath | None = None
    venv_path: AbsolutePath | None = None
    # Not in the role (it installs the latest ``open-webui`` into the latest ``3.11``).
    version: Version = "0.7.2"
    python_version: Version = "3.11.14"
    python_security_floor_enabled: bool = True
    # None: ``<site_dir>/.python-security-constraints.txt``.
    python_security_constraints_path: AbsolutePath | None = None
    manage_uv: bool = True
    uv_install_dir: AbsolutePath = "/usr/local/bin"

    bind_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:\[\]-]+$")] = "127.0.0.1"
    host_port: int = Field(default=3000, ge=1, le=65535)
    use_host_flag: bool = True
    extra_args: tuple[str, ...] = ()
    systemd_restart: Annotated[str, Field(pattern=r"^(no|always|on-success|on-failure|on-abnormal|on-abort)$")] = (
        "on-failure"
    )
    systemd_restart_sec: int = Field(default=5, ge=0, le=3600)
    systemd_hardening: bool = False

    ollama_base_url: str = "http://localhost:11434"
    webui_auth_enabled: bool = True
    openai_api_base_url: str = ""
    extra_env: dict[str, str] = Field(default_factory=dict)

    traefik_enabled: bool = True
    traefik_host: str = ""
    traefik_entrypoints: tuple[str, ...] = ("web-secure",)
    traefik_cert_resolver: str = ""
    traefik_middlewares: tuple[str, ...] = ()
    basic_auth_enabled: bool = True
    basic_auth_remove_header: bool = True
    internal_ip_ranges: tuple[str, ...] = ROLE_INTERNAL_IP_RANGES

    healthcheck_enabled: bool = True
    healthcheck_host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:\[\]-]+$")] = "127.0.0.1"
    healthcheck_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")] = "/"
    healthcheck_status: int = Field(default=200, ge=100, le=599)
    healthcheck_timeout: int = Field(default=10, ge=1, le=600)
    healthcheck_retries: int = Field(default=12, ge=1, le=100)
    # Not in the role: mount points ``data_dir`` must live on; checked (read-only) before any change.
    mounts_required: tuple[AbsolutePath, ...] = ()

    @field_validator("python_version")
    @classmethod
    def _exact_python(cls, value: str) -> str:
        if not _PATCH.fullmatch(value):
            raise ValueError("python_version must be an exact release such as 3.11.14")
        return value

    @field_validator("ollama_base_url", "openai_api_base_url")
    @classmethod
    def _url(cls, value: str, info: Any) -> str:
        if value and not _URL.fullmatch(value):
            raise ValueError(f"{info.field_name} must be an http(s) URL")
        return value

    @field_validator("extra_env")
    @classmethod
    def _env(cls, value: dict[str, str]) -> dict[str, str]:
        for key, item in value.items():
            if not _ENV_KEY.fullmatch(key):
                raise ValueError("extra_env keys must be upper-case environment variable names")
            if key in REFUSED_ENV:
                raise ValueError(f"extra_env must not set {key}")
            if not _ENV_VALUE.fullmatch(item):
                raise ValueError(f"extra_env {key} must be one printable line without quotes or backslashes")
        return value

    @field_validator("extra_args")
    @classmethod
    def _args(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(_ARG.fullmatch(item) for item in value):
            raise ValueError("extra_args must be plain words")
        return value

    @field_validator("traefik_entrypoints")
    @classmethod
    def _entrypoints(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or not all(_WORD.fullmatch(item) for item in value):
            raise ValueError("traefik_entrypoints must be one or more plain names")
        return value

    @field_validator("traefik_cert_resolver")
    @classmethod
    def _resolver(cls, value: str) -> str:
        if value and not _WORD.fullmatch(value):
            raise ValueError("traefik_cert_resolver must be a plain name")
        return value

    @field_validator("traefik_middlewares")
    @classmethod
    def _middlewares(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(_MIDDLEWARE.fullmatch(item) for item in value):
            raise ValueError("traefik_middlewares must be plain names (provider suffix allowed)")
        return value

    @field_validator("internal_ip_ranges")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("internal_ip_ranges must not be empty")
        for item in value:
            if not re.fullmatch(r"[0-9A-Fa-f:.]+(/[0-9]{1,3})?", item):
                raise ValueError("internal_ip_ranges must contain IP networks")
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("internal_ip_ranges must contain IP networks") from None
        return value

    @model_validator(mode="after")
    def _role_rules(self) -> OpenWebUIConfig:
        if self.traefik_enabled and not _hostname(self.traefik_host):
            raise ValueError("traefik_host is required when Traefik is enabled")
        paths = {
            "home": self.home_dir,
            "site_dir": self.site_dir,
            "data_dir": self.data_dir,
            "log_dir": self.log_dir,
            "venv_path": self.venv,
        }
        for name, path in paths.items():
            parts = PurePosixPath(path).parts
            if ".." in parts or len(parts) < 2:
                raise ValueError(f"{name} must be a directory below /")
        if len(set(paths.values())) != len(paths):
            raise ValueError("home, site_dir, data_dir, log_dir and venv_path must be distinct")
        venv = PurePosixPath(self.venv)
        for name in ("home", "site_dir", "data_dir", "log_dir"):
            if PurePosixPath(paths[name]).is_relative_to(venv):
                raise ValueError(f"{name} must not be inside venv_path (it is removed when recreated)")
        if self.version not in shipped_constraints():
            raise ValueError(f"no shipped install constraints for open-webui {self.version}")
        if self.mounts_required and not any(
            PurePosixPath(self.data_dir).is_relative_to(mount) for mount in self.mounts_required
        ):
            raise ValueError("data_dir must be below one of mounts_required")
        return self

    @property
    def home_dir(self) -> str:
        return self.home or f"/home/{self.user}"

    @property
    def env_file(self) -> str:
        return self.env_path or f"{self.site_dir}/open-webui.env"

    @property
    def venv(self) -> str:
        return self.venv_path or f"{self.site_dir}/.venv"

    @property
    def security_constraints(self) -> str:
        return self.python_security_constraints_path or f"{self.site_dir}/.python-security-constraints.txt"

    @property
    def health_url(self) -> str:
        return f"http://{self.healthcheck_host}:{self.host_port}{self.healthcheck_path}"


def _hostname(value: str) -> bool:
    try:
        TypeAdapter(Hostname).validate_python(value)
    except ValidationError:
        return False
    return True


@cache
def shipped_constraints() -> dict[str, str]:
    """``files/open-webui-<version>-constraints.txt`` by version."""

    found = {}
    for entry in files_of(PACKAGE).joinpath("files").iterdir():
        match = re.fullmatch(r"open-webui-([0-9.]+)-constraints\.txt", entry.name)
        if match:
            found[match.group(1)] = entry.read_text()
    return found


# -- rendering -----------------------------------------------------------------------


def _ansible_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "on", "1", "true", "y", "t")


@cache
def _templates() -> jinja2.Environment:
    # Rendered like Ansible's template module (trim_blocks), for byte parity.
    env = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["bool"] = _ansible_bool
    env.filters["dict2items"] = lambda mapping: [{"key": key, "value": value} for key, value in mapping.items()]
    return env


def environment(cfg: OpenWebUIConfig) -> dict[str, str]:
    """env.yml's ``open_webui_env``: the role's defaults combined with ``extra_env``."""

    return {
        "OLLAMA_BASE_URL": cfg.ollama_base_url,
        "WEBUI_SECRET_KEY": "",
        "WEBUI_AUTH": "true" if cfg.webui_auth_enabled else "false",
        "OPENAI_API_KEY": "",
        "OPENAI_API_BASE_URL": cfg.openai_api_base_url,
        **cfg.extra_env,
    }


def role_vars(cfg: OpenWebUIConfig) -> dict[str, Any]:
    """The role's variables the environment and unit templates read."""

    return {
        "open_webui_env": environment(cfg),
        "open_webui_user": cfg.user,
        "open_webui_group": cfg.group,
        "open_webui_home": cfg.home_dir,
        "open_webui_site_dir": cfg.site_dir,
        "open_webui_data_dir": cfg.data_dir,
        "open_webui_log_dir": cfg.log_dir,
        "open_webui_env_path": cfg.env_file,
        "open_webui_venv_path": cfg.venv,
        "open_webui_host_port": cfg.host_port,
        "open_webui_bind_host": cfg.bind_host,
        "open_webui_use_host_flag": cfg.use_host_flag,
        "open_webui_extra_args": list(cfg.extra_args),
        "open_webui_systemd_restart": cfg.systemd_restart,
        "open_webui_systemd_restart_sec": cfg.systemd_restart_sec,
        "open_webui_systemd_hardening": cfg.systemd_hardening,
    }


def route_vars(cfg: OpenWebUIConfig, *, user: str, auth_hash: str) -> dict[str, Any]:
    """The role's variables the Traefik template reads."""

    return {
        "open_webui_basic_auth_enabled": cfg.basic_auth_enabled,
        "open_webui_basic_auth_password_hash": auth_hash,
        "open_webui_basic_auth_remove_header": cfg.basic_auth_remove_header,
        "open_webui_basic_auth_user": user,
        "open_webui_host_port": cfg.host_port,
        "open_webui_internal_ip_ranges": list(cfg.internal_ip_ranges),
        "open_webui_traefik_cert_resolver": cfg.traefik_cert_resolver,
        "open_webui_traefik_entrypoints": list(cfg.traefik_entrypoints),
        "open_webui_traefik_host": cfg.traefik_host,
        "open_webui_traefik_middlewares": list(cfg.traefik_middlewares),
    }


def render_env(cfg: OpenWebUIConfig) -> str:
    """The role's ``open-webui.env.j2``."""

    return _templates().get_template("open-webui.env.j2").render(**role_vars(cfg))


def render_unit(cfg: OpenWebUIConfig) -> str:
    """The role's ``open-webui.service.j2``."""

    return _templates().get_template("open-webui.service.j2").render(**role_vars(cfg))


def traefik_config(cfg: OpenWebUIConfig, basic_auth: BasicAuth | None) -> TraefikRoute:
    return TraefikRoute(
        name=ROUTE_NAME,
        title="Open WebUI",
        host=cfg.traefik_host,
        app_port=cfg.host_port,
        basic_auth=basic_auth if cfg.basic_auth_enabled else None,
        internal_ip_ranges=cfg.internal_ip_ranges,
        cert_resolver=cfg.traefik_cert_resolver,
    )


def render_route(cfg: OpenWebUIConfig, route: TraefikRoute, auth_hash: str | None) -> str:
    """The role's ``open-webui-traefik.yml.j2``."""

    user = route.basic_auth.user if route.basic_auth else ""
    variables = route_vars(cfg, user=user, auth_hash=auth_hash or "")
    return _templates().get_template("open-webui-traefik.yml.j2").render(**variables)


def security_constraints_text() -> str:
    """python_security_floor's constraint file: one ``name>=floor`` line per floor, sorted."""

    return "".join(f"{name}>={'.'.join(map(str, floor))}\n" for name, floor in sorted(SECURITY_FLOORS.items()))


# -- planning probes ---------------------------------------------------------------------

_VERSION = "import sys;print('%d.%d.%d' % sys.version_info[:3])"
_INSTALLED = (
    "import importlib.metadata as m;"
    "print(next((d.version for d in m.distributions() if (d.metadata['Name'] or '').lower().replace('_', '-')"
    f" == '{DISTRIBUTION}'), 'absent'))"
)


def venv_probe(cfg: OpenWebUIConfig) -> str:
    """Prints ``missing``, ``broken`` or ``python=<version>`` for the virtualenv's interpreter."""

    python = shlex.quote(f"{cfg.venv}/bin/python")
    run = shlex.join([f"{cfg.venv}/bin/python", "-I", "-B", "-c", _VERSION])
    return (
        f"if [ ! -e {python} ] && [ ! -L {python} ]; then echo missing; "
        f"elif out=$({run} 2>/dev/null); then echo python=$out; else echo broken; fi"
    )


def installed_probe(cfg: OpenWebUIConfig) -> str:
    """Prints the installed ``open-webui`` version or ``absent`` (the interpreter must run)."""

    return shlex.join([f"{cfg.venv}/bin/python", "-I", "-B", "-c", _INSTALLED])


def venv_state(cfg: OpenWebUIConfig) -> str:
    """``current``, ``missing`` (no interpreter) or ``recreate`` (broken, another Python, failed probe)."""

    answer = (probe(venv_probe(cfg), name="Open WebUI virtualenv interpreter") or "").strip()
    if answer == "missing":
        return "missing"
    if answer == f"python={cfg.python_version}":
        return "current"
    return "recreate"


def installed_version(cfg: OpenWebUIConfig) -> str | None:
    answer = probe(installed_probe(cfg), name="installed Open WebUI version")
    return None if answer is None else answer.strip()


def port_preflight(cfg: OpenWebUIConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but the unit may listen on the port (loopback or wildcard)."""

    unit = f"{cfg.service_name}.service"
    script = (
        f"out=$(ss -Hltnp 'sport = :{cfg.host_port}') || exit 1; "
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
        server.shell(name=f"Port preflight tcp/{cfg.host_port}", commands=[f"sh -c {shlex.quote(script)}"])
    )


def check_basic_auth(cfg: OpenWebUIConfig, basic_auth: BasicAuth | None) -> None:
    """validate.yml's basic auth assertion; errors never quote the password."""

    wanted = cfg.traefik_enabled and cfg.basic_auth_enabled
    if wanted and basic_auth is None:
        raise ValueError("basic_auth is required when Traefik and basic auth are enabled")
    if not wanted and basic_auth is not None:
        raise ValueError("basic_auth given, but Traefik or basic auth is disabled")
    if basic_auth is not None and PLACEHOLDER in basic_auth.password.get_secret_value():
        raise ValueError("basic auth password must not be a placeholder")


# -- the role's task files ------------------------------------------------------------------


def _user(cfg: OpenWebUIConfig) -> list[OperationMeta]:
    """user.yml: group and system user; an existing user is only added to the group.

    The home directory is created (``0750``, as ``useradd -m`` does on Ubuntu)
    only while it is missing; an existing one is never changed.
    """

    ops = [server.group(name=f"Ensure group {cfg.group}", group=cfg.group, system=True)]
    existing = host.get_fact(Users).get(cfg.user)
    if existing is None:
        ops.append(
            server.user(
                name=f"Ensure user {cfg.user}",
                user=cfg.user,
                group=cfg.group,
                home=cfg.home_dir,
                shell="/usr/sbin/nologin",
                system=True,
                create_home=False,
                ensure_home=False,
            )
        )
    else:
        wanted = {"home": cfg.home_dir, "shell": "/usr/sbin/nologin", "group": cfg.group}
        for key, value in wanted.items():
            if existing.get(key) != value:
                logger.warning(
                    f"{host.name}: existing user {cfg.user} has {key} {existing.get(key)!r}, "
                    f"wanted {value!r}; left unchanged"
                )
        if cfg.group != existing.get("group") and cfg.group not in existing.get("groups", []):
            ops.append(
                server.user(
                    name=f"Add {cfg.user} to group {cfg.group}",
                    user=cfg.user,
                    groups=[cfg.group],
                    append=True,
                    create_home=False,
                    ensure_home=False,
                )
            )
    if not host.get_fact(Directory, path=cfg.home_dir):
        ops.append(
            files.directory(
                name=f"Create home {cfg.home_dir}", path=cfg.home_dir, user=cfg.user, group=cfg.group, mode="0750"
            )
        )
    return ops


def _uv(cfg: OpenWebUIConfig, *argv: str) -> str:
    """``uv <argv>`` as the service user from ``site_dir`` (uv looks for project files from the cwd)."""

    uv = f"{cfg.uv_install_dir}/uv"
    command = _as_user(cfg.user, PurePosixPath(cfg.home_dir), {"UV_NO_PROGRESS": "1"}, [uv, *argv])
    return f"cd {shlex.quote(cfg.site_dir)} && {command}"


def install_command(cfg: OpenWebUIConfig) -> str:
    """``uv pip install open-webui==<version>`` with the floors and the shipped constraints (from stdin).

    The constraints arrive on stdin into a temporary file the service user can
    read, which is removed whatever uv answers.
    """

    argv = ["pip", "install", "--python", cfg.venv, f"{DISTRIBUTION}=={cfg.version}"]
    if cfg.python_security_floor_enabled:
        argv += ["--constraints", cfg.security_constraints]
    install = _uv(cfg, *argv) + ' --constraints "$constraints"'
    return (
        'constraints=$(mktemp) && cat > "$constraints" && chmod 0644 "$constraints" && '
        f'{{ {install}; status=$?; rm -f "$constraints"; exit $status; }}'
    )


def _python(cfg: OpenWebUIConfig, state: str) -> list[OperationMeta]:
    """python.yml: interpreter, virtualenv and package, each only when the host needs it."""

    ops: list[OperationMeta] = []
    if state != "current":
        if state == "recreate":
            logger.warning(f"{host.print_prefix}Open WebUI virtualenv {cfg.venv} is not Python {cfg.python_version}")
        ops.append(
            server.shell(
                name=f"Install Python {cfg.python_version} via uv",
                commands=[_uv(cfg, "python", "install", cfg.python_version)],
            )
        )
        ops.append(
            server.shell(
                name=f"Create virtual environment {cfg.venv}",
                commands=[
                    f"rm -rf -- {shlex.quote(cfg.venv)}",
                    _uv(cfg, "venv", "--managed-python", "--python", cfg.python_version, cfg.venv),
                ],
            )
        )
    if state != "current" or installed_version(cfg) != cfg.version:
        ops.append(
            server.shell(
                name=f"Install Open WebUI {cfg.version} via uv pip",
                commands=[install_command(cfg)],
                **stdin_arguments(shipped_constraints()[cfg.version]),
            )
        )
        verify_probe(installed_probe(cfg), name=f"Open WebUI {cfg.version} installed", expect=cfg.version)
    return ops


def _directories(cfg: OpenWebUIConfig) -> None:
    """directories.yml."""

    for path in (cfg.site_dir, cfg.data_dir, cfg.log_dir):
        files.directory(name=f"Ensure {path}", path=path, user=cfg.user, group=cfg.group, mode="0755")


@deploy("Deploy Open WebUI")
def deploy_open_webui(cfg: OpenWebUIConfig, basic_auth: BasicAuth | None = None) -> None:
    check_basic_auth(cfg, basic_auth)
    require_linux("open_webui")
    require_systemd("open_webui")
    for mount in cfg.mounts_required:
        quoted = shlex.quote(mount)
        mark_read_only(
            server.shell(
                name=f"Require the mount {mount}",
                commands=[
                    f"findmnt --mountpoint {quoted} >/dev/null || {{ echo {quoted}' is not mounted' >&2; exit 1; }}"
                ],
            )
        )
    port_preflight(cfg)
    python = PurePosixPath(cfg.venv) / "bin" / "python"
    home = PurePosixPath(cfg.home_dir)
    state = venv_state(cfg)
    if cfg.python_security_floor_enabled and state == "current":
        # Before any change, on an environment that is kept; certifi is not deferred (see the service docs).
        verify_trust(python, user=cfg.user, home=home, name="Open WebUI environment (before the deploy)")

    if cfg.manage_uv:
        deploy_uv_install(cfg=UvInstallConfig(install_dir=cfg.uv_install_dir))
    elif not host.get_fact(File, path=f"{cfg.uv_install_dir}/uv"):
        raise DeployError(f"open_webui: uv not found at {cfg.uv_install_dir}/uv; enable manage_uv or install uv")
    _user(cfg)
    _directories(cfg)
    env_op = secret_file(
        name=f"Write {cfg.env_file}",
        path=cfg.env_file,
        content=SecretContent(render_env(cfg)),
        user="root",
        group="root",
        mode="0600",
    )
    if cfg.python_security_floor_enabled:
        files.put(
            name=f"Write the certifi/pip install constraints {cfg.security_constraints}",
            src=StringIO(security_constraints_text()),
            dest=cfg.security_constraints,
            user=cfg.user,
            group=cfg.group,
            mode="0644",
        )
    python_ops = _python(cfg, state)
    if cfg.python_security_floor_enabled:
        verify_trust(python, user=cfg.user, home=home, name="Open WebUI environment")

    unit = systemd_unit(cfg.service_name, render_unit(cfg))
    service_rollout(cfg.service_name, units=[unit], restart_when=[env_op, *python_ops])

    if cfg.traefik_enabled:

        def renderer(route: TraefikRoute, auth_hash: str | None) -> str:
            return render_route(cfg, route, auth_hash)

        traefik_route(traefik_config(cfg, basic_auth), renderer=renderer, restart="none")

    if cfg.healthcheck_enabled:
        wait_port(
            cfg.host_port,
            host=cfg.healthcheck_host,
            retries=cfg.healthcheck_timeout * cfg.healthcheck_retries,
            delay=1,
            name="Wait for Open WebUI port to become available",
        )
        http_check(
            cfg.health_url,
            status=cfg.healthcheck_status,
            retries=cfg.healthcheck_retries,
            delay=5,
            timeout=cfg.healthcheck_timeout,
            name="Check Open WebUI HTTP endpoint",
        )
