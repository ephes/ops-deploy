"""opaq_app: daybook's ``services/opaq_app`` (Django + SQLite, gunicorn) behind a Traefik allowlist.

Port of the ``opaq_app_deploy`` Ansible role together with the steps around it
in ops-control's ``deploy-opaq-app.yml``: the guard against taking over a name
a static page still routes, the login and allowlist checks, and the Echoport
backup target and Nyxmon health check upserts. The env file, unit and Traefik
route are byte-identical to the role's (``tests/test_opaq_app_parity.py``), so
Ansible and ops-deploy can take turns on one host without churn. The database
lives in ``data/``, outside the synced tree, so no sync can remove it.

Not ported: the ``uv_install`` role (uv must already be at
``/usr/local/bin/uv``) and the playbook's second play, which hands the upload
token to the Atlas workstation (macOS, out of scope for this campaign).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Generator
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pyinfra import host
from pyinfra.api import FunctionCommand, OperationError, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File
from pyinfra.facts.server import Command
from pyinfra.operations import files, server

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.core.templates import render
from ops_deploy.helpers import (
    TraefikRoute,
    mark_read_only,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    wait_port,
)
from ops_deploy.helpers.python import _as_user, _gate
from ops_deploy.helpers.traefik import Hostname
from ops_deploy.ops import secret_file, sync_tree

TEMPLATE_PACKAGE = "ops_deploy.services.opaq_app"
FILES = Path(__file__).parent / "files"
ECHOPORT_TARGET = (FILES / "echoport_target.py").read_text()
NYXMON_CHECK = (FILES / "nyxmon_check.py").read_text()

SECRET_KEY = re.compile(r"^[A-Za-z0-9_-]{50,}$")
Name = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")]
SourceEntry = Annotated[str, Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$")]
# Fetch ``url`` (verifying the certificate or not) without following redirects:
# (status, Location header).
Fetcher = Callable[[str, bool], tuple[int, str]]


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EchoportTarget(_Part):
    """The playbook's Echoport backup target upsert (needs Echoport on the host).

    Like the playbook, every deploy sets the target's fields, the schedule
    included; a deploy that finds them as wanted writes nothing.
    """

    name: Name = "opaq_app"
    schedule: Annotated[str, Field(pattern=r"^\S+( \S+){4}$")] = "20 2 * * *"
    user: UnixUser = "echoport"
    site_path: PurePosixPath = PurePosixPath("/home/echoport/site")


class NyxmonCheck(_Part):
    """The playbook's Nyxmon health check upsert (needs Nyxmon on the host)."""

    service_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ._-]{1,64}$")] = "Opaq app"
    check_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9 ._-]{1,64}$")] = "Opaq app health"
    interval: int = Field(default=300, ge=30, le=86400)
    user: UnixUser = "nyxmon"
    site_path: PurePosixPath = PurePosixPath("/home/nyxmon/site")


class RouteChecks(_Part):
    """What the playbook's post-tasks check about the published route.

    ``controller_login`` (production): the controller itself requests
    ``https://<host>/`` and must be sent to the login. ``refused_address``: a
    request from the host to that address (its LAN address) must be refused
    with 403 by the allowlist. ``verify_tls`` off is for hosts with a
    self-signed default certificate.
    """

    controller_login: bool = False
    login_retries: int = Field(default=20, ge=1, le=200)
    login_delay: float = Field(default=3, ge=0, le=60)
    refused_address: Annotated[str, Field(pattern=r"^[0-9A-Fa-f.:]+$")] | None = None
    verify_tls: bool = True


class OpaqAppConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("django_secret_key", "upload_token")

    service_name: ServiceName = "opaq-app"
    user: UnixUser = "opaq-app"
    site_path: PurePosixPath = PurePosixPath("/home/opaq-app/site")
    # A daybook checkout.
    source_path: Path
    source_dirs: tuple[SourceEntry, ...] = ("src", "services/opaq_app")
    source_files: tuple[SourceEntry, ...] = ("pyproject.toml", "uv.lock")
    # Never shipped, and kept on the host across --delete.
    rsync_excludes: tuple[str, ...] = (
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        "*.sqlite3",
        "*.sqlite3-*",
        "staticfiles",
        ".env",
    )
    app_host: Literal["127.0.0.1"] = "127.0.0.1"
    app_port: int = Field(default=10065, ge=1024, le=65535)
    workers: int = Field(default=2, ge=1, le=64)
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    dependency_group: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")] = "opaq-app"
    traefik_enabled: bool = True
    traefik_host: Hostname | None = None
    traefik_entrypoint: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")] = "web-secure"
    traefik_http_entrypoint: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")] = "web"
    allowed_networks: tuple[str, ...] = ()
    # Refuse to deploy while this file exists (a static page's route for the same name).
    refuse_while_exists: PurePosixPath | None = None
    route_checks: RouteChecks = RouteChecks()
    echoport: EchoportTarget | None = None
    nyxmon_check: NyxmonCheck | None = None

    @field_validator("source_path")
    @classmethod
    def _source_is_a_checkout(cls, value: Path) -> Path:
        missing = [p for p in ("services/opaq_app/manage.py", "src/daybook/opaq_site.py") if not (value / p).is_file()]
        if missing:
            raise ValueError(f"source_path is not a daybook checkout (missing {', '.join(missing)})")
        return value

    @field_validator("allowed_networks")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("allowed_networks must contain CIDR ranges") from None
            if "/" not in item:
                raise ValueError("allowed_networks must contain CIDR ranges")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.traefik_enabled and (self.traefik_host is None or not self.allowed_networks):
            raise ValueError("Traefik needs traefik_host and a non-empty allowed_networks")
        if self.route_checks != RouteChecks() and not self.traefik_enabled:
            raise ValueError("route_checks need Traefik")
        missing = [p for p in (*self.source_dirs, *self.source_files) if not (self.source_path / p).exists()]
        if missing:
            raise ValueError(f"source_path lacks {', '.join(missing)}")
        return self

    @property
    def home(self) -> PurePosixPath:
        return PurePosixPath("/home") / self.user

    @property
    def data_path(self) -> PurePosixPath:
        return self.home / "data"

    @property
    def database_path(self) -> PurePosixPath:
        return self.data_path / "db.sqlite3"

    @property
    def static_root(self) -> PurePosixPath:
        return self.home / "static"

    @property
    def env_path(self) -> PurePosixPath:
        return self.home / "opaq-app.env"

    @property
    def venv_path(self) -> PurePosixPath:
        return self.home / "venv"

    @property
    def app_dir(self) -> PurePosixPath:
        return self.site_path / "services" / "opaq_app"


def check_secrets(secrets: SecretValues) -> None:
    """The role's and the playbook's asserts, naming keys only."""

    secrets.require(OpaqAppConfig.required_secret_keys)
    if not SECRET_KEY.match(secrets["django_secret_key"]):
        raise ValueError("django_secret_key needs 50 or more characters of [A-Za-z0-9_-]")
    if len(secrets["upload_token"]) < 32:
        raise ValueError("upload_token needs 32 or more characters")


def upload_token_sha256(secrets: SecretValues) -> str:
    """The digest that reaches the host; the token itself never does."""

    return hashlib.sha256(secrets["upload_token"].encode()).hexdigest()


def traefik_config(cfg: OpaqAppConfig) -> TraefikRoute:
    assert cfg.traefik_host is not None
    return TraefikRoute(name=cfg.service_name, host=cfg.traefik_host, app_port=cfg.app_port, app_host=cfg.app_host)


def render_route(cfg: OpaqAppConfig) -> str:
    return render(
        TEMPLATE_PACKAGE, "opaq-app.traefik.yml.j2", cfg=cfg, allowed_networks_json=json.dumps(cfg.allowed_networks)
    )


def render_env(cfg: OpaqAppConfig, secrets: SecretValues) -> SecretContent:
    """The environment file (systemd ``EnvironmentFile`` and shell-sourceable)."""

    # The role's union filter has no defined order; the host name comes first here.
    names = [cfg.traefik_host] if cfg.traefik_host else []
    return SecretContent(
        render(
            TEMPLATE_PACKAGE,
            "opaq-app.env.j2",
            cfg=cfg,
            secret_key=secrets["django_secret_key"],
            upload_token_sha256=upload_token_sha256(secrets),
            allowed_hosts=",".join([*names, "127.0.0.1"]),
            csrf_trusted_origins=f"https://{cfg.traefik_host}" if cfg.traefik_host else "",
        )
    )


def _as(cfg_user: str, home: PurePosixPath, cwd: PurePosixPath, script: str, env: dict[str, str] | None = None) -> str:
    return f"cd {shlex.quote(str(cwd))} && {_as_user(cfg_user, home, env or {}, ['bash', '-c', script])}"


def _probe(command: str) -> str:
    return str(host.get_fact(Command, command=f"{command} 2>/dev/null || true") or "")


def _urllib_fetch(url: str, verify: bool) -> tuple[int, str]:
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: object, **kwargs: object) -> None:
            return None

    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(url, timeout=10) as response:
            return response.status, response.headers.get("Location", "")
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("Location", "")


def _await_login(url: str, fetch: Fetcher, verify: bool, retries: int, delay: float) -> None:
    seen = "nothing"
    for _ in range(retries):
        try:
            status, location = fetch(url, verify)
        except OSError as error:
            seen = type(error).__name__
        else:
            seen = str(status)
            if status == 302:
                if re.search(r"/login/\?next=/$", location):
                    return
                seen = "a redirect away from the login"
        time.sleep(delay)
    raise OperationError(f"an anonymous request to {url} answered {seen}, not the login redirect")


@operation()
def _controller_login(
    url: str, fetch: Fetcher, verify: bool, retries: int, delay: float
) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_await_login, (url, fetch, verify, retries, delay), {})


def _refused_check(cfg: OpaqAppConfig) -> OperationMeta:
    checks = cfg.route_checks
    assert cfg.traefik_host is not None
    assert checks.refused_address is not None
    curl = [
        "curl",
        "--silent",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--max-time",
        "10",
        "--resolve",
        f"{cfg.traefik_host}:443:{checks.refused_address}",
    ]
    if not checks.verify_tls:
        curl.append("--insecure")
    curl.append(f"https://{cfg.traefik_host}/login/")
    # Traefik's file provider picks the route up a moment after it is written.
    script = (
        f"for i in $(seq 1 20); do code=$({shlex.join(curl)} || true); "
        '[ "$code" = 403 ] && exit 0; sleep 3; done; '
        'echo "a request from the host answered ${code:-nothing}, expected 403" >&2; exit 1'
    )
    return mark_read_only(
        server.shell(
            name="Check the allowlist refuses the host's own address", commands=[f"sh -c {shlex.quote(script)}"]
        )
    )


def _port_preflight(cfg: OpaqAppConfig) -> OperationMeta:
    """The playbook's port preflight: nothing but opaq-app may listen on the app port.

    Like ``common/preflight_ports.yml`` with ``bind: loopback``: a TCP listener
    on the port at a loopback or wildcard address fails the deploy unless every
    process behind it runs in ``opaq-app.service``. Read-only; runs before any
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
        server.shell(name=f"Port preflight tcp/{cfg.app_port}", commands=[f"sh -c {shlex.quote(script)}"])
    )


def _health_check(cfg: OpaqAppConfig) -> OperationMeta:
    url = f"http://{cfg.app_host}:{cfg.app_port}/healthz"
    script = (
        "for i in $(seq 1 20); do "
        f"body=$(curl -sS --max-time 5 -w '|%{{http_code}}' {shlex.quote(url)} 2>/dev/null); "
        '[ "$body" = "ok|200" ] && exit 0; sleep 3; done; '
        f'echo "{url} did not answer ok" >&2; exit 1'
    )
    return mark_read_only(server.shell(name=f"Check {url}", commands=[f"sh -c {shlex.quote(script)}"]))


def _upsert(
    *,
    name: str,
    user: str,
    cwd: PurePosixPath,
    python: PurePosixPath,
    code: str,
    env_name: str,
    params: dict[str, object],
    preamble: str = "",
) -> None:
    """Run ``code`` through ``manage.py shell`` twice: a read-only probe, then (if pending) the write."""

    manage = shlex.quote(str(cwd / "manage.py"))
    home = PurePosixPath("/home") / user

    def command(apply: bool) -> str:
        env = {env_name: json.dumps({**params, "apply": apply}, separators=(",", ":"))}
        script = f"{preamble}exec {shlex.quote(str(python))} {manage} shell -c {shlex.quote(code)}"
        return _as(user, home, cwd, script, env)

    installed = _probe(f"test -f {manage} && echo installed")
    state = _probe(command(apply=False)).strip().splitlines()
    server.shell(
        name=f"Require {name}",
        commands=[f"test -f {manage} || {{ echo '{name} must be deployed before opaq_app' >&2; exit 1; }}"],
        _if=lambda: installed.strip() != "installed",
    )
    server.shell(
        name=f"Upsert {name} entry",
        commands=[command(apply=True)],
        _if=lambda: not state or state[-1] != "unchanged",
    )


def _echoport(cfg: OpaqAppConfig, target: EchoportTarget) -> None:
    _upsert(
        name="Echoport",
        user=target.user,
        cwd=target.site_path,
        python=target.site_path / ".venv/bin/python",
        code=ECHOPORT_TARGET,
        env_name="OPAQ_ECHOPORT",
        params={
            "name": target.name,
            "schedule": target.schedule,
            "db_path": str(cfg.database_path),
            "service_name": f"{cfg.service_name}.service",
            "restore_owner": f"{cfg.user}:{cfg.user}",
        },
    )


def _nyxmon(cfg: OpaqAppConfig, check: NyxmonCheck) -> None:
    _upsert(
        name="Nyxmon",
        user=check.user,
        cwd=check.site_path,
        python=check.site_path / ".venv/bin/python",
        code=NYXMON_CHECK,
        env_name="OPAQ_NYXMON",
        params={
            "service_name": check.service_name,
            "check_name": check.check_name,
            "url": f"http://{cfg.app_host}:{cfg.app_port}/healthz",
            "interval": check.interval,
            "data": {"timeout": 5, "retries": 1, "retry_delay": 2},
        },
        # Nyxmon's own settings come from its shell-safe environment file.
        preamble=f"set -e; set -a; . {shlex.quote(str(check.site_path / '.env.shell'))}; set +a; ",
    )


@deploy("Deploy opaq_app service")
def deploy_opaq_app(
    cfg: OpaqAppConfig,
    secrets: SecretValues,
    rsync: RsyncRunner = subprocess_rsync_runner,
    fetch: Fetcher = _urllib_fetch,
) -> None:
    check_secrets(secrets)
    env_content = render_env(cfg, secrets)

    _port_preflight(cfg)
    if cfg.refuse_while_exists is not None:
        path = shlex.quote(str(cfg.refuse_while_exists))
        server.shell(
            name="Refuse to take over a name a static page routes",
            commands=[
                f"test ! -e {path} || {{ echo '{cfg.refuse_while_exists} still routes this name' >&2; exit 1; }}"
            ],
        )

    user, home, site = cfg.user, cfg.home, cfg.site_path
    # Real figures live here: nothing is readable by others.
    system_user(
        user,
        home=home,
        shell="/usr/sbin/nologin",
        mode="0700",
        directories=[site, site / "services", cfg.data_path, cfg.static_root],
    )

    synced: list[OperationMeta] = [
        sync_tree(
            name=f"Sync {name}",
            src=cfg.source_path / name,
            dest=site / name,
            excludes=cfg.rsync_excludes,
            runner=rsync,
            user=user,
            group=user,
        )
        for name in cfg.source_dirs
    ]
    project_files = [
        files.put(
            name=f"Copy {name}",
            src=str(cfg.source_path / name),
            dest=str(site / name),
            user=user,
            group=user,
            mode="0600",
        )
        for name in cfg.source_files
    ]
    code = [*synced, *project_files]
    tree, owner = shlex.quote(str(site)), f"{user}:{user}"
    exposed = f"find {tree} \\( ! -user {user} -o ! -group {user} -o -perm /077 \\) -print -quit"
    pending_privacy = _probe(exposed).strip()
    private = server.shell(
        name="Own and privatize the synced tree",
        commands=[f"chown -R {owner} {tree} && chmod -R u+rwX,go-rwx {tree}"],
        _if=lambda: bool(pending_privacy) or any(meta.did_change() for meta in synced),
    )

    # Only the app's dependency group: daybook's own modules come from the
    # synced src/ via PYTHONPATH, so none of its desktop dependencies are installed.
    interpreter = shlex.quote(str(cfg.venv_path / "bin" / "python"))
    venv_missing = _probe(f"test -x {interpreter} && echo present").strip() != "present"
    running = _probe(
        _as(user, home, site, f"exec {interpreter} -c 'import sys; print(\"%d.%d\" % sys.version_info[:2])'")
    ).strip()
    stale_python = bool(running) and running != cfg.python_version
    uv_args = [
        "sync",
        "--frozen",
        "--only-group",
        cfg.dependency_group,
        "--no-install-project",
        "--python",
        cfg.python_version,
    ]
    uv_env = {"UV_PROJECT_ENVIRONMENT": str(cfg.venv_path), "UV_PYTHON_INSTALL_DIR": str(home / "python")}

    def uv(*extra: str) -> str:
        return f"cd {tree} && " + _as_user(user, home, uv_env, ["/usr/local/bin/uv", *uv_args, *extra])

    # A venv that is not in sync with the lock (an earlier run died after the
    # files were copied) is as pending as new files.
    out_of_sync = venv_missing or _probe(f"{uv('--check')} >/dev/null && echo ok").strip() != "ok"
    deps = server.shell(
        name=f"uv sync {site} ({cfg.dependency_group})",
        commands=[uv()],
        _if=_gate(project_files, force=out_of_sync or stale_python),
    )

    env = secret_file(
        name="Write environment file", path=cfg.env_path, content=env_content, mode="0600", user=user, group=user
    )

    database_missing = host.get_fact(File, path=str(cfg.database_path)) is None
    env_file = shlex.quote(str(cfg.env_path))
    python = shlex.quote(str(cfg.venv_path / "bin" / "python"))
    # Private by construction: bytecode caches written into the synced tree
    # would otherwise be readable by others and make the next run privatize
    # the tree (and so migrate and restart) again.
    script = (
        f"umask 077; set -euo pipefail; set -a; . {env_file}; set +a; "
        f"{python} manage.py migrate --noinput; {python} manage.py collectstatic --noinput --clear"
    )
    triggers = [*code, private, deps, env]
    # Unapplied migrations (an earlier run died after the sync) are pending too. The
    # probe runs at plan time, so it must leave nothing behind: no bytecode caches.
    check = (
        f"umask 077; export PYTHONDONTWRITEBYTECODE=1; set -a; . {env_file}; set +a; "
        f"{python} manage.py migrate --check --noinput >/dev/null && echo ok"
    )
    unmigrated = database_missing or venv_missing or _probe(_as(user, home, cfg.app_dir, check)).strip() != "ok"
    manage = server.shell(
        name="manage.py migrate and collectstatic",
        commands=[_as(user, home, cfg.app_dir, script)],
        _if=lambda: unmigrated or any(meta.did_change() for meta in triggers),
    )
    files.file(
        name="Restrict the database",
        path=str(cfg.database_path),
        user=user,
        group=user,
        mode="0600",
    )

    unit = systemd_unit(cfg.service_name, render(TEMPLATE_PACKAGE, "opaq-app.service.j2", cfg=cfg))
    if cfg.traefik_enabled:
        # The role writes the file and relies on the file provider's watch.
        traefik_route(traefik_config(cfg), renderer=lambda _route, _hash: render_route(cfg), restart="none")
    service_rollout(cfg.service_name, units=[unit], restart_when=[*triggers, manage])

    wait_port(cfg.app_port, host=cfg.app_host)
    _health_check(cfg)
    if cfg.route_checks.controller_login:
        mark_read_only(
            _controller_login(
                name="Check an anonymous request is sent to the login",
                url=f"https://{cfg.traefik_host}/",
                fetch=fetch,
                verify=cfg.route_checks.verify_tls,
                retries=cfg.route_checks.login_retries,
                delay=cfg.route_checks.login_delay,
            )
        )
    if cfg.route_checks.refused_address is not None:
        _refused_check(cfg)
    if cfg.echoport is not None:
        _echoport(cfg, cfg.echoport)
    if cfg.nyxmon_check is not None:
        _nyxmon(cfg, cfg.nyxmon_check)
