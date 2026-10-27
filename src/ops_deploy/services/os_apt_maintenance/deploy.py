"""os_apt_maintenance: host-local apt maintenance timers, their state endpoint and Nyxmon checks.

Port of ops-library's ``os_apt_maintenance`` role as ops-control's
``deploy-os-apt-maintenance.yml`` runs it (the endpoint always on), and of
that playbook's second play, the Nyxmon upsert on the Nyxmon host. The role's
templates are shipped unchanged and rendered as Ansible's ``template`` module
renders them, so both engines write the same bytes and can take turns.

:func:`deploy_os_apt_maintenance` (one host) installs the runner
(``/usr/local/sbin/os-apt-maintenance``), the HTTP server, the maintenance and
index-refresh units and timers, the endpoint unit and its htpasswd file, and
selects the endpoint's HTTP server (Python or the pinned Rust
``metrics-httpd``, :mod:`ops_deploy.services._metrics_httpd`). As in the
role, ``state.json`` is created once (``--init-state``) when it is missing,
and only then the maintenance service runs (``run_on_first_deploy``); a host
that has its state never runs apt on a deploy. Unlike the role,
``systemctl daemon-reload`` runs only when a unit or drop-in changed, not on
every run, and the endpoint restarts once, after the state exists.

:func:`deploy_os_apt_maintenance_nyxmon` (the Nyxmon host) upserts one
json-metrics check per endpoint with the playbook's exact semantics (type,
URL, interval and data compared, ``disabled`` not; an update re-enables the
check but keeps its status), after a read-only digest probe. Current checks
skip the upsert; SQLite readers may still update WAL/SHM bookkeeping.

It owns neither ``unattended-upgrades`` nor ``/etc/apt``.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Callable
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal

import jinja2
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.helpers.systemd import systemd_unit
from ops_deploy.ops import secret_stdin
from ops_deploy.services import _metrics_httpd as httpd
from ops_deploy.services.metrics_endpoint.common import (
    Bind,
    EndpointConfig,
    Package,
    PlainPath,
    UrlPath,
    account,
    bind_address,
    credentials,
    password,
)

NYXMON_SCRIPT = (Path(__file__).parent / "files" / "nyxmon_checks.py").read_text()
# A systemd calendar or time span written unquoted into a unit: no line breaks or specifiers.
Calendar = Annotated[str, Field(pattern=r"^[A-Za-z0-9 *:/.,~-]+$")]
TimeSpan = Annotated[str, Field(pattern=r"^[0-9]+ ?[a-z]*$")]
Positive = Annotated[StrictInt, Field(ge=1)]
TimerState = Literal["started", "stopped"]


class OsAptMaintenanceConfig(EndpointConfig):
    """The role's variables without the ``os_apt_maintenance_`` prefix, with the playbook's values as defaults.

    The endpoint is always on (``endpoint_enabled: true`` in the playbook);
    its password is the deploy secret ``endpoint_password``. ``bind``
    ``tailscale`` is the playbook's ``tailscale ip --4``.
    """

    required_secret_keys: ClassVar[tuple[str, ...]] = ("endpoint_password",)
    enabled: StrictBool = True
    # The endpoint unit (the role's endpoint_service_name).
    service_name: ServiceName = "os-apt-maintenance-endpoint"
    bind: Bind = "tailscale"
    port: Annotated[StrictInt, Field(ge=1, le=65535)] = 9106
    path: UrlPath = "/.well-known/os-apt-maintenance"
    server_path: PlainPath = PurePosixPath("/usr/local/bin/os_apt_maintenance_httpd.py")
    htpasswd_dir: PlainPath = PurePosixPath("/etc/os-apt-maintenance-endpoint")
    packages: tuple[Package, ...] = ("python3", "apache2-utils")
    maintenance_packages: tuple[Package, ...] = ("python3",)
    endpoint_timeout: Positive = 10
    endpoint_state_max_age_seconds: Positive = 1296000
    ip_allow: tuple[Annotated[str, Field(pattern=r"^[0-9a-f.:/]+$")], ...] = ("100.64.0.0/10",)

    host_id: Annotated[str, Field(min_length=1, pattern=r"^[^\s\"'\\]+$")]
    state_dir: PlainPath = PurePosixPath("/var/lib/os-apt-maintenance")
    state_file: PlainPath | None = None
    lock_file: PlainPath = PurePosixPath("/run/os-apt-maintenance.lock")
    script_path: PlainPath = PurePosixPath("/usr/local/sbin/os-apt-maintenance")
    update_cache: StrictBool = True
    dist_upgrade: StrictBool = True
    autoremove: StrictBool = True
    autoclean: StrictBool = True
    auto_reboot: StrictBool = False
    apt_get_path: PlainPath = PurePosixPath("/usr/bin/apt-get")
    systemctl_path: PlainPath = PurePosixPath("/usr/bin/systemctl")
    command_timeout: Positive = 7200
    freshness_max_age_seconds: Positive = 1209600

    maintenance_service_name: ServiceName = "os-apt-maintenance"
    timer_on_calendar: Calendar = "Sun *-*-* 04:00:00"
    timer_randomized_delay_sec: TimeSpan = "4h"
    timer_accuracy_sec: TimeSpan = "1h"
    timer_persistent: StrictBool = True
    timer_enabled: StrictBool = True
    timer_state: TimerState = "started"
    run_on_deploy: StrictBool = False
    run_on_first_deploy: StrictBool = True

    refresh_enabled: StrictBool = True
    refresh_service_name: ServiceName = "os-apt-maintenance-refresh"
    refresh_timer_on_calendar: Calendar = "*-*-* 06:00:00"
    refresh_timer_randomized_delay_sec: TimeSpan = "1h"
    refresh_timer_accuracy_sec: TimeSpan = "10m"
    refresh_timer_persistent: StrictBool = True
    refresh_timer_enabled: StrictBool = True
    refresh_timer_state: TimerState = "started"
    refresh_command_timeout: Positive = 900

    @model_validator(mode="after")
    def _distinct_units(self) -> OsAptMaintenanceConfig:
        if self.refresh_enabled and self.refresh_service_name == self.maintenance_service_name:
            raise ValueError("refresh_service_name must differ from maintenance_service_name")
        return self

    @property
    def state_path(self) -> PurePosixPath:
        return self.state_file or self.state_dir / "state.json"


def role_vars(cfg: OsAptMaintenanceConfig, bind: str) -> dict[str, Any]:
    values: dict[str, Any] = {
        "host_id": cfg.host_id,
        "state_dir": str(cfg.state_dir),
        "state_file": str(cfg.state_path),
        "lock_file": str(cfg.lock_file),
        "script_path": str(cfg.script_path),
        "update_cache": cfg.update_cache,
        "dist_upgrade": cfg.dist_upgrade,
        "autoremove": cfg.autoremove,
        "autoclean": cfg.autoclean,
        "auto_reboot": cfg.auto_reboot,
        "apt_get_path": str(cfg.apt_get_path),
        "systemctl_path": str(cfg.systemctl_path),
        "command_timeout": cfg.command_timeout,
        "freshness_max_age_seconds": cfg.freshness_max_age_seconds,
        "service_name": cfg.maintenance_service_name,
        "timer_on_calendar": cfg.timer_on_calendar,
        "timer_randomized_delay_sec": cfg.timer_randomized_delay_sec,
        "timer_accuracy_sec": cfg.timer_accuracy_sec,
        "timer_persistent": cfg.timer_persistent,
        "refresh_service_name": cfg.refresh_service_name,
        "refresh_timer_on_calendar": cfg.refresh_timer_on_calendar,
        "refresh_timer_randomized_delay_sec": cfg.refresh_timer_randomized_delay_sec,
        "refresh_timer_accuracy_sec": cfg.refresh_timer_accuracy_sec,
        "refresh_timer_persistent": cfg.refresh_timer_persistent,
        "refresh_command_timeout": cfg.refresh_command_timeout,
        "endpoint_enabled": True,
        "endpoint_user": cfg.user,
        "endpoint_group": cfg.group_name,
        "endpoint_bind": bind,
        "endpoint_port": cfg.port,
        "endpoint_path": cfg.path,
        "endpoint_server_path": str(cfg.server_path),
        "endpoint_htpasswd_path": str(cfg.htpasswd_path),
        "endpoint_timeout": cfg.endpoint_timeout,
        "endpoint_state_max_age_seconds": cfg.endpoint_state_max_age_seconds,
        "endpoint_ip_allow": list(cfg.ip_allow),
    }
    return {f"os_apt_maintenance_{key}": value for key, value in values.items()}


def _as_bool(value: Any) -> bool:
    return value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")


@cache
def environment() -> jinja2.Environment:
    """The role's templates with the options and filters of Ansible's ``template`` module."""

    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.os_apt_maintenance", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["bool"] = _as_bool
    env.filters["to_json"] = lambda value: json.dumps(value)
    return env


def render_role(template: str, cfg: OsAptMaintenanceConfig, bind: str) -> str:
    return environment().get_template(template).render(**role_vars(cfg, bind))


def httpd_endpoint(cfg: OsAptMaintenanceConfig, bind: str) -> httpd.Endpoint:
    """The role's ``metrics_httpd_switch_*`` inputs (argv, sandbox and IP allow list of the unit)."""

    state, htpasswd = str(cfg.state_path), str(cfg.htpasswd_path)
    return httpd.Endpoint(
        service_name=cfg.service_name,
        argv=(
            *("apt-state", "--bind", bind, "--port", str(cfg.port), "--path", cfg.path),
            *("--json-path", state, "--htpasswd-file", htpasswd),
            *("--freshness-max-age", str(cfg.freshness_max_age_seconds)),
            *("--state-max-age", str(cfg.endpoint_state_max_age_seconds)),
            *("--realm", "os-apt-maintenance", "--server-name", "os-apt-maintenance-httpd/0.1"),
        ),
        user=cfg.user,
        group=cfg.group_name,
        sandbox=(
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            f"ReadOnlyPaths={state}",
            f"ReadOnlyPaths={htpasswd}",
        ),
        python_script=str(cfg.server_path),
        probe_bind=bind,
        probe_port=cfg.port,
        probe_path=cfg.path,
        probe_realm="os-apt-maintenance",
        ip_address_allow=("localhost", *cfg.ip_allow),
    )


def endpoint_url(bind: str, cfg: OsAptMaintenanceConfig) -> str:
    """The URL Nyxmon polls (the playbook's ``os_apt_maintenance_nyxmon_url``)."""

    return f"http://{bind}:{cfg.port}{cfg.path}"


def _restart(unit: str, start: OperationMeta, triggers: list[OperationMeta]) -> None:
    """A handler's ``state: restarted``: after a trigger changed, unless this run just started the unit."""

    systemd.service(
        name=f"Restart {unit}",
        service=unit,
        running=None,
        restarted=True,
        _if=lambda: not start.did_change() and any(op.did_change() for op in triggers),
    )


def _timer(name: str, *, enabled: bool, state: TimerState, unit: OperationMeta) -> None:
    timer = f"{name}.timer"
    start = systemd.service(
        name=f"Ensure {timer} is {'enabled' if enabled else 'disabled'} and {state}",
        service=timer,
        running=state == "started",
        enabled=enabled,
    )
    if state == "started":
        _restart(timer, start, [unit])


def _refresh_off(cfg: OsAptMaintenanceConfig) -> list[OperationMeta]:
    """The role's refresh-disabled branch: stop and disable the timer, remove both units."""

    timer = f"{cfg.refresh_service_name}.timer"
    # A loaded timer can remain active after its unit file is removed. Let
    # systemd status facts decide; an absent/inactive/disabled unit is a no-op.
    systemd.service(
        name=f"Stop apt index refresh timer {timer}",
        service=timer,
        running=False,
        enabled=False,
        _ignore_errors=True,
    )
    return [
        files.file(
            name=f"Remove /etc/systemd/system/{cfg.refresh_service_name}.{kind}",
            path=f"/etc/systemd/system/{cfg.refresh_service_name}.{kind}",
            present=False,
        )
        for kind in ("service", "timer")
    ]


def _state(cfg: OsAptMaintenanceConfig) -> None:
    """``--init-state`` once when ``state.json`` is missing, then (first deploy) one maintenance run."""

    state = shlex.quote(str(cfg.state_path))
    found = probe(f"if test -e {state}; then echo present; else echo absent; fi", name="apt maintenance state")
    if found is None or found.strip() not in ("present", "absent"):
        # Never guess "first deploy": that would run apt.
        raise DeployError(f"cannot tell whether {cfg.state_path} exists; nothing initialized or run")
    first = found.strip() == "absent"
    if first:
        server.shell(
            name="Initialize apt maintenance state file without running apt",
            commands=[f"{shlex.quote(str(cfg.script_path))} --init-state"],
        )
    if cfg.run_on_deploy or (cfg.run_on_first_deploy and first):
        server.shell(
            name="Run apt maintenance once on deploy",
            commands=[f"systemctl start {shlex.quote(cfg.maintenance_service_name + '.service')}"],
        )
    owner = f"root:{cfg.group_name}"
    if first:
        server.shell(
            name="Ensure apt maintenance state permissions for endpoint",
            commands=[f"chown {owner} {state} && chmod 0640 {state}"],
        )
    else:
        files.file(
            name="Ensure apt maintenance state permissions for endpoint",
            path=str(cfg.state_path),
            user="root",
            group=cfg.group_name,
            mode="0640",
        )


@deploy("Deploy os apt maintenance")
def deploy_os_apt_maintenance(
    cfg: OsAptMaintenanceConfig,
    secrets: SecretValues,
    on_endpoint: Callable[[str], None] | None = None,
) -> None:
    """One host. ``on_endpoint`` is called (while planning) with the endpoint URL once the bind is known.

    The playbook sets the URL in its pre-tasks, before the role, so a host that
    fails later in the role still gets its Nyxmon check; the caller collects it
    the same way.
    """

    value = password(secrets)
    bind = bind_address(cfg)
    if on_endpoint is not None:
        on_endpoint(endpoint_url(bind, cfg))
    if not cfg.enabled:
        logger.info(f"{host.print_prefix}OS apt maintenance role disabled; endpoint URL fact retained.")
        return
    apt.packages(name="Install apt maintenance dependencies", packages=list(cfg.maintenance_packages))
    apt.packages(name="Install endpoint dependencies", packages=list(cfg.packages))
    account(cfg)
    files.directory(
        name="Ensure apt maintenance state directory exists",
        path=str(cfg.state_dir),
        user="root",
        group=cfg.group_name,
        mode="0750",
    )
    files.put(
        name="Deploy apt maintenance runner",
        src=StringIO(render_role("os_apt_maintenance.py.j2", cfg, bind)),
        dest=str(cfg.script_path),
        user="root",
        group="root",
        mode="0755",
    )
    units = [
        systemd_unit(f"{cfg.maintenance_service_name}.service", render_role("os-apt-maintenance.service.j2", cfg, bind))
    ]
    timer = systemd_unit(f"{cfg.maintenance_service_name}.timer", render_role("os-apt-maintenance.timer.j2", cfg, bind))
    units.append(timer)
    refresh_timer = None
    if cfg.refresh_enabled:
        units.append(
            systemd_unit(
                f"{cfg.refresh_service_name}.service", render_role("os-apt-maintenance-refresh.service.j2", cfg, bind)
            )
        )
        refresh_timer = systemd_unit(
            f"{cfg.refresh_service_name}.timer", render_role("os-apt-maintenance-refresh.timer.j2", cfg, bind)
        )
        units.append(refresh_timer)
    server_script = files.put(
        name="Deploy apt maintenance HTTP server",
        src=StringIO(render_role("os_apt_maintenance_httpd.py.j2", cfg, bind)),
        dest=str(cfg.server_path),
        user="root",
        group="root",
        mode="0755",
    )
    auth = credentials(cfg, value)
    endpoint_unit = systemd_unit(cfg.service_name, render_role("os-apt-maintenance-endpoint.service.j2", cfg, bind))
    units.append(endpoint_unit)
    # The role's first handler flush: systemd sees the units before the state is initialized.
    systemd.daemon_reload(name="Reload systemd for the apt maintenance units", _if=any_changed(*units))

    _state(cfg)
    selection = httpd.select(httpd_endpoint(cfg, bind), cfg)
    later = [selection.dropin]
    if not cfg.refresh_enabled:
        later += _refresh_off(cfg)
    systemd.daemon_reload(name="Reload systemd for the endpoint implementation", _if=any_changed(*later))

    _timer(cfg.maintenance_service_name, enabled=cfg.timer_enabled, state=cfg.timer_state, unit=timer)
    if refresh_timer is not None:
        _timer(
            cfg.refresh_service_name,
            enabled=cfg.refresh_timer_enabled,
            state=cfg.refresh_timer_state,
            unit=refresh_timer,
        )
    endpoint = f"{cfg.service_name}.service"
    start = systemd.service(
        name=f"Ensure {endpoint} is enabled and running", service=endpoint, running=True, enabled=True
    )
    _restart(endpoint, start, [server_script, *auth, endpoint_unit, selection.dropin])
    httpd.verify(selection)


# -- the playbook's second play: Nyxmon checks on the Nyxmon host ---------------------


class NyxmonTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    display_name: Annotated[str, Field(min_length=1)]
    url: Annotated[str, Field(pattern=r"^http://[^\s\"'\\]+$")]


class OsAptNyxmonConfig(BaseServiceConfig):
    """The playbook's Nyxmon play. ``targets`` in the playbook's fixed order; the password is ``endpoint_password``."""

    required_secret_keys: ClassVar[tuple[str, ...]] = ("endpoint_password",)
    service_name: ServiceName = "os-apt-maintenance-nyxmon"
    user: UnixUser = "nyxmon"
    site_path: PlainPath = PurePosixPath("/home/nyxmon/site")
    db_path: PlainPath = PurePosixPath("/home/nyxmon/site/db.sqlite3")
    nyxmon_service: Annotated[str, Field(min_length=1)] = "OS package maintenance"
    check_interval: Positive = 3600
    auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "nyxmon"
    targets: Annotated[tuple[NyxmonTarget, ...], Field(min_length=1)]


def nyxmon_checks(cfg: OsAptNyxmonConfig, secret: str) -> list[dict[str, Any]]:
    """The playbook's ``_nyxmon_checks_json``, decoded."""

    return [
        {
            "name": f"OS apt maintenance ({target.display_name})",
            "check_type": "json-metrics",
            "url": target.url,
            "check_interval": cfg.check_interval,
            "data": {
                "url": target.url,
                "timeout": 10.0,
                "retries": 1,
                "retry_delay": 2.0,
                "auth": {"username": cfg.auth_user, "password": secret},
                "checks": [
                    {"path": "$.summary.last_run_ok", "op": "==", "value": True, "severity": "critical"},
                    {"path": "$.summary.last_success_fresh", "op": "==", "value": True, "severity": "critical"},
                    {"path": "$.meta.state_file_fresh", "op": "==", "value": True, "severity": "warning"},
                    {"path": "$.reboot_required", "op": "==", "value": False, "severity": "warning"},
                ],
            },
        }
        for target in cfg.targets
    ]


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def nyxmon_current(probe_output: str | None, checks: list[dict[str, Any]]) -> bool:
    """Whether the probed database already holds the service and every check as ``apply`` would leave it."""

    if probe_output is None:
        return False
    lines = probe_output.splitlines()
    if "service present" not in lines:
        return False
    for check in checks:
        state = json.dumps(
            [check["check_type"], check["url"], int(check["check_interval"]), json.dumps(check["data"], sort_keys=True)]
        )
        if f"check {_digest(check['name'])} {_digest(state)}" not in lines:
            return False
    return True


def _nyxmon(cfg: OsAptNyxmonConfig, *args: str) -> str:
    return shlex.join(["runuser", "-u", cfg.user, "--", "python3", "-I", "-c", NYXMON_SCRIPT, *args])


@deploy("Upsert Nyxmon OS apt maintenance checks")
def deploy_os_apt_maintenance_nyxmon(cfg: OsAptNyxmonConfig, secrets: SecretValues) -> None:
    secret = password(secrets)
    db = shlex.quote(str(cfg.db_path))
    exists = (probe(f"if test -e {db}; then echo present; else echo absent; fi", name="Nyxmon database") or "").strip()
    if exists == "absent":
        logger.info(
            f"{host.print_prefix}Nyxmon DB not found at {cfg.db_path}, skipping OS apt maintenance check provisioning."
        )
        return
    checks = nyxmon_checks(cfg, secret)
    names = [check["name"] for check in checks]
    probe_command = _nyxmon(cfg, "probe", str(cfg.db_path), cfg.nyxmon_service, *names)
    found = probe(probe_command, name="Nyxmon OS apt maintenance checks")
    if not nyxmon_current(found, checks):
        payload = json.dumps({"db": str(cfg.db_path), "service": cfg.nyxmon_service, "checks": checks})
        secret_stdin(
            name="Upsert Nyxmon OS apt maintenance json-metrics checks",
            command=_nyxmon(cfg, "apply") + " >/dev/null",
            content=SecretContent(payload),
        )
    if found is None:
        mark_read_only(verify_probe(probe_command, name="Nyxmon OS apt maintenance checks"))
