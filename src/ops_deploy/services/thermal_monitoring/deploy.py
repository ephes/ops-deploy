"""Thermal monitoring: the thermal exporter, its cached authenticated endpoint and a Nyxmon freshness check.

Port of the ``thermal_metrics_exporter`` and ``thermal_metrics_endpoint``
Ansible roles together with the play around them on the private side (the
endpoint bound to the host's Tailscale IPv4 address, then one Nyxmon
json-metrics check of the endpoint's freshness, upserted like the shared
``tasks/upsert-nyxmon-json-metrics-check.yml``). The roles' templates ship
unchanged and are rendered the way Ansible's ``template`` module renders
them, so every file is byte-identical to the roles' and the tools can take
turns on a host without churn.

The endpoint's HTTP server is the role's Python script or the pinned Rust
``metrics-httpd`` (``httpd_impl``; the role's ``metrics_httpd_switch``, see
:mod:`ops_deploy.services._metrics_httpd`).

The endpoint password reaches the host only inside the htpasswd file
(``secret_file``) and the Nyxmon check data (the upsert's stdin): it is
compared with the installed bcrypt hash on the controller, so an unchanged
password never rewrites the file or restarts the endpoint.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import shlex
from functools import cache
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Any, ClassVar, Literal

import bcrypt
import jinja2
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StrictFloat, StrictInt, StrictStr, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.facts.server import Users
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only, service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.ops import secret_file
from ops_deploy.services import _metrics_httpd as metrics_httpd
from ops_deploy.services._nyxmon_json_metrics import JsonMetricsCheck, upsert_json_metrics_check
from ops_deploy.services.nyxmon_site_checks.deploy import PlainPath

TEMPLATE_PACKAGE = "ops_deploy.services.thermal_monitoring"
# The deploy's key for the endpoint password (also the Nyxmon check's login).
PASSWORD_KEY = "endpoint_password"
TAILSCALE: Literal["tailscale"] = "tailscale"
# ``systemctl show`` values of a timer without a next elapse (the role's list).
NOT_ARMED = frozenset({"", "infinity", "0", "n/a"})
ELAPSE_KEYS = ("NextElapseUSecRealtime", "NextElapseUSecMonotonic")
_BCRYPT = re.compile(r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _sensor_text(value: str) -> str:
    # The exporter embeds the sensor lists as JSON inside r'''...''': a quote
    # could end that literal, a control character has no place in a sensor spec.
    if _CONTROL.search(value) or "'" in value:
        raise ValueError("sensor values must not contain control characters or single quotes")
    return value


SensorText = Annotated[StrictStr, Field(min_length=1), AfterValidator(_sensor_text)]
SensorId = Annotated[StrictStr, Field(pattern=r"^[A-Za-z0-9_]+$")]
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]*$")]
Port = Annotated[StrictInt, Field(ge=1, le=65535)]
Seconds = Annotated[StrictInt, Field(ge=0)]
UnitWord = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")]
UrlPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")]
AuthUser = Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")]
Calendar = Annotated[str, Field(pattern=r"^[A-Za-z0-9*:/,.~-][A-Za-z0-9*:/,.~ -]*$")]


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)


class LmSensor(_Part):
    """An ``lm_sensors`` entry: ``sensors -j`` chip (by regex or NVMe device), feature and value key."""

    id: SensorId
    source_entity_id: SensorText
    chip_name_regex: SensorText | None = None
    device_path: SensorText | None = None
    feature_name: SensorText
    value_key: SensorText
    sensor_label: SensorText | None = None
    sensor_class: SensorText | None = None
    metric_kind: SensorText | None = None
    unit: SensorText | None = None

    @model_validator(mode="after")
    def _chip_selector(self) -> LmSensor:
        if self.chip_name_regex is None and (self.device_path is None or not self.device_path.startswith("/")):
            raise ValueError("lm sensors need chip_name_regex or an absolute device_path")
        return self


class SysfsSensor(_Part):
    """A ``sysfs`` entry: one file matched by an absolute glob, optionally scaled."""

    id: SensorId
    source_entity_id: SensorText
    value_path_glob: SensorText
    sensor_label: SensorText | None = None
    sensor_class: SensorText | None = None
    metric_kind: SensorText | None = None
    unit: SensorText | None = None
    scale: StrictInt | StrictFloat | None = None

    @model_validator(mode="after")
    def _absolute_finite(self) -> SysfsSensor:
        if not self.value_path_glob.startswith("/"):
            raise ValueError("value_path_glob must be absolute")
        if self.scale is not None and not math.isfinite(self.scale):
            raise ValueError("scale must be a finite number")
        return self


class IpmiSensor(_Part):
    """An ``ipmi`` entry: one ``ipmitool sensor list`` row by name."""

    id: SensorId
    sensor_name: SensorText
    source_entity_id: SensorText
    sensor_label: SensorText | None = None
    sensor_class: SensorText | None = None
    metric_kind: SensorText | None = None


class ThermalExporter(_Part):
    """The ``thermal_metrics_exporter`` role's variables without the prefix."""

    packages: tuple[Package, ...] = ("python3", "lm-sensors", "ipmitool")
    bin_path: PlainPath = PurePosixPath("/usr/local/bin/thermal-metrics-exporter")
    lm_sensors: tuple[LmSensor, ...] = ()
    sysfs_sensors: tuple[SysfsSensor, ...] = ()
    ipmi_sensors: tuple[IpmiSensor, ...] = ()


class ThermalMonitoringConfig(BaseServiceConfig, metrics_httpd.HttpdSwitchFields):
    """The ``thermal_metrics_endpoint`` role's variables, the exporter and the optional Nyxmon check.

    ``service_name`` is the endpoint's unit, ``user`` its system user and
    ``site_path`` its data directory (the role's ``data_dir``). ``bind`` is
    an IPv4 address or ``"tailscale"``: the address ``tailscale ip --4``
    prints on the host. ``httpd_impl``, ``httpd_rust_version`` and
    ``httpd_rust_sha256`` select the HTTP server (the role's
    ``thermal_metrics_endpoint_impl`` and the fleet pin).
    """

    required_secret_keys: ClassVar[tuple[str, ...]] = (PASSWORD_KEY,)

    service_name: ServiceName = "thermal-metrics-endpoint"
    user: UnixUser = "metrics"
    group: UnixUser | None = None
    site_path: PlainPath = PurePosixPath("/var/lib/thermal-metrics")
    bind: Literal["tailscale"] | ipaddress.IPv4Address = TAILSCALE
    port: Port = 9104
    path: UrlPath = "/.well-known/thermal"
    auth_user: AuthUser
    packages: tuple[Package, ...] = ("python3", "apache2-utils")
    server_path: PlainPath = PurePosixPath("/usr/local/bin/thermal_metrics_httpd.py")
    htpasswd_dir: PlainPath = PurePosixPath("/etc/thermal-metrics-endpoint")
    timer_name: UnitWord = "thermal-metrics-collector"
    timer_interval: Annotated[StrictInt, Field(ge=1)] = 300
    timer_on_boot_sec: Seconds = 30
    timer_on_calendar: Calendar = "*:0/5"
    timer_accuracy_sec: Seconds = 10
    timer_randomized_delay_sec: Seconds = 30
    exporter: ThermalExporter = ThermalExporter()
    nyxmon_check: JsonMetricsCheck | None = None

    @model_validator(mode="after")
    def _consistent(self) -> ThermalMonitoringConfig:
        if self.auth_user == "CHANGE_ME":
            raise ValueError("auth_user is still the role's CHANGE_ME placeholder")
        check = self.nyxmon_check
        if check is not None and check.auth_username not in (None, self.auth_user):
            raise ValueError("nyxmon_check.auth_username must be the endpoint's auth_user")
        return self

    @property
    def group_name(self) -> str:
        return self.group or self.user

    @property
    def json_path(self) -> PurePosixPath:
        return self.site_path / "thermal.json"

    @property
    def htpasswd_path(self) -> PurePosixPath:
        return self.htpasswd_dir / "htpasswd"


class ThermalCheckConfig(BaseServiceConfig):
    """Only the Nyxmon freshness check of a thermal endpoint that another host serves.

    The play around the roles may upsert its check on the Nyxmon host rather
    than on the endpoint's host (two plays, two hosts); this is that second
    play on its own: the same check (``JsonMetricsCheck``) through the same
    upsert as :class:`ThermalMonitoringConfig`'s ``nyxmon_check``, with the
    endpoint password as the check's login. ``service_name``, ``user`` and
    ``site_path`` name the Nyxmon instance the row lands in; nothing else
    happens on that host.
    """

    required_secret_keys: ClassVar[tuple[str, ...]] = (PASSWORD_KEY,)

    service_name: ServiceName = "nyxmon"
    user: UnixUser = "nyxmon"
    site_path: PlainPath = PurePosixPath("/home/nyxmon/site")
    nyxmon_check: JsonMetricsCheck

    @model_validator(mode="after")
    def _the_check_is_this_nyxmon(self) -> ThermalCheckConfig:
        check = self.nyxmon_check
        if check.user != self.user or check.db_path != self.site_path / "db.sqlite3":
            raise ValueError("nyxmon_check must write this Nyxmon (its user and site_path/db.sqlite3)")
        return self


def role_vars(cfg: ThermalMonitoringConfig, bind: str = "127.0.0.1") -> dict[str, Any]:
    """The roles' variables for ``cfg``, as the templates read them."""

    exporter = cfg.exporter
    return {
        "thermal_metrics_exporter_lm_sensors": [s.model_dump(exclude_none=True) for s in exporter.lm_sensors],
        "thermal_metrics_exporter_sysfs_sensors": [s.model_dump(exclude_none=True) for s in exporter.sysfs_sensors],
        "thermal_metrics_exporter_ipmi_sensors": [s.model_dump(exclude_none=True) for s in exporter.ipmi_sensors],
        "thermal_metrics_endpoint_user": cfg.user,
        "thermal_metrics_endpoint_group": cfg.group_name,
        "thermal_metrics_endpoint_bind": bind,
        "thermal_metrics_endpoint_port": cfg.port,
        "thermal_metrics_endpoint_path": cfg.path,
        "thermal_metrics_endpoint_data_dir": str(cfg.site_path),
        "thermal_metrics_endpoint_json_path": str(cfg.json_path),
        "thermal_metrics_endpoint_server_path": str(cfg.server_path),
        "thermal_metrics_endpoint_htpasswd_path": str(cfg.htpasswd_path),
        "thermal_metrics_endpoint_exporter_path": str(exporter.bin_path),
        "thermal_metrics_endpoint_timer_interval": cfg.timer_interval,
        "thermal_metrics_endpoint_timer_on_boot_sec": cfg.timer_on_boot_sec,
        "thermal_metrics_endpoint_timer_on_calendar": cfg.timer_on_calendar,
        "thermal_metrics_endpoint_timer_accuracy_sec": cfg.timer_accuracy_sec,
        "thermal_metrics_endpoint_timer_randomized_delay_sec": cfg.timer_randomized_delay_sec,
    }


@cache
def _environment() -> jinja2.Environment:
    """The role templates, rendered with the options and filters of Ansible's ``template`` module."""

    env = jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["to_json"] = lambda value: json.dumps(value)
    return env


def render_role(template: str, cfg: ThermalMonitoringConfig, bind: str = "127.0.0.1") -> str:
    return _environment().get_template(template).render(**role_vars(cfg, bind))


def render_exporter(cfg: ThermalMonitoringConfig) -> str:
    return render_role("thermal-metrics-exporter.py.j2", cfg)


def render_httpd(cfg: ThermalMonitoringConfig) -> str:
    return render_role("thermal_metrics_httpd.py.j2", cfg)


def render_collector_service(cfg: ThermalMonitoringConfig) -> str:
    return render_role("thermal-metrics-collector.service.j2", cfg)


def render_collector_timer(cfg: ThermalMonitoringConfig) -> str:
    return render_role("thermal-metrics-collector.timer.j2", cfg)


def render_endpoint_unit(cfg: ThermalMonitoringConfig, bind: str) -> str:
    return render_role("thermal-metrics-endpoint.service.j2", cfg, bind)


def httpd_endpoint(cfg: ThermalMonitoringConfig, bind: str) -> metrics_httpd.Endpoint:
    """The role's ``metrics_httpd_switch`` inputs; argv, sandbox and IP filter mirror the endpoint unit."""

    return metrics_httpd.Endpoint(
        service_name=cfg.service_name,
        argv=(
            *("json-file", "--bind", bind, "--port", str(cfg.port), "--path", cfg.path),
            *("--json-path", str(cfg.json_path), "--htpasswd-file", str(cfg.htpasswd_path)),
            *("--realm", "thermal-metrics", "--server-name", "thermal-metrics-httpd/0.1"),
        ),
        user=cfg.user,
        group=cfg.group_name,
        sandbox=(
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            f"ReadOnlyPaths={cfg.site_path}",
        ),
        python_script=str(cfg.server_path),
        probe_bind=bind,
        probe_port=cfg.port,
        probe_path=cfg.path,
        probe_realm="thermal-metrics",
        ip_address_allow=("localhost", "100.64.0.0/10"),
    )


def _password(secrets: SecretValues) -> str:
    password = secrets.get(PASSWORD_KEY, "")
    if not password or password == "CHANGE_ME":
        raise DeployError(f"thermal_monitoring: the secret {PASSWORD_KEY} is missing, empty or CHANGE_ME")
    # htpasswd reads one line and C strings end at NUL: a control character
    # would make the endpoint check another password than the one verified here.
    if _CONTROL.search(password) or len(password.encode()) > 72:
        raise DeployError(
            f"thermal_monitoring: {PASSWORD_KEY} must be at most 72 bytes (bcrypt) without control characters"
        )
    return password


def _bind(cfg: ThermalMonitoringConfig) -> str:
    if cfg.bind != TAILSCALE:
        return str(cfg.bind)
    words = (probe("tailscale ip --4", name="Tailscale IPv4 address") or "").split()
    try:
        return str(ipaddress.IPv4Address(words[0])) if len(words) == 1 else ""
    except ValueError:
        return ""


def _service_account(cfg: ThermalMonitoringConfig) -> None:
    """The role's group and no-login system user without a home directory (the distribution default)."""

    group = cfg.group_name
    server.group(name=f"Ensure group {group}", group=group, system=True)
    existing = host.get_fact(Users).get(cfg.user)
    if existing is None:
        server.user(
            name=f"Ensure user {cfg.user}",
            user=cfg.user,
            group=group,
            home=f"/home/{cfg.user}",
            shell="/usr/sbin/nologin",
            system=True,
            ensure_home=False,
            create_home=False,
        )
    elif existing.get("group") != group or existing.get("shell") != "/usr/sbin/nologin":
        logger.warning(f"{host.name}: existing user {cfg.user} differs from the endpoint's account; left unchanged")


def credentials_verify(lines: list[str] | None, user: str, password: str) -> bool:
    """Whether ``user``'s htpasswd line holds a bcrypt hash of ``password`` (``htpasswd -v``)."""

    for line in lines or ():
        name, sep, hashed = line.partition(":")
        if sep and name == user:
            hashed = hashed.strip()
            if not _BCRYPT.fullmatch(hashed):
                return False
            try:
                return bcrypt.checkpw(password.encode(), hashed.encode())
            except ValueError:
                return False
    return False


def _credentials(cfg: ThermalMonitoringConfig, password: str) -> list[OperationMeta]:
    """The role's verify-then-regenerate: the file is only written when the password does not verify.

    A verifying file keeps its content, but its owner and mode are still
    brought to ``root:<group> 0640``: the endpoint reads it as its user.
    """

    current = host.get_fact(FileContents, path=str(cfg.htpasswd_path))
    if credentials_verify(current, cfg.auth_user, password):
        files.file(
            name=f"Ensure owner and mode of {cfg.htpasswd_path}",
            path=str(cfg.htpasswd_path),
            user="root",
            group=cfg.group_name,
            mode="0640",
        )
        return []
    return [
        secret_file(
            name=f"Write {cfg.htpasswd_path}",
            path=cfg.htpasswd_path,
            content=SecretContent(f"{cfg.auth_user}:{hash_password(password)}\n"),
            user="root",
            group=cfg.group_name,
            mode="0640",
        )
    ]


def timer_armed(output: str) -> bool:
    """Whether ``systemctl show`` reports a next elapse (realtime or monotonic) for the timer."""

    values: dict[str, str] = {}
    for line in output.splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    return any(values.get(key, "").strip().lower() not in NOT_ARMED for key in ELAPSE_KEYS)


def armed_check(timer: str) -> str:
    """The role's re-read after the repair: up to six reads 2 s apart; fails if none shows a next elapse."""

    show = shlex.join(["systemctl", "show", timer, *(f"--property={key}" for key in (*ELAPSE_KEYS, "SubState"))])
    rule = " || ".join(f'$1 == "{key}"' for key in ELAPSE_KEYS)
    awk = (
        f'{rule} {{ v = tolower($2); gsub(/^ +| +$/, "", v); '
        'if (v != "" && v != "infinity" && v != "0" && v != "n/a") ok = 1 } END { exit !ok }'
    )
    message = f"{timer} has no next elapse (realtime or monotonic); the metrics payload would freeze. Observed:"
    return (
        f"i=0; while :; do out=$({show}) || out=''; "
        f"if printf '%s\\n' \"$out\" | awk -F= {shlex.quote(awk)}; then exit 0; fi; "
        'i=$((i + 1)); [ "$i" -gt 5 ] && break; sleep 2; done; '
        f'echo {shlex.quote(message)} "$out" >&2; exit 1'
    )


def _collector(cfg: ThermalMonitoringConfig, changed: list[OperationMeta]) -> None:
    """The role's first collector run, while there is no metrics file or the collector changed."""

    path = shlex.quote(str(cfg.json_path))
    state = probe(f"if test -e {path}; then echo present; else echo absent; fi", name="thermal metrics file")
    missing = (state or "").strip() != "present"
    service = f"{cfg.timer_name}.service"
    server.shell(
        name=f"Run {service} once",
        commands=[shlex.join(["systemctl", "start", service])],
        _if=lambda: missing or any(meta.did_change() for meta in changed),
    )


def _timer(cfg: ThermalMonitoringConfig, unit_file: OperationMeta) -> None:
    """Enable and start the timer, restart it on change, re-arm it when it elapsed without a next trigger."""

    timer = f"{cfg.timer_name}.timer"
    rollout = service_rollout(timer, restart_when=[unit_file])
    show = shlex.join(["systemctl", "show", timer, *(f"--property={key}" for key in ELAPSE_KEYS)])
    answer = probe(show, name=f"{timer} next elapse")
    if answer is None or not timer_armed(answer):
        # A timer this run wrote, started or restarted is armed by that.
        server.shell(
            name=f"Re-arm {timer}, which elapsed without a next trigger",
            commands=[shlex.join(["systemctl", "restart", timer])],
            _if=lambda: not any(meta.did_change() for meta in (unit_file, rollout.start, rollout.restart)),
        )
    mark_read_only(server.shell(name=f"Require an armed {timer}", commands=[armed_check(timer)]))


@deploy("Thermal endpoint check")
def deploy_thermal_check(cfg: ThermalCheckConfig, secrets: SecretValues) -> None:
    """The json-metrics check of a thermal endpoint served elsewhere, upserted into this host's Nyxmon."""

    # The endpoint password is required either way, and checked before any operation.
    password = _password(secrets)
    check = cfg.nyxmon_check
    upsert_json_metrics_check(check, password if check.auth_username is not None else None)


@deploy("Thermal monitoring")
def deploy_thermal_monitoring(cfg: ThermalMonitoringConfig, secrets: SecretValues) -> None:
    password = _password(secrets)
    bind = _bind(cfg)
    if not bind:
        raise DeployError("thermal_monitoring: `tailscale ip --4` printed no single IPv4 address; is Tailscale up?")
    exporter = cfg.exporter
    group = cfg.group_name

    # thermal_metrics_exporter
    apt.packages(name="Install the thermal exporter packages", packages=list(exporter.packages))
    exporter_file = files.put(
        name=f"Install {exporter.bin_path}",
        src=StringIO(render_exporter(cfg)),
        dest=str(exporter.bin_path),
        user="root",
        group="root",
        mode="0755",
    )

    # thermal_metrics_endpoint
    apt.packages(name="Install the thermal endpoint packages", packages=list(cfg.packages))
    _service_account(cfg)
    for directory in (cfg.site_path, cfg.htpasswd_dir):
        files.directory(name=f"Ensure {directory}", path=str(directory), user="root", group=group, mode="0750")
    httpd = files.put(
        name=f"Install {cfg.server_path}",
        src=StringIO(render_httpd(cfg)),
        dest=str(cfg.server_path),
        user="root",
        group="root",
        mode="0755",
    )
    credentials = _credentials(cfg, password)
    collector_unit = systemd_unit(f"{cfg.timer_name}.service", render_collector_service(cfg))
    timer_unit = systemd_unit(f"{cfg.timer_name}.timer", render_collector_timer(cfg))
    endpoint_unit = systemd_unit(cfg.service_name, render_endpoint_unit(cfg, bind))
    # Python or the pinned Rust metrics-httpd (drop-in metrics-httpd-impl.conf).
    selection = metrics_httpd.select(httpd_endpoint(cfg, bind), cfg)
    systemd.daemon_reload(
        name="Reload systemd for the thermal metrics units",
        _if=any_changed(collector_unit, timer_unit, endpoint_unit, selection.dropin),
    )
    _collector(cfg, [exporter_file, collector_unit])
    _timer(cfg, timer_unit)
    service_rollout(cfg.service_name, restart_when=[endpoint_unit, httpd, *credentials, selection.dropin])
    # The unit runs the selected server and answers 401 with its realm; then pin and prune.
    metrics_httpd.verify(selection)

    # The play's tasks: the Nyxmon freshness check of this endpoint.
    check = cfg.nyxmon_check
    if check is not None:
        upsert_json_metrics_check(check, password if check.auth_username is not None else None)
