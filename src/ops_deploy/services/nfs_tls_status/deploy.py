"""NFS-over-TLS status: an exporter on a timer, its authenticated JSON endpoint and Nyxmon checks.

Native to ops-deploy (no Ansible role behind it), shaped like
:mod:`ops_deploy.services.thermal_monitoring`: the root exporter
(``files/nfs_tls_status.py``, Python stdlib only) runs on a systemd timer and
writes ``<site_path>/status.json``; the endpoint serves that file in
metrics-httpd's ``json-file`` mode through the shared switch
(:mod:`ops_deploy.services._metrics_httpd`), with os_lifecycle's Python
``json-file`` server as the fallback, basic auth and the Tailscale bind. The
account, bind, htpasswd and port preflight are the shared ones of
:mod:`ops_deploy.services.metrics_endpoint.common`; the Nyxmon json-metrics
row is :mod:`ops_deploy.services._nyxmon_json_metrics`'s upsert, either on the
endpoint's host (``nyxmon_check``) or, for an endpoint another host serves,
with :func:`deploy_nfs_tls_status_check` on the Nyxmon host.

:meth:`NfsTlsStatusConfig.check_conditions` produces the json-metrics rules
that match the report; the report's keys are ids derived from unit names and
paths (:func:`status_id`) so they are plain JSONPath dot-notation names.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Literal

from pydantic import Field, StrictInt, model_validator
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base import RoleConfig
from ops_deploy.base._packages import install_packages
from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers import service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe
from ops_deploy.services import _metrics_httpd as metrics_httpd
from ops_deploy.services._nyxmon_json_metrics import JsonMetricsCheck, upsert_json_metrics_check
from ops_deploy.services.metrics_endpoint.common import (
    CREDENTIAL_FIELD,
    EndpointConfig,
    Package,
    PlainPath,
    Port,
    UrlPath,
    account,
    bind_address,
    credentials,
    password,
    port_preflight,
)
from ops_deploy.services.os_lifecycle.deploy import HTTPD_SCRIPT

EXPORTER_SCRIPT = (Path(__file__).parent / "files" / "nfs_tls_status.py").read_text()
# The deploy's key for the endpoint password (also the Nyxmon check's login).
PASSWORD_KEY = CREDENTIAL_FIELD
PYTHON = "/usr/bin/python3"
REALM = "nfs-tls-status"
SERVER_NAME = "nfs-tls-status-httpd/1"
SANDBOX = ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes")
ALLOW = ("localhost", "100.64.0.0/10")
_ID = re.compile(r"^[a-z][a-z0-9_]*$")

UnitName = Annotated[
    str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9@_.:\\-]*\.(service|socket|mount|automount|target|timer|path|swap)$")
]
MountSource = Annotated[str, Field(pattern=r"^[A-Za-z0-9._:/@\[\]-]{1,255}$")]
MountOption = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:/=-]{1,128}$")]


def status_id(text: str) -> str:
    """The report key of a unit name or path: lowercase, every run of other characters one ``_``."""

    key = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    if not _ID.fullmatch(key):
        raise ValueError("unit names and paths must give a report key starting with a letter")
    return key


def _unique(kind: str, ids: list[str]) -> None:
    if len(set(ids)) != len(ids):
        raise ValueError(f"{kind} must give distinct report keys (lowercase, non-alphanumerics as _)")


class NfsStatusMount(RoleConfig):
    """A mount that must be present: ``where`` mounted from ``source`` as ``fstype`` with ``required_options``.

    ``unit``: the mount unit that must be active as well (for example
    ``mnt-cryptdata-media.mount``).
    """

    where: PlainPath
    source: MountSource
    fstype: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,31}$")] = "nfs4"
    required_options: tuple[MountOption, ...] = ()
    unit: UnitName | None = None

    @property
    def id(self) -> str:
        return status_id(str(self.where))


class NfsTlsStatusConfig(EndpointConfig):
    """One host's NFS-over-TLS status report, its endpoint and an optional same-host Nyxmon check.

    ``service_name`` is the endpoint's unit, ``user`` its system user (the
    report's group), ``site_path`` the report's directory. ``bind`` is an
    IPv4 address or ``"tailscale"`` (the address ``tailscale ip --4`` prints).
    ``port`` has no default: each host picks a free one. ``units`` must be
    active; ``mounts`` present as configured; ``certificates`` are warned
    about below ``warn_days`` days and critical once expired. ``httpd_impl``,
    ``httpd_rust_version`` and ``httpd_rust_sha256`` select the HTTP server.
    """

    required_secret_keys: ClassVar[tuple[str, ...]] = (PASSWORD_KEY,)

    service_name: ServiceName = "nfs-tls-status-endpoint"
    user: UnixUser = "metrics"
    site_path: PlainPath = PurePosixPath("/var/lib/nfs-tls-status")
    bind: Literal["tailscale"] | ipaddress.IPv4Address = "tailscale"
    port: Port
    path: UrlPath = "/.well-known/nfs-tls"
    auth_user: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "nyxmon"
    packages: tuple[Package, ...] = ("python3", "apache2-utils", "openssl")
    server_path: PlainPath = PurePosixPath("/usr/local/lib/nfs-tls-status/nfs_tls_status_httpd.py")
    exporter_path: PlainPath = PurePosixPath("/usr/local/lib/nfs-tls-status/nfs_tls_status.py")
    htpasswd_dir: PlainPath = PurePosixPath("/etc/nfs-tls-status")
    timer_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")] = "nfs-tls-status-collector"
    timer_interval: Annotated[StrictInt, Field(ge=60, le=3600)] = 300
    units: tuple[UnitName, ...]
    mounts: tuple[NfsStatusMount, ...] = ()
    certificates: tuple[PlainPath, ...] = ()
    warn_days: Annotated[StrictInt, Field(ge=1, le=3650)] = 60
    nyxmon_check: JsonMetricsCheck | None = None

    @model_validator(mode="after")
    def _consistent(self) -> NfsTlsStatusConfig:
        _unique("units", [status_id(unit) for unit in self.units])
        _unique("mounts", [mount.id for mount in self.mounts])
        _unique("certificates", [status_id(str(path)) for path in self.certificates])
        check = self.nyxmon_check
        if check is not None and check.auth_username not in (None, self.auth_user):
            raise ValueError("nyxmon_check.auth_username must be the endpoint's auth_user")
        return self

    @property
    def json_path(self) -> PurePosixPath:
        return self.site_path / "status.json"

    @property
    def config_path(self) -> PurePosixPath:
        return self.htpasswd_dir / "config.json"

    @property
    def max_age_seconds(self) -> int:
        """Three timer intervals (900 s by default): a report older than that is stale."""

        return 3 * self.timer_interval

    def check_conditions(self) -> list[dict[str, Any]]:
        """The json-metrics rules of this report (Nyxmon compares a JSON path with a constant).

        Units and mounts: ``ok == true``, critical. Certificates: ``ok == true``
        (at least ``warn_days`` left), warning, and ``days_left > 0``,
        critical (a missing or unreadable certificate has ``days_left`` null,
        which fails the rule). The report must be younger than
        :attr:`max_age_seconds`, warning.
        """

        def rule(path: str, op: str, value: Any, severity: str) -> dict[str, Any]:
            return {"path": path, "op": op, "value": value, "severity": severity}

        rules = [rule("$.meta.age_seconds", "<", self.max_age_seconds, "warning")]
        rules += [rule(f"$.units.{status_id(unit)}.ok", "==", True, "critical") for unit in self.units]
        rules += [rule(f"$.mounts.{mount.id}.ok", "==", True, "critical") for mount in self.mounts]
        for path in self.certificates:
            key = status_id(str(path))
            rules += [
                rule(f"$.certificates.{key}.ok", "==", True, "warning"),
                rule(f"$.certificates.{key}.days_left", ">", 0, "critical"),
            ]
        return rules


class NfsTlsStatusCheckConfig(BaseServiceConfig):
    """Only the Nyxmon check of an NFS-over-TLS status endpoint that another host serves.

    The same check (``JsonMetricsCheck``, its rules from the endpoint's
    :meth:`NfsTlsStatusConfig.check_conditions`) through the same upsert as
    ``nyxmon_check``, with the endpoint password as the check's login.
    ``service_name``, ``user`` and ``site_path`` name the Nyxmon instance the
    row lands in; nothing else happens on that host.
    """

    required_secret_keys: ClassVar[tuple[str, ...]] = (PASSWORD_KEY,)

    service_name: ServiceName = "nyxmon"
    user: UnixUser = "nyxmon"
    site_path: PlainPath = PurePosixPath("/home/nyxmon/site")
    nyxmon_check: JsonMetricsCheck

    @model_validator(mode="after")
    def _the_check_is_this_nyxmon(self) -> NfsTlsStatusCheckConfig:
        check = self.nyxmon_check
        if check.user != self.user or check.db_path != self.site_path / "db.sqlite3":
            raise ValueError("nyxmon_check must write this Nyxmon (its user and site_path/db.sqlite3)")
        return self


# -- rendered files ------------------------------------------------------------------------


def render_config(cfg: NfsTlsStatusConfig) -> str:
    """The exporter's ``config.json``: every entry with its report key."""

    config = {
        "state_group": cfg.group_name,
        "warn_days": cfg.warn_days,
        "units": [{"id": status_id(unit), "unit": unit} for unit in cfg.units],
        "mounts": [
            {
                "id": mount.id,
                "where": str(mount.where),
                "source": mount.source,
                "fstype": mount.fstype,
                "required_options": list(mount.required_options),
                "unit": mount.unit,
            }
            for mount in cfg.mounts
        ],
        "certificates": [{"id": status_id(str(path)), "path": str(path)} for path in cfg.certificates],
    }
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def collect_command(cfg: NfsTlsStatusConfig) -> str:
    return shlex.join(
        [PYTHON, "-I", str(cfg.exporter_path), "--config", str(cfg.config_path), "--out", str(cfg.json_path)]
    )


def render_collector_service(cfg: NfsTlsStatusConfig) -> str:
    """Root (the certificates are root-only), read-only system, writing only ``site_path``."""

    return (
        "[Unit]\nDescription=Write the NFS-over-TLS status report\n\n"
        "[Service]\nType=oneshot\nUser=root\nGroup=root\n"
        f"ExecStart={collect_command(cfg)}\nTimeoutStartSec=120\n"
        "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\n"
        f"ReadWritePaths={cfg.site_path}\n"
    )


def render_timer(cfg: NfsTlsStatusConfig) -> str:
    # Relative to the timer's start and the last run: a (re)started timer is always armed.
    return (
        "[Unit]\nDescription=Write the NFS-over-TLS status report periodically\n\n"
        f"[Timer]\nOnActiveSec=30s\nOnUnitActiveSec={cfg.timer_interval}s\nAccuracySec=10s\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )


def endpoint_argv(cfg: NfsTlsStatusConfig, bind: str) -> tuple[str, ...]:
    """The metrics-httpd ``json-file`` command line (also the Python fallback's)."""

    return (
        *("json-file", "--bind", bind, "--port", str(cfg.port), "--path", cfg.path),
        *("--json-path", str(cfg.json_path), "--htpasswd-file", str(cfg.htpasswd_path)),
        *("--realm", REALM, "--server-name", SERVER_NAME),
    )


def render_endpoint_unit(cfg: NfsTlsStatusConfig, bind: str) -> str:
    argv = shlex.join(endpoint_argv(cfg, bind)[1:])
    return "\n".join(
        [
            "[Unit]",
            "Description=NFS-over-TLS status endpoint",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=exec",
            f"User={cfg.user}",
            f"Group={cfg.group_name}",
            f"ExecStart={PYTHON} -I {cfg.server_path} {argv}",
            "Restart=always",
            "RestartSec=5",
            *SANDBOX,
            "IPAddressDeny=any",
            *(f"IPAddressAllow={entry}" for entry in ALLOW),
            f"ReadOnlyPaths={cfg.site_path}",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def httpd_endpoint(cfg: NfsTlsStatusConfig, bind: str) -> metrics_httpd.Endpoint:
    return metrics_httpd.Endpoint(
        service_name=cfg.service_name,
        argv=endpoint_argv(cfg, bind),
        user=cfg.user,
        group=cfg.group_name,
        sandbox=(*SANDBOX, f"ReadOnlyPaths={cfg.site_path}"),
        python_script=str(cfg.server_path),
        probe_bind=bind,
        probe_port=cfg.port,
        probe_path=cfg.path,
        probe_realm=REALM,
        ip_address_allow=ALLOW,
    )


# -- the deploys ---------------------------------------------------------------------------


def _put(path: PurePosixPath, content: str, mode: str = "0644") -> OperationMeta:
    return files.put(
        name=f"Install {path}", src=StringIO(content), dest=str(path), user="root", group="root", mode=mode
    )


def _first_run(cfg: NfsTlsStatusConfig, changed: list[OperationMeta]) -> None:
    """Run the collector while there is no report yet or its inputs changed."""

    quoted = shlex.quote(str(cfg.json_path))
    state = probe(f"if test -e {quoted}; then echo present; else echo absent; fi", name="NFS-over-TLS status report")
    missing = (state or "").strip() != "present"
    service = f"{cfg.timer_name}.service"
    server.shell(
        name=f"Run {service} once",
        commands=[shlex.join(["systemctl", "start", service])],
        _if=lambda: missing or any(meta.did_change() for meta in changed),
    )


@deploy("NFS-over-TLS status")
def deploy_nfs_tls_status(cfg: NfsTlsStatusConfig, secrets: SecretValues) -> None:
    value = password(secrets)
    bind = bind_address(cfg)
    port_preflight(cfg, bind)
    # needrestart suspended and in list mode, as for the NFS packages: it must not
    # restart services (Samba, Docker) for libraries upgraded earlier.
    install_packages(cfg.packages, what="nfs_tls_status")
    account(cfg)  # also htpasswd_dir (root:<group> 0750), which holds config.json
    files.directory(
        name=f"Ensure {cfg.site_path}", path=str(cfg.site_path), user="root", group=cfg.group_name, mode="0750"
    )
    for directory in sorted({cfg.exporter_path.parent, cfg.server_path.parent}):
        files.directory(name=f"Ensure {directory}", path=str(directory), user="root", group="root", mode="0755")

    # The exporter on its timer.
    inputs = [_put(cfg.exporter_path, EXPORTER_SCRIPT), _put(cfg.config_path, render_config(cfg))]
    collector = systemd_unit(f"{cfg.timer_name}.service", render_collector_service(cfg))
    timer = systemd_unit(f"{cfg.timer_name}.timer", render_timer(cfg))
    reload = "Reload systemd for the NFS-over-TLS status collector"
    systemd.daemon_reload(name=reload, _if=any_changed(collector, timer))
    _first_run(cfg, [collector, *inputs])
    service_rollout(f"{cfg.timer_name}.timer", restart_when=[timer])

    # The endpoint: Python fallback or the pinned Rust metrics-httpd.
    httpd = [_put(cfg.server_path, HTTPD_SCRIPT), *credentials(cfg, value)]
    unit = systemd_unit(cfg.service_name, render_endpoint_unit(cfg, bind))
    selection = metrics_httpd.select(httpd_endpoint(cfg, bind), cfg)
    systemd.daemon_reload(name=f"Reload systemd for {cfg.service_name}", _if=any_changed(unit, selection.dropin))
    service_rollout(cfg.service_name, restart_when=[unit, selection.dropin, *httpd])
    metrics_httpd.verify(selection)

    check = cfg.nyxmon_check
    if check is not None:
        upsert_json_metrics_check(check, value if check.auth_username is not None else None)


@deploy("NFS-over-TLS status check")
def deploy_nfs_tls_status_check(cfg: NfsTlsStatusCheckConfig, secrets: SecretValues) -> None:
    """The json-metrics check of an endpoint served elsewhere, upserted into this host's Nyxmon."""

    # The endpoint password is required either way, and checked before any operation.
    value = password(secrets)
    check = cfg.nyxmon_check
    upsert_json_metrics_check(check, value if check.auth_username is not None else None)


__all__ = [
    "PASSWORD_KEY",
    "NfsStatusMount",
    "NfsTlsStatusCheckConfig",
    "NfsTlsStatusConfig",
    "deploy_nfs_tls_status",
    "deploy_nfs_tls_status_check",
    "status_id",
]
