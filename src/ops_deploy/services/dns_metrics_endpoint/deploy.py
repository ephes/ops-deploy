"""Authoritative-DNS health: root collector/timer and an authenticated endpoint (``dns_metrics_endpoint``).

Port of ops-library's ``dns_metrics_endpoint`` role. The role's templates are
vendored byte for byte (``templates/``) and rendered as Ansible's ``template``
module renders them, so a host the role set up converges without a change.

The deploy follows the role: its configuration checks (``validate.yml``, here
pydantic validators, so a bad value never reaches a host), the packages and
``dig -v``, the ``metrics`` account, the data and credentials directories, the
collector and HTTP server scripts, the bcrypt ``htpasswd`` entry (kept while it
verifies), the three units, the metrics-httpd implementation switch
(:mod:`ops_deploy.services._metrics_httpd`), one collector run when the JSON
file is missing or the collector changed, the enabled timer and endpoint, and
the switch's verification. A unit change reloads systemd; the endpoint is
restarted when its script, credentials, unit or drop-in changed, and the timer
when its unit changed (the role's handlers). Like the other endpoint ports, a
read-only preflight refuses a port another process listens on before anything
changes.
"""

from __future__ import annotations

import ipaddress
import json
import shlex
from functools import cache
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

import jinja2
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.facts.files import File
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import ServiceName
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.systemd import service_rollout, systemd_unit
from ops_deploy.services import _metrics_httpd as httpd
from ops_deploy.services.metrics_endpoint.common import (
    Bind,
    EndpointConfig,
    Package,
    PlainPath,
    Port,
    UrlPath,
    Word,
    account,
    bind_address,
    credentials,
    password,
    port_preflight,
)

Family = Literal["ipv4", "ipv6"]
Transport = Literal["udp", "tcp"]
# Dot-free: ids appear in Nyxmon JSON paths (``$.nameservers.<id>.ok``), whose resolver splits on dots.
NameserverId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
Label = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$", max_length=253)]
DnsName = Annotated[
    str,
    Field(
        max_length=254,
        pattern=r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9])?)*\.?$",
    ),
]
QType = Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9]{0,9}$")]
Positive = Annotated[StrictInt, Field(ge=1)]
Seconds = Annotated[StrictInt, Field(ge=0)]
Reason = Annotated[str, Field(min_length=1, max_length=500, pattern=r"^[^\x00-\x1f\x7f'\\]+$")]


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class Nameserver(_Part):
    """One entry of ``dns_metrics_endpoint_nameservers``; unset fields stay out of the collector's JSON."""

    id: NameserverId
    label: Label | None = None
    role: Label | None = None
    # An empty or missing address skips that family's endpoints of this nameserver.
    ipv4: str | None = None
    ipv6: str | None = None
    # Narrow the global matrix for this nameserver only (a proven vantage-point limitation).
    families: tuple[Family, ...] | None = None
    transports: tuple[Transport, ...] | None = None

    @field_validator("ipv4", "ipv6")
    @classmethod
    def _stripped(cls, value: str | None) -> str | None:
        if value is not None and value != value.strip():
            raise ValueError("addresses must not carry surrounding whitespace")
        return value

    def as_role(self) -> dict[str, Any]:
        """The entry as the role's variable (field order kept, unset fields dropped)."""

        return self.model_dump(mode="json", exclude_none=True)


class Limitation(_Part):
    """A matrix cell this vantage point provably cannot reach: ``<nameserver>-<family>-<transport>``."""

    id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*-ipv[46]-(udp|tcp)$")]
    reason: Reason


def _folded(name: str) -> str:
    return name.strip().lower().removesuffix(".")


class DnsMetricsEndpointConfig(EndpointConfig):
    service_name: ServiceName = "dns-metrics-endpoint"
    site_path: PlainPath = PurePosixPath("/var/lib/dns-metrics")
    bind: Bind = "tailscale"
    port: Port = 9107
    request_timeout: Positive = 15
    path: UrlPath = "/.well-known/dns"
    packages: tuple[Package, ...] = ("python3", "apache2-utils", "bind9-dnsutils")
    json_file: PlainPath | None = None
    server_path: PlainPath = PurePosixPath("/usr/local/bin/dns_metrics_httpd.py")
    collector_path: PlainPath = PurePosixPath("/usr/local/bin/dns_metrics_collector.py")
    htpasswd_dir: PlainPath = PurePosixPath("/etc/dns-metrics-endpoint")
    timer_interval: Positive = 300
    timer_name: Word = "dns-metrics-collector"
    timer_on_boot_sec: Seconds = 30
    timer_accuracy_sec: Seconds = 10
    timer_randomized_delay_sec: Seconds = 15
    nameservers: tuple[Nameserver, ...]
    zones: tuple[DnsName, ...]
    families: tuple[Family, ...] = ("ipv4", "ipv6")
    transports: tuple[Transport, ...] = ("udp", "tcp")
    vantage_point_limitations: tuple[Limitation, ...] = ()
    foreign_name: DnsName = "example.net"
    foreign_qtype: QType = "A"
    open_resolver_transport: Transport = "udp"
    dig_timeout: Positive = 3
    dig_tries: Positive = 2
    dig_subprocess_timeout: Positive = 15
    max_workers: Positive = 8
    ipv6_probe_address: ipaddress.IPv6Address = ipaddress.IPv6Address("2001:4860:4860::8888")

    @property
    def json_path(self) -> PurePosixPath:
        return self.json_file or self.site_path / "dns.json"

    @model_validator(mode="after")
    def _the_roles_validation(self) -> DnsMetricsEndpointConfig:
        """``tasks/validate.yml`` of the role, check by check."""

        if not self.nameservers:
            raise ValueError("nameservers must be a non-empty list")
        ids = [ns.id for ns in self.nameservers]
        if len(set(ids)) != len(ids):
            raise ValueError("nameserver ids must be unique")
        if not self.zones or not self.families or not self.transports:
            raise ValueError("zones, families and transports must be non-empty")
        if len(set(self.families)) != len(self.families) or len(set(self.transports)) != len(self.transports):
            raise ValueError("families and transports must not repeat an entry")
        # Otherwise every foreign probe is skipped and overall_ok can never be true.
        if self.open_resolver_transport not in self.transports:
            raise ValueError("open_resolver_transport must be one of the probed transports")
        if self.dig_subprocess_timeout <= self.dig_timeout * self.dig_tries:
            raise ValueError("dig_subprocess_timeout must exceed dig_timeout * dig_tries")
        problems = []
        for ns in self.nameservers:
            for name, chosen, allowed in (
                ("families", ns.families, self.families),
                ("transports", ns.transports, self.transports),
            ):
                if chosen is not None and (not chosen or set(chosen) - set(allowed)):
                    problems.append(
                        f"{ns.id}: {name} must be a non-empty subset of the global {name} (overrides only narrow)"
                    )
            problems += _address_problems(ns, self.families)
        if problems:
            raise ValueError("; ".join(problems))
        valid = {
            f"{ns}-{family}-{transport}" for ns in ids for family in self.families for transport in self.transports
        }
        for limitation in self.vantage_point_limitations:
            if limitation.id not in valid:
                raise ValueError(
                    f"vantage point limitation {limitation.id!r} matches no configured endpoint "
                    f"({', '.join(sorted(valid))}); it would hide nothing while appearing to"
                )
        # The nameservers are authoritative inside a monitored zone and answer
        # instead of REFUSED, so the open-resolver probe would fail forever.
        foreign = _folded(self.foreign_name)
        for zone in self.zones:
            folded = _folded(zone)
            if foreign == folded or foreign.endswith("." + folded):
                raise ValueError(f"foreign_name {self.foreign_name!r} is inside the monitored zone {zone!r}")
        return self


def _address_problems(ns: Nameserver, families: tuple[str, ...]) -> list[str]:
    """The role's controller-side address check (exact parsing, never a regex)."""

    problems = []
    if not (ns.ipv4 or ns.ipv6):
        problems.append(f"{ns.id}: needs at least one non-empty ipv4 or ipv6 address")
        return problems
    effective = ns.families or families
    probeable = 0
    for key, want in (("ipv4", 4), ("ipv6", 6)):
        value = getattr(ns, key) or ""
        if not value:
            continue
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            problems.append(f"{ns.id}: {key}={value!r} is not a literal IP address")
            continue
        if address.version != want:
            problems.append(f"{ns.id}: {key}={value!r} is IPv{address.version}, not IPv{want}")
            continue
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            problems.append(
                f"{ns.id}: ipv6={value!r} is IPv4-mapped; it would be queried over IPv4 "
                "while being reported as IPv6 coverage"
            )
            continue
        if key in effective:
            probeable += 1
    if not problems and not probeable:
        problems.append(
            f"{ns.id}: has no usable address in its effective families {sorted(effective)}, "
            "so every one of its endpoints would be skipped"
        )
    return problems


def role_vars(cfg: DnsMetricsEndpointConfig, bind: str) -> dict[str, Any]:
    """The role variables the templates read, with ``bind`` resolved."""

    values = {
        "user": cfg.user,
        "group": cfg.group_name,
        "bind": bind,
        "port": cfg.port,
        "request_timeout": cfg.request_timeout,
        "path": cfg.path,
        "data_dir": str(cfg.site_path),
        "json_path": str(cfg.json_path),
        "server_path": str(cfg.server_path),
        "collector_path": str(cfg.collector_path),
        "htpasswd_path": str(cfg.htpasswd_path),
        "timer_interval": cfg.timer_interval,
        "timer_on_boot_sec": cfg.timer_on_boot_sec,
        "timer_accuracy_sec": cfg.timer_accuracy_sec,
        "timer_randomized_delay_sec": cfg.timer_randomized_delay_sec,
        "nameservers": [ns.as_role() for ns in cfg.nameservers],
        "zones": list(cfg.zones),
        "families": list(cfg.families),
        "transports": list(cfg.transports),
        "vantage_point_limitations": [item.model_dump(mode="json") for item in cfg.vantage_point_limitations],
        "foreign_name": cfg.foreign_name,
        "foreign_qtype": cfg.foreign_qtype,
        "open_resolver_transport": cfg.open_resolver_transport,
        "dig_timeout": cfg.dig_timeout,
        "dig_tries": cfg.dig_tries,
        "dig_subprocess_timeout": cfg.dig_subprocess_timeout,
        "max_workers": cfg.max_workers,
        "ipv6_probe_address": str(cfg.ipv6_probe_address),
    }
    return {"dns_metrics_endpoint_" + key: value for key, value in values.items()}


@cache
def environment() -> jinja2.Environment:
    # ansible.builtin.template: trim_blocks on, lstrip_blocks off, the final newline kept.
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.dns_metrics_endpoint", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["to_json"] = json.dumps
    return env


def render_role(template: str, cfg: DnsMetricsEndpointConfig, bind: str) -> str:
    return environment().get_template(template).render(**role_vars(cfg, bind))


def httpd_endpoint(cfg: DnsMetricsEndpointConfig, bind: str) -> httpd.Endpoint:
    """The role's ``metrics_httpd_switch_*`` inputs (argv, sandbox and allow list as in its unit)."""

    return httpd.Endpoint(
        service_name=cfg.service_name,
        argv=(
            "json-file",
            "--bind",
            bind,
            "--port",
            str(cfg.port),
            "--path",
            cfg.path,
            "--json-path",
            str(cfg.json_path),
            "--htpasswd-file",
            str(cfg.htpasswd_path),
            "--realm",
            "dns-metrics",
            "--server-name",
            "dns-metrics-httpd/0.1",
            "--meta",
            "merge",
            "--request-timeout",
            str(cfg.request_timeout),
        ),
        user=cfg.user,
        group=cfg.group_name,
        sandbox=("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes"),
        python_script=str(cfg.server_path),
        probe_bind=bind,
        probe_port=cfg.port,
        probe_path=cfg.path,
        probe_realm="dns-metrics",
        ip_address_allow=("localhost", "100.64.0.0/10", "fd7a:115c:a1e0::/48"),
    )


@deploy("Deploy DNS metrics endpoint")
def deploy_dns_metrics_endpoint(cfg: DnsMetricsEndpointConfig, secrets: SecretValues) -> None:
    value = password(secrets)
    bind = bind_address(cfg)
    port_preflight(cfg, bind)
    apt.packages(name="Install dependencies for DNS metrics endpoint", packages=list(cfg.packages))
    mark_read_only(server.shell(name="Verify dig is available", commands=["dig -v"]))
    account(cfg)
    files.directory(
        name=f"Ensure {cfg.site_path}", path=str(cfg.site_path), user="root", group=cfg.group_name, mode="0750"
    )
    collector = files.put(
        name=f"Install {cfg.collector_path}",
        src=StringIO(render_role("dns_metrics_collector.py.j2", cfg, bind)),
        dest=str(cfg.collector_path),
        user="root",
        group="root",
        mode="0755",
    )
    wrapper = files.put(
        name=f"Install {cfg.server_path}",
        src=StringIO(render_role("dns_metrics_httpd.py.j2", cfg, bind)),
        dest=str(cfg.server_path),
        user="root",
        group="root",
        mode="0755",
    )
    auth = credentials(cfg, value)
    collector_unit = systemd_unit(
        cfg.timer_name + ".service", render_role("dns-metrics-collector.service.j2", cfg, bind)
    )
    timer_unit = systemd_unit(cfg.timer_name + ".timer", render_role("dns-metrics-collector.timer.j2", cfg, bind))
    endpoint_unit = systemd_unit(cfg.service_name, render_role("dns-metrics-endpoint.service.j2", cfg, bind))
    selection = httpd.select(httpd_endpoint(cfg, bind), cfg)
    systemd.daemon_reload(
        name="Reload systemd for DNS metrics",
        _if=any_changed(collector_unit, timer_unit, endpoint_unit, selection.dropin),
    )
    missing = host.get_fact(File, path=str(cfg.json_path)) is None
    server.shell(
        name="Run collector once to create initial metrics file",
        commands=[shlex.join(["systemctl", "start", cfg.timer_name + ".service"])],
        _if=lambda: missing or collector.did_change(),
    )
    service_rollout(cfg.timer_name + ".timer", restart_when=[timer_unit])
    service_rollout(cfg.service_name, restart_when=[wrapper, endpoint_unit, selection.dropin, *auth])
    httpd.verify(selection)
