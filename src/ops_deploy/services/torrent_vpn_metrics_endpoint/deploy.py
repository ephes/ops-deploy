"""Torrent VPN collector/timer and authenticated endpoint, with role templates."""

from __future__ import annotations

import json
import shlex
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any

import jinja2
from pydantic import BaseModel, ConfigDict, Field, StrictInt
from pyinfra.api import deploy
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import ServiceName
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, when_present
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
from ops_deploy.services.thermal_monitoring.deploy import armed_check, timer_armed

SafeUrl = Annotated[str, Field(pattern=r"""^https?://[^\s"'\\]+$""")]
JsonPath = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*$")]


class ProviderCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    url: SafeUrl
    flag: JsonPath
    country: JsonPath


class TorrentVpnMetricsEndpointConfig(EndpointConfig):
    service_name: ServiceName = "torrent-vpn-metrics-endpoint"
    site_path: PlainPath = PurePosixPath("/var/lib/torrent-vpn-metrics")
    bind: Bind = "tailscale"
    port: Port = 9102
    path: UrlPath = "/.well-known/vpn-egress"
    packages: tuple[Package, ...] = ("python3", "apache2-utils", "curl", "util-linux")
    server_path: PlainPath = PurePosixPath("/usr/local/bin/torrent_vpn_metrics_httpd.py")
    htpasswd_dir: PlainPath = PurePosixPath("/etc/torrent-vpn-metrics-endpoint")
    json_file: PlainPath | None = None
    collector_path: PlainPath = PurePosixPath("/usr/local/bin/torrent_vpn_metrics_collect")
    timer_name: Word = "torrent-vpn-metrics-collector"
    timer_interval: Annotated[StrictInt, Field(ge=1)] = 300
    script_timeout: Annotated[StrictInt, Field(ge=1)] = 10
    gluetun_container: Word = "torrent-gluetun-1"
    attached_containers: tuple[Word, ...] = ("torrent-qbittorrent-1", "torrent-jackett-1")
    host_ip_url: SafeUrl = "https://api.ipify.org?format=json"
    vpn_interface: Word = "tun0"
    provider_checks: dict[Word, ProviderCheck] = Field(
        default_factory=lambda: {
            "mullvad": ProviderCheck(url="https://am.i.mullvad.net/json", flag="mullvad_exit_ip", country="country"),
            "airvpn": ProviderCheck(url="https://airvpn.org/api/whatismyip/", flag="airvpn", country="geo.name"),
        }
    )

    @property
    def json_path(self) -> PurePosixPath:
        return self.json_file or self.site_path / "vpn.json"


def role_vars(cfg: TorrentVpnMetricsEndpointConfig, bind: str) -> dict[str, Any]:
    values = {
        "user": cfg.user,
        "group": cfg.group_name,
        "bind": bind,
        "port": cfg.port,
        "path": cfg.path,
        "data_dir": str(cfg.site_path),
        "json_path": str(cfg.json_path),
        "server_path": str(cfg.server_path),
        "htpasswd_path": str(cfg.htpasswd_path),
        "collector_path": str(cfg.collector_path),
        "timer_interval": cfg.timer_interval,
        "gluetun_container": cfg.gluetun_container,
        "attached_containers": list(cfg.attached_containers),
        "host_ip_url": cfg.host_ip_url,
        "vpn_interface": cfg.vpn_interface,
        "script_timeout": cfg.script_timeout,
        "provider_checks": {name: part.model_dump() for name, part in cfg.provider_checks.items()},
    }
    return {"torrent_vpn_metrics_endpoint_" + key: value for key, value in values.items()}


@cache
def environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.torrent_vpn_metrics_endpoint", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    env.filters["to_json"] = json.dumps
    return env


def render_role(template: str, cfg: TorrentVpnMetricsEndpointConfig, bind: str) -> str:
    return environment().get_template(template).render(**role_vars(cfg, bind))


def httpd_endpoint(cfg: TorrentVpnMetricsEndpointConfig, bind: str) -> httpd.Endpoint:
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
            "torrent-vpn-metrics",
            "--server-name",
            "torrent-vpn-metrics-httpd/0.1",
            "--request-timeout",
            "10",
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
        probe_realm="torrent-vpn-metrics",
        ip_address_allow=("localhost", "100.64.0.0/10"),
    )


@deploy("Deploy torrent VPN metrics endpoint")
def deploy_torrent_vpn_metrics_endpoint(cfg: TorrentVpnMetricsEndpointConfig, secrets: SecretValues) -> None:
    value = password(secrets)
    bind = bind_address(cfg)
    port_preflight(cfg, bind)
    apt.packages(name="Install torrent VPN metrics packages", packages=list(cfg.packages))
    account(cfg)
    files.directory(
        name=f"Ensure {cfg.site_path}", path=str(cfg.site_path), user="root", group=cfg.group_name, mode="0750"
    )
    collector = files.put(
        name=f"Install {cfg.collector_path}",
        src=StringIO(render_role("torrent-vpn-metrics-collect.py.j2", cfg, bind)),
        dest=str(cfg.collector_path),
        user="root",
        group="root",
        mode="0755",
    )
    wrapper = files.put(
        name=f"Install {cfg.server_path}",
        src=StringIO(render_role("torrent_vpn_metrics_httpd.py.j2", cfg, bind)),
        dest=str(cfg.server_path),
        user="root",
        group="root",
        mode="0755",
    )
    auth = credentials(cfg, value)
    collector_unit = systemd_unit(
        cfg.timer_name + ".service", render_role("torrent-vpn-metrics-collector.service.j2", cfg, bind)
    )
    timer_unit = systemd_unit(
        cfg.timer_name + ".timer", render_role("torrent-vpn-metrics-collector.timer.j2", cfg, bind)
    )
    endpoint_unit = systemd_unit(cfg.service_name, render_role("torrent-vpn-metrics-endpoint.service.j2", cfg, bind))
    selection = httpd.select(httpd_endpoint(cfg, bind), cfg)
    systemd.daemon_reload(
        name="Reload systemd for torrent VPN metrics",
        _if=any_changed(collector_unit, timer_unit, endpoint_unit, selection.dropin),
    )
    payload_check = (Path(__file__).parent / "files" / "payload_state.py").read_text()
    state = probe(
        shlex.join(["python3", "-I", "-c", payload_check, str(cfg.json_path), str(2 * cfg.timer_interval)]),
        name="Torrent VPN metrics payload validity and freshness",
    )
    missing = (state or "").strip() != "present"
    timer = cfg.timer_name + ".timer"
    answer = probe(
        when_present(
            [PurePosixPath("/etc/systemd/system") / timer],
            shlex.join(
                ["systemctl", "show", timer, "--property=NextElapseUSecRealtime", "--property=NextElapseUSecMonotonic"]
            ),
            otherwise="missing",
        ),
        name="Torrent VPN collector timer next elapse",
    )
    timer_rollout = service_rollout(timer, restart_when=[collector, timer_unit])
    # Keep the timer loaded before activating its service: otherwise systemd
    # may garbage-collect an inactive oneshot and forget its activation time.
    # OnUnitActiveSec needs a collector activation in this boot. A valid
    # persisted payload alone cannot seed it after OnBootSec has elapsed.
    unarmed = answer is None or not timer_armed(answer)
    server.shell(
        name="Initialize torrent VPN metrics payload when needed",
        commands=[shlex.join(["systemctl", "start", cfg.timer_name + ".service"])],
        _if=lambda: missing or unarmed or collector.did_change() or collector_unit.did_change(),
    )
    if answer is None or not timer_armed(answer):
        server.shell(
            name="Re-arm elapsed torrent VPN collector timer",
            commands=[shlex.join(["systemctl", "restart", timer])],
            _if=lambda: not any(op.did_change() for op in (timer_unit, timer_rollout.start, timer_rollout.restart)),
        )
    mark_read_only(
        server.shell(
            name="Require an armed torrent VPN collector timer", commands=[shlex.join(["sh", "-c", armed_check(timer)])]
        )
    )
    service_rollout(cfg.service_name, restart_when=[wrapper, endpoint_unit, selection.dropin, *auth])
    httpd.verify(selection)
