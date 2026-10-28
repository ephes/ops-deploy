"""Original cached Tailscale endpoint policy and explicit refresh freshness."""

from __future__ import annotations

import ipaddress
import re

from pydantic import Field, StrictBool, StrictInt, model_validator

from ops_deploy.base._common import AbsolutePath
from ops_deploy.services.fractal_monitoring.config import EndpointConfig


class TailscaleMetricsConfig(EndpointConfig):
    enabled: StrictBool = False
    service_name: str = "tailscale-metrics-endpoint"
    timer_name: str = "tailscale-metrics-collector"
    path: str = "/.well-known/tailscale"
    port: StrictInt = Field(default=9107, ge=1, le=65535)
    auth_user: str = "nyxmon"
    data_dir: AbsolutePath = "/var/lib/tailscale-metrics"
    json_path: AbsolutePath = "/var/lib/tailscale-metrics/tailscale.json"
    exporter_path: AbsolutePath = "/usr/local/bin/tailscale-metrics-exporter"
    server_path: AbsolutePath = "/usr/local/bin/tailscale_metrics_httpd.py"
    htpasswd_dir: AbsolutePath = "/etc/tailscale-metrics-endpoint"
    htpasswd_path: AbsolutePath = "/etc/tailscale-metrics-endpoint/htpasswd"
    tailscale_bin: AbsolutePath = "/usr/bin/tailscale"
    ip_bin: AbsolutePath = "/usr/sbin/ip"
    bpftool_bin: AbsolutePath = "/usr/sbin/bpftool"
    ip_address_allow: tuple[str, ...] = ("localhost", "100.64.0.0/10")
    require_effective_ip_filter: StrictBool = False
    default_route_interface: str = ""
    require_default_ipv4_route: StrictBool = False
    require_self_online: StrictBool = False
    mdstat_path: AbsolutePath = "/proc/mdstat"
    require_mdraid_healthy: StrictBool = False
    required_mdraid_arrays: tuple[str, ...] = ()
    warning_days: StrictInt = 3
    critical_days: StrictInt = 1
    timer_on_boot_sec: StrictInt = 45
    timer_on_calendar: str = "*:0/5"
    freshness_sec: StrictInt = 900

    @model_validator(mode="after")
    def _endpoint_policy(self) -> TailscaleMetricsConfig:
        if self.default_route_interface and not re.fullmatch(r"[A-Za-z0-9_.:-]+", self.default_route_interface):
            raise ValueError("invalid default-route interface")
        if self.require_default_ipv4_route and not self.default_route_interface:
            raise ValueError("required default route needs its explicit interface")
        if not self.warning_days >= self.critical_days > 0:
            raise ValueError("expiry thresholds must retain warning >= critical > 0")
        if not self.ip_address_allow:
            raise ValueError("endpoint requires an explicit IP allow list")
        for value in self.ip_address_allow:
            if value in {"localhost", "link-local", "multicast"}:
                continue
            network = ipaddress.ip_network(value, strict=False)
            if network.prefixlen < (8 if network.version == 4 else 32):
                raise ValueError("endpoint allow list must not be world open or overly broad")
        if not self.timer_on_calendar or any(c in self.timer_on_calendar for c in "\r\n\0"):
            raise ValueError("collector requires its original calendar backstop")
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in self.required_mdraid_arrays):
            raise ValueError("invalid required mdraid name")
        return self
