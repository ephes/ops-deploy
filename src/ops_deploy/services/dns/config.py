"""Explicit inputs for the ordinary Unbound/DDNS deployment."""

from __future__ import annotations

import ipaddress
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, field_validator, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.services.metrics_endpoint.common import EndpointConfig, PlainPath, UrlPath

Domain = Annotated[str, Field(pattern=r"^(?:[\w*][\w.*-]*|\.)$", max_length=253)]
IPv4 = ipaddress.IPv4Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class SplitService(Input):
    name: Domain
    lan_ip: IPv4
    tailscale_ip: IPv4


class ForwardZone(Input):
    name: Domain
    forward_addrs: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    forward_first: StrictBool = False

    @field_validator("forward_addrs")
    @classmethod
    def addresses_required(
        cls, value: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]
    ) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
        if not value:
            raise ValueError("forward zone requires addresses")
        return value


class LocalRecord(Input):
    name: Domain
    type: Literal["A", "AAAA", "CNAME", "TXT", "MX", "PTR", "SRV"]
    value: str

    @field_validator("value")
    @classmethod
    def safe_value(cls, value: str) -> str:
        if not value or any(c in value for c in '\n\r\x00"\\'):
            raise ValueError("local record value contains unsupported quoting")
        return value


class DdnsEndpointConfig(EndpointConfig):
    service_name: Literal["ddns-status-endpoint"] = "ddns-status-endpoint"
    user: Literal["ddns"] = "ddns"
    group: Literal["ddns"] | None = None
    bind: Literal["tailscale-interface"] = "tailscale-interface"
    port: Annotated[StrictInt, Field(ge=1, le=65535)] = 9112
    path: UrlPath = "/.well-known/ddns"
    server_path: PlainPath = PurePosixPath("/usr/local/bin/ddns_status_httpd.py")
    htpasswd_dir: PlainPath = PurePosixPath("/etc/ddns-status-endpoint")
    packages: tuple[str, ...] = ("python3", "apache2-utils")


class DnsConfig(BaseServiceConfig):
    service_name: ServiceName = "dns"
    user: UnixUser = "root"
    site_path: PurePosixPath = PurePosixPath("/etc/unbound")
    local_domain: Domain = "home.example.com"
    local_domain_punycode: Domain = "home.example.com"
    # None means derive from the target's route/address facts, not this controller.
    split_lan_ip: IPv4 | None = None
    split_tailscale_ip: IPv4 | None = None
    processor_vcpus: Annotated[StrictInt, Field(ge=1, le=1024)] | None = None
    split_lan_network: ipaddress.IPv4Network = ipaddress.IPv4Network("192.168.0.0/16")
    split_tailscale_network: ipaddress.IPv4Network = ipaddress.IPv4Network("100.64.0.0/10")
    split_lan_ipv6_networks: tuple[ipaddress.IPv6Network, ...] = ()
    split_tailscale_ipv6_networks: tuple[ipaddress.IPv6Network, ...] = ()
    split_services: tuple[SplitService, ...] = ()
    forward_zones: tuple[ForwardZone, ...] = ()
    local_records: tuple[LocalRecord, ...] = ()
    unbound_serve_expired: StrictBool = False
    unbound_serve_expired_ttl: Annotated[StrictInt, Field(ge=0)] = 86400
    unbound_serve_expired_reply_ttl: Annotated[StrictInt, Field(ge=0)] = 30
    unbound_serve_expired_ttl_reset: StrictBool = False
    unbound_serve_expired_client_timeout: Annotated[StrictInt, Field(ge=0)] = 0
    unbound_prefetch: StrictBool = False
    unbound_prefetch_key: StrictBool = False
    unbound_num_queries_per_thread: Annotated[StrictInt, Field(ge=0)] = 0
    blocklists: tuple[str, ...] = (
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://someonewhocares.org/hosts/zero/hosts",
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    )
    # Deliberately follows the actual role template, not its unused dns_allowlist default.
    whitelist_domains: tuple[Domain, ...] = ()
    custom_blocked_domains: tuple[Domain, ...] = ()
    update_resolv_conf: StrictBool = True
    ddns_enabled: StrictBool = False
    ddns_domain: Domain = "example.com"
    ddns_subdomain: Domain = "home"
    ddns_update_wildcard: StrictBool = True
    ddns_ttl: Annotated[StrictInt, Field(ge=1)] = 300
    ddns_interval: Annotated[str, Field(pattern=r"^[1-9][0-9]*(s|min|h)$")] = "5min"
    ddns_ipv4_enabled: StrictBool = True
    ddns_ipv6_enabled: StrictBool = True
    ddns_ipv4_source_url: str = "https://ipv4.icanhazip.com"
    ddns_ipv6_source_url: str = "https://ipv6.icanhazip.com"
    ddns_verify_nameservers: tuple[str, ...] = ()
    ddns_log_max_size_mb: Annotated[StrictInt, Field(ge=1)] = 10
    ddns_gandi_auth_scheme: Literal["bearer", "apikey"] = "bearer"
    ddns_rfc2136_server: ipaddress.IPv4Address | ipaddress.IPv6Address = IPv4("127.0.0.1")
    ddns_rfc2136_port: Annotated[StrictInt, Field(ge=1, le=65535)] = 53
    ddns_rfc2136_key_name: Domain = "ddns-home"
    ddns_rfc2136_key_algorithm: Literal["hmac-sha256", "hmac-sha384", "hmac-sha512"] = "hmac-sha256"
    ddns_rfc2136_update_zone: Domain = "home.example.com"
    endpoint: DdnsEndpointConfig | None = None

    @field_validator("blocklists", "ddns_verify_nameservers")
    @classmethod
    def no_shell_syntax(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not value or any(c in value for c in '\n\r\x00"\\`$'):
                raise ValueError("unsupported characters in DNS input")
        return values

    @model_validator(mode="after")
    def coherent(self) -> DnsConfig:
        keys = [(r.name.lower(), r.type) for r in self.local_records]
        if len(keys) != len(set(keys)) or any(
            r.name.lower() in {z.name.lower() for z in self.forward_zones} for r in self.local_records
        ):
            raise ValueError("duplicate local records or forwarded-zone apex shadowing")
        if self.endpoint is not None and not self.ddns_enabled:
            raise ValueError("DDNS endpoint requires DDNS")
        if self.ddns_enabled and not (self.ddns_ipv4_enabled or self.ddns_ipv6_enabled):
            raise ValueError("DDNS requires an enabled address family")
        return self
