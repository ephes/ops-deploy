"""Typed persistent network configuration; original netplan/guard policy is retained."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig

InterfaceName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:-]+$", min_length=1, max_length=15)]
UnitName = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@-]*$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]*$", max_length=253)]


class NetplanRoute(RoleConfig):
    to: str
    via: str
    metric: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def _addresses(self) -> NetplanRoute:
        if self.to != "default":
            target = ipaddress.ip_network(self.to, strict=False)
            if target.version != ipaddress.ip_address(self.via).version:
                raise ValueError("route destination and gateway address families differ")
        ipaddress.ip_address(self.via)
        return self


class NetplanNameservers(RoleConfig):
    addresses: tuple[str, ...] = ()
    search: tuple[Hostname, ...] = ()

    @model_validator(mode="after")
    def _addresses(self) -> NetplanNameservers:
        for address in self.addresses:
            ipaddress.ip_address(address)
        return self


class NetplanDhcpOverrides(RoleConfig):
    """Documented DHCP overrides; spelling is the original YAML spelling."""

    model_config = ConfigDict(populate_by_name=True)

    use_dns: bool | None = Field(default=None, alias="use-dns")
    use_ntp: bool | None = Field(default=None, alias="use-ntp")
    use_mtu: bool | None = Field(default=None, alias="use-mtu")
    use_routes: bool | None = Field(default=None, alias="use-routes")
    use_hostname: bool | None = Field(default=None, alias="use-hostname")
    send_hostname: bool | None = Field(default=None, alias="send-hostname")
    hostname: Hostname | None = None
    route_metric: Annotated[int, Field(ge=0)] | None = Field(default=None, alias="route-metric")


class NetplanNetworkManager(RoleConfig):
    passthrough: dict[Literal["ipv4.dhcp-hostname", "ipv6.dhcp-hostname"], Hostname] = Field(default_factory=dict)


class NetplanInterface(RoleConfig):
    name: InterfaceName
    dhcp4: bool | None = None
    dhcp6: bool | None = None
    addresses: tuple[str, ...] = ()
    mtu: Annotated[int, Field(ge=68, le=65535)] | None = None
    optional: bool | None = None
    dhcp4_overrides: NetplanDhcpOverrides | None = None
    dhcp6_overrides: NetplanDhcpOverrides | None = None
    routes: tuple[NetplanRoute, ...] = ()
    nameservers: NetplanNameservers | None = None
    networkmanager: NetplanNetworkManager | None = None

    @model_validator(mode="after")
    def _addressing(self) -> NetplanInterface:
        if self.dhcp4 is None and self.dhcp6 is None and not self.addresses:
            raise ValueError("each interface needs explicit DHCP or addresses")
        for address in self.addresses:
            ipaddress.ip_interface(address)
        if self.dhcp4 and any(route.to in {"default", "0.0.0.0/0"} for route in self.routes):
            raise ValueError("DHCP4 must not be combined with a manual default route")
        return self


class NetplanRouteGuard(RoleConfig):
    enabled: bool = False
    interfaces: tuple[InterfaceName, ...] = ()
    interval_sec: Annotated[int, Field(ge=15)] = 60
    confirmation_delay_sec: Annotated[int, Field(ge=0, le=60)] = 5
    recovery_delay_sec: Annotated[int, Field(ge=0, le=300)] = 10
    script_path: AbsolutePath = "/usr/local/sbin/netplan-route-guard"
    service_name: UnitName = "netplan-route-guard"

    @model_validator(mode="after")
    def _paths(self) -> NetplanRouteGuard:
        if ".." in self.script_path.split("/") or self.script_path == "/":
            raise ValueError("route guard script must be an absolute file path without traversal")
        if self.enabled and not self.interfaces:
            raise ValueError("enabled route guard requires managed interfaces")
        return self


class NetplanConfig(RoleConfig):
    renderer: Literal["networkd", "NetworkManager"] = "networkd"
    interfaces: tuple[NetplanInterface, ...]
    cleanup_files: tuple[AbsolutePath, ...] = ()
    apply: bool = True
    reconfigure_interfaces: bool = False
    single_static_default: bool = False
    route_guard: NetplanRouteGuard = Field(default_factory=NetplanRouteGuard)

    @model_validator(mode="after")
    def _policy(self) -> NetplanConfig:
        names = [interface.name for interface in self.interfaces]
        if not names or len(set(names)) != len(names):
            raise ValueError("network interfaces must be nonempty and unique")
        if self.route_guard.enabled:
            if self.renderer != "networkd" or not self.apply:
                raise ValueError("route guard requires networkd and actual apply")
            if set(self.route_guard.interfaces) - set(names):
                raise ValueError("guard interfaces must be drawn from configured interfaces")
        if self.single_static_default:
            defaults = [
                route
                for interface in self.interfaces
                for route in interface.routes
                if route.to in {"default", "0.0.0.0/0"}
            ]
            if (
                not self.apply
                or self.renderer != "networkd"
                or len(self.interfaces) != 1
                or self.interfaces[0].dhcp4 is not False
                or not self.interfaces[0].addresses
                or len(defaults) != 1
                or ipaddress.ip_address(defaults[0].via).version != 4
            ):
                raise ValueError("single static default requires one static networkd interface and one IPv4 gateway")
        if len(set(self.cleanup_files)) != len(self.cleanup_files):
            raise ValueError("cleanup files must be unique")
        for path in self.cleanup_files:
            if (
                not path.startswith("/etc/netplan/")
                or ".." in path.split("/")
                or path == "/etc/netplan/99-ops-library.yaml"
            ):
                raise ValueError("cleanup must name other explicit files under /etc/netplan")
        return self
