"""Persistent-network admission and the exact bytes of the files it writes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra.netplan.config import (
    NetplanConfig,
    NetplanDhcpOverrides,
    NetplanInterface,
    NetplanNameservers,
    NetplanNetworkManager,
    NetplanRoute,
    NetplanRouteGuard,
)
from ops_deploy.infra.netplan.render import render
from tests.goldens import assert_golden


def test_static_network_retains_original_yaml_bytes() -> None:
    cfg = NetplanConfig(
        interfaces=(
            NetplanInterface(
                name="eth0",
                dhcp4=False,
                dhcp6=False,
                addresses=("192.0.2.20/24",),
                routes=(NetplanRoute(to="default", via="192.0.2.1"),),
                nameservers=NetplanNameservers(addresses=("192.0.2.53",)),
            ),
        )
    )
    assert render(cfg, "netplan.yaml") == (
        "---\nnetwork:\n  version: 2\n  renderer: networkd\n  ethernets:\n    eth0:\n"
        "      dhcp4: false\n      dhcp6: false\n      addresses:\n        - 192.0.2.20/24\n"
        "      routes:\n        - to: default\n          via: 192.0.2.1\n"
        "      nameservers:\n        addresses:\n          - 192.0.2.53\n"
    )


def test_networkmanager_retains_both_dhcp_hostnames() -> None:
    cfg = NetplanConfig(
        renderer="NetworkManager",
        interfaces=(
            NetplanInterface(
                name="eth0",
                dhcp4=True,
                dhcp6=True,
                networkmanager=NetplanNetworkManager(
                    passthrough={"ipv4.dhcp-hostname": "owned-node", "ipv6.dhcp-hostname": "owned-node"}
                ),
            ),
        ),
    )
    assert render(cfg, "netplan.yaml") == (
        "---\nnetwork:\n  version: 2\n  renderer: NetworkManager\n  ethernets:\n    eth0:\n"
        "      dhcp4: true\n      dhcp6: true\n      networkmanager:\n        passthrough:\n"
        "            ipv4.dhcp-hostname: owned-node\n            ipv6.dhcp-hostname: owned-node\n\n"
    )


@pytest.mark.parametrize(
    "fields",
    [
        dict(name="eth0; false", dhcp4=True),
        dict(name="eth0", dhcp4=True, routes=[dict(to="default", via="192.0.2.1")]),
        dict(name="eth0", addresses=["192.0.2.4/999"]),
        dict(name="eth0"),
        dict(name="eth0", dhcp4=True, networkmanager={"passthrough": {"wifi-security.psk": "unsupported"}}),
    ],
)
def test_invalid_interface_refuses_before_operations(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        NetplanInterface(**fields)


@pytest.mark.parametrize("path", ["/etc/passwd", "/etc/netplan/../ssh/sshd_config", "/etc/netplan/99-ops-library.yaml"])
def test_cleanup_cannot_remove_other_domains_or_its_managed_candidate(path: str) -> None:
    with pytest.raises(ValidationError):
        NetplanConfig(interfaces=(NetplanInterface(name="eth0", dhcp4=True),), cleanup_files=(path,))


def test_guard_keeps_original_recovery_parameters_and_requires_apply() -> None:
    guard = NetplanRouteGuard(enabled=True, interfaces=("eth0",))
    with pytest.raises(ValidationError):
        NetplanConfig(interfaces=(NetplanInterface(name="eth0", dhcp4=True),), route_guard=guard, apply=False)
    cfg = NetplanConfig(interfaces=(NetplanInterface(name="eth0", dhcp4=True),), route_guard=guard)
    script = render(cfg, "netplan-route-guard.sh")
    assert "readonly CONFIRMATION_DELAY=5\nreadonly RECOVERY_DELAY=10\n" in script
    assert '"${recovery_carrier_state}" != "1"' in script
    assert "OnUnitActiveSec=60s\n" in render(cfg, "netplan-route-guard.timer")
    assert "TimeoutStartSec=75s\n" in render(cfg, "netplan-route-guard.service")


def test_dhcp_override_python_names_and_original_yaml_aliases_match() -> None:
    cfg = NetplanDhcpOverrides(use_dns=False, route_metric=100)
    assert cfg.model_dump(exclude_none=True, by_alias=True) == {"use-dns": False, "route-metric": 100}


GOLDEN = Path(__file__).parent / "golden" / "netplan"


@pytest.mark.parametrize("name", ["netplan-route-guard.sh", "netplan-route-guard.service", "netplan-route-guard.timer"])
def test_route_guard_files_are_golden(name: str) -> None:
    """The guard reverts the network when routes vanish; a changed byte restarts it on the host."""

    guard = NetplanRouteGuard(enabled=True, interfaces=("eth0",))
    cfg = NetplanConfig(interfaces=(NetplanInterface(name="eth0", dhcp4=True),), route_guard=guard)

    assert_golden(GOLDEN / name, render(cfg, name))
