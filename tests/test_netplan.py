"""Persistent-network admission and exact original template resource contracts."""

from __future__ import annotations

import hashlib
import json
import os
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


def test_original_selected_role_resource_provenance() -> None:
    root = Path(__file__).parents[1]
    hashes = json.loads((root / "tests/parity/netplan_sources.json").read_text())
    actual = root / "src/ops_deploy/infra/netplan/templates"
    for name, digest in hashes["resources"].items():
        assert hashlib.sha256((actual / name).read_bytes()).hexdigest() == digest


def test_paired_original_selected_role_resource_provenance() -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if not library:
        pytest.skip("Explicit paired ops-library checkout required for original-role provenance")
    root = Path(__file__).parents[1]
    hashes = json.loads((root / "tests/parity/netplan_sources.json").read_text())
    for name, digest in hashes["resources"].items():
        path = Path(library) / "roles/netplan_config/templates" / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
