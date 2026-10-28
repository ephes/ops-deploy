"""Fail-closed target predicates complement genuine owned native tests."""

from __future__ import annotations

import json
import runpy
from pathlib import Path
from typing import Any, cast

import pytest

SCRIPT = Path(__file__).parents[1] / "src/ops_deploy/infra/files/netplan_host.py"


def helper() -> dict[str, Any]:
    loaded = runpy.run_path(str(SCRIPT))
    return cast(dict[str, Any], loaded["inspect"].__globals__)


def interface() -> dict[str, Any]:
    return {"name": "owned0", "routes": [{"to": "default", "via": "192.0.2.1"}]}


@pytest.mark.parametrize("setup", ["pending", "initialized", "configuring", "unmanaged", "linger"])
def test_transient_route_setup_is_not_final_convergence(tmp_path: Path, setup: str) -> None:
    module = helper()
    module["carrier_state"] = lambda _: True
    module["run"] = lambda argv: (0, json.dumps({"AdministrativeState": setup}) if argv[0] == "networkctl" else "[]")
    state = module["interface_health"](interface(), False)
    assert state["pending"] is True
    assert state["repair"] is (setup in {"unmanaged", "linger"})


def test_configured_route_is_current_and_historical_guard_failure_is_separate() -> None:
    module = helper()
    module["carrier_state"] = lambda _: True
    module["run"] = lambda argv: (
        0,
        '{"AdministrativeState":"configured"}' if argv[0] == "networkctl" else '[{"protocol":"static"}]',
    )
    assert module["interface_health"](interface(), False) == dict(repair=False, pending=False, dhcp=False)


def test_absent_carrier_retains_periodic_skip_but_strict_contract_refuses() -> None:
    module = helper()
    module["carrier_state"] = lambda _: False
    module["run"] = lambda _: pytest.fail("No recovery or route query permitted without carrier")
    assert module["interface_health"](interface(), False) == dict(repair=False, pending=False, dhcp=False)
    with pytest.raises(module["Refused"], match="no carrier"):
        module["interface_health"](interface(), True)


def test_original_operstate_fallback_is_not_fabricated_carrier(tmp_path: Path) -> None:
    module = helper()
    root = tmp_path / "owned0"
    root.mkdir()
    (root / "operstate").write_text("lowerlayerdown\n")
    module["SYS_NET"] = tmp_path
    assert module["carrier_state"]("owned0") is False
    (root / "operstate").write_text("unknown\n")
    with pytest.raises(module["Refused"], match="unavailable"):
        module["carrier_state"]("owned0")


@pytest.mark.parametrize("text", ["[]", "null", '{"AdministrativeState":null}', '{"AdministrativeState":"invented"}'])
def test_unknown_setup_never_becomes_healthy(text: str) -> None:
    module = helper()
    module["carrier_state"] = lambda _: True
    module["run"] = lambda _: (0, text)
    with pytest.raises(module["Refused"], match="unsupported"):
        module["interface_health"](interface(), False)


def test_candidate_native_validation_sees_all_three_original_merge_roots(tmp_path: Path) -> None:
    module = helper()
    roots = [(tmp_path / sub, sub + "/netplan") for sub in ("etc", "run", "lib")]
    for root, _ in roots:
        root.mkdir()
        (root / "98-owned.yaml").write_text("network: {version: 2}\n")
    module["NETPLAN_SEARCH"] = tuple(roots)
    module["CONFIG"] = roots[0][0] / "99-ops-library.yaml"
    seen: list[bool] = []

    def validate(argv: list[str]) -> tuple[int, str]:
        assert argv[:3] == ["netplan", "generate", "--root-dir"]
        stage = Path(argv[3])
        assert all(
            (stage / relative / "98-owned.yaml").read_text() == "network: {version: 2}\n" for _, relative in roots
        )
        assert (stage / "etc/netplan/99-ops-library.yaml").read_text() == "network: {version: 2}\n"
        seen.append(True)
        raise module["Refused"]("native merged input rejected")

    module["run"] = validate
    with pytest.raises(module["Refused"], match="merged input"):
        module["validate_candidate"](
            {"cleanup_files": [], "resources": {str(module["CONFIG"]): {"content": "network: {version: 2}\n"}}}
        )
    assert seen == [True]
    assert not module["CONFIG"].exists()
    assert all((root / "98-owned.yaml").read_text() == "network: {version: 2}\n" for root, _ in roots)


def test_single_link_and_symlink_refusal_does_not_read_target(tmp_path: Path) -> None:
    module = helper()
    source = tmp_path / "unowned"
    source.write_text("unowned fixture")
    alias = tmp_path / "alias"
    alias.symlink_to(source)
    with pytest.raises(module["Refused"], match="single-link"):
        module["regular"](alias)
    alias.unlink()
    alias.hardlink_to(source)
    with pytest.raises(module["Refused"], match="single-link"):
        module["regular"](source)
    assert source.read_text() == "unowned fixture"


def test_ipv6_default_is_not_an_ipv4_recovery_requirement() -> None:
    module = helper()
    module["carrier_state"] = lambda _: True
    module["run"] = lambda argv: (0, '{"AdministrativeState":"configured"}' if argv[0] == "networkctl" else "[]")
    value = {"name": "owned0", "routes": [{"to": "default", "via": "2001:db8::1"}]}
    assert module["interface_health"](value, False) == dict(repair=False, pending=False, dhcp=False)


def test_health_scope_never_requires_repair_from_an_unavailable_actor() -> None:
    module = helper()
    managed, unrelated = interface(), {"name": "other0", "routes": []}
    cfg: dict[str, Any] = dict(
        apply=True,
        reconfigure_interfaces=False,
        single_static_default=False,
        interfaces=[managed, unrelated],
        route_guard=dict(enabled=True, interfaces=["owned0"]),
    )
    assert module["recovery_interfaces"](cfg) == [managed]
    cfg["route_guard"]["enabled"] = False
    cfg["apply"], cfg["reconfigure_interfaces"] = False, True
    assert module["recovery_interfaces"](cfg) == []
    cfg["apply"] = True
    assert module["recovery_interfaces"](cfg) == [managed, unrelated]


def test_long_guard_unit_wait_and_activation_deadlines_stay_ordered() -> None:
    from ops_deploy.infra.netplan import NetplanConfig, NetplanInterface, NetplanRouteGuard
    from ops_deploy.infra.netplan.deploy import NetworkJobWaitCommand, activation_deadline
    from ops_deploy.infra.netplan.render import render

    guard = NetplanRouteGuard(
        enabled=True, interfaces=("one0", "two0", "three0"), confirmation_delay_sec=60, recovery_delay_sec=300
    )
    cfg = NetplanConfig(
        interfaces=tuple(NetplanInterface(name=name, dhcp4=True) for name in guard.interfaces), route_guard=guard
    )
    unit = render(cfg, "netplan-route-guard.service")
    unit_timeout = int(
        next(row.split("=", 1)[1][:-1] for row in unit.splitlines() if row.startswith("TimeoutStartSec="))
    )
    wait = helper()["guard_start_timeout"](guard.model_dump())
    deadline = activation_deadline(guard.model_dump())
    command = NetworkJobWaitCommand("owned.service", timeout=deadline + 120)
    assert unit_timeout == 1140
    assert unit_timeout < wait < deadline < command.timeout
