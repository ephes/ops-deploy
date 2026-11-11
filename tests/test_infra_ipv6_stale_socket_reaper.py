"""IPv6 stale socket reaper: which sockets it closes, and its fake-host rollout."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ops_deploy.infra.ipv6_stale_socket_reaper import (
    SCRIPT_PATH,
    SERVICE,
    UNIT_PATH,
    Ipv6StaleSocketReaperConfig,
    deploy_ipv6_stale_socket_reaper,
    render_script,
    render_unit,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

SCRIPT_FILE = Path(__file__).parents[1] / "src/ops_deploy/infra/files/ipv6_stale_socket_reaper.py"

OLD = "2a02:3100:4433:7d00:92e2:baff:fed3:a869"
NEW = "2a02:3100:4721:3100:92e2:baff:fed3:a869"
OLD_TEMP = "2a02:3100:4433:7d00:1111:2222:3333:4444"
CONTROL = "2606:b740:49::102"


def reaper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ipv6_stale_socket_reaper", SCRIPT_FILE)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def address(local: str, *, preferred: int = 3600, **flags: bool) -> dict[str, Any]:
    return {"family": "inet6", "local": local, "prefixlen": 64, "preferred_life_time": preferred, **flags}


def fake_host(
    module: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    sockets: list[str],
    addresses: list[dict[str, Any]],
    *,
    peer: str = CONTROL,
    scope: str = "",
) -> list[list[str]]:
    """``sockets`` are local addresses, each connected from port 40000+i to ``peer``."""
    links = [{"ifname": "enp1s0f1", "addr_info": [*addresses, address("fe80::1", preferred=4294967295)]}]
    rows = [(f"[{local}]{scope}:{40000 + index}", f"[{peer}]:443") for index, local in enumerate(sockets)]

    def run(args: list[str]) -> str:
        if args[:2] == ["ip", "-j"]:
            return json.dumps(links)
        if args[0] == "ss":
            if "src" in args:
                wanted = (args[args.index("src") + 1], args[args.index("dst") + 1])
                return "".join(
                    f"0 0 {local} {remote}\n" for local, remote in rows if (local.replace(scope, ""), remote) == wanted
                )
            return "".join(f"0 0 {local} {remote}\n" for local, remote in rows)
        raise AssertionError(args)

    killed: list[list[str]] = []

    def subprocess_run(args: list[str], **_: Any) -> None:
        killed.append(args)

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module.subprocess, "run", subprocess_run)
    monkeypatch.setattr(module, "log", lambda message: None)
    return killed


def test_prefix_change_closes_only_the_old_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    module = reaper()
    killed = fake_host(module, monkeypatch, [OLD, NEW], [address(OLD, preferred=0, deprecated=True), address(NEW)])
    assert module.reap() == 1
    assert killed == [
        ["ss", "-K", "-H", "-t", "-n", "-6", "state", "connected", "src", f"[{OLD}]:40000", "dst", f"[{CONTROL}]:443"]
    ]


def test_removed_address_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = reaper()
    killed = fake_host(module, monkeypatch, [OLD], [address(NEW)])
    assert module.reap() == 1
    assert killed[0][-3:] == [f"[{OLD}]:40000", "dst", f"[{CONTROL}]:443"]


def test_lan_peer_on_the_old_prefix_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    # A LAN SSH session between two hosts on the old /64 still works on-link.
    module = reaper()
    lan_peer = "2a02:3100:4433:7d00:6afe:f7ff:fe0c:fc3"
    killed = fake_host(
        module, monkeypatch, [OLD], [address(OLD, preferred=0, deprecated=True), address(NEW)], peer=lan_peer
    )
    assert module.reap() == 0
    assert killed == []


def test_lan_peer_on_the_new_prefix_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    module = reaper()
    killed = fake_host(
        module,
        monkeypatch,
        [OLD],
        [address(OLD, preferred=0, deprecated=True), address(NEW)],
        peer="2a02:3100:4721:3100::99",
    )
    assert module.reap() == 0
    assert killed == []


def test_device_bound_socket_is_recognised(monkeypatch: pytest.MonkeyPatch) -> None:
    module = reaper()
    killed = fake_host(
        module, monkeypatch, [OLD], [address(OLD, preferred=0, deprecated=True), address(NEW)], scope="%enp1s0f1"
    )
    assert module.reap() == 1
    assert killed[0][-3:] == [f"[{OLD}]:40000", "dst", f"[{CONTROL}]:443"]


def test_deprecated_without_replacement_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    # Uplink down: the router deprecates the prefix but offers no new one.
    module = reaper()
    killed = fake_host(module, monkeypatch, [OLD], [address(OLD, preferred=0, deprecated=True)])
    assert module.reap() == 0
    assert killed == []


def test_deprecated_privacy_address_in_a_preferred_prefix_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    module = reaper()
    killed = fake_host(module, monkeypatch, [OLD_TEMP], [address(OLD_TEMP, preferred=0, deprecated=True), address(OLD)])
    assert module.reap() == 0
    assert killed == []


def test_non_global_addresses_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    # ULA, link-local and v4-mapped sockets are never candidates, even if missing.
    module = reaper()
    killed = fake_host(module, monkeypatch, ["fd50:3e45:c454::1", "fe80::1", "::ffff:192.168.178.116"], [address(NEW)])
    assert module.reap() == 0
    assert killed == []


def test_tentative_replacement_does_not_count(monkeypatch: pytest.MonkeyPatch) -> None:
    module = reaper()
    killed = fake_host(
        module,
        monkeypatch,
        [OLD],
        [address(OLD, preferred=0, deprecated=True), address(NEW, tentative=True)],
    )
    assert module.reap() == 0
    assert killed == []


def test_no_sockets_reads_no_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    module = reaper()
    fake_host(module, monkeypatch, [], [address(NEW)])
    calls: list[list[str]] = []
    original = module.run

    def recording(args: list[str]) -> str:
        calls.append(args)
        return str(original(args))

    monkeypatch.setattr(module, "run", recording)
    assert module.reap() == 0
    assert all(call[0] == "ss" for call in calls)


def test_unit_is_a_restarting_daemon_with_only_net_admin() -> None:
    unit = render_unit()
    assert f"ExecStart=/usr/bin/python3 -I {SCRIPT_PATH}\n" in unit
    assert "Restart=always\n" in unit
    assert "CapabilityBoundingSet=CAP_NET_ADMIN\n" in unit
    assert "WantedBy=multi-user.target\n" in unit


def host(*, script: bool = False, unit: bool = False, running: bool = False) -> dict[str, Any]:
    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.service(SERVICE, running=running, enabled=running),
        **fakehost.directory("/usr/local/sbin"),
        **fakehost.directory("/etc/systemd/system"),
    }
    if script:
        responses.update(fakehost.file(SCRIPT_PATH, render_script(), mode="-rwxr-xr-x"))
    if unit:
        responses.update(fakehost.file(UNIT_PATH, render_unit()))
    return responses


def test_fresh_host_installs_and_starts() -> None:
    cfg = Ipv6StaleSocketReaperConfig()
    run = run_deploy_fake(deploy_ipv6_stale_socket_reaper, cfg, responses=host())
    assert run.succeeded, run.error
    assert run.written(SCRIPT_PATH) == render_script().encode()
    assert run.written(UNIT_PATH) == render_unit().encode()
    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index(f"systemctl start {SERVICE}")
    assert f"systemctl enable {SERVICE}" in commands
    assert f"systemctl restart {SERVICE}" not in commands


def test_second_run_is_a_noop() -> None:
    cfg = Ipv6StaleSocketReaperConfig()
    run = run_deploy_fake(deploy_ipv6_stale_socket_reaper, cfg, responses=host(script=True, unit=True, running=True))
    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert run.executed_commands == []


def test_changed_script_restarts_without_reload() -> None:
    cfg = Ipv6StaleSocketReaperConfig()
    responses = host(unit=True, running=True)
    responses.update(fakehost.file(SCRIPT_PATH, "old\n", mode="-rwxr-xr-x"))
    run = run_deploy_fake(deploy_ipv6_stale_socket_reaper, cfg, responses=responses)
    assert "systemctl daemon-reload" not in run.executed_commands
    assert f"systemctl restart {SERVICE}" in run.executed_commands


def test_absent_stops_and_removes() -> None:
    cfg = Ipv6StaleSocketReaperConfig(state="absent")
    run = run_deploy_fake(deploy_ipv6_stale_socket_reaper, cfg, responses=host(script=True, unit=True, running=True))
    commands = run.executed_commands
    assert f"systemctl stop {SERVICE}" in commands
    assert f"systemctl disable {SERVICE}" in commands
    assert any(UNIT_PATH in command and "rm" in command for command in commands)
    assert any(SCRIPT_PATH in command and "rm" in command for command in commands)
    assert commands[-1] == "systemctl daemon-reload"
