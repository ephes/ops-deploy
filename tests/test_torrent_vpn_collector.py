"""Torrent VPN collector: a leak stays a leak, a failed probe is reported as unknown.

The collector is rendered from the role template with the default config and
its command runner is replaced, so nothing touches docker, nsenter or curl.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ops_deploy.services.torrent_vpn_metrics_endpoint import TorrentVpnMetricsEndpointConfig
from ops_deploy.services.torrent_vpn_metrics_endpoint import deploy as torrent

HOST_IP = "198.51.100.10"
EXIT_IP = "203.0.113.7"
TUN_IP = "10.69.217.11"
GLUETUN_ID = "3fc9febe3aa25866ac61fbb77fcde292a1e61d99fabe52df7a33cbd62c3a95b3"


def done(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="" if returncode == 0 else "curl: (6)")


class FakeHost:
    """A healthy AirVPN setup; `failures[(netns, service)]` makes requests fail.

    service is "ipify", "ipinfo" or "provider"; the value is how many requests
    fail before one succeeds (-1: all of them).
    """

    def __init__(self) -> None:
        self.exit_ip = EXIT_IP
        self.provider: dict[str, Any] = {"ip": EXIT_IP, "airvpn": True, "geo": {"name": "Netherlands"}}
        self.failures: dict[tuple[bool, str], int] = {}
        self.curls: list[tuple[bool, str]] = []

    def _fails(self, key: tuple[bool, str]) -> bool:
        left = self.failures.get(key, 0)
        if left == 0:
            return False
        if left > 0:
            self.failures[key] = left - 1
        return True

    def run(self, cmd: list[str], timeout: object = None) -> subprocess.CompletedProcess[str]:
        if cmd[:2] == ["docker", "inspect"]:
            fmt = cmd[3]
            if ".Id" in fmt:
                return done(GLUETUN_ID)
            if ".State.Pid" in fmt:
                return done("4242")
            if "NetworkMode" in fmt:
                return done(f"container:{GLUETUN_ID}")
            return done(json.dumps(["VPN_SERVICE_PROVIDER=airvpn", "FIREWALL_VPN_INPUT_PORTS=51234"]))
        netns = cmd[:1] == ["nsenter"]
        tail = cmd[4:] if netns else cmd
        if tail[:1] == ["curl"]:
            url = tail[-1]
            service = "ipify" if "ipify" in url else "ipinfo" if "ipinfo" in url else "provider"
            self.curls.append((netns, service))
            if self._fails((netns, service)):
                return done(returncode=6)
            if service == "provider":
                return done(json.dumps(self.provider))
            return done(json.dumps({"ip": self.exit_ip if netns else HOST_IP}))
        if tail[:2] == ["ip", "-4"]:
            return done(f"3: tun0    inet {TUN_IP}/32 scope global tun0\n")
        if tail[:1] == ["ss"]:
            return done(f"LISTEN 0 30 {TUN_IP}%tun0:51234 0.0.0.0:*\n")
        raise AssertionError(f"unexpected command {cmd}")


@pytest.fixture
def collector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    cfg = TorrentVpnMetricsEndpointConfig.model_validate(
        {"auth_user": "nyxmon", "bind": "100.64.0.7", "secrets": "secrets/fixture.yml"}
    )
    source = torrent.render_role("torrent-vpn-metrics-collect.py.j2", cfg, "100.64.0.7")
    assert 'PROBE_STATE_PATH = "/var/lib/torrent-vpn-metrics/probe-state.json"' in source
    assert 'IP_FALLBACK_URLS = ["https://ipinfo.io/json"]' in source
    module = ModuleType("torrent_vpn_collector")
    exec(compile(source, "torrent-vpn-metrics-collect.py", "exec"), module.__dict__)
    monkeypatch.setattr(module, "PROBE_STATE_PATH", str(tmp_path / "probe-state.json"))
    monkeypatch.setattr(module, "PROBE_RETRY_DELAY", 0)
    return module


def collect(module: ModuleType, host: FakeHost) -> dict[str, Any]:
    module.__dict__["_run"] = host.run
    payload: dict[str, Any] = module.Collector().collect()
    return payload


def test_healthy(collector: ModuleType) -> None:
    payload = collect(collector, FakeHost())
    vpn = payload["vpn"]
    assert (vpn["egress_ok"], vpn["provider_exit"], vpn["probe_failed"], vpn["probe_failures"]) == (1, 1, 0, 0)
    assert vpn["probe_errors"] == []
    assert payload["error"] is False


def test_exit_equal_to_host_is_a_leak_not_a_probe_failure(collector: ModuleType) -> None:
    host = FakeHost()
    host.exit_ip = HOST_IP
    vpn = collect(collector, host)["vpn"]
    assert vpn["egress_ok"] == 0
    assert vpn["probe_failed"] == 0


def test_provider_saying_no_is_a_leak(collector: ModuleType) -> None:
    host = FakeHost()
    host.provider = {"ip": EXIT_IP, "airvpn": False}
    vpn = collect(collector, host)["vpn"]
    assert (vpn["provider_exit"], vpn["probe_failed"]) == (0, 0)


def test_failed_probes_are_unknown_not_a_leak(collector: ModuleType) -> None:
    host = FakeHost()
    for service in ("ipify", "ipinfo", "provider"):
        host.failures[(True, service)] = -1
    payload = collect(collector, host)
    vpn = payload["vpn"]
    assert vpn["egress_ok"] is None
    assert vpn["provider_exit"] is None
    assert vpn["probe_failed"] == 1
    assert vpn["probe_errors"] == ["egress_ip_failed", "provider_failed"]
    assert payload["error_type"] == "egress_ip_failed"


def test_fallback_service_answers_when_the_first_fails(collector: ModuleType) -> None:
    host = FakeHost()
    host.failures[(True, "ipify")] = -1
    host.failures[(False, "ipify")] = -1
    vpn = collect(collector, host)["vpn"]
    assert (vpn["egress_ok"], vpn["exit_ip_v4"], vpn["probe_failed"]) == (1, EXIT_IP, 0)


def test_one_retry_recovers_a_short_outage(collector: ModuleType) -> None:
    host = FakeHost()
    host.failures = {(True, "ipify"): 1, (True, "ipinfo"): 1, (True, "provider"): 1}
    vpn = collect(collector, host)["vpn"]
    assert (vpn["egress_ok"], vpn["provider_exit"], vpn["probe_failed"]) == (1, 1, 0)
    assert host.curls.count((True, "provider")) == 2


def test_a_leak_is_seen_even_when_the_provider_probe_fails(collector: ModuleType) -> None:
    host = FakeHost()
    host.exit_ip = HOST_IP
    host.failures[(True, "provider")] = -1
    vpn = collect(collector, host)["vpn"]
    assert (vpn["egress_ok"], vpn["provider_exit"], vpn["probe_failed"]) == (0, None, 1)


def test_non_ipv4_answer_counts_as_a_failed_probe(collector: ModuleType) -> None:
    host = FakeHost()
    host.exit_ip = "not-an-ip"
    vpn = collect(collector, host)["vpn"]
    assert (vpn["egress_ok"], vpn["exit_ip_v4"], vpn["probe_failed"]) == (None, None, 1)


def test_consecutive_probe_failures_count_up_and_reset(collector: ModuleType) -> None:
    def failing() -> FakeHost:
        host = FakeHost()
        host.failures[(True, "provider")] = -1
        return host

    assert [collect(collector, failing())["vpn"]["probe_failures"] for _ in range(3)] == [1, 2, 3]
    assert collect(collector, FakeHost())["vpn"]["probe_failures"] == 0
    assert collect(collector, failing())["vpn"]["probe_failures"] == 1


def test_unreadable_probe_state_starts_from_zero(collector: ModuleType) -> None:
    Path(collector.PROBE_STATE_PATH).write_text("garbage")
    host = FakeHost()
    host.failures[(True, "provider")] = -1
    assert collect(collector, host)["vpn"]["probe_failures"] == 1


def test_unwritable_probe_state_makes_the_failure_count_unknown(
    collector: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A directory as target: os.replace fails, the stale count must not stay green.
    blocked = tmp_path / "blocked"
    (blocked / "probe-state.json").mkdir(parents=True)
    monkeypatch.setattr(collector, "PROBE_STATE_PATH", str(blocked / "probe-state.json"))
    host = FakeHost()
    host.failures[(True, "provider")] = -1
    payloads = [collect(collector, host) for _ in range(3)]
    for payload in payloads:
        vpn = payload["vpn"]
        assert vpn["probe_failures"] is None
        assert vpn["probe_state_ok"] == 0
        assert payload["error"] is True
    # Healthy runs keep the reset count, only flag the state problem.
    healthy = collect(collector, FakeHost())["vpn"]
    assert (healthy["probe_failures"], healthy["probe_state_ok"], healthy["probe_failed"]) == (0, 0, 0)


def test_healthy_run_reports_state_ok(collector: ModuleType) -> None:
    assert collect(collector, FakeHost())["vpn"]["probe_state_ok"] == 1
