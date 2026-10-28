"""Terminal failure, disconnect and cleanup boundaries of native network jobs."""

from __future__ import annotations

from typing import Any, cast

import pytest
from pyinfra.api import DeployError, StringCommand
from pyinfra.api.host import Host
from pyinfra.api.state import State
from pyinfra.connectors.util import CommandOutput, OutputLine

from ops_deploy.infra.netplan.deploy import NetworkJobWaitCommand


class JobHost:
    def __init__(self, states: list[str | None], *, stop_ok: bool = True) -> None:
        self.connected = True
        self.states = iter(states)
        self.stop_ok = stop_ok
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.reconnects = 0

    def connect(self, **kwargs: Any) -> None:
        assert kwargs == {"show_errors": False}
        self.reconnects += 1
        self.connected = True

    def disconnect(self) -> None:
        self.connected = False

    def run_shell_command(self, command: StringCommand, **kwargs: Any) -> tuple[bool, CommandOutput]:
        text = command.get_raw_value()
        self.calls.append((text, kwargs))
        if text.startswith(("systemctl stop", "systemctl reset-failed")):
            return self.stop_ok, CommandOutput([])
        state = next(self.states)
        return state is not None, CommandOutput([OutputLine("stdout", row) for row in (state or "").splitlines()])


def terminal(active: str = "active", result: str = "success", pid: str = "0") -> str:
    return (
        f"LoadState=loaded\nActiveState={active}\nResult={result}\nExecMainStatus=0\n"
        f"MainPID={pid}\nControlPID=0\nJob=0\nExecMainExitTimestampMonotonic=10"
    )


def run_job(host: JobHost) -> None:
    NetworkJobWaitCommand("ops-deploy-netplan-owned.service").execute(
        cast(State, None), cast(Host, host), {"_sudo": True, "_sudo_user": "root"}
    )


def test_reconnect_preserves_original_privilege_and_waits_for_terminal_job(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ops_deploy.infra.netplan.deploy.time.sleep", lambda _: None)
    host = JobHost([None, terminal("activating", pid="123"), terminal(), terminal("inactive")])
    run_job(host)
    assert host.reconnects == 1
    assert sum(command.startswith("systemctl stop") for command, _ in host.calls) == 1
    assert all(options["_sudo"] is True and options["_sudo_user"] == "root" for _, options in host.calls)
    assert all("_timeout" in options for _, options in host.calls)


def test_native_failure_stops_only_owned_job_and_preserves_failure() -> None:
    host = JobHost([terminal("failed", "exit-code"), terminal("inactive")])
    with pytest.raises(DeployError, match="activation failed"):
        run_job(host)
    assert host.calls[1][0] == "systemctl stop ops-deploy-netplan-owned.service"


@pytest.mark.parametrize(("stop_ok", "final"), [(False, ""), (True, terminal("inactive", pid="456"))])
def test_unproven_cleanup_requires_writer_retention(stop_ok: bool, final: str) -> None:
    host = JobHost([terminal(), final], stop_ok=stop_ok)
    with pytest.raises(DeployError, match="retain writer ownership"):
        run_job(host)


def test_unknown_job_does_not_retry_activation_or_claim_cleanup(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([0, 1, 1000])
    monkeypatch.setattr("ops_deploy.infra.netplan.deploy.time.monotonic", lambda: next(ticks))
    monkeypatch.setattr("ops_deploy.infra.netplan.deploy.time.sleep", lambda _: None)
    host = JobHost(["LoadState=not-found\nActiveState=inactive"])
    with pytest.raises(DeployError, match="outcome unknown"):
        run_job(host)
    assert len(host.calls) == 1


def test_inactive_queued_and_never_executed_unit_is_not_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ops_deploy.infra.netplan.deploy.time.sleep", lambda _: None)
    queued = "LoadState=loaded\nActiveState=inactive\nJob=42\nExecMainExitTimestampMonotonic=0"
    never = "LoadState=loaded\nActiveState=inactive\nJob=0\nExecMainExitTimestampMonotonic=0"
    host = JobHost([queued, never, terminal(), terminal("inactive")])
    run_job(host)
    assert [command.startswith("systemctl stop") for command, _ in host.calls] == [False, False, False, True, False]
