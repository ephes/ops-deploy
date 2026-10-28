"""Persistent network convergence with a bounded native activation/reconnect job."""

from __future__ import annotations

import base64
import json
import shlex
import time
import uuid
from collections.abc import Generator, Mapping
from pathlib import Path
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.arguments import ConnectorArguments
from pyinfra.api.command import PyinfraCommand
from pyinfra.api.host import Host
from pyinfra.api.state import State

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.helpers.probes import probe, verify_probe

from .config import NetplanConfig
from .payload import payload

SCRIPT = (Path(__file__).parents[1] / "files/netplan_host.py").read_text()
# Overall activation deadline, distinct from individual native command maxima.
# Long configured guard budgets extend it; no persistent adoption state.
JOB_TIMEOUT = 720
RECONNECT_TIMEOUT = 840


def activation_deadline(guard: Mapping[str, Any]) -> int:
    guard_timeout = 60 + (int(guard["confirmation_delay_sec"]) + int(guard["recovery_delay_sec"])) * len(
        guard["interfaces"]
    )
    return max(JOB_TIMEOUT, guard_timeout + 180)


def command(action: str, data: str) -> str:
    if action not in {"check", "verify", "apply"}:
        raise ValueError("unknown persistent network action")
    return shlex.join(["python3", "-I", "-B", "-c", SCRIPT, action, base64.b64encode(data.encode()).decode()])


def _unit_state(target: Host, unit: str, arguments: ConnectorArguments) -> dict[str, str] | None:
    query = shlex.join(
        [
            "systemctl",
            "show",
            unit,
            "-p",
            "LoadState",
            "-p",
            "ActiveState",
            "-p",
            "Result",
            "-p",
            "ExecMainStatus",
            "-p",
            "MainPID",
            "-p",
            "ControlPID",
            "-p",
            "Job",
            "-p",
            "ExecMainStartTimestampMonotonic",
            "-p",
            "ExecMainExitTimestampMonotonic",
        ]
    )
    options: ConnectorArguments = {**arguments, "_timeout": 15, "_get_pty": False, "_success_exit_codes": [0, 1]}
    success, output = target.run_shell_command(StringCommand(query), **options)
    if not success:
        return None
    return dict(row.split("=", 1) for row in output.stdout.splitlines() if "=" in row)


class NetworkJobWaitCommand(PyinfraCommand):
    """Keep the operation's connector/auth/privilege arguments during reconnect."""

    def __init__(self, unit: str, timeout: int = RECONNECT_TIMEOUT) -> None:
        super().__init__()
        self.unit = unit
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"NetworkJobWaitCommand({self.unit!r})"

    def execute(self, state: State, host: Host, connector_arguments: ConnectorArguments) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if not host.connected:
                host.connect(show_errors=False)
            if host.connected:
                try:
                    values = _unit_state(host, self.unit, connector_arguments)
                except Exception:
                    values = None
                if values and values.get("LoadState") == "loaded":
                    active = values.get("ActiveState")
                    queued = values.get("Job", "").strip() not in {"", "0"}
                    exited = (
                        values.get("ExecMainExitTimestampMonotonic", "0").isdigit()
                        and int(values.get("ExecMainExitTimestampMonotonic", "0")) > 0
                    )
                    if not queued and (active in {"active", "failed"} or (active == "inactive" and exited)):
                        # Type=oneshot/RemainAfterExit becomes active only after
                        # its child exits. The service's cgroup owns descendants.
                        success = (
                            active == "active"
                            and values.get("Result") == "success"
                            and values.get("ExecMainStatus") == "0"
                        )
                        cleanup = StringCommand(shlex.join(["systemctl", "stop", self.unit]))
                        stopped, _ = host.run_shell_command(cleanup, **{**connector_arguments, "_timeout": 30})
                        if stopped and active == "failed":
                            reset = StringCommand(shlex.join(["systemctl", "reset-failed", self.unit]))
                            stopped, _ = host.run_shell_command(reset, **{**connector_arguments, "_timeout": 15})
                        final = _unit_state(host, self.unit, connector_arguments) if stopped else None
                        if (
                            not final
                            or final.get("ActiveState") != "inactive"
                            or final.get("MainPID") != "0"
                            or final.get("ControlPID") != "0"
                        ):
                            raise DeployError("owned network job cleanup is unproven; retain writer ownership")
                        if not success:
                            raise DeployError("native network activation failed; preserve receipt and partial state")
                        return
                # Networkd restart may invalidate the original SSH channel.
                if values is None:
                    host.disconnect()
            time.sleep(2)
        raise DeployError("owned network job outcome unknown after reconnect budget; retain writer ownership")


@operation()
def _configure(data: str) -> Generator[StringCommand | NetworkJobWaitCommand, None, None]:
    raw = probe(command("check", data), name="Persistent network admission")
    try:
        answer: Any = json.loads(raw or "null")
    except ValueError:
        answer = None
    if isinstance(answer, dict) and answer.get("state") == "refused":
        reason = answer.get("reason")
        if isinstance(reason, str) and len(reason) < 256 and not any(ord(char) < 32 for char in reason):
            raise DeployError("persistent network admission refused: " + reason)
    if not isinstance(answer, dict) or answer.get("state") not in {"current", "pending"}:
        raise DeployError("persistent network admission failed; no activation attempted")
    if answer["state"] == "current":
        host.noop("Persistent network configuration and declared health are current")
        return
    cfg = json.loads(data)
    guard = cfg["route_guard"]
    deadline = activation_deadline(guard)
    unit = "ops-deploy-netplan-" + uuid.uuid4().hex + ".service"
    launch = shlex.join(
        [
            "systemd-run",
            "--quiet",
            "--no-block",
            "--description=ops-deploy bounded netplan activation",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=30",
            "--unit=" + unit,
            "--property=Type=oneshot",
            "--property=RemainAfterExit=yes",
            "--property=TimeoutStartSec=" + str(deadline),
            "python3",
            "-I",
            "-B",
            "-c",
            SCRIPT,
            "apply",
            base64.b64encode(data.encode()).decode(),
        ]
    )
    yield StringCommand(launch, _get_pty=False, _shell_executable="sh")
    yield NetworkJobWaitCommand(unit, timeout=deadline + 120)


@deploy("Configure persistent netplan network")
def deploy_netplan(cfg: NetplanConfig) -> None:
    require_linux("netplan")
    require_systemd("netplan")
    data = json.dumps(payload(cfg))
    _configure(name="Reconcile network and recover only actual configuration/health drift", data=data)
    verify_probe(command("verify", data), name="Persistent network state")
