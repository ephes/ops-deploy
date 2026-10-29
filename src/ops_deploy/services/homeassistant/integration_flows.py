"""Prepared original Matter, OTBR and Wyoming config-flow operations.

Registry inspection stays host-local. Readiness and configuration POSTs run only
inside a needed managed operation, with fixed status output and protected stdin.
The outer deploy owns original enable flags and readiness reset after handlers.
"""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Literal

from pydantic import SecretStr, StrictBool, StrictInt
from pyinfra import host
from pyinfra.api import FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.probes import StdinLines

from .runtime_config import HomeAssistantRuntimeConfig


class HomeAssistantApiConfig(RoleConfig):
    url: SecretStr = SecretStr("http://localhost:10020")
    token: SecretStr = SecretStr("")
    timeout: StrictInt = 30
    validate_certs: StrictBool = True
    retries: StrictInt = 30
    retry_delay: StrictInt = 5
    forwarded_for: str = ""
    forwarded_proto: str = "http"
    default_ipv4: str | None = None

    def validate_selected(self) -> None:
        value = self.token.get_secret_value()
        if len(value) < 32 or value.lower() in {"change_me", "changeme", "replace_me", "replace-me"}:
            raise ValueError("Home Assistant selected integration needs the original valid long-lived token")
        if not self.url.get_secret_value():
            raise ValueError("Home Assistant selected integration needs an API URL")


class IntegrationSelection(RoleConfig):
    domain: Literal["matter", "otbr", "wyoming"]
    url: SecretStr = SecretStr("")
    wyoming_host: str = ""
    wyoming_port: StrictInt = 10300

    def desired(self) -> dict[str, Any]:
        if self.domain == "wyoming":
            if not self.wyoming_host or self.wyoming_port <= 0:
                raise ValueError("Selected Wyoming integration needs the original host and positive port")
            return {"host": self.wyoming_host, "port": self.wyoming_port}
        value = self.url.get_secret_value()
        if not value:
            raise ValueError("Selected URL integration needs the original nonempty URL")
        return {"url": value}


@dataclass
class ApiReadiness:
    """One host/role invocation only; caller resets after the original flush."""

    ready: bool = False


def flow_command(cfg: HomeAssistantRuntimeConfig) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/integration_flow.py").read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-flow>','exec'))"
    )
    return shlex.join([cfg.security.system_python, "-I", "-B", "-c", launcher])


def _run(target: Host, command: str, payload: SecretStr, *, timeout: int) -> dict[str, Any]:
    success, output = target.run_shell_command(
        StringCommand(command),
        _stdin=StdinLines(payload.get_secret_value()),
        _get_pty=False,
        print_input=False,
        print_output=False,
        _timeout=timeout,
    )
    try:
        report = json.loads(str(output.stdout))
        if not isinstance(report, dict) or set(report) != {
            "success",
            "phase",
            "needed",
            "ready",
            "http_requests",
            "mutation_attempts",
            "changed",
            "error",
        }:
            raise ValueError
        if any(type(report[key]) is not bool for key in ("success", "needed", "ready", "changed")):
            raise ValueError
        if any(type(report[key]) is not int or report[key] < 0 for key in ("http_requests", "mutation_attempts")):
            raise ValueError
        if report["phase"] not in {
            "input",
            "inspect",
            "readiness",
            "matter-port",
            "start-flow",
            "submit-flow",
            "complete",
        }:
            raise ValueError
        if not isinstance(report["error"], str) or not report["error"].isascii() or len(report["error"]) > 64:
            raise ValueError
        if success is not report["success"]:
            raise ValueError
    except (TypeError, ValueError, KeyError):
        raise OperationError("Home Assistant integration returned an invalid fixed report") from None
    return report


def _apply(state: State, host: Host, command: str, payload: SecretStr, readiness: ApiReadiness, timeout: int) -> None:
    value = json.loads(payload.get_secret_value())
    value["ready"] = readiness.ready
    report = _run(host, command, SecretStr(json.dumps(value)), timeout=timeout)
    readiness.ready = report["ready"]
    if not report["success"]:
        # No response body, registry value, flow ID, URL or token is surfaced.
        raise OperationError(
            "Home Assistant integration failed during "
            + report["phase"]
            + f" after {report['mutation_attempts']} configuration request attempts"
        )


@operation()
def _integrate(
    command: str, inspect_payload: SecretStr, apply_payload: SecretStr, readiness: ApiReadiness, timeout: int
) -> Generator[FunctionCommand, None, None]:
    report = _run(host, command, inspect_payload, timeout=90)
    if not report["success"]:
        raise OperationError("Home Assistant integration registry inspection failed")
    if report["needed"]:
        yield FunctionCommand(_apply, (command, apply_payload, readiness, timeout), {})


def integrate(
    runtime: HomeAssistantRuntimeConfig,
    api: HomeAssistantApiConfig,
    selection: IntegrationSelection,
    readiness: ApiReadiness,
) -> OperationMeta:
    api.validate_selected()
    value: dict[str, Any] = {
        "action": "inspect",
        "config_path": runtime.config_path,
        "domain": selection.domain,
        "desired": selection.desired(),
    }
    inspect_payload = SecretStr(json.dumps(value))
    value.update(
        action="apply",
        api={
            **api.model_dump(exclude={"url", "token", "default_ipv4"}),
            "url": api.url.get_secret_value(),
            "token": api.token.get_secret_value(),
        },
        manage_matter_server=runtime.manage_matter_server,
        matter_port=runtime.matter_server_port,
    )
    if api.default_ipv4 is not None:
        value["default_ipv4"] = api.default_ipv4
    # Finite original initial+retry requests/delays, optional Matter port wait,
    # two flow calls. This is a finite operation budget, not a bound on every
    # possible socket/auth hop. The target enforces its own wall clock and exits
    # with a fixed partial-effect report before the controller grace expires.
    budget = (max(0, api.retries) + 1) * (api.timeout * 11 + max(0, api.retry_delay)) + api.timeout * 3 + 60
    value["deadline_seconds"] = budget
    return _integrate(
        command=flow_command(runtime),
        name=f"Provision Home Assistant {selection.domain} integration",
        inspect_payload=inspect_payload,
        apply_payload=SecretStr(json.dumps(value)),
        readiness=readiness,
        timeout=budget + 30,
    )
