"""Prepared area protocol component; outer deploy/readiness composition follows."""

from __future__ import annotations

import base64
import json
from collections.abc import Generator
from dataclasses import dataclass
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import SecretStr
from pyinfra import host, state
from pyinfra.api import FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.probes import StdinLines
from ops_deploy.helpers.python import _as_user

from .integration_flows import ApiReadiness, HomeAssistantApiConfig, ensure_api_readiness
from .runtime_config import HomeAssistantRuntimeConfig


def validate_updates(updates: list[dict[str, Any]]) -> None:
    # Keep the original aggregate selector check, including its duplicate-key
    # edge case. Resolution remains a host-side protocol error, not a new gate.
    if sum("area_id" in item for item in updates) + sum("name" in item for item in updates) < len(updates):
        raise ValueError("Home Assistant areas need the original ID/name selectors")
    if any("aliases" in item and not isinstance(item["aliases"], list) for item in updates):
        raise ValueError("Home Assistant area aliases must be a list")


def area_command(cfg: HomeAssistantRuntimeConfig) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/area_registry.py").read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-areas>','exec'))"
    )
    return _as_user(
        cfg.user,
        PurePosixPath(cfg.home),
        {"PYTHONDONTWRITEBYTECODE": "1"},
        [cfg.virtualenv_path + "/bin/python", "-I", "-B", "-c", launcher],
    )


def area_payload(
    api: HomeAssistantApiConfig,
    updates: list[dict[str, Any]],
    action: Literal["inspect", "apply"],
    *,
    app_port: int,
) -> SecretStr:
    api.validate_selected()
    validate_updates(updates)
    url = api.url.get_secret_value()
    if api.default_ipv4 is not None and ("localhost" in url.lower() or "127.0.0.1" in url):
        url = f"http://{api.default_ipv4}:{app_port}"
    return SecretStr(
        json.dumps(
            {
                "action": action,
                "url": url,
                "token": api.token.get_secret_value(),
                "timeout": api.timeout,
                "updates": updates,
            }
        )
    )


def run_area_protocol(target: Host, command: str, payload: SecretStr, *, timeout: int) -> dict[str, Any]:
    """Actual host call; callers must keep apply inside a managed operation.

    The original HTTP readiness/enable flag and cold-bootstrap sequencing belong
    to the forthcoming outer deployment. This is not a complete deploy API.
    """
    success, output = target.run_shell_command(
        StringCommand(command),
        _stdin=StdinLines(payload.get_secret_value()),
        _get_pty=False,
        print_input=False,
        print_output=False,
        _timeout=timeout + 30,
    )
    try:
        result = json.loads(str(output.stdout))
        if not isinstance(result, dict) or set(result) != {
            "success",
            "phase",
            "pending",
            "mutation_attempts",
            "applied",
            "changed",
            "error",
        }:
            raise ValueError
        if any(type(result[key]) is not bool for key in ("success", "changed")):
            raise ValueError
        if any(type(result[key]) is not int or result[key] < 0 for key in ("pending", "mutation_attempts", "applied")):
            raise ValueError
        if result["phase"] not in {"input", "connect", "authenticate", "list", "compare", "update", "complete"}:
            raise ValueError
        if not isinstance(result["error"], str) or not result["error"].isascii() or len(result["error"]) > 64:
            raise ValueError
        if not result["applied"] <= result["mutation_attempts"] <= result["pending"]:
            raise ValueError
        if result["changed"] != (result["mutation_attempts"] > 0):
            raise ValueError
        if result["success"] and (result["phase"] != "complete" or result["error"]):
            raise ValueError
        if success is not result["success"]:
            raise ValueError
    except (ValueError, TypeError):
        raise OperationError("Home Assistant area protocol returned an invalid fixed report") from None
    return result


@dataclass
class AreaResult:
    """Fixed counters only, reset on execution; no area IDs/names/bodies."""

    completed: bool = False
    reported_changed: bool | None = None
    mutation_attempts: int | None = None
    applied: int | None = None

    def reset(self) -> None:
        self.completed = False
        self.reported_changed = None
        self.mutation_attempts = None
        self.applied = None


def _checked_area_report(
    target: Host, command: str, payload: SecretStr, timeout: int, result: AreaResult
) -> dict[str, Any]:
    try:
        report = run_area_protocol(target, command, payload, timeout=timeout)
    except (TimeoutError, OperationError):
        raise OperationError(
            "Home Assistant area protocol failed without a complete report; "
            "partial effects or remote activity may exist"
        ) from None
    result.reported_changed = report["changed"]
    result.mutation_attempts = report["mutation_attempts"]
    result.applied = report["applied"]
    if not report["success"]:
        raise OperationError(
            "Home Assistant area protocol failed during "
            + report["phase"]
            + f" after {report['mutation_attempts']} mutation attempts; prior effects may remain"
        )
    return report


def _apply_areas(state: State, host: Host, command: str, payload: SecretStr, timeout: int, result: AreaResult) -> None:
    # Clear the preceding inspection counts: an invalid apply response cannot
    # turn its known zero attempts into a false zero-effect failure report.
    result.reset()
    _checked_area_report(host, command, payload, timeout, result)
    result.completed = True


def _inspection_failure(state: State, host: Host, message: str) -> None:
    # pyinfra records callback errors per host; generator exceptions bypass its
    # completion/error accounting and can abort unrelated hosts in the batch.
    raise OperationError(message)


@operation()
def _manage_areas(
    command: str, inspect_payload: SecretStr, apply_payload: SecretStr, timeout: int, result: AreaResult
) -> Generator[FunctionCommand, None, None]:
    # Original check mode does not call this API. Planning must also work before
    # the application/venv exists; the unresolved row is not claimed read-only.
    if state.is_executing:
        result.reset()
        try:
            report = _checked_area_report(host, command, inspect_payload, timeout, result)
        except OperationError as error:
            yield FunctionCommand(_inspection_failure, (str(error),), {})
            return
        if report["pending"] == 0:
            result.completed = True
            return
    yield FunctionCommand(_apply_areas, (command, apply_payload, timeout, result), {})


def manage_area_registry(
    runtime: HomeAssistantRuntimeConfig,
    api: HomeAssistantApiConfig,
    readiness: ApiReadiness,
    updates: list[dict[str, Any]],
    result: AreaResult,
    *,
    app_port: int,
) -> tuple[OperationMeta, OperationMeta]:
    """Original selected area task group after service startup, not a full deploy.

    Caller retains original enablement. Readiness executes before fresh protected
    inspection; only actual drift yields a managed apply. Plan has no API calls
    and retains an unresolved managed row. Repeat still reads API state, with no
    configuration request when converged. No global I/O or hardware claim.
    """
    inspect_payload = area_payload(api, updates, "inspect", app_port=app_port)
    apply_payload = area_payload(api, updates, "apply", app_port=app_port)
    ready = ensure_api_readiness(runtime, api, readiness)
    change = _manage_areas(
        name="Reconcile Home Assistant area registry",
        command=area_command(runtime),
        inspect_payload=inspect_payload,
        apply_payload=apply_payload,
        timeout=api.timeout,
        result=result,
    )
    return ready, change
