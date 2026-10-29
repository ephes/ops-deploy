"""Prepared execution wiring for original list and standalone voice pipelines."""

from __future__ import annotations

import base64
import json
from collections.abc import Generator
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, Literal

from paramiko import SSHException
from pydantic import SecretStr
from pyinfra import host, logger, state
from pyinfra.api import FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import StdinLines
from ops_deploy.helpers.python import _as_user

from .builtin_conversation import ConversationResult
from .integration_flows import ApiReadiness, HomeAssistantApiConfig, ensure_api_readiness
from .pipeline_state import read_pipeline_preparation
from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command

Mode = Literal["list", "voice"]


@dataclass
class PipelineResult:
    """Selected operational payload in protected RAM; fixed public counters."""

    _host_name: str | None = field(default=None, init=False, repr=False)
    selected: SecretStr = field(default_factory=lambda: SecretStr(""))
    prepared: bool = False
    needed: bool = False
    completed: bool = False
    reported_changed: bool | None = None
    mutation_attempts: int | None = None
    applied: int | None = None

    def bind(self, host_name: str) -> None:
        """Reject programmer reuse before any registration/execution on another host."""
        if self._host_name is not None and self._host_name != host_name:
            raise ValueError("Home Assistant pipeline result must be created separately for each host")
        self._host_name = host_name

    def required(self) -> bool:
        return self.prepared and self.needed

    def reset_outcome(self) -> None:
        self.completed = False
        self.reported_changed = None
        self.mutation_attempts = None
        self.applied = None


def pipeline_command(runtime: HomeAssistantRuntimeConfig, *, wait: bool = False) -> str:
    name = "pipeline_wait.py" if wait else "pipelines.py"
    source = files("ops_deploy.services.homeassistant").joinpath("files", name).read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-pipeline>','exec'))"
    )
    return _as_user(
        runtime.user,
        PurePosixPath(runtime.home),
        {"PYTHONDONTWRITEBYTECODE": "1"},
        [runtime.virtualenv_path + "/bin/python", "-I", "-B", "-c", launcher],
    )


def _prepare(
    state: State,
    host: Host,
    runtime: HomeAssistantRuntimeConfig,
    mode: Mode,
    options: SecretStr,
    builtin: ConversationResult | None,
    custom: ConversationResult | None,
    result: PipelineResult,
) -> None:
    result.selected = SecretStr("")
    result.prepared = result.needed = False
    result.reset_outcome()
    value = json.loads(options.get_secret_value())
    value["config_path"] = runtime.config_path
    value["check_mode"] = False  # This callback executes only, never during dry planning.
    value["llama_cpp_entity_id"] = builtin.entity_id.get_secret_value() if builtin and builtin.completed else ""
    value["custom_conversation_entity_id"] = custom.entity_id.get_secret_value() if custom and custom.completed else ""
    if (
        mode == "list"
        and not value["custom_conversation_entity_id"]
        and any(item.get("conversation_engine") == "auto:custom_conversation" for item in value.get("pipelines", []))
    ):
        logger.warning("Home Assistant pipeline custom conversation is unresolved; using the original default agent")
    result.selected = read_pipeline_preparation(host, runtime, mode, SecretStr(json.dumps(value)), timeout=90)
    selected = json.loads(result.selected.get_secret_value())
    result.needed = bool(selected) if mode == "list" else selected["needed"]
    result.prepared = True
    if not result.needed:
        result.completed = True
        result.reported_changed = False
        result.mutation_attempts = result.applied = 0


@operation()
def _prepare_operation(
    runtime: HomeAssistantRuntimeConfig,
    mode: Mode,
    options: SecretStr,
    builtin: ConversationResult | None,
    custom: ConversationResult | None,
    result: PipelineResult,
) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_prepare, (runtime, mode, options, builtin, custom, result), {})


def _wait_stt(
    state: State, host: Host, runtime: HomeAssistantRuntimeConfig, api: HomeAssistantApiConfig, result: PipelineResult
) -> None:
    value = json.loads(result.selected.get_secret_value())
    if not value["manage_stt"]:
        return
    payload = {
        "registry": runtime.config_path + "/.storage/core.entity_registry",
        "entity_id": value["voice"]["stt_engine"],
        "retries": api.retries,
        "delay": api.retry_delay,
    }
    success, output = run_protected_command(
        host,
        StringCommand(pipeline_command(runtime, wait=True)),
        _stdin=StdinLines(json.dumps(payload)),
        _get_pty=False,
        _timeout=max(0, api.retries) * max(0, api.retry_delay) + 90,
    )
    try:
        report = json.loads(str(output.stdout))
        if (
            not success
            or not isinstance(report, dict)
            or set(report) != {"success", "attempts"}
            or report["success"] is not True
            or type(report["attempts"]) is not int
            or not 1 <= report["attempts"] <= max(0, api.retries) + 1
        ):
            raise ValueError
    except (ValueError, TypeError):
        raise OperationError("Home Assistant desired STT entity did not become available") from None


@operation()
def _wait_operation(
    runtime: HomeAssistantRuntimeConfig, api: HomeAssistantApiConfig, result: PipelineResult
) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_wait_stt, (runtime, api, result), {})


def pipeline_payload(
    api: HomeAssistantApiConfig, result: PipelineResult, mode: Mode, action: Literal["inspect", "apply"], app_port: int
) -> SecretStr:
    value = json.loads(result.selected.get_secret_value())
    url = api.url.get_secret_value()
    if api.default_ipv4 is not None and ("localhost" in url.lower() or "127.0.0.1" in url):
        url = f"http://{api.default_ipv4}:{app_port}"
    payload = {
        "url": url,
        "token": api.token.get_secret_value(),
        "timeout": api.timeout,
        "mode": mode,
        "action": action,
    }
    if mode == "list":
        payload["desired"] = value
    else:
        payload.update({key: value[key] for key in ("pipeline_id", "voice", "manage_stt", "manage_tts")})
    return SecretStr(json.dumps(payload))


def _protocol(target: Host, command: str, payload: SecretStr, timeout: int, result: PipelineResult) -> dict[str, Any]:
    result.reset_outcome()
    try:
        success, output = run_protected_command(
            target,
            StringCommand(command),
            _stdin=StdinLines(payload.get_secret_value()),
            _get_pty=False,
            _timeout=timeout + 30,
        )
        report = json.loads(str(output.stdout))
        if not isinstance(report, dict) or set(report) != {
            "success",
            "phase",
            "pending",
            "mutation_attempts",
            "applied",
            "changed",
            "error",
        }:
            raise ValueError
        if any(type(report[key]) is not bool for key in ("success", "changed")):
            raise ValueError
        if any(type(report[key]) is not int or report[key] < 0 for key in ("pending", "mutation_attempts", "applied")):
            raise ValueError
        if (
            report["phase"]
            not in {
                "input",
                "connect",
                "authenticate",
                "list",
                "get",
                "compare",
                "create",
                "update",
                "preferred",
                "complete",
            }
            or not isinstance(report["error"], str)
            or not report["error"].isascii()
            or len(report["error"]) > 64
            or not report["applied"] <= report["mutation_attempts"] <= report["pending"]
            or report["changed"] != (report["mutation_attempts"] > 0)
            or success is not report["success"]
            or (report["success"] and (report["phase"] != "complete" or report["error"]))
        ):
            raise ValueError
    except (ValueError, TypeError, OSError, SSHException):
        raise OperationError(
            "Home Assistant pipeline returned no complete report; partial effects or remote activity may exist"
        ) from None
    result.reported_changed = report["changed"]
    result.mutation_attempts = report["mutation_attempts"]
    result.applied = report["applied"]
    if not report["success"]:
        raise OperationError(
            "Home Assistant pipeline failed during "
            + report["phase"]
            + f" after {report['mutation_attempts']} mutation attempts; prior effects may remain"
        )
    return report


def _apply(state: State, host: Host, command: str, payload: SecretStr, timeout: int, result: PipelineResult) -> None:
    _protocol(host, command, payload, timeout, result)
    result.completed = True


def _failed(state: State, host: Host, message: str) -> None:
    raise OperationError(message)


@operation()
def _reconcile(
    runtime: HomeAssistantRuntimeConfig, api: HomeAssistantApiConfig, mode: Mode, result: PipelineResult, app_port: int
) -> Generator[FunctionCommand, None, None]:
    command = pipeline_command(runtime)
    if state.is_executing:
        try:
            report = _protocol(
                host, command, pipeline_payload(api, result, mode, "inspect", app_port), api.timeout, result
            )
        except OperationError as error:
            yield FunctionCommand(_failed, (str(error),), {})
            return
        if report["pending"] == 0:
            result.completed = True
            return
        payload = pipeline_payload(api, result, mode, "apply", app_port)
    else:
        # Protected selected definitions do not exist until preparation executes.
        payload = SecretStr("{}")
    yield FunctionCommand(_apply, (command, payload, api.timeout, result), {})


def manage_pipelines(
    runtime: HomeAssistantRuntimeConfig,
    api: HomeAssistantApiConfig,
    readiness: ApiReadiness,
    mode: Mode,
    options: SecretStr,
    result: PipelineResult,
    *,
    app_port: int,
    builtin: ConversationResult | None = None,
    custom: ConversationResult | None = None,
) -> tuple[OperationMeta, ...]:
    """Call in original selected list-or-voice branch, after conversation results.

    Create result/readiness/conversation state separately inside each host deploy.
    Cross-host result reuse is rejected at registration, before execution.
    Plan makes no registry/API call. Root-context selection and service-user
    protocol stay distinct; selected fields remain only in protected process RAM.
    Current standalone voice skips all API calls. Original list still checks
    readiness and current API state. No full deployment/native claim here.
    """
    if mode not in {"list", "voice"}:
        raise ValueError("Unknown Home Assistant pipeline mode")
    api.validate_selected()
    result.bind(host.name)
    ops = [
        mark_read_only(
            _prepare_operation(
                name="Prepare Home Assistant pipeline selection",
                runtime=runtime,
                mode=mode,
                options=options,
                builtin=builtin,
                custom=custom,
                result=result,
            )
        ),
        ensure_api_readiness(runtime, api, readiness, required=result.required),
    ]
    if mode == "voice":
        ops.append(
            mark_read_only(
                _wait_operation(
                    name="Wait for Home Assistant STT selection",
                    runtime=runtime,
                    api=api,
                    result=result,
                    _if=result.required,
                )
            )
        )
    ops.append(
        _reconcile(
            name="Reconcile Home Assistant pipelines",
            runtime=runtime,
            api=api,
            mode=mode,
            result=result,
            app_port=app_port,
            _if=result.required,
        )
    )
    return tuple(ops)
