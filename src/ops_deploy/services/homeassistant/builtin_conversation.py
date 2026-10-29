"""Original built-in conversation helper, protected execution-only component."""

from __future__ import annotations

import json
from collections.abc import Generator
from dataclasses import dataclass, field
from importlib.resources import files as resources
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, SecretStr, StrictInt
from pyinfra.api import FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.helpers.probes import StdinLines
from ops_deploy.helpers.python import _as_user

from .integration_flows import HomeAssistantApiConfig
from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command

Action = Literal["ensure", "disable", "retire"]


class BuiltinConversationConfig(RoleConfig):
    base_url: SecretStr = SecretStr("")
    api_key: SecretStr = SecretStr("")
    model: SecretStr = SecretStr("")
    instructions: SecretStr = SecretStr("")
    canary_text: SecretStr = SecretStr("Reply with the single word OK.")
    helper_path: AbsolutePath | None = None
    command_timeout: StrictInt = Field(default=3600, ge=1)


@dataclass
class ConversationResult:
    """Only this invocation; no body/credential/model response leaves host RAM."""

    entity_id: SecretStr = field(default_factory=lambda: SecretStr(""))
    reported_changed: bool | None = None
    completed: bool = False


def helper_path(runtime: HomeAssistantRuntimeConfig, config: BuiltinConversationConfig) -> str:
    return config.helper_path or runtime.bin_path + "/llama_cpp_provision.py"


def install_builtin_helper(runtime: HomeAssistantRuntimeConfig, config: BuiltinConversationConfig) -> OperationMeta:
    return files.put(
        name="Install original Home Assistant built-in conversation helper",
        src=str(resources("ops_deploy.services.homeassistant").joinpath("files/llama_cpp_provision.py")),
        dest=helper_path(runtime, config),
        user=runtime.user,
        group=runtime.group,
        mode="0755",
    )


def builtin_payload(
    runtime: HomeAssistantRuntimeConfig, api: HomeAssistantApiConfig, config: BuiltinConversationConfig, action: Action
) -> SecretStr:
    if action not in {"ensure", "disable", "retire"}:
        raise ValueError("Unsupported Home Assistant built-in conversation action")
    api.validate_selected()
    return SecretStr(
        json.dumps(
            {
                "action": action,
                "api_url": api.url.get_secret_value(),
                "api_token": api.token.get_secret_value(),
                "forwarded_for": api.forwarded_for or api.default_ipv4 or "127.0.0.1",
                "forwarded_proto": api.forwarded_proto,
                "validate_certs": api.validate_certs,
                "storage_path": runtime.config_path + "/.storage/core.config_entries",
                "base_url": config.base_url.get_secret_value(),
                "api_key": config.api_key.get_secret_value(),
                "model": config.model.get_secret_value(),
                "instructions": config.instructions.get_secret_value(),
                "canary_text": config.canary_text.get_secret_value(),
            }
        )
    )


def builtin_command(runtime: HomeAssistantRuntimeConfig, config: BuiltinConversationConfig) -> str:
    return _as_user(
        runtime.user,
        PurePosixPath(runtime.home),
        {"PYTHONDONTWRITEBYTECODE": "1"},
        [runtime.virtualenv_path + "/bin/python", "-B", helper_path(runtime, config)],
    )


def _execute(
    state: State,
    host: Host,
    command: str,
    payload: SecretStr,
    timeout: int,
    action: Action,
    result: ConversationResult,
) -> None:
    # A retry must not inherit an earlier successful canary/partial invocation.
    result.completed = False
    result.reported_changed = None
    result.entity_id = SecretStr("")
    try:
        success, output = run_protected_command(
            host,
            StringCommand(command),
            _stdin=StdinLines(payload.get_secret_value()),
            _get_pty=False,
            _timeout=timeout,
        )
    except TimeoutError:
        raise OperationError(
            "Home Assistant built-in conversation timed out; partial effects and remote activity may exist"
        ) from None
    diagnostic = "helper could not start; inspect service logs"
    try:
        report = json.loads(str(output.stdout))
        if not success and isinstance(report, dict) and set(report) == {"error"} and isinstance(report["error"], str):
            # The exact original helper emits only its sanitized
            # ProvisionError diagnostic or an exception type name here,
            # never upstream response text or credentials. Preserve the
            # same operator recovery messages as the original role.
            diagnostic = report["error"]
        expected = {"changed"} if action == "retire" else {"changed", "entity_id"}
        if not success or not isinstance(report, dict) or set(report) != expected:
            raise ValueError
        if type(report["changed"]) is not bool:
            raise ValueError
        if action != "retire" and not isinstance(report["entity_id"], str):
            raise ValueError
        if action == "ensure" and not report["entity_id"].startswith("conversation."):
            raise ValueError
        if action == "disable" and report["entity_id"] != "":
            raise ValueError
    except (ValueError, TypeError):
        # A failing helper can already have changed entries/pipelines. Do not
        # fabricate zero effects or print upstream/model/registry error bodies.
        raise OperationError(
            "Home Assistant built-in conversation failed: " + diagnostic + "; partial effects may exist"
        ) from None
    result.entity_id = SecretStr(report.get("entity_id", ""))
    result.reported_changed = report["changed"]
    result.completed = True


@operation()
def run_builtin_conversation(
    runtime: HomeAssistantRuntimeConfig,
    api: HomeAssistantApiConfig,
    config: BuiltinConversationConfig,
    action: Action,
    result: ConversationResult,
) -> Generator[FunctionCommand, None, None]:
    """Managed execution, including the real ensure canary on unchanged state.

    Caller supplies original enablement, readiness and handler-flush order. Dry
    registration makes no helper/API calls. Successful helper changed:false is
    separate from this intentionally managed execution; it is not a zero-I/O claim.
    """
    yield FunctionCommand(
        _execute,
        (
            builtin_command(runtime, config),
            builtin_payload(runtime, api, config, action),
            config.command_timeout,
            action,
            result,
        ),
        {},
    )
