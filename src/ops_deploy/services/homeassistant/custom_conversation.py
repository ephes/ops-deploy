"""Original Custom Conversation flow/canary, protected execution-only component."""

from __future__ import annotations

import base64
import json
from collections.abc import Generator
from dataclasses import dataclass
from importlib.resources import files
from pathlib import PurePosixPath

from pydantic import Field, SecretStr, StrictBool, StrictInt
from pyinfra.api import FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host

from ops_deploy.base._common import RoleConfig
from ops_deploy.helpers.probes import StdinLines
from ops_deploy.helpers.python import _as_user

from .builtin_conversation import ConversationResult
from .integration_flows import HomeAssistantApiConfig
from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command


class CustomConversationConfig(RoleConfig):
    enabled: StrictBool = False
    provider: SecretStr = SecretStr("openai")
    base_url: SecretStr = SecretStr("")
    api_key: SecretStr = SecretStr("")
    model: SecretStr = SecretStr("")
    instructions: SecretStr = SecretStr("")
    version: str = "1.7.0"
    canary_text: SecretStr = SecretStr("Reply with the single word OK.")
    canary_timeout: StrictInt = Field(default=90, ge=1)
    resolve_retries: StrictInt = Field(default=20, ge=1)
    resolve_delay: StrictInt = Field(default=3, ge=0)
    command_timeout: StrictInt = Field(default=3600, ge=1)

    def validate_selected(self) -> None:
        if self.enabled and any(
            not field.get_secret_value() for field in (self.provider, self.base_url, self.api_key, self.model)
        ):
            raise ValueError("Enabled Custom Conversation requires provider, base_url, api_key and model")


@dataclass
class CustomConversationResult(ConversationResult):
    phase: str = "not-run"
    mutation_attempts: int | None = None
    partial_possible: bool | None = None


def custom_payload(
    runtime: HomeAssistantRuntimeConfig, api: HomeAssistantApiConfig, config: CustomConversationConfig
) -> SecretStr:
    config.validate_selected()
    api.validate_selected()
    return SecretStr(
        json.dumps(
            {
                "secrets": {
                    "HA_TOKEN": api.token.get_secret_value(),
                    "HA_CC_API_KEY": config.api_key.get_secret_value(),
                },
                "settings": {
                    "HA_API_URL": api.url.get_secret_value(),
                    "HA_STORAGE_PATH": runtime.config_path + "/.storage/core.config_entries",
                    "HA_CC_ENABLED": "1" if config.enabled else "0",
                    "HA_CC_PROVIDER": config.provider.get_secret_value(),
                    "HA_CC_BASE_URL": config.base_url.get_secret_value(),
                    "HA_CC_MODEL": config.model.get_secret_value(),
                    "HA_CC_INSTRUCTIONS": config.instructions.get_secret_value(),
                    "HA_CC_VERSION": config.version,
                    "HA_CANARY_TEXT": config.canary_text.get_secret_value(),
                    "HA_TIMEOUT": str(api.timeout),
                    "HA_CANARY_TIMEOUT": str(config.canary_timeout),
                    "HA_RESOLVE_RETRIES": str(config.resolve_retries),
                    "HA_RESOLVE_DELAY": str(config.resolve_delay),
                    "HA_FORWARDED_FOR": api.forwarded_for or api.default_ipv4 or "127.0.0.1",
                    "HA_FORWARDED_PROTO": api.forwarded_proto,
                },
            }
        )
    )


def custom_command(runtime: HomeAssistantRuntimeConfig) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/custom_conversation.py").read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-custom>','exec'))"
    )
    return _as_user(
        runtime.user,
        PurePosixPath(runtime.home),
        {"PYTHONDONTWRITEBYTECODE": "1"},
        [runtime.virtualenv_path + "/bin/python", "-B", "-c", launcher],
    )


def _execute(
    state: State,
    host: Host,
    command: str,
    payload: SecretStr,
    timeout: int,
    enabled: bool,
    result: CustomConversationResult,
) -> None:
    result.completed = False
    result.reported_changed = None
    result.entity_id = SecretStr("")
    result.phase = "unknown"
    result.mutation_attempts = None
    result.partial_possible = None
    try:
        success, output = run_protected_command(
            host,
            StringCommand(command),
            _stdin=StdinLines(payload.get_secret_value()),
            _get_pty=False,
            _timeout=timeout,
        )
    except TimeoutError:
        raise OperationError("Custom Conversation timed out; partial effects and remote activity may exist") from None
    diagnostic = "helper failed or returned an invalid report"
    try:
        report = json.loads(str(output.stdout))
        if not isinstance(report, dict):
            raise ValueError
        if (
            not success
            and set(report) == {"status", "diagnostic", "phase", "mutation_attempts", "partial_possible"}
            and report.get("status") == "error"
            and isinstance(report.get("diagnostic"), str)
            and report["phase"]
            in {
                "input",
                "canary",
                "configuration",
                "read",
                "entity-registry",
                "start",
                "provider",
                "credentials",
                "model",
                "reconfigure_start",
                "reconfigure_provider",
                "reconfigure_credentials",
                "reconfigure_model",
                "options_start",
                "options",
            }
            and type(report["mutation_attempts"]) is int
            and report["mutation_attempts"] >= 0
            and type(report["partial_possible"]) is bool
            and report["partial_possible"] == (report["mutation_attempts"] > 0)
        ):
            # The bound helper emits only fixed source-owned diagnostics or an
            # exception class, never arbitrary upstream text/credentials/IDs.
            result.phase = report["phase"]
            result.mutation_attempts = report["mutation_attempts"]
            result.partial_possible = report["partial_possible"]
            diagnostic = (
                report["diagnostic"] + f" (phase={result.phase}, mutation_attempts={result.mutation_attempts}, "
                f"partial_possible={result.partial_possible})"
            )
        if not success or set(report) != {"status", "changed", "action", "entity_id", "mutation_attempts"}:
            raise ValueError
        if report["status"] != "success" or type(report["changed"]) is not bool:
            raise ValueError
        if report["action"] not in {"unchanged", "created", "updated", "removed"}:
            raise ValueError
        if type(report["mutation_attempts"]) is not int or report["mutation_attempts"] < 0:
            raise ValueError
        if not isinstance(report["entity_id"], str):
            raise ValueError
        if enabled and not report["entity_id"].startswith("conversation."):
            raise ValueError
        if not enabled and report["entity_id"] != "":
            raise ValueError
    except (ValueError, TypeError):
        effects = (
            "; helper made no mutation attempt" if result.partial_possible is False else "; partial effects may exist"
        )
        raise OperationError("Custom Conversation failed: " + diagnostic + effects) from None
    result.entity_id = SecretStr(report["entity_id"])
    result.reported_changed = report["changed"]
    result.completed = True
    result.phase = "complete"
    result.mutation_attempts = report["mutation_attempts"]
    result.partial_possible = False


@operation()
def run_custom_conversation(
    runtime: HomeAssistantRuntimeConfig,
    api: HomeAssistantApiConfig,
    config: CustomConversationConfig,
    result: CustomConversationResult,
) -> Generator[FunctionCommand, None, None]:
    """Managed real canary even if config is unchanged; no API calls at planning.

    Caller supplies original enabled-or-existing selection, readiness and flush
    order. The original helper always uses aiohttp's certificate verification;
    the other integration helper's validate_certs setting does not override it.
    """
    yield FunctionCommand(
        _execute,
        (custom_command(runtime), custom_payload(runtime, api, config), config.command_timeout, config.enabled, result),
        {},
    )
