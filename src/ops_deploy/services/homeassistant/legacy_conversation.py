"""Original legacy migration observation/removal; retirement remains a real API call."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from dataclasses import dataclass
from importlib.resources import files

from pyinfra import host
from pyinfra.api import OperationError, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.probes import StdinLines

from .runtime_config import HomeAssistantRuntimeConfig
from .security import _present


@dataclass(frozen=True)
class LegacyConversationState:
    component_present: bool
    litellm_present: bool
    rebuild: bool
    retire: bool
    skipped_metadata: int


def inspect_legacy_conversation(target: Host, cfg: HomeAssistantRuntimeConfig) -> LegacyConversationState:
    """Original root-context observation before Python replacement; fixed flags only.

    Caller retains this initial rebuild flag after component removal and retires
    selected entries through the original helper before removing that component.
    The metadata walk is the original scoped virtualenv/lib search, not a user
    data walk. Skipped metadata is preserved as a count, never fabricated absence
    certainty or a new refusal. Read activity can update filesystem atime.
    """
    source = files("ops_deploy.services.homeassistant").joinpath("files/legacy_conversation.py").read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-legacy>','exec'))"
    )
    command = shlex.join([cfg.security.system_python, "-I", "-B", "-c", launcher])
    success, output = target.run_shell_command(
        StringCommand(command),
        _stdin=StdinLines(json.dumps({"config_path": cfg.config_path, "virtualenv_path": cfg.virtualenv_path})),
        _get_pty=False,
        print_input=False,
        print_output=False,
        _timeout=90,
    )
    try:
        result = json.loads(str(output.stdout))
        if not success or not isinstance(result, dict) or result.pop("success", None) is not True:
            raise ValueError
        if set(result) != {"component_present", "litellm_present", "rebuild", "retire", "skipped_metadata"}:
            raise ValueError
        if any(
            type(result[field]) is not bool for field in ("component_present", "litellm_present", "rebuild", "retire")
        ):
            raise ValueError
        if type(result["skipped_metadata"]) is not int or result["skipped_metadata"] < 0:
            raise ValueError
        if result["rebuild"] != (result["component_present"] or result["litellm_present"]):
            raise ValueError
    except (ValueError, TypeError):
        raise OperationError("Home Assistant legacy conversation inspection failed") from None
    return LegacyConversationState(**result)


@operation()
def _remove_legacy_component(cfg: HomeAssistantRuntimeConfig) -> Generator[StringCommand, None, None]:
    path = cfg.config_path + "/custom_components/custom_conversation"
    # lstat includes dangling links; rm removes only this exact root without
    # following a root symlink, as original file state:absent. Fresh at execution.
    if _present(host, path, cfg.security.system_python):
        yield StringCommand("rm -rf -- " + shlex.quote(path))


def remove_legacy_component(cfg: HomeAssistantRuntimeConfig) -> OperationMeta:
    """Call after successful original live retirement, before Python upgrade."""
    return _remove_legacy_component(name="Remove retired Custom Conversation component", cfg=cfg)
