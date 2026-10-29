"""Protected host-local pipeline preparation; outer role composition follows."""

from __future__ import annotations

import base64
import json
import shlex
from importlib.resources import files
from typing import Literal

from pydantic import SecretStr
from pyinfra.api import OperationError, StringCommand
from pyinfra.api.host import Host

from ops_deploy.helpers.probes import StdinLines

from .runtime_config import HomeAssistantRuntimeConfig


def preparation_command(cfg: HomeAssistantRuntimeConfig) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/pipeline_state.py").read_bytes()
    encoded = base64.b64encode(source).decode()
    launcher = f"import base64;exec(compile(base64.b64decode({encoded!r}),'<ha-pipeline-state>','exec'))"
    # Original stat/slurp runs in deployment context (root), not as the service
    # user. Protocol calls are separately run as the selected service user.
    return shlex.join([cfg.security.system_python, "-I", "-B", "-c", launcher])


def read_pipeline_preparation(
    target: Host, cfg: HomeAssistantRuntimeConfig, mode: Literal["list", "voice"], options: SecretStr, *, timeout: int
) -> SecretStr:
    """Return only selected operational values, masked and in process RAM.

    No raw registry bodies, durable result file or logging. A caller must not
    unwrap/log the result; it belongs in protected protocol input. This helper
    does not replace the original managed HTTP readiness or STT availability wait.
    """
    payload = json.dumps({"mode": mode, "options": json.loads(options.get_secret_value())})
    success, output = target.run_shell_command(
        StringCommand(preparation_command(cfg)),
        _stdin=StdinLines(payload),
        _get_pty=False,
        print_input=False,
        print_output=False,
        _timeout=timeout,
    )
    try:
        result = json.loads(str(output.stdout))
        if not success or not isinstance(result, dict) or set(result) != {"success", "result"}:
            raise ValueError
        if result["success"] is not True:
            raise ValueError
        if not isinstance(result["result"], list if mode == "list" else dict):
            raise ValueError
    except (ValueError, TypeError):
        raise OperationError("Home Assistant pipeline preparation failed") from None
    return SecretStr(json.dumps(result["result"]))
