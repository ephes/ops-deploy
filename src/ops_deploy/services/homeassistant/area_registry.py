"""Prepared area protocol component; outer deploy/readiness composition follows."""

from __future__ import annotations

import base64
import json
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import SecretStr
from pyinfra.api import OperationError, StringCommand
from pyinfra.api.host import Host

from ops_deploy.helpers.probes import StdinLines
from ops_deploy.helpers.python import _as_user

from .integration_flows import HomeAssistantApiConfig
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
