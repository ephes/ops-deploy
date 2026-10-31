"""Protected read-only live engine projection for Assist preparation/readiness."""

from __future__ import annotations

import base64
import json
from importlib.resources import files
from pathlib import PurePosixPath

from paramiko import SSHException
from pydantic import SecretStr
from pyinfra.api import OperationError, StringCommand
from pyinfra.api.host import Host

from ops_deploy.helpers.probes import StdinLines
from ops_deploy.helpers.python import _as_user

from .integration_flows import HomeAssistantApiConfig
from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command


def registry_command(runtime: HomeAssistantRuntimeConfig) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/live_registry.py").read_bytes()
    launcher = (
        f"import base64;exec(compile(base64.b64decode({base64.b64encode(source).decode()!r}),'<ha-registry>','exec'))"
    )
    return _as_user(
        runtime.user,
        PurePosixPath(runtime.home),
        {"PYTHONDONTWRITEBYTECODE": "1"},
        [runtime.virtualenv_path + "/bin/python", "-I", "-B", "-c", launcher],
    )


def registry_payload(api: HomeAssistantApiConfig, app_port: int) -> dict[str, object]:
    url = api.url.get_secret_value()
    if api.default_ipv4 is not None and ("localhost" in url.lower() or "127.0.0.1" in url):
        url = f"http://{api.default_ipv4}:{app_port}"
    auth_value = api.token.get_secret_value()
    return {
        "url": url,
        "token": auth_value,
        "timeout": api.timeout,
        "validate_certs": api.validate_certs,
    }


def read_live_registry(
    target: Host, runtime: HomeAssistantRuntimeConfig, api: HomeAssistantApiConfig, app_port: int, selection: SecretStr
) -> SecretStr:
    payload = {
        **registry_payload(api, app_port),
        **json.loads(selection.get_secret_value()),
        "retries": api.retries,
        "delay": api.retry_delay,
    }
    try:
        success, output = run_protected_command(
            target,
            StringCommand(registry_command(runtime)),
            _stdin=StdinLines(json.dumps(payload)),
            _get_pty=False,
            _timeout=(max(0, api.retries) + 1) * api.timeout + max(0, api.retries) * max(0, api.retry_delay) + 10,
        )
        report = json.loads(str(output.stdout))
        if not success or report.get("success") is not True or not isinstance(report.get("entities"), list):
            raise ValueError
        for item in report["entities"]:
            if not isinstance(item, dict) or set(item) != {"entity_id", "platform", "config_entry_id"}:
                raise ValueError
    except (ValueError, TypeError, AttributeError, OSError, SSHException):
        raise OperationError("Home Assistant live Assist registry query failed") from None
    return SecretStr(json.dumps(report["entities"]))
