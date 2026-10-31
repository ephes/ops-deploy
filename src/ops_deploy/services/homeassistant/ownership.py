"""Prepared recursive environment ownership, with fresh metadata-only checks."""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Generator
from importlib.resources import files

from pyinfra import state
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.probes import StdinLines, probe

from .runtime_config import HomeAssistantRuntimeConfig


def ownership_command() -> str:
    body = files("ops_deploy.services.homeassistant").joinpath("files/venv_ownership.py").read_bytes()
    encoded = base64.b64encode(body).decode()
    source = f"import base64;exec(compile(base64.b64decode('{encoded}'),'<ha-venv-ownership>','exec'))"
    return shlex.join(["python3", "-I", "-B", "-c", source])


@operation()
def _ownership(cfg: HomeAssistantRuntimeConfig, path: str, deferred: bool) -> Generator[StringCommand, None, None]:
    payload = {"root": path, "user": cfg.user, "group": cfg.group, "apply": False}
    if not (deferred and not state.is_executing):
        result = probe(ownership_command(), name="Home Assistant environment ownership", stdin=json.dumps(payload))
        if result not in {"current", "pending"}:
            raise DeployError("Home Assistant environment ownership inspection failed")
        if result == "current":
            return
    payload["apply"] = True
    yield StringCommand(ownership_command(), _stdin=StdinLines(json.dumps(payload)), _get_pty=False)


def environment_ownership(
    cfg: HomeAssistantRuntimeConfig, *, matter: bool = False, deferred: bool = False
) -> OperationMeta:
    """Original ownership scope; caller binds preceding account/venv creation.

    Existing symlink targets are part of the original recursive follow policy;
    this must not be substituted with a check of the root directory alone.
    ``deferred`` only postpones planning queries when a preceding declared
    creation prerequisite is pending. Execution always inspects before repair.
    """
    path = cfg.matter_server_virtualenv_path if matter else cfg.virtualenv_path
    return _ownership(
        name="Ensure Matter environment ownership" if matter else "Ensure Home Assistant environment ownership",
        cfg=cfg,
        path=path,
        deferred=deferred,
        _timeout=300,
    )
