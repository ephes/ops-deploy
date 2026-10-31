"""Original trust admission, managed drop-in write and post-handler verification."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from collections.abc import Generator
from importlib.resources import files
from io import StringIO
from pathlib import PurePosixPath
from typing import Literal

from pyinfra.api import DeployError, FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files as file_ops

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe

from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command


def dropin_text() -> str:
    return files("ops_deploy.services.homeassistant").joinpath("templates/uv-system-certs.conf.j2").read_text()


def trust_command(
    cfg: HomeAssistantRuntimeConfig,
    mode: Literal["preflight", "verify"],
    *,
    allow_missing_unit: bool = False,
) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/uv_system_certs_check.py").read_bytes()
    encoded = base64.b64encode(source).decode()
    launcher = f"import base64;exec(compile(base64.b64decode('{encoded}'),'<ha-unit-trust>','exec'))"
    args = [
        "/usr/bin/python3",
        "-I",
        "-B",
        "-c",
        launcher,
        "--unit",
        cfg.service_name + ".service",
        "--dropin",
        cfg.uv_system_certs_dropin_path,
        "--dropin-sha256",
        hashlib.sha256(dropin_text().encode()).hexdigest(),
        "--mode",
        mode,
    ]
    if allow_missing_unit:
        args.append("--allow-missing-unit")
    args.extend("--allow-dropin=" + path for path in cfg.uv_system_certs_allowed_dropins)
    return shlex.join(args)


def inspect_trust(
    cfg: HomeAssistantRuntimeConfig,
    mode: Literal["preflight", "verify"],
    *,
    allow_missing_unit: bool = False,
) -> dict[str, object]:
    """Run the unchanged original host program; expose only its fixed schema."""
    result = probe(
        trust_command(cfg, mode, allow_missing_unit=allow_missing_unit),
        name=f"Home Assistant unit trust {mode}",
    )
    return _validated_report(result)


def _validated_report(result: str | None) -> dict[str, object]:
    try:
        value = json.loads(result or "")
        base = {"load_state", "active_state", "managed_dropin", "problems"}
        if not isinstance(value, dict):
            raise ValueError
        expected = base | {"running_managed_value"} if value.get("load_state") == "loaded" else base
        if set(value) != expected:
            raise ValueError
        if not all(type(value[key]) is str for key in ("load_state", "active_state")):
            raise ValueError
        if type(value["managed_dropin"]) is not bool:
            raise ValueError
        if "running_managed_value" in value and type(value["running_managed_value"]) is not bool:
            raise ValueError
        if type(value["problems"]) is not list or not all(type(item) is str for item in value["problems"]):
            raise ValueError
    except (TypeError, ValueError):
        raise DeployError("Home Assistant unit trust inspection returned an invalid status") from None
    if value["problems"]:
        # Unchanged original messages contain keys/paths only, never values.
        raise DeployError("Home Assistant unit trust: " + "; ".join(value["problems"]))
    return dict(value)


def write_managed_dropin(cfg: HomeAssistantRuntimeConfig) -> OperationMeta | None:
    """Original root-owned directory/file; caller already ran trust preflight.

    Return only the file result: a directory metadata correction alone did not
    notify the original reload/restart handlers. This component does not flush
    handlers or remove an existing drop-in when management is disabled.
    """
    if not cfg.uv_system_certs:
        return None
    file_ops.directory(
        name="Ensure Home Assistant trust drop-in directory",
        path=str(PurePosixPath(cfg.uv_system_certs_dropin_path).parent),
        user="root",
        group="root",
        mode="0755",
    )
    return file_ops.put(
        name="Write Home Assistant managed trust drop-in",
        src=StringIO(dropin_text()),
        dest=cfg.uv_system_certs_dropin_path,
        user="root",
        group="root",
        mode="0644",
    )


def _verify_after_handlers(state: State, host: Host, cfg: HomeAssistantRuntimeConfig) -> None:
    success, output = run_protected_command(host, StringCommand(trust_command(cfg, "verify")), _timeout=60)
    if not success:
        raise OperationError("Home Assistant unit trust verification command failed")
    try:
        _validated_report(str(output.stdout))
    except DeployError as error:
        raise OperationError(str(error)) from None


@operation()
def _verify_running_trust(cfg: HomeAssistantRuntimeConfig) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_verify_after_handlers, (cfg,), {})


def verify_running_trust(cfg: HomeAssistantRuntimeConfig) -> OperationMeta | None:
    """Original verification only for managed trust and desired started state.

    Register after the original final handler flush. Planning never executes the
    verification callback. A failed actual report remains failure, without a
    restart/repair or automatic fallback to alternative trust configuration.
    """
    if not cfg.uv_system_certs or cfg.service_state != "started":
        return None
    return mark_read_only(_verify_running_trust(name="Verify running Home Assistant managed trust", cfg=cfg))
