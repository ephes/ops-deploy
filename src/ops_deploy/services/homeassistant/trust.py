"""Original trust admission, managed drop-in write and post-handler verification."""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from collections.abc import Callable, Generator
from functools import partial
from importlib.resources import files
from io import StringIO
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, FunctionCommand, OperationError, State, StringCommand, operation
from pyinfra.api.host import Host
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import files as file_ops

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import StdinLines, probe

from .configuration_deploy import TaskRenderer, protected_template, render_task
from .runtime_config import HomeAssistantRuntimeConfig
from .transport import run_protected_command


def dropin_text() -> str:
    return files("ops_deploy.services.homeassistant").joinpath("templates/uv-system-certs.conf.j2").read_text()


def trust_command(
    cfg: HomeAssistantRuntimeConfig,
    mode: Literal["preflight", "verify"],
    *,
    allow_missing_unit: bool = False,
    protected_digest: bool = False,
) -> str:
    source = files("ops_deploy.services.homeassistant").joinpath("files/uv_system_certs_check.py").read_bytes()
    encoded = base64.b64encode(source).decode()
    launcher = f"import base64;exec(compile(base64.b64decode('{encoded}'),'<ha-unit-trust>','exec'))"
    if protected_digest:
        # Preserve the original host program byte-for-byte. Only its private
        # expected hash is appended to Python's in-memory argv after stdin
        # admission, never to the remote command or /proc command line.
        launcher = (
            "import json,re,sys;v=json.load(sys.stdin);"
            "assert isinstance(v,dict) and set(v)=={'expected_sha256'};"
            "assert isinstance(v['expected_sha256'],str) and re.fullmatch('[0-9a-f]{64}',v['expected_sha256']);"
            "sys.argv.extend(['--dropin-sha256',v['expected_sha256']]);" + launcher
        )
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
        *([] if protected_digest else ["--dropin-sha256", hashlib.sha256(dropin_text().encode()).hexdigest()]),
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
    expected_digest: SecretStr | None = None,
) -> dict[str, object]:
    """Run the unchanged original host program; expose only its fixed schema."""
    if expected_digest is not None:
        success, output = run_protected_command(
            host,
            StringCommand(trust_command(cfg, mode, allow_missing_unit=allow_missing_unit, protected_digest=True)),
            _stdin=StdinLines(json.dumps({"expected_sha256": expected_digest.get_secret_value()})),
            _get_pty=False,
            _timeout=60,
        )
        if not success:
            raise DeployError("Home Assistant unit trust inspection command failed")
        return _validated_report(str(output.stdout))
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


def write_managed_dropin(
    cfg: HomeAssistantRuntimeConfig, *, task_renderer: TaskRenderer | None = None
) -> OperationMeta | None:
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
    if task_renderer is not None:
        return protected_template(
            cfg,
            label="Write Home Assistant managed trust drop-in",
            path=cfg.uv_system_certs_dropin_path,
            content=partial(render_task, task_renderer, "uv_certs"),
        )
    return file_ops.put(
        name="Write Home Assistant managed trust drop-in",
        src=StringIO(dropin_text()),
        dest=cfg.uv_system_certs_dropin_path,
        user="root",
        group="root",
        mode="0644",
    )


def _verify_after_handlers(
    state: State,
    host: Host,
    cfg: HomeAssistantRuntimeConfig,
    expected_digest: Callable[[str, bool], SecretStr] | None = None,
) -> None:
    kwargs: dict[str, Any] = {}
    if expected_digest is not None:
        try:
            value = expected_digest("verify", True)
        except Exception:
            raise OperationError("Home Assistant original trust template failed") from None
        kwargs["_stdin"] = StdinLines(json.dumps({"expected_sha256": value.get_secret_value()}))
        kwargs["_get_pty"] = False
    success, output = run_protected_command(
        host,
        StringCommand(trust_command(cfg, "verify", protected_digest=expected_digest is not None)),
        _timeout=60,
        **kwargs,
    )
    if not success:
        raise OperationError("Home Assistant unit trust verification command failed")
    try:
        _validated_report(str(output.stdout))
    except DeployError as error:
        raise OperationError(str(error)) from None


@operation()
def _verify_running_trust(
    cfg: HomeAssistantRuntimeConfig,
    expected_digest: Callable[[str, bool], SecretStr] | None = None,
) -> Generator[FunctionCommand, None, None]:
    yield FunctionCommand(_verify_after_handlers, (cfg, expected_digest), {})


def verify_running_trust(
    cfg: HomeAssistantRuntimeConfig,
    *,
    expected_digest: Callable[[str, bool], SecretStr] | None = None,
) -> OperationMeta | None:
    """Original verification only for managed trust and desired started state.

    Register after the original final handler flush. Planning never executes the
    verification callback. A failed actual report remains failure, without a
    restart/repair or automatic fallback to alternative trust configuration.
    """
    if not cfg.uv_system_certs or cfg.service_state != "started":
        return None
    return mark_read_only(
        _verify_running_trust(
            name="Verify running Home Assistant managed trust", cfg=cfg, expected_digest=expected_digest
        )
    )
