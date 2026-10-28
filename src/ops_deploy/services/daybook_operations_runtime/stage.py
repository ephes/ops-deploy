"""Original disabled-first install/replace after separately guarded code install."""

from __future__ import annotations

import base64
import io
import json
import shlex
from collections.abc import Mapping
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os

from ops_deploy.core.git_source import SourceTree
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin

from .config import DaybookRuntimeConfig
from .inspect import observation_payload

PACKAGE = "ops_deploy.services.daybook_operations_runtime"


def stage_command(action: str) -> str:
    if action not in {"status", "apply", "verify"}:
        raise ValueError("Unsupported disabled runtime stage operation")
    parts = ["import base64,sys,types"]
    for module, resource in (("ops_daybook_observer", "files/runtime_state.py"), ("ops_daybook_guards", "guards.py")):
        encoded = base64.b64encode(files(PACKAGE).joinpath(resource).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{module}>','exec'),m.__dict__)"
        )
    script = base64.b64encode(files(PACKAGE).joinpath("files/runtime_stage.py").read_bytes()).decode()
    parts.append(f"exec(compile(base64.b64decode('{script}'),'<runtime-stage>','exec'))")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts), action])


@deploy("Stage original disabled Daybook runtime resources")
def stage_daybook_runtime(cfg: DaybookRuntimeConfig, secrets: Mapping[str, str], source: SourceTree) -> None:
    if cfg.action not in {"install", "replace"}:
        raise ValueError("Disabled runtime staging requires the original install or replace action")
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    body = json.dumps(observation_payload(cfg, secrets, source)) + "\n"
    with io.StringIO(body) as stream:
        current = host.get_fact(Command, command=stage_command("status"), _stdin=stream, _get_pty=False)
    if current not in {"current", "change"}:
        raise DeployError("Disabled runtime staging preflight is unavailable")
    if current == "change":
        secret_stdin(
            name="Stage disabled profile, private store, credential and candidate plist",
            command=stage_command("apply"),
            content=SecretContent(body),
        )
    mark_read_only(
        secret_stdin(
            name="Verify staged disabled runtime without executor or Journal calls",
            command=stage_command("verify"),
            content=SecretContent(body),
        )
    )
