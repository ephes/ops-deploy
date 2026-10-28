"""Original confirmed closeout; does not stop or reconfigure a running keeper."""

from __future__ import annotations

import base64
import io
import json
import shlex
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os

from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.ops import secret_stdin

from .config import DaybookRuntimeConfig

PACKAGE = "ops_deploy.services.daybook_operations_runtime"


def closeout_command(action: str) -> str:
    if action not in {"status", "apply", "verify"}:
        raise ValueError("Unsupported original runtime closeout action")
    filesystem = files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py").read_bytes()
    script = files(PACKAGE).joinpath("files/runtime_closeout.py").read_bytes()
    parts = [
        "import base64,sys,types;m=types.ModuleType('ops_closeout_filesystem');sys.modules[m.__name__]=m",
        "exec(compile(base64.b64decode('"
        + base64.b64encode(filesystem).decode()
        + "'),'<closeout-filesystem>','exec'),m.__dict__)",
        "exec(compile(base64.b64decode('"
        + base64.b64encode(script).decode()
        + "'),'<runtime-closeout>','exec'),{'__name__':'__main__'})",
    ]
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts), action])


@deploy("Close out original Daybook rollback command without touching keeper")
def closeout_daybook_runtime(cfg: DaybookRuntimeConfig) -> None:
    if cfg.action != "closeout" or not cfg.confirmed or cfg.start:
        raise ValueError("Runtime closeout requires its original confirmation and no start")
    if host.get_fact(Os) != "Darwin":
        raise DeployError("Protected Daybook runtime supports Darwin targets only")
    body = (
        json.dumps(
            {
                "legacy_plist": str(cfg.legacy_plist),
                "marker": str(cfg.closeout_marker),
                "owner": "root" if cfg.owner == "root" else cfg.user,
                "group": "wheel" if cfg.owner == "root" else "staff",
            }
        )
        + "\n"
    )
    with io.StringIO(body) as stream:
        current = host.get_fact(Command, command=closeout_command("status"), _stdin=stream, _get_pty=False)
    if current not in {"current", "change"}:
        raise DeployError("Original runtime closeout metadata is unavailable")
    if current == "change":
        secret_stdin(
            name="Delete original saved command and publish closeout marker",
            command=closeout_command("apply"),
            content=SecretContent(body),
        )
    mark_read_only(
        secret_stdin(
            name="Verify original closeout marker and absent rollback command",
            command=closeout_command("verify"),
            content=SecretContent(body),
        )
    )
