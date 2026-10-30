"""One managed explicit control command, including original repeat attempts."""

from __future__ import annotations

import base64
import json
import shlex
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.arguments import ConnectorArguments
from pyinfra.facts.server import Command, Os

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin

from .config import DaybookControlConfig

DIRECT: ConnectorArguments = {
    "_sudo": False,
    "_sudo_user": "",
    "_su_user": "",
    "_doas": False,
    "_doas_user": "",
    "_dzdo": False,
    "_dzdo_user": "",
}


def control_command(*, inbox: bool = False) -> str:
    pieces = ["import base64,sys,types"]
    modules = (
        ()
        if inbox
        else (
            ("ops_control_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
            ("ops_control_launchd", "ops_deploy.services.daybook_photos_offload", "files/photos_controls.py"),
        )
    )
    for name, package, resource in modules:
        encoded = base64.b64encode(files(package).joinpath(resource).read_bytes()).decode()
        pieces.append(
            f"m=types.ModuleType('{name}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<{name}>','exec'),m.__dict__)"
        )
    encoded = base64.b64encode(
        files("ops_deploy.services.daybook_controls")
        .joinpath("files/inbox_emergency_host.py" if inbox else "files/controls_host.py")
        .read_bytes()
    ).decode()
    pieces.append(f"exec(compile(base64.b64decode('{encoded}'),'<daybook-control>','exec'),{{'__name__':'__main__'}})")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces)])


@deploy("Explicit Daybook launchd operator")
def run_daybook_control(cfg: DaybookControlConfig) -> None:
    if host.get_fact(Os, **DIRECT) != "Darwin":
        raise DeployError("Daybook launchd operators require macOS")
    try:
        connecting = int(host.get_fact(Command, command="/usr/bin/id -u", **DIRECT) or "")
        owner_uid = int(host.get_fact(Command, command=shlex.join(["/usr/bin/id", "-u", cfg.owner]), **DIRECT) or "")
    except (TypeError, ValueError):
        raise DeployError("Daybook control identity is unavailable") from None
    if owner_uid <= 0 or connecting != (owner_uid if cfg.service == "archive" else 0):
        raise DeployError("Daybook control requires its original connecting identity")
    data = {**cfg.model_dump(), "uid": owner_uid}
    # Even an already absent label retains its original imperative cleanup
    # attempts. Never label this operation read-only or claim a zero-op repeat.
    secret_stdin(
        name="Disable exact Daybook label and remove only an explicitly confirmed attention plist",
        command=control_command(inbox=cfg.service == "inbox"),
        content=SecretContent(json.dumps(data) + "\n"),
        **DIRECT,
    )
