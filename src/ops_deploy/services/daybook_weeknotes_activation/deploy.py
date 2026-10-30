"""Two managed sequences: original disable, then bound apply/verify/enable."""

from __future__ import annotations

import base64
import json
import shlex
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin
from ops_deploy.services.daybook_controls.deploy import DIRECT
from ops_deploy.services.daybook_weeknotes_controls import WeeknotesDisableConfig, disable_weeknotes_schedule
from ops_deploy.services.daybook_weeknotes_identity.deploy import operator_payload

from .config import WeeknotesActivationConfig


def activation_command() -> str:
    pieces = ["import base64,sys,types"]
    for name, package, resource in (
        ("ops_identity_filesystem", "daybook_sessions", "files/resources_host.py"),
        ("ops_weeknotes_identity", "daybook_weeknotes_identity", "files/identity_operator_host.py"),
    ):
        body = files("ops_deploy.services." + package).joinpath(resource).read_bytes()
        encoded = base64.b64encode(body).decode()
        pieces.append(
            f"m=types.ModuleType('{name}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{encoded}'),'<activation-{name}>','exec'),m.__dict__)"
        )
    body = files("ops_deploy.services.daybook_weeknotes_activation").joinpath("files/activation_host.py").read_bytes()
    encoded = base64.b64encode(body).decode()
    pieces.append(
        f"exec(compile(base64.b64decode('{encoded}'),'<weeknotes-activation>','exec'),{{'__name__':'__main__'}})"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(pieces)])


@deploy("Activate only fresh-apply-bound original Weeknotes schedule")
def activate_weeknotes_schedule(cfg: WeeknotesActivationConfig) -> None:
    if host.get_fact(Os, **DIRECT) != "Darwin":
        raise DeployError("Weeknotes activation requires macOS")
    if host.get_fact(Command, command="/usr/bin/id -u", **DIRECT) != "0":
        raise DeployError("Weeknotes activation retains the original root connection")
    identity = cfg.identity
    uid = host.get_fact(Command, command=shlex.join(["/usr/bin/id", "-u", identity.owner]), **DIRECT) or ""
    if not uid.isdecimal() or int(uid) <= 0:
        raise DeployError("Weeknotes activation owner uid is unavailable")
    timer = WeeknotesDisableConfig().model_copy(
        update={"label": identity.scheduler_label, "plist": identity.scheduler_plist}
    )
    disable_weeknotes_schedule(cfg=timer)
    payload = operator_payload(identity, int(uid))
    payload["activation"] = cfg.model_dump(mode="json", exclude={"identity"})
    secret_stdin(
        name="Fresh verified apply and exact epoch/proof-bound schedule activation",
        command=activation_command(),
        content=SecretContent(json.dumps(payload) + "\n"),
        **DIRECT,
    )
