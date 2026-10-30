"""One original raw cleanup sequence, including repeat verification."""

from __future__ import annotations

import shlex
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os
from pyinfra.operations import server

from ops_deploy.services.daybook_controls.deploy import DIRECT

from .config import WeeknotesDisableConfig


def disable_command(cfg: WeeknotesDisableConfig) -> str:
    body = files("ops_deploy.services.daybook_weeknotes_controls").joinpath("files/weeknotes_disable.sh").read_text()
    return shlex.join(
        ["/usr/bin/env", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "/bin/bash", "-c", body, "--", cfg.label, cfg.plist]
    )


@deploy("Disable original Weeknotes schedule only")
def disable_weeknotes_schedule(cfg: WeeknotesDisableConfig) -> None:
    if host.get_fact(Os, **DIRECT) != "Darwin":
        raise DeployError("Weeknotes launchd control requires macOS")
    if host.get_fact(Command, command="/usr/bin/id -u", **DIRECT) != "0":
        raise DeployError("Weeknotes emergency disable retains its original root connection")
    # The original raw shell reports changed/already-disabled itself, but both
    # paths execute a real operator sequence. Do not claim a read-only fact or
    # a zero-managed-operation repeat. No application or local body is read.
    server.shell(
        name="Disable and unload only the original Weeknotes system label",
        commands=[disable_command(cfg)],
        _sudo=False,
        _sudo_user="",
        _su_user="",
        _doas=False,
        _doas_user="",
        _dzdo=False,
        _dzdo_user="",
    )
