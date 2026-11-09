"""One original disabled/retired convergence sequence on the root connection."""

from __future__ import annotations

import shlex
from importlib.resources import files

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command, Os
from pyinfra.operations import server

from ops_deploy.services.daybook_controls.deploy import DIRECT

from .config import VoiceMemoWorkConfig


def disable_command(cfg: VoiceMemoWorkConfig) -> str:
    body = files("ops_deploy.services.daybook_voice_memo_work").joinpath("files/voice_memo_work_disable.sh").read_text()
    return shlex.join(
        [
            "/usr/bin/env",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "/bin/bash",
            "-c",
            body,
            "--",
            cfg.owner,
            cfg.label,
            cfg.plist,
            "true" if cfg.retired else "false",
        ]
    )


@deploy("Converge the original disabled Voice Memo work LaunchAgent")
def apply_voice_memo_work_state(cfg: VoiceMemoWorkConfig) -> None:
    if host.get_fact(Os, **DIRECT) != "Darwin":
        raise DeployError("Voice Memo work requires macOS")
    if host.get_fact(Command, command="/usr/bin/id -u", **DIRECT) != "0":
        raise DeployError("Voice Memo work retains its original root connection")
    # The original role disables and probes on every run, so even an already
    # retired label executes this sequence. It is not a read-only repeat.
    server.shell(
        name="Disable, unload and (retired) remove only the Voice Memo work LaunchAgent",
        commands=[disable_command(cfg)],
        **DIRECT,
    )
