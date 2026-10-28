"""Native persistent disk policy with no repeat physical reassertion."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from pathlib import Path

from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.server import Which
from pyinfra.operations import apt

from ops_deploy.base._common import require_linux
from ops_deploy.helpers.probes import StdinLines, probe

from .config import HdparmTuneConfig
from .render import render_block

SCRIPT = (Path(__file__).parent.parent / "files" / "hdparm_tune_host.py").read_text()


def command(action: str) -> str:
    if action not in {"check", "apply"}:
        raise ValueError("unknown hdparm action")
    return shlex.join(["python3", "-I", "-c", SCRIPT, action])


@operation()
def _configure(payload: str) -> Generator[StringCommand, None, None]:
    raw = probe(command("check"), name="Persistent hdparm block only; hardware unqueried", stdin=payload)
    try:
        result = json.loads(raw or "null")
        state = result.get("state") if isinstance(result, dict) else None
    except ValueError:
        state = None
    if state == "current":
        host.noop("Persistent hdparm block is current; physical state is unqueried")
    elif state == "pending":
        yield StringCommand(command("apply"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Persistent hdparm block state is unknown; no setting command attempted")


@deploy("Configure persistent hdparm policy")
def deploy_hdparm_tune(cfg: HdparmTuneConfig) -> None:
    require_linux("hdparm tuning")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("hdparm tuning needs Debian/Ubuntu apt")
    installed = host.get_fact(DebPackages)
    apt.packages(name="Ensure hdparm package", packages=["hdparm"], update="hdparm" not in installed, cache_time=3600)
    if cfg.devices:
        payload = json.dumps(
            {
                "devices": [device.model_dump() for device in cfg.devices],
                "block": render_block(cfg),
                "apply_now": cfg.apply_now,
            }
        )
        _configure(name="Reconcile hdparm block and apply only a changed block", payload=payload)
