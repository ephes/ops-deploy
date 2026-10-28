"""Package policy and reconcile the timer without running the oneshot."""

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

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.helpers.probes import StdinLines, probe

from .config import SanoidConfig
from .render import render

SCRIPT = (Path(__file__).parent.parent.parent / "infra/files/sanoid_host.py").read_text()


def command(action: str) -> str:
    if action not in {"check", "apply"}:
        raise ValueError("invalid Sanoid action")
    return shlex.join(["python3", "-I", "-c", SCRIPT, action])


@operation()
def _configure(payload: str) -> Generator[StringCommand, None, None]:
    result = probe(command("check"), name="Sanoid config and timer metadata, no dataset query", stdin=payload)
    if result == "current":
        host.noop("Sanoid configuration and timer are current")
    elif result == "pending":
        yield StringCommand(command("apply"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Sanoid reconciliation state is unknown; refusing changes")


@deploy("Configure Sanoid policy and timer")
def deploy_sanoid(cfg: SanoidConfig) -> None:
    if not cfg.enabled:
        return
    require_linux("Sanoid")
    if cfg.manage_systemd:
        require_systemd("Sanoid")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("Sanoid requires Debian/Ubuntu apt")
    installed = host.get_fact(DebPackages)
    apt.packages(
        name="Ensure Sanoid packages",
        packages=list(cfg.packages),
        update=any(pkg not in installed for pkg in cfg.packages),
        cache_time=3600,
    )
    request = cfg.model_dump()
    request["config"] = render(cfg, "sanoid.conf")
    if cfg.manage_systemd:
        request["service"] = render(cfg, "sanoid-ops-library.service")
        request["timer"] = render(cfg, "sanoid-ops-library.timer")
    _configure(name="Reconcile Sanoid policy and timer, never run snapshots", payload=json.dumps(request))
