"""Postfix's role-owned derived hash maps; native semantics and durable retry."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from pathlib import Path

from pyinfra import host
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import StdinLines, probe

SCRIPT = (Path(__file__).parent / "files" / "mail_postfix_maps.py").read_text()
HEALTH = (Path(__file__).parent / "files" / "mail_postfix_health.py").read_text()


def verify_master() -> OperationMeta:
    return mark_read_only(
        server.shell(
            name="Verify actual Postfix master process",
            commands=[shlex.join(["python3", "-I", "-c", HEALTH])],
        )
    )


def command(mode: str) -> str:
    if mode not in {"check", "apply"}:
        raise ValueError("invalid Postfix map action")
    return shlex.join(["python3", "-I", "-c", SCRIPT, mode])


@operation()
def ensure_maps(
    paths: tuple[str, ...], restart_marker: str, source_changes: tuple[OperationMeta, ...] = ()
) -> Generator[StringCommand, None, None]:
    """Call AFTER source file ops. Missing maps are built; identical maps stay byte-exact.

    Credential material never appears in the fact result or command line.
    Unknown tool/database errors refuse before regeneration.
    """
    payload = json.dumps({"paths": paths, "restart_marker": restart_marker})
    state = (
        "pending"
        if any(op.will_change for op in source_changes)
        else probe(command("check"), name="Postfix map semantics", stdin=payload)
    )
    if state == "current":
        host.noop("Postfix hash maps are current")
        return
    if state != "pending":
        raise DeployError("Postfix map state is unknown; no map regeneration attempted")
    yield StringCommand(command("apply"), _stdin=StdinLines(payload), _get_pty=False, _shell_executable="sh")
