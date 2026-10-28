"""Small shared operation for the three known alerting components."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator
from pathlib import Path
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.server import Which
from pyinfra.operations import apt

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.helpers.probes import StdinLines, probe

SCRIPT = (Path(__file__).parent / "files" / "monitoring_infra_host.py").read_text()


def prerequisites(packages: tuple[str, ...]) -> None:
    require_linux("Monitoring infrastructure")
    require_systemd("Monitoring infrastructure")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("Monitoring infrastructure requires Debian/Ubuntu apt")
    installed = host.get_fact(DebPackages)
    apt.packages(
        name="Ensure monitoring packages",
        packages=list(packages),
        update=any(p not in installed for p in packages),
        cache_time=3600,
    )


@operation()
def configure(payload: dict[str, Any]) -> Generator[StringCommand, None, None]:
    content = json.dumps(payload)
    command = shlex.join(["python3", "-I", "-c", SCRIPT])
    result = probe(command + " check", name="Known monitoring configuration and unit state", stdin=content)
    if result == "current":
        host.noop("Monitoring configuration and services are current")
    elif result == "pending":
        yield StringCommand(command + " apply", _stdin=StdinLines(content), _get_pty=False, _shell_executable="sh")
    else:
        raise DeployError("Monitoring configuration state is unknown; no mutation admitted")


@operation()
def bootstrap_postfix() -> Generator[StringCommand, None, None]:
    """Fresh admission is bound by deploy_mail_relay_client before apt runs."""
    command = shlex.join(["python3", "-I", "-c", SCRIPT, "bootstrap"])
    yield StringCommand(command, _get_pty=False, _shell_executable="sh")
