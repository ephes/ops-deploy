"""Deploy or remove one host's software inventory publisher.

Linux: :mod:`.linux` (pyinfra operations on a root connection). macOS:
``files/darwin_host.py`` on the host, connected as the owner (Atlas) or as
root (Studio, where the file part runs as the owner); see its docstring. A
status fact decides while planning whether the apply runs; a converged host
gets no mutating operation, only the read-only verification.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from typing import Any

from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.ops import secret_stdin

from .config import SoftwareEstatePublisherConfig
from .linux import deploy_linux
from .render import PROGRAMS, config_json, program, release_path, render

JOB_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
# The same text as darwin_host.py's LAUNCHER, which runs the file part as the owner.
LAUNCHER = (
    "import base64;S=base64.b64decode('%s').decode();"
    "exec(compile(S,'<software-estate-publisher>','exec'),{'__name__':'__main__','SOURCE':S})"
)


def darwin_contents(cfg: SoftwareEstatePublisherConfig) -> dict[str, tuple[str, int]]:
    """Every file the macOS role writes: path -> (content, mode)."""

    target = release_path(cfg)
    contents = {f"{target}/{name}": (program(name), 0o600) for name in PROGRAMS}
    contents[str(cfg.config_path)] = (config_json(cfg), 0o600)
    contents[f"{cfg.program}/run"] = (render(cfg, "run.j2"), 0o700)
    contents[str(cfg.plist)] = (render(cfg, "publisher.plist.j2"), 0o600)
    return contents


def darwin_request(cfg: SoftwareEstatePublisherConfig, *, writer: str | None = None, apply: bool = False) -> str:
    """The host program's JSON request; file contents and writer only for ``apply``."""

    contents = darwin_contents(cfg) if cfg.state == "present" else {}
    data: dict[str, Any] = {
        "state": cfg.state,
        "owner": cfg.owner,
        "home": str(cfg.home),
        "hostnames": list(cfg.hostnames),
        "label": cfg.label,
        "python": str(cfg.python),
        "job_path": JOB_PATH,
        "program": str(cfg.program),
        "release": release_path(cfg),
        "programs": list(PROGRAMS),
        "directory": str(cfg.directory),
        "config": str(cfg.config_path),
        "plist": str(cfg.plist),
        "launch_agents": str(cfg.plist.parent),
        "credential_file": str(cfg.credential_file) if cfg.credential_file else "",
        "provision_writer": bool(writer) and cfg.state == "present",
        "files": {
            path: {"sha256": hashlib.sha256(text.encode()).hexdigest(), "mode": mode}
            for path, (text, mode) in contents.items()
        },
    }
    if apply:
        data["contents"] = {path: text for path, (text, _mode) in contents.items()}
        if data["provision_writer"]:
            assert writer is not None
            data["writer_value"] = writer.strip()
    return json.dumps(data) + "\n"


def darwin_command(action: str) -> str:
    """``files/darwin_host.py`` as one command; it gets its own text as ``SOURCE``."""

    encoded = base64.b64encode(program("darwin_host.py").encode()).decode()
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", LAUNCHER % encoded, action])


def deploy_darwin(cfg: SoftwareEstatePublisherConfig, writer: str | None) -> None:
    status_request = darwin_request(cfg, writer=writer)
    state = host.get_fact(Command, command=darwin_command("status"), **stdin_arguments(status_request))
    if state not in ("current", "pending"):
        raise DeployError("the macOS publisher status is unavailable")
    action = "Remove the publisher job" if cfg.state == "absent" else "Install and load the publisher job"
    if state == "pending":
        secret_stdin(
            name=action,
            command=darwin_command("apply"),
            content=SecretContent(darwin_request(cfg, writer=writer, apply=True)),
        )
    mark_read_only(
        server.shell(
            name=f"Verify the publisher is {cfg.state}",
            commands=[darwin_command("verify")],
            **stdin_arguments(status_request),
        )
    )


@deploy("Software estate publisher")
def deploy_software_estate_publisher(cfg: SoftwareEstatePublisherConfig, secrets: SecretValues | None = None) -> None:
    """Install (``state="present"``) or unschedule (``"absent"``) the publisher.

    ``secrets["writer"]``, when given, is the host-bound Graphyard writer: on
    Linux it is installed on every run, on macOS only when the credential
    file is missing. Removal needs no secret.
    """

    writer = secrets.get("writer") if secrets is not None and cfg.state == "present" else None
    if cfg.platform == "linux":
        deploy_linux(cfg, writer)
    else:
        deploy_darwin(cfg, writer)
