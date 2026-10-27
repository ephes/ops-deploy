"""Shared facts and filters for the deploys with a metrics-httpd switch (services._metrics_httpd)."""

from __future__ import annotations

import re
from typing import Any

from ops_deploy.helpers.rust_release import HOST_PYTHON
from tests import fakehost

ROOT = "/opt/metrics-httpd"
VERSION = "0.1.0"
SHA = "7befbd0f4151d6eb11009d7a93a7e7defbd4559cb0c2086915fa598c6d85fc27"
BINARY = f"{ROOT}/{VERSION}/metrics-httpd"
# The commands of the switch's host scripts (rust_release and verify_host.py on stdin).
SWITCH_COMMANDS = (f"{HOST_PYTHON} -I - ", f"( {HOST_PYTHON} -I - ")


def switch_command(command: str) -> bool:
    """Whether ``command`` runs one of the switch's host scripts (pin, prune, install, verify)."""

    return command.startswith(SWITCH_COMMANDS)


def without_switch(stdin: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """``FakeRun.stdin`` without the switch's host scripts (they carry no secret)."""

    return [(command, text) for command, text in stdin if not switch_command(command)]


def verify_op(prefix: str, unit: str, impl: str = "python") -> str:
    """The name of the switch's read-only check after the restart."""

    label = "Rust" if impl == "rust" else "Python"
    return f"{prefix}Check {unit} runs the {label} HTTP server and answers"


def installed(version: str = VERSION) -> dict[Any, Any]:
    """Facts of a host with ``version`` installed under the shared install root."""

    return {
        **fakehost.directory(f"{ROOT}/{version}"),
        re.compile(r"install --name metrics-httpd .* --check "): ["current"],
    }
