"""Smoke tests against a real host over SSH (``just smoke``; see docs/concepts/smoke.md).

They run only when ``SMOKE_SSH_HOST`` is set; ``smoke/vm.sh env`` prints the
settings for the local lima VM. Everything else in the suite stays offline.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

SMOKE_DIR = Path(__file__).parent
TIMINGS: dict[str, float] = {}


@dataclass(frozen=True)
class SmokeHost:
    hostname: str
    port: int
    key: str
    known_hosts: str
    user: str = "root"
    host_data: dict[str, Any] = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "host_data",
            {
                "ssh_hostname": self.hostname,
                "ssh_port": self.port,
                "ssh_user": self.user,
                "ssh_key": self.key,
                "ssh_known_hosts_file": self.known_hosts,
                "ssh_strict_host_key_checking": "yes",
            },
        )

    @property
    def name(self) -> str:
        return f"{self.hostname}:{self.port}"

    def ssh_argv(self, command: str) -> list[str]:
        return [
            "ssh",
            "-i",
            self.key,
            "-p",
            str(self.port),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "StrictHostKeyChecking=yes",
            f"{self.user}@{self.hostname}",
            command,
        ]

    def run(self, command: str, *, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
        """Run ``command`` through the host's shell; output is captured as text."""

        result = subprocess.run(
            self.ssh_argv(command), input=input, text=True, capture_output=True, check=False, timeout=120
        )
        if check and result.returncode != 0:
            raise AssertionError(f"{command!r} exited {result.returncode}: {result.stderr.strip()}")
        return result

    def out(self, command: str) -> str:
        return self.run(command).stdout.strip()


def pytest_collection_modifyitems(config: pytest.Config, items: Sequence[pytest.Item]) -> None:
    if os.environ.get("SMOKE_SSH_HOST"):
        return
    skip = pytest.mark.skip(reason="no smoke target (run `just smoke`)")
    for item in items:
        if SMOKE_DIR in Path(item.path).parents:
            item.add_marker(skip)


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if TIMINGS:
        terminalreporter.section("smoke timings")
        for label, seconds in TIMINGS.items():
            terminalreporter.write_line(f"{label}: {seconds:.1f} s")


@pytest.fixture(scope="session")
def smoke_host() -> SmokeHost:
    env = os.environ
    return SmokeHost(
        hostname=env["SMOKE_SSH_HOST"],
        port=int(env["SMOKE_SSH_PORT"]),
        key=env["SMOKE_SSH_KEY"],
        known_hosts=env["SMOKE_SSH_KNOWN_HOSTS"],
    )
