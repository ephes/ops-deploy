"""Smoke tests against a real host over SSH (``just smoke``; see docs/concepts/smoke.md).

They run only when ``SMOKE_SSH_HOST`` is set; ``smoke/vm.sh env`` prints the
settings for the local lima VM. Everything else in the suite stays offline.
"""

from __future__ import annotations

import base64
import logging
import os
import subprocess
from collections.abc import Iterator, Sequence
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

    def run(
        self, command: str, *, input: str | None = None, check: bool = True, login_shell: bool = False
    ) -> subprocess.CompletedProcess[str]:
        """Run ``command`` with ``sh`` on the host; output is captured as text.

        Root's login shell on the VM is fish, as on macmini, so ``command``
        travels base64-encoded and ``sh`` evaluates it: the checks mean the
        same whatever the login shell. ``login_shell=True`` hands ``command``
        to the login shell as it is, as pyinfra's connector does.
        """

        if not login_shell:
            encoded = base64.b64encode(command.encode()).decode()
            command = f"""exec sh -c 'eval "$(printf %s {encoded} | base64 -d)"'"""
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


class _FailedProbes(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if "probe failed:" in message:
            self.messages.append(message)


@pytest.fixture(scope="session", autouse=True)
def no_failed_probes() -> Iterator[None]:
    """No strict probe (``ops_deploy.helpers.probes``) may fail in a smoke run.

    A failed probe does not fail its deploy when the step it gates and the
    probe after it succeed, so the warning it logs is checked here.
    """

    handler = _FailedProbes()
    logger = logging.getLogger("pyinfra")
    logger.addHandler(handler)
    try:
        yield
    finally:
        logger.removeHandler(handler)
    assert handler.messages == []
