"""Controller-side rsync execution behind an injectable runner.

Deploy code never calls ``subprocess`` for rsync directly; it takes an
:class:`RsyncRunner`. Production uses :func:`subprocess_rsync_runner`, tests
inject :class:`ops_deploy.testing.RecordingRsyncRunner` so a deploy-level test
performs no external I/O.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RsyncResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def itemized_lines(self) -> list[str]:
        """Non-empty output lines, one per itemized change."""

        return [line for line in self.stdout.splitlines() if line.strip()]


class RsyncError(RuntimeError):
    """Raised when rsync exits non-zero."""


class RsyncRunner(Protocol):
    def __call__(self, argv: Sequence[str]) -> RsyncResult: ...


def subprocess_rsync_runner(argv: Sequence[str]) -> RsyncResult:
    """Run rsync on the controller and capture its output."""

    completed = subprocess.run(list(argv), check=False, text=True, capture_output=True)
    return RsyncResult(completed.returncode, completed.stdout, completed.stderr)


def run_checked(runner: RsyncRunner, argv: Sequence[str]) -> RsyncResult:
    result = runner(argv)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise RsyncError(f"rsync exited {result.returncode}: {detail}")
    return result
