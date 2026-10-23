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

_NONEMPTY = "cannot delete non-empty directory: "


@dataclass(frozen=True)
class RsyncResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def itemized_lines(self) -> list[str]:
        """Candidate changes, excluding known nonempty-directory refusals.

        Our ``%i %n%L`` format emits ``*deleting   path/`` even when an
        excluded descendant prevents deleting that directory. The exact
        refusal diagnostic and its exact directory candidate are not changes;
        standalone ancestor refusals are not changes either. Unmatched deletes
        and unknown stdout remain candidates. Raw stdout/stderr are untouched,
        and ``run_checked`` still refuses every nonzero exit before planning.
        """

        lines = [line for line in self.stdout.splitlines() if line.strip()]
        blocked = {f"*deleting   {line[len(_NONEMPTY) :]}/" for line in lines if line.startswith(_NONEMPTY)}
        return [line for line in lines if not line.startswith(_NONEMPTY) and line not in blocked]


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
