"""Shared-memory hygiene for throwaway PostgreSQL clusters started by tests.

A postmaster on macOS keeps one 56-byte System V shared memory header attached
for its whole life and removes it on any ``pg_ctl stop``. One that is killed
(SIGKILL, a crash) leaves the header behind, and a fresh temporary data
directory never reuses its key; with ``kern.sysv.shmmni`` at 32 such orphans
filled Studio's table on 2026-11-16 and every later ``initdb`` failed at
``shmget``.

- :func:`remove_orphaned_segments` runs before ``initdb`` and removes only
  segments that ``ipcs -m`` shows as owned and created by the current user, with
  nothing attached, exactly a PostgreSQL header's size, and a creator PID that no
  longer exists. An unrecognised table (Linux's ``ipcs``, a changed format)
  removes nothing.
- :func:`immediate_stop_on_signals` makes SIGTERM/SIGINT run
  ``pg_ctl stop -m immediate`` for the owned cluster and then hands the signal to
  the handler that was there before (pytest's KeyboardInterrupt for SIGINT, the
  default termination for SIGTERM).

Kernel and sysctl settings are never changed.
"""

from __future__ import annotations

import os
import pwd
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import Any

# sizeof(PGShmemHeader) on 64-bit macOS: the only SysV segment of a postmaster
# with shared_memory_type=mmap. Segments of any other size are never touched.
POSTGRES_HEADER_SEGMENT_SIZES = frozenset({56})
IPCS_COMMAND = ("ipcs", "-m", "-b", "-c", "-o", "-p")
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)
_REQUIRED_COLUMNS = ("T", "ID", "OWNER", "CREATOR", "NATTCH", "SEGSZ", "CPID")

Runner = Callable[..., "subprocess.CompletedProcess[Any]"]


@dataclass(frozen=True)
class Segment:
    id: int
    owner: str
    creator: str
    nattch: int
    segsz: int
    cpid: int


def parse_ipcs(text: str) -> list[Segment] | None:
    """Parse BSD/macOS ``ipcs -m -b -c -o -p``; None for any other shape."""
    header: list[str] | None = None
    segments: list[Segment] = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "T" and header is None:
            header = fields
            if not all(column in header for column in _REQUIRED_COLUMNS):
                return None
            continue
        if fields[0] != "m":
            continue
        if header is None or len(fields) != len(header):
            return None
        row = dict(zip(header, fields, strict=True))
        try:
            segments.append(
                Segment(
                    id=int(row["ID"]),
                    owner=row["OWNER"],
                    creator=row["CREATOR"],
                    nattch=int(row["NATTCH"]),
                    segsz=int(row["SEGSZ"]),
                    cpid=int(row["CPID"]),
                )
            )
        except ValueError:
            return None
    return segments if header is not None else None


def process_exists(pid: int) -> bool:
    """True unless the kernel says there is no such process; doubt counts as alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def orphaned_segments(
    segments: Sequence[Segment], user: str, exists: Callable[[int], bool] = process_exists
) -> list[Segment]:
    return [
        segment
        for segment in segments
        if segment.owner == user
        and segment.creator == user
        and segment.nattch == 0
        and segment.segsz in POSTGRES_HEADER_SEGMENT_SIZES
        and segment.cpid > 0
        and not exists(segment.cpid)
    ]


def current_user() -> str:
    return pwd.getpwuid(os.geteuid()).pw_name


def _stderr(message: str) -> None:
    print(message, file=sys.stderr)


def remove_orphaned_segments(
    *,
    run: Runner | None = None,
    user: str | None = None,
    exists: Callable[[int], bool] = process_exists,
    log: Callable[[str], None] = _stderr,
) -> list[int]:
    """Remove this user's dead PostgreSQL header segments; return the removed ids.

    Best effort: a missing or unparseable ``ipcs`` or a failing ``ipcrm`` removes
    nothing more and never fails the caller. ``run`` is resolved at call time so
    a test that patches ``subprocess.run`` never reaches the real table.
    """
    run = run or subprocess.run
    try:
        listing = run(list(IPCS_COMMAND), capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        log(f"throwaway-postgres: ipcs unavailable ({type(error).__name__}); no shared memory segment removed")
        return []
    if listing.returncode != 0:
        # e.g. a sandbox that denies the sysctl ipcs reads: the table may be partial.
        log(f"throwaway-postgres: ipcs exited {listing.returncode}; no shared memory segment removed")
        return []
    segments = parse_ipcs(listing.stdout)
    if segments is None:
        log("throwaway-postgres: unrecognised ipcs output; no shared memory segment removed")
        return []
    removed: list[int] = []
    for segment in orphaned_segments(segments, user or current_user(), exists):
        try:
            result = run(["ipcrm", "-m", str(segment.id)], capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0:
            removed.append(segment.id)
    if removed:
        log(f"throwaway-postgres: removed {len(removed)} orphaned PostgreSQL shared memory segment(s)")
    return removed


@contextmanager
def immediate_stop_on_signals(
    pg_ctl: str | Path,
    data: str | Path,
    *,
    env: Mapping[str, str] | None = None,
    run: Runner | None = None,
    signals: Sequence[int] = STOP_SIGNALS,
) -> Iterator[None]:
    """While active, SIGTERM/SIGINT stop the owned cluster immediately.

    After the stop the previous handler is restored and the signal re-delivered,
    so the process ends exactly as it would have without this guard. Off the
    main thread (where handlers cannot be installed) the guard does nothing.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {signum: signal.getsignal(signum) for signum in signals}
    stopping = False

    def restore() -> None:
        for signum, old in previous.items():
            signal.signal(signum, old if old is not None else signal.SIG_DFL)

    def handler(signum: int, _frame: FrameType | None) -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        if (Path(data) / "postmaster.pid").exists():
            with suppress(OSError, subprocess.SubprocessError):
                (run or subprocess.run)(
                    [str(pg_ctl), "-D", str(data), "-m", "immediate", "-w", "stop"],
                    capture_output=True,
                    timeout=30,
                    check=False,
                    env=dict(os.environ if env is None else env),
                )
        restore()
        signal.raise_signal(signum)

    for signum in signals:
        signal.signal(signum, handler)
    try:
        yield
    finally:
        restore()
