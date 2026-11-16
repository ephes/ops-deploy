"""Shared-memory hygiene for throwaway PostgreSQL clusters, against mocked ``ipcs``.

Nothing here lists, removes or creates a real System V segment or cluster.
"""

from __future__ import annotations

import os
import signal
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import FrameType
from typing import Any

import pytest

from tests import throwaway_postgres as hygiene

HEADER = "T     ID     KEY        MODE       OWNER    GROUP  CREATOR   CGROUP NATTCH  SEGSZ  CPID  LPID"


def listing(*rows: str) -> str:
    return (
        "\n".join(
            ["IPC status from <running system> as of Tue Nov 17 00:04:15 CET 2026", HEADER, "Shared Memory:", *rows]
        )
        + "\n"
    )


def row(
    segment_id: int, *, owner: str = "alice", creator: str = "alice", nattch: int = 0, segsz: int = 56, cpid: int = 4242
) -> str:
    return (
        f"m {segment_id} 0x43e1fa07 --rw-------   {owner}    staff   {creator}    staff"
        f"      {nattch}     {segsz}   {cpid}      0"
    )


class FakeRun:
    def __init__(self, ipcs_stdout: str, *, ipcs_code: int = 0, ipcrm_codes: dict[str, int] | None = None) -> None:
        self.ipcs_stdout = ipcs_stdout
        self.ipcs_code = ipcs_code
        self.ipcrm_codes = ipcrm_codes or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[0] == "ipcs":
            return subprocess.CompletedProcess(argv, self.ipcs_code, self.ipcs_stdout, "")
        if argv[:2] == ["ipcrm", "-m"]:
            return subprocess.CompletedProcess(argv, self.ipcrm_codes.get(argv[2], 0), "", "")
        raise AssertionError(f"unexpected command {argv}")

    def removed(self) -> list[str]:
        return [call[2] for call in self.calls if call[0] == "ipcrm"]


def dead(pid: int) -> bool:
    return False


def test_parses_the_macos_listing() -> None:
    assert hygiene.parse_ipcs(listing(row(7929856), row(2424833, nattch=6, cpid=72078))) == [
        hygiene.Segment(id=7929856, owner="alice", creator="alice", nattch=0, segsz=56, cpid=4242),
        hygiene.Segment(id=2424833, owner="alice", creator="alice", nattch=6, segsz=56, cpid=72078),
    ]
    assert hygiene.parse_ipcs(listing()) == []


@pytest.mark.parametrize(
    "text",
    [
        "",
        "------ Shared Memory Segments --------\nkey shmid owner perms bytes nattch status\n"
        "0x00000000 32768 alice 600 56 0 dest\n",
        listing("m 1 0x1 --rw------- alice staff alice staff 0 56"),
        listing(row(1).replace(" 56 ", " big ")),
        "T ID KEY MODE OWNER GROUP\nm 1 0x1 --rw------- alice staff\n",
    ],
    ids=["empty", "linux", "truncated-row", "non-numeric", "missing-columns"],
)
def test_an_unrecognised_listing_is_none(text: str) -> None:
    assert hygiene.parse_ipcs(text) is None


def test_only_dead_unattached_header_segments_of_this_user_are_orphans() -> None:
    segments = hygiene.parse_ipcs(
        listing(
            row(1),
            row(2, nattch=1),
            row(3, cpid=1111),
            row(4, owner="bob", creator="bob"),
            row(5, creator="bob"),
            row(6, owner="bob"),
            row(7, segsz=134217728),
            row(8, cpid=0),
            row(9, cpid=5151),
        )
    )
    assert segments is not None
    orphans = hygiene.orphaned_segments(segments, "alice", lambda pid: pid == 1111)
    assert [segment.id for segment in orphans] == [1, 9]


def test_removes_exactly_the_orphans() -> None:
    run = FakeRun(listing(row(1), row(2, nattch=1), row(3, owner="bob", creator="bob"), row(4)))
    messages: list[str] = []
    assert hygiene.remove_orphaned_segments(run=run, user="alice", exists=dead, log=messages.append) == [1, 4]
    assert run.calls[0] == list(hygiene.IPCS_COMMAND)
    assert run.removed() == ["1", "4"]
    assert messages == ["throwaway-postgres: removed 2 orphaned PostgreSQL shared memory segment(s)"]


def test_a_failed_ipcrm_is_not_reported_and_does_not_stop_the_rest() -> None:
    run = FakeRun(listing(row(1), row(2)), ipcrm_codes={"1": 1})
    assert hygiene.remove_orphaned_segments(run=run, user="alice", exists=dead, log=lambda message: None) == [2]
    assert run.removed() == ["1", "2"]


def test_an_unrecognised_failing_or_missing_ipcs_removes_nothing() -> None:
    messages: list[str] = []
    run = FakeRun("T ID KEY\nm 1 0x1\n")
    assert hygiene.remove_orphaned_segments(run=run, user="alice", exists=dead, log=messages.append) == []
    assert messages == ["throwaway-postgres: unrecognised ipcs output; no shared memory segment removed"]
    failing = FakeRun(listing(row(1)), ipcs_code=1)
    assert hygiene.remove_orphaned_segments(run=failing, user="alice", exists=dead, log=messages.append) == []
    assert run.removed() == failing.removed() == []

    def missing(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError(argv[0])

    assert hygiene.remove_orphaned_segments(run=missing, user="alice", exists=dead, log=messages.append) == []
    assert messages[1:] == [
        "throwaway-postgres: ipcs exited 1; no shared memory segment removed",
        "throwaway-postgres: ipcs unavailable (FileNotFoundError); no shared memory segment removed",
    ]


def test_the_runner_is_resolved_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    # A default bound at import time would bypass a caller's patched subprocess.run
    # and list and remove real segments.
    run = FakeRun(listing(row(1, nattch=1)))
    monkeypatch.setattr(subprocess, "run", run)
    assert hygiene.remove_orphaned_segments(user="alice", exists=dead) == []
    assert run.calls == [list(hygiene.IPCS_COMMAND)]


def test_process_exists_treats_only_a_missing_process_as_dead(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_kill(pid: int, sig: int) -> None:
        if pid == 1:
            raise ProcessLookupError
        if pid == 2:
            raise PermissionError

    monkeypatch.setattr(os, "kill", fake_kill)
    assert hygiene.process_exists(1) is False
    assert hygiene.process_exists(2) is True
    assert hygiene.process_exists(3) is True


class StopRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        self.calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, 0, b"", b"")


@pytest.fixture
def previous_handlers() -> Iterator[list[int]]:
    """Record re-delivered signals in place of pytest's or the default handlers."""
    seen: list[int] = []
    saved = {signum: signal.getsignal(signum) for signum in hygiene.STOP_SIGNALS}

    def record(signum: int, _frame: FrameType | None) -> None:
        seen.append(signum)

    for signum in hygiene.STOP_SIGNALS:
        signal.signal(signum, record)
    try:
        yield seen
    finally:
        for signum, old in saved.items():
            signal.signal(signum, old)


@pytest.mark.parametrize("signum", hygiene.STOP_SIGNALS)
def test_a_stop_signal_stops_the_cluster_immediately_then_reaches_the_previous_handler(
    tmp_path: Path, previous_handlers: list[int], signum: int
) -> None:
    (tmp_path / "postmaster.pid").write_text("123\n")
    run = StopRecorder()
    before = signal.getsignal(signum)
    with hygiene.immediate_stop_on_signals("/pg/pg_ctl", tmp_path, env={"LC_ALL": "C"}, run=run):
        signal.raise_signal(signum)
    assert [call[0] for call in run.calls] == [["/pg/pg_ctl", "-D", str(tmp_path), "-m", "immediate", "-w", "stop"]]
    assert run.calls[0][1]["env"] == {"LC_ALL": "C"}
    assert run.calls[0][1]["check"] is False
    assert previous_handlers == [signum]
    assert signal.getsignal(signum) is before


def test_a_signal_before_the_cluster_exists_only_reaches_the_previous_handler(
    tmp_path: Path, previous_handlers: list[int]
) -> None:
    run = StopRecorder()
    with hygiene.immediate_stop_on_signals("/pg/pg_ctl", tmp_path, run=run):
        signal.raise_signal(signal.SIGTERM)
    assert run.calls == []
    assert previous_handlers == [signal.SIGTERM]


def test_sigint_still_interrupts_pytest_style(tmp_path: Path) -> None:
    (tmp_path / "postmaster.pid").write_text("123\n")
    run = StopRecorder()
    saved = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with (
            pytest.raises(KeyboardInterrupt),
            hygiene.immediate_stop_on_signals("/pg/pg_ctl", tmp_path, run=run),
        ):
            signal.raise_signal(signal.SIGINT)
    finally:
        signal.signal(signal.SIGINT, saved)
    assert len(run.calls) == 1


def test_a_failing_immediate_stop_still_reaches_the_previous_handler(
    tmp_path: Path, previous_handlers: list[int]
) -> None:
    (tmp_path / "postmaster.pid").write_text("123\n")

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(argv, 30)

    with hygiene.immediate_stop_on_signals("/pg/pg_ctl", tmp_path, run=run):
        signal.raise_signal(signal.SIGTERM)
    assert previous_handlers == [signal.SIGTERM]


def test_handlers_are_restored_without_a_signal(tmp_path: Path) -> None:
    before = {signum: signal.getsignal(signum) for signum in hygiene.STOP_SIGNALS}
    with hygiene.immediate_stop_on_signals("/pg/pg_ctl", tmp_path, run=StopRecorder()):
        assert all(signal.getsignal(signum) is not before[signum] for signum in hygiene.STOP_SIGNALS)
    assert {signum: signal.getsignal(signum) for signum in hygiene.STOP_SIGNALS} == before


def test_current_user_is_the_effective_user() -> None:
    import pwd

    assert hygiene.current_user() == pwd.getpwuid(os.geteuid()).pw_name
