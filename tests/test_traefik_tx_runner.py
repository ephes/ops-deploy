"""The host side of detached Traefik transactions (``traefik_tx.runner``) on a fake host.

The engine runs for real, in process, on ``traefik_tx_fixtures.FakeHost``; systemd
(``systemctl``, ``systemd-run``), the release download, root and file ownership are
faked. A killed engine is simulated by freezing the fake host at the moment of the kill
(state record, binary, transaction directory, which binary runs) and putting it back
after the engine's own rollback ran: what is left is exactly what a ``SIGKILL`` at that
point leaves behind, and the safe-restore unit's program then runs on it.
"""

from __future__ import annotations

import ast
import fcntl
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from ops_deploy.infra.traefik_tx import engine, runner
from tests.traefik_tx_fixtures import NEW, OLD, FakeHost, Setup, base_setup, fake_traefik, reference, sha256

TX = "6f1c2c1e-0a3b-4c5d-8e9f-0123456789ab"
TX2 = "0b7e4f7a-1c2d-4e3f-9a4b-5c6d7e8f9a0b"
Frozen = dict[str, tuple[int, bytes | None]]
Completed = subprocess.CompletedProcess[str]


class Killed(BaseException):
    """Where a test kills the engine."""


class FakeResponse:
    def __init__(self, data: bytes, url: str) -> None:
        self.stream = io.BytesIO(data)
        self.url = url

    def geturl(self) -> str:
        return self.url

    def read(self, size: int = -1) -> bytes:
        return self.stream.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def relaxed_private_dir(path: Path, *, parents: bool = True) -> None:
    """``private_dir`` without root ownership, which a test cannot provide."""

    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise runner.Refused(f"not a private root-owned directory: {path}")


def freeze(root: Path) -> Frozen:
    entries: Frozen = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        content = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        entries[str(path.relative_to(root))] = (stat.S_IMODE(info.st_mode), content)
    return entries


def thaw(root: Path, frozen: Frozen) -> None:
    """Put ``root`` back to ``frozen``: what a kill at that moment leaves on disk."""

    for path in sorted(root.rglob("*"), reverse=True):
        if str(path.relative_to(root)) not in frozen:
            if path.is_dir() and not path.is_symlink():
                path.rmdir()
            else:
                path.unlink()
    for name, (mode, content) in frozen.items():
        path = root / name
        if content is None:
            path.mkdir(exist_ok=True)
        else:
            path.write_bytes(content)
        path.chmod(mode)


@dataclass
class Box:
    """The engine's fake host plus the transport: systemd, downloads and the transport root."""

    root: Path
    host: FakeHost
    setup: Setup
    units: dict[str, tuple[str, str]] = field(default_factory=dict)
    commands: list[list[str]] = field(default_factory=list)
    downloads: list[str] = field(default_factory=list)
    archive: bytes = b""
    final_url: str | None = None
    download_error: Exception | None = None
    engine_run: Callable[[list[str]], Completed] | None = None
    started_before_engine: list[bool] = field(default_factory=list)
    # Called with the unit name before ``systemctl show`` answers: what happens on the host meanwhile.
    on_show: Callable[[str], None] | None = None

    @property
    def transport(self) -> Path:
        return self.root / "transport"

    @property
    def units_dir(self) -> Path:
        return self.root / "units"

    def dir(self, transaction_id: str = TX) -> Path:
        return self.transport / transaction_id

    def command(self, argv: list[str], *, timeout: float | None = 60, check: bool = True) -> Completed:
        self.commands.append(list(argv))
        if argv[:2] == ["systemctl", "show"]:
            if self.on_show is not None:
                self.on_show(argv[2])
            # systemd loads an instance of an installed template on demand.
            known = (
                argv[2].startswith("traefik-tx-safe-restore@")
                and (self.units_dir / runner.SAFE_RESTORE_TEMPLATE).exists()
            )
            load, active = self.units.get(argv[2], ("loaded" if known else "not-found", "inactive"))
            return subprocess.CompletedProcess(argv, 0, f"LoadState={load}\nActiveState={active}\n", "")
        if argv == ["systemctl", "daemon-reload"] or argv[0] == "systemd-run":
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:2] == [runner.PYTHON, "-I"] and argv[2].endswith("/engine.py"):
            self.started_before_engine.append((Path(argv[2]).parent / runner.STARTED).exists())
            return (self.engine_run or self.run_engine)(argv[3:])
        raise AssertionError(f"unexpected command: {argv}")

    def run_engine(self, args: list[str]) -> Completed:
        """The engine's command line, in process on the fake host."""

        output = io.StringIO()
        previous = os.umask(0o022)
        try:
            with redirect_stdout(output):
                code = engine.main(args)
        finally:
            os.umask(previous)
        return subprocess.CompletedProcess(["engine.py", *args], code, output.getvalue(), "")

    def open_url(self, url: str) -> FakeResponse:
        self.downloads.append(url)
        if self.download_error is not None:
            raise self.download_error
        return FakeResponse(self.archive, self.final_url or url)

    def live_digests(self, _engine: Any, policy: dict[str, Any]) -> tuple[str | None, str | None]:
        running = self.host.running
        return runner.file_sha256(Path(policy["binary_path"])), None if running is None else sha256(running)

    @contextmanager
    def patched(self) -> Iterator[None]:
        with ExitStack() as stack:
            stack.enter_context(self.host.patched())
            for name, value in {
                "TRANSPORT_ROOT": self.transport,
                "UNIT_DIR": self.units_dir,
                "ROOT_UID": os.getuid(),
                "command": self.command,
                "open_url": self.open_url,
                "require_root": lambda: None,
                "private_dir": relaxed_private_dir,
                "load_engine": lambda path: engine,
                "live_digests": self.live_digests,
                # Not in the test process: tests/test_traefik_tx_runner.py checks it on its own.
                "exit_on_stop": lambda: None,
            }.items():
                stack.enter_context(patch.object(runner, name, value))
            stack.enter_context(patch.dict(runner.ARCHITECTURES, {os.uname().machine: "amd64"}))
            yield

    # -- steps ------------------------------------------------------------------------

    def source(self, request: dict[str, Any] | None = None) -> Path:
        """The controller's private directory with engine, runner and request."""

        source = self.root / "source"
        shutil.rmtree(source, ignore_errors=True)
        source.mkdir(mode=0o700)
        (source / runner.ENGINE).write_bytes(Path(engine.__file__).read_bytes())
        (source / runner.RUNNER).write_bytes(Path(runner.__file__).read_bytes())
        (source / runner.REQUEST).write_text(json.dumps(self.setup.request if request is None else request))
        return source

    def stage(self, transaction_id: str = TX, request: dict[str, Any] | None = None) -> dict[str, Any]:
        return runner.stage(transaction_id, self.source(request))

    def record(self) -> dict[str, Any] | None:
        path = self.host.state_root / "state.json"
        return json.loads(path.read_text()) if path.exists() else None

    def saved_record(self) -> dict[str, Any]:
        record = self.record()
        assert record is not None
        return record

    def read(self, name: str, transaction_id: str = TX) -> Any:
        return json.loads((self.dir(transaction_id) / name).read_text())


@pytest.fixture
def box(tmp_path: Path) -> Iterator[Box]:
    """An enrolled fake host at 3.7.14, a valid binary request for 3.7.16, the transport patched in."""

    host = FakeHost(engine, tmp_path / "host")
    host.root.mkdir()
    host.install()
    made = Box(tmp_path, host, Setup(host=host, request={}, state=None))
    with made.patched():
        setup = base_setup(host, "binary")
        made.setup = setup
        made.archive = Path(setup.request["archive_path"]).read_bytes()
        host.state_root.mkdir(mode=0o700)
        engine.save(host.state_root / "state.json", setup.state)
        made.units_dir.mkdir()
        yield made


def kill_engine(box: Box, *, on_call: int = 1, restart_first: bool = True) -> Callable[[list[str]], Completed]:
    """An engine run that is killed at its ``on_call``-th restart-and-verify.

    ``restart_first``: Traefik was already restarted on the binary on disk when the kill
    came (the acceptance probe ran). The fake host is then put back to that moment,
    and the run reports ``SIGKILL`` with no output.
    """

    def run(args: list[str]) -> Completed:
        frozen: Frozen = {}
        running: list[bytes | None] = []
        calls = 0

        def restart_verify(policy: dict[str, Any], *rest: Any) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            if restart_first or calls < on_call:
                box.host.run(["systemctl", "restart", "traefik.service"])
            if calls == on_call:
                frozen.update(freeze(box.host.root))
                running.append(box.host.running)
            raise Killed

        with patch.object(engine, "restart_verify", restart_verify):
            box.run_engine(args)
        assert frozen, "the engine never got to the kill"
        thaw(box.host.root, frozen)
        box.host.running = running[0]
        return subprocess.CompletedProcess(["engine.py", *args], -9, "", "")

    return run


def kill_before_replace(box: Box) -> Callable[[list[str]], Completed]:
    """An engine run killed after its pending record, before the binary is replaced."""

    def run(args: list[str]) -> Completed:
        frozen: Frozen = {}
        real = engine.atomic

        def atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
            if path == box.host.binary and not frozen:
                frozen.update(freeze(box.host.root))
                raise Killed
            real(path, data, mode)

        with patch.object(engine, "atomic", atomic):
            box.run_engine(args)
        thaw(box.host.root, frozen)
        box.host.running = fake_traefik(OLD)
        return subprocess.CompletedProcess(["engine.py", *args], -9, "", "")

    return run


# -- stage ----------------------------------------------------------------------------


def test_stage_copies_the_files_fetches_the_archive_and_installs_the_template(box: Box) -> None:
    staged = box.stage()

    directory = box.dir()
    assert sorted(p.name for p in directory.iterdir()) == [
        "engine.py",
        "release.tar.gz",
        "request.json",
        "runner.py",
        "staged.json",
    ]
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in directory.iterdir())
    assert stat.S_IMODE(directory.stat().st_mode) == stat.S_IMODE(box.transport.stat().st_mode) == 0o700
    assert (directory / "engine.py").read_bytes() == Path(engine.__file__).read_bytes()
    assert (directory / "runner.py").read_bytes() == Path(runner.__file__).read_bytes()
    assert (directory / "release.tar.gz").read_bytes() == box.archive
    # The request the engine reads: the controller's, with the transport's archive.
    request = box.read("request.json")
    assert request == {**box.setup.request, "archive_path": str(directory / "release.tar.gz")}
    assert box.downloads == [
        f"https://github.com/traefik/traefik/releases/download/v{NEW}/traefik_v{NEW}_linux_amd64.tar.gz"
    ]
    assert staged == {
        "schema": 1,
        "id": TX,
        "action": "binary",
        "engine_sha256": sha256(Path(engine.__file__).read_bytes()),
        "runner_sha256": sha256(Path(runner.__file__).read_bytes()),
        "request_sha256": sha256((directory / "request.json").read_bytes()),
        "archive_sha256": sha256(box.archive),
        "staged_at": staged["staged_at"],
    }
    assert box.read("staged.json") == staged
    template = box.units_dir / runner.SAFE_RESTORE_TEMPLATE
    assert stat.S_IMODE(template.stat().st_mode) == 0o644
    assert box.commands == [["systemctl", "daemon-reload"]]
    # Nothing on the host changed, nothing ran.
    assert box.host.calls == []


def test_the_safe_restore_template_runs_the_runner_of_its_instance(box: Box) -> None:
    box.stage()

    text = (box.units_dir / runner.SAFE_RESTORE_TEMPLATE).read_text()
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert lines == [
        "[Unit]",
        "Description=Traefik transaction %i safe-restore",
        "CollectMode=inactive-or-failed",
        "[Service]",
        "Type=oneshot",
        "UMask=0077",
        "SyslogIdentifier=traefik-tx",
        f"ExecStart=/usr/bin/python3 -I {box.transport}/%i/runner.py safe-restore %i",
        "TimeoutStartSec=600",
    ]


def test_an_installed_template_is_not_rewritten_or_reloaded(box: Box) -> None:
    box.stage()
    box.commands.clear()
    inode = (box.units_dir / runner.SAFE_RESTORE_TEMPLATE).stat().st_ino

    box.stage(TX2)

    assert box.commands == []
    assert (box.units_dir / runner.SAFE_RESTORE_TEMPLATE).stat().st_ino == inode


def test_a_changed_template_is_rewritten_and_reloaded(box: Box) -> None:
    box.stage()
    (box.units_dir / runner.SAFE_RESTORE_TEMPLATE).write_text("[Service]\nExecStart=/bin/true\n")
    box.commands.clear()

    box.stage(TX2)

    assert box.commands == [["systemctl", "daemon-reload"]]
    assert "safe-restore %i" in (box.units_dir / runner.SAFE_RESTORE_TEMPLATE).read_text()


def test_stage_resume_fetches_nothing_and_drops_an_archive_path(box: Box) -> None:
    request = {**box.setup.request, "action": "resume", "recovery_review_reference": "review"}

    staged = box.stage(request=request)

    assert (staged["action"], staged["archive_sha256"]) == ("resume", None)
    assert box.downloads == []
    assert "archive_path" not in box.read("request.json")
    assert not (box.dir() / "release.tar.gz").exists()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"action": "inspect"}, "only binary, resume and rebaseline transactions run detached"),
        ({"action": "alias"}, "only binary, resume and rebaseline transactions run detached"),
        ({"release": None}, "binary transactions need a release"),
        ({"release": {"version": "3.7.16; rm", "arch": "amd64", "sha256": "0" * 64}}, "unsupported release"),
        ({"release": {"version": "2.11.9", "arch": "amd64", "sha256": "0" * 64}}, "unsupported release"),
        ({"release": {"version": NEW, "arch": "amd64", "sha256": "sha256:" + "0" * 64}}, "exact SHA256 is required"),
        ({"release": {"version": NEW, "arch": "arm64", "sha256": "0" * 64}}, "release architecture is not the host's"),
    ],
)
def test_stage_refuses_before_downloading(box: Box, change: dict[str, Any], message: str) -> None:
    with pytest.raises(runner.Refused, match=rf"^{message}$"):
        box.stage(request={**box.setup.request, **change})

    assert box.downloads == []
    assert not box.dir().exists()


@pytest.mark.parametrize(
    ("knob", "message"),
    [
        ({"archive": b"not the release"}, "release archive checksum mismatch"),
        ({"download_error": OSError("unreachable")}, r"release download failed \(OSError\)"),
        ({"final_url": "http://objects.example/release"}, "release download left HTTPS"),
    ],
)
def test_a_failed_download_leaves_no_transaction(box: Box, knob: dict[str, Any], message: str) -> None:
    for name, value in knob.items():
        setattr(box, name, value)

    with pytest.raises(runner.Refused, match=rf"^{message}$"):
        box.stage()

    assert box.downloads != []
    assert list(box.transport.iterdir()) == []


def test_an_oversized_archive_is_refused(box: Box) -> None:
    with patch.object(runner, "MAX_ARCHIVE", len(box.archive) - 1), pytest.raises(runner.Refused, match="too large"):
        box.stage()

    assert list(box.transport.iterdir()) == []


def test_a_transaction_id_is_staged_once(box: Box) -> None:
    box.stage()
    before = freeze(box.dir())

    with pytest.raises(runner.Refused, match=r"^transaction id is already staged$"):
        box.stage()

    assert freeze(box.dir()) == before


@pytest.mark.parametrize("value", ["../etc", "6F1C2C1E-0A3B-4C5D-8E9F-0123456789AB", TX + "/x", "", TX[:-1]])
def test_transaction_ids_are_canonical_uuid4(box: Box, value: str) -> None:
    calls: list[Callable[[], object]] = [
        lambda: box.stage(value),
        lambda: runner.poll(value),
        lambda: runner.cleanup(value),
    ]
    for call in calls:
        with pytest.raises(runner.Refused, match=r"^invalid transaction id$"):
            call()


# -- start ----------------------------------------------------------------------------


def test_start_launches_the_transient_unit(box: Box) -> None:
    box.stage()
    box.commands.clear()

    assert runner.start(TX, 900) == {
        "schema": 1,
        "id": TX,
        "started": True,
        "unit": f"traefik-tx-{TX}.service",
    }

    assert box.commands == [
        ["systemctl", "show", f"traefik-tx-{TX}.service", "-p", "LoadState", "-p", "ActiveState"],
        [
            "systemd-run",
            f"--unit=traefik-tx-{TX}.service",
            f"--description=Traefik transaction {TX}",
            "--collect",
            "--quiet",
            "--no-ask-password",
            "--property=Type=exec",
            "--property=RuntimeMaxSec=900",
            "--property=TimeoutStopSec=30",
            "--property=KillMode=control-group",
            f"--property=OnFailure=traefik-tx-safe-restore@{TX}.service",
            "--property=UMask=0077",
            "--property=SyslogIdentifier=traefik-tx",
            "--",
            "/usr/bin/python3",
            "-I",
            str(box.dir() / "runner.py"),
            "run",
            TX,
        ],
    ]


def test_start_reinstalls_a_missing_template(box: Box) -> None:
    box.stage()
    (box.units_dir / runner.SAFE_RESTORE_TEMPLATE).unlink()

    runner.start(TX, 60)

    assert (box.units_dir / runner.SAFE_RESTORE_TEMPLATE).exists()
    assert ["systemctl", "daemon-reload"] in box.commands


@pytest.mark.parametrize("seconds", [59, 3601, 0, -1])
def test_start_bounds_the_runtime(box: Box, seconds: int) -> None:
    box.stage()

    with pytest.raises(runner.Refused, match=r"^unsupported RuntimeMaxSec$"):
        runner.start(TX, seconds)


@pytest.mark.parametrize("name", ["engine.py", "runner.py", "request.json", "release.tar.gz"])
def test_start_refuses_changed_staged_files(box: Box, name: str) -> None:
    box.stage()
    (box.dir() / name).write_bytes(b"changed")

    with pytest.raises(runner.Refused, match=r"^staged files changed$"):
        runner.start(TX, 900)

    assert not any(argv[0] == "systemd-run" for argv in box.commands)


def test_start_refuses_unstaged_started_and_existing_transactions(box: Box) -> None:
    with pytest.raises(runner.Refused, match=r"^transaction is not staged$"):
        runner.start(TX, 900)
    box.stage()
    (box.dir() / "staged.json").unlink()
    with pytest.raises(runner.Refused, match=r"^transaction is not staged$"):
        runner.start(TX, 900)

    box.stage(TX2)
    box.units[f"traefik-tx-{TX2}.service"] = ("loaded", "active")
    with pytest.raises(runner.Refused, match=r"^transaction unit already exists$"):
        runner.start(TX2, 900)
    box.units.clear()
    runner.write_json(box.dir(TX2) / "started.json", {})
    with pytest.raises(runner.Refused, match=r"^transaction already started$"):
        runner.start(TX2, 900)
    assert not any(argv[0] == "systemd-run" for argv in box.commands)


# -- run ------------------------------------------------------------------------------


def test_run_executes_the_engine_and_records_its_result(box: Box) -> None:
    box.stage()

    assert runner.run_transaction(TX) == 0

    result = box.read("result.json")
    assert result == {
        "schema": 1,
        "id": TX,
        "engine_exit": 0,
        "response": {"changed": True, "state": box.record()},
        "host_phase": "clear",
        "restore_expected": False,
        "finished_at": result["finished_at"],
    }
    assert box.saved_record()["phase"] == "clear"
    assert box.saved_record()["identity"]["version"] == NEW
    assert box.started_before_engine == [True]
    started = box.read("started.json")
    assert set(started) == {"schema", "id", "invocation_id", "pid", "started_at"}
    # The archive is not needed after the engine ran; the evidence stays.
    assert not (box.dir() / "release.tar.gz").exists()
    assert (box.dir() / "engine.stderr").exists()


def test_a_rolled_back_engine_run_is_final(box: Box) -> None:
    box.host.failing["acceptance"] = 1
    box.stage()

    assert runner.run_transaction(TX) == 0

    result = box.read("result.json")
    assert (result["engine_exit"], result["host_phase"], result["restore_expected"]) == (1, "recovery", False)
    assert result["response"]["state"] == box.record()


def test_a_refused_engine_run_is_final(box: Box) -> None:
    request = {**box.setup.request, "controller_state": {**box.saved_record(), "revision": "other"}}
    box.stage(request=request)

    assert runner.run_transaction(TX) == 0

    result = box.read("result.json")
    assert (result["engine_exit"], result["host_phase"], result["restore_expected"]) == (2, "clear", False)
    assert result["response"] == {"failed": True, "error": "controller and host recovery records disagree"}
    assert box.host.calls == []


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [(-9, ""), (-15, ""), (0, "not json"), (0, "[1]"), (3, json.dumps({"changed": False}))],
)
def test_an_engine_without_a_usable_result_fails_the_unit(box: Box, returncode: int, stdout: str) -> None:
    box.engine_run = lambda args: subprocess.CompletedProcess(args, returncode, stdout, "")
    box.stage()

    assert runner.run_transaction(TX) == 1

    result = box.read("result.json")
    assert result["restore_expected"] is True
    assert result["host_phase"] == "clear"


def test_a_pending_record_after_the_engine_fails_the_unit(box: Box) -> None:
    box.engine_run = kill_engine(box)
    box.stage()

    assert runner.run_transaction(TX) == 1

    result = box.read("result.json")
    assert (result["engine_exit"], result["response"], result["host_phase"]) == (-9, None, "pending")
    assert result["restore_expected"] is True


def test_an_unreadable_record_fails_the_unit(box: Box) -> None:
    box.stage()
    with patch.object(engine, "load_state", side_effect=engine.Refused("invalid recovery state")):
        assert runner.run_transaction(TX) == 1

    assert box.read("result.json")["host_phase"] == "unreadable"


def test_run_refuses_changed_files_before_the_engine_starts(box: Box) -> None:
    box.stage()
    (box.dir() / "request.json").write_text("{}")

    with pytest.raises(runner.Refused, match=r"^staged files changed$"):
        runner.run_transaction(TX)

    assert box.started_before_engine == []
    assert not (box.dir() / "started.json").exists()


def test_run_is_one_shot(box: Box) -> None:
    box.stage()
    runner.run_transaction(TX)

    with pytest.raises(runner.Refused, match=r"^transaction already started$"):
        runner.run_transaction(TX)

    assert box.started_before_engine == [True]


def test_a_rebaseline_runs_detached_like_resume(box: Box) -> None:
    (box.host.dynamic / "app.yml").write_text("http:\n  routers: {deployed: {}}\n")
    live = box.host.identity(box.host.policy())
    evidence = {**box.setup.request["evidence"], "baseline": live}
    staged = box.stage(request={**box.setup.request, "action": "rebaseline", "evidence": evidence})
    assert (staged["action"], staged["archive_sha256"], box.downloads) == ("rebaseline", None, [])

    assert runner.run_transaction(TX) == 0

    result, record = box.read("result.json"), box.saved_record()
    assert (result["engine_exit"], result["host_phase"], result["restore_expected"]) == (0, "clear", False)
    assert result["response"] == {"changed": True, "state": record}
    assert (record["identity"], record["rebaselined_from"]) == (live, box.setup.request["controller_state"]["revision"])
    assert box.host.calls == ["probe baseline"]
    assert runner.safe_restore(TX)["reason"] == "not_binary"


def test_a_stop_signal_fails_the_unit() -> None:
    """``systemctl stop`` sends SIGTERM; a plain SIGTERM death would count as a clean stop."""

    saved = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    try:
        runner.exit_on_stop()
        assert {signum: signal.getsignal(signum) for signum in saved} == dict.fromkeys(saved, runner._stopped)
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler)
    with pytest.raises(SystemExit) as stopped:
        runner._stopped(15, None)
    assert stopped.value.code == 143


@pytest.mark.parametrize("main", ["run_transaction", "safe_restore"])
def test_both_unit_programs_exit_on_stop(box: Box, main: str) -> None:
    box.stage()
    with patch.object(runner, "exit_on_stop") as installed:
        getattr(runner, main)(TX)

    installed.assert_called_once_with()


# -- safe-restore ---------------------------------------------------------------------


def run_killed(box: Box, kill: Callable[[list[str]], Completed]) -> dict[str, Any]:
    """Stage and run a transaction whose engine is killed; the pending record it leaves."""

    box.engine_run = kill
    box.stage()
    assert runner.run_transaction(TX) == 1
    box.engine_run = None
    pending = box.saved_record()
    assert pending["phase"] == "pending"
    box.host.calls.clear()
    return pending


def test_safe_restore_after_a_kill_during_acceptance(box: Box) -> None:
    pending = run_killed(box, kill_engine(box))
    assert box.host.binary.read_bytes() == box.host.running == fake_traefik(NEW)

    outcome = runner.safe_restore(TX)

    record = box.saved_record()
    assert outcome == {
        "schema": 1,
        "id": TX,
        "acted": True,
        "reason": "restored",
        "phase": "recovery",
        "state": record,
        "finished_at": outcome["finished_at"],
    }
    assert box.read("safe-restore.json") == outcome
    assert set(box.read("restore-started.json")) == {"schema", "id", "invocation_id", "started_at"}
    assert record == {
        "schema": 1,
        "host": "fixture",
        "phase": "recovery",
        "identity": pending["identity"],
        "revision": record["revision"],
        "updated_at": record["updated_at"],
        "owner": "operator",
        "transaction": pending["transaction"],
        "reason": "EngineInterrupted",
        "review_due": record["updated_at"] + 3600,
        "safe_restore": TX,
    }
    assert record["revision"] != pending["revision"]
    # The original is back and runs; the engine's rollback order.
    assert box.host.binary.read_bytes() == box.host.running == fake_traefik(OLD)
    assert stat.S_IMODE(box.host.binary.stat().st_mode) == 0o755
    assert box.host.calls == ["probe cleanup", "restart", "probe baseline", "probe cleanup"]


def test_safe_restore_after_a_kill_before_the_restart(box: Box) -> None:
    run_killed(box, kill_engine(box, restart_first=False))
    assert box.host.binary.read_bytes() == fake_traefik(NEW)
    assert box.host.running == fake_traefik(OLD)

    outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["phase"]) == (True, "recovery")
    assert box.host.binary.read_bytes() == box.host.running == fake_traefik(OLD)


def test_safe_restore_after_a_kill_inside_the_engines_rollback(box: Box) -> None:
    """The original is back on disk but the candidate still runs: only the restart is missing."""

    run_killed(box, kill_engine(box, on_call=2, restart_first=False))
    assert box.host.binary.read_bytes() == fake_traefik(OLD)
    assert box.host.running == fake_traefik(NEW)
    inode = box.host.binary.stat().st_ino

    outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["phase"]) == (True, "recovery")
    assert box.host.running == fake_traefik(OLD)
    assert box.host.binary.stat().st_ino == inode  # not rewritten
    assert "restart" in box.host.calls


def test_safe_restore_restarts_a_stopped_traefik(box: Box) -> None:
    run_killed(box, kill_engine(box, on_call=2, restart_first=False))
    box.host.running = None

    outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["phase"]) == (True, "recovery")
    assert box.host.running == fake_traefik(OLD)


def test_safe_restore_leaves_an_untouched_binary_pending(box: Box) -> None:
    """Killed after the pending record, before the replacement: nothing to restore, review needed."""

    pending = run_killed(box, kill_before_replace(box))
    assert box.host.binary.read_bytes() == box.host.running == fake_traefik(OLD)

    outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["reason"], outcome["state"]) == (False, "binary_unchanged", None)
    assert box.saved_record() == pending
    assert box.host.calls == []


def test_safe_restore_then_a_second_run_refuses(box: Box) -> None:
    run_killed(box, kill_engine(box))
    recovery = runner.safe_restore(TX)["state"]
    box.host.calls.clear()

    # The safe-restore unit again: the record is not pending any more.
    again = runner.safe_restore(TX)
    assert (again["acted"], again["reason"]) == (False, "not_pending")
    # A new binary transaction, paired with the recovery record: refused before anything.
    box.stage(TX2, {**box.setup.request, "controller_state": recovery})
    assert runner.run_transaction(TX2) == 0
    result = box.read("result.json", TX2)
    assert (result["engine_exit"], result["restore_expected"]) == (2, False)
    assert result["response"]["error"] == "active recovery or unreviewed baseline drift"
    # Paired with the stale clear record instead: refused too.
    box.stage(TX2.replace("0b7e", "1b7e"), box.setup.request)
    assert runner.run_transaction(TX2.replace("0b7e", "1b7e")) == 0
    stale = box.read("result.json", TX2.replace("0b7e", "1b7e"))["response"]
    assert stale["error"] == "controller and host recovery records disagree"
    assert box.saved_record() == recovery
    assert box.host.calls == []
    assert box.host.binary.read_bytes() == box.host.running == fake_traefik(OLD)


def test_the_reference_engine_takes_the_safe_restore_record(box: Box) -> None:
    """ops-library's engine loads it, refuses a binary update on it and resumes from it."""

    run_killed(box, kill_engine(box))
    recovery = runner.safe_restore(TX)["state"]
    other = FakeHost(reference, box.host.root, running=box.host.running)

    with other.patched():
        assert reference.load_state(other.state_root / "state.json") == recovery
        binary = {**box.setup.request, "controller_state": recovery}
        with pytest.raises(RuntimeError, match=r"^active recovery or unreviewed baseline drift$"):
            reference.execute(binary)
        resume = {**binary, "action": "resume", "recovery_review_reference": "reviewed"}
        resumed = reference.execute(resume)["state"]

    assert (resumed["phase"], resumed["resumed_from"]) == ("clear", recovery["revision"])


@pytest.mark.parametrize(
    ("failure", "error"),
    [
        ({"restart_failures": 1}, "Refused"),
        ({"failing": {"baseline": 1}}, "Refused"),
        ({"failing": {"cleanup": 1}}, "Refused"),
        ({"unsettled_restarts": 20}, "Refused"),
    ],
)
def test_a_failed_safe_restore_is_degraded(box: Box, failure: dict[str, Any], error: str) -> None:
    run_killed(box, kill_engine(box))
    for name, value in failure.items():
        setattr(box.host, name, value)

    outcome = runner.safe_restore(TX)

    record = box.saved_record()
    assert (outcome["acted"], outcome["reason"], outcome["phase"]) == (True, "restore_failed", "degraded")
    assert (record["phase"], record["recovery_error"], record["reason"]) == ("degraded", error, "EngineInterrupted")
    assert record == outcome["state"]


def test_a_route_change_meanwhile_makes_the_safe_restore_degraded(box: Box) -> None:
    run_killed(box, kill_engine(box))
    (box.host.dynamic / "new.yml").write_text("http: {}\n")
    (box.host.dynamic / "new.yml").chmod(0o644)

    outcome = runner.safe_restore(TX)

    assert (outcome["phase"], box.saved_record()["recovery_error"]) == ("degraded", "Refused")
    assert box.host.binary.read_bytes() == fake_traefik(OLD)


def test_a_stopped_safe_restore_records_degraded(box: Box) -> None:
    """``systemctl stop`` or ``TimeoutStartSec`` while restoring: degraded, not a silent pending record."""

    run_killed(box, kill_engine(box))
    with patch.object(engine, "restart_verify", side_effect=SystemExit(143)):
        outcome = runner.safe_restore(TX)

    record = box.saved_record()
    assert (outcome["acted"], outcome["reason"], outcome["phase"]) == (True, "restore_failed", "degraded")
    assert (record["phase"], record["recovery_error"]) == ("degraded", "SystemExit")
    assert box.host.binary.read_bytes() == fake_traefik(OLD)
    assert box.read("safe-restore.json") == outcome


def test_a_stop_during_the_first_cleanup_probe_still_restores(box: Box) -> None:
    """As in the engine's rollback: a failed (or stopped) cleanup probe does not stop the restore."""

    run_killed(box, kill_engine(box))
    real = box.host.check_probe

    def check_probe(spec: dict[str, Any]) -> None:
        if not box.host.calls:
            box.host.calls.append("probe cleanup (stopped)")
            raise SystemExit(143)
        real(spec)

    with patch.object(engine, "check_probe", check_probe):
        outcome = runner.safe_restore(TX)

    assert (outcome["phase"], box.saved_record()["recovery_error"]) == ("degraded", "SystemExit")
    assert box.host.binary.read_bytes() == box.host.running == fake_traefik(OLD)
    assert box.host.calls == ["probe cleanup (stopped)", "restart", "probe baseline", "probe cleanup"]


def test_safe_restore_never_records_clear(box: Box) -> None:
    run_killed(box, kill_engine(box))
    with patch.object(engine, "identity", side_effect=KeyboardInterrupt):
        outcome = runner.safe_restore(TX)

    assert (outcome["phase"], box.saved_record()["recovery_error"]) == ("degraded", "KeyboardInterrupt")


def test_an_unsaved_safe_restore_record_is_reported(box: Box) -> None:
    pending = run_killed(box, kill_engine(box))
    with patch.object(engine, "save", side_effect=OSError("disk full")):
        outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["reason"], outcome["state"]) == (True, "record_not_saved", None)
    assert box.saved_record() == pending


def pending_of_another_transaction(box: Box) -> dict[str, Any]:
    """The record pending, binary replaced, by another run (the Ansible path, another transport)."""

    run_killed(box, kill_engine(box))
    return box.saved_record()


@pytest.mark.parametrize(
    "tamper",
    [
        "request",
        "archive",
        "previous_revision",
        "transaction_elsewhere",
        "transaction_missing",
        "operation",
    ],
)
def test_safe_restore_only_takes_its_own_transaction(box: Box, tamper: str) -> None:
    pending = pending_of_another_transaction(box)
    transaction = Path(pending["transaction"])
    if tamper == "request":
        saved = json.loads((transaction / "request.json").read_text())
        saved["evidence"]["owner"] = "someone else"
        engine.save(transaction / "request.json", saved)
    elif tamper == "archive":
        saved = json.loads((transaction / "request.json").read_text())
        engine.save(transaction / "request.json", {**saved, "archive_path": "/tmp/ansible/release.tar.gz"})
    elif tamper == "previous_revision":
        engine.save(box.host.state_root / "state.json", {**pending, "previous_revision": "another"})
    elif tamper == "transaction_elsewhere":
        moved = box.root / "elsewhere" / transaction.name
        shutil.copytree(transaction, moved)
        engine.save(box.host.state_root / "state.json", {**pending, "transaction": str(moved)})
    elif tamper == "transaction_missing":
        shutil.rmtree(transaction)
    else:
        engine.save(box.host.state_root / "state.json", {**pending, "operation": "alias"})
    before = box.record()

    outcome = runner.safe_restore(TX)

    expected = "not_pending" if tamper == "operation" else "not_this_transaction"
    assert (outcome["acted"], outcome["reason"]) == (False, expected)
    assert box.record() == before
    assert box.host.binary.read_bytes() == fake_traefik(NEW)


@pytest.mark.parametrize("phase", ["clear", "recovery", "degraded"])
def test_safe_restore_leaves_a_record_that_is_not_pending(box: Box, phase: str) -> None:
    run_killed(box, kill_engine(box))
    engine.save(box.host.state_root / "state.json", {**box.saved_record(), "phase": phase})
    before = box.record()

    outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["reason"]) == (False, "not_pending")
    assert box.record() == before


def test_safe_restore_needs_a_record_an_original_and_the_lock(box: Box) -> None:
    pending = run_killed(box, kill_engine(box))
    original = Path(pending["transaction"]) / "original"
    content = original.read_bytes()

    original.unlink()
    assert runner.safe_restore(TX)["reason"] == "no_original"
    original.write_bytes(content)
    original.chmod(0o755)

    with (box.host.root / "lock").open("a") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert runner.safe_restore(TX)["reason"] == "lock_held"

    (box.host.state_root / "state.json").unlink()
    assert runner.safe_restore(TX)["reason"] == "no_record"
    assert box.host.binary.read_bytes() == fake_traefik(NEW)
    assert box.host.calls == []


def test_safe_restore_of_a_resume_does_nothing(box: Box) -> None:
    box.stage(request={**box.setup.request, "action": "resume", "recovery_review_reference": "review"})

    outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["reason"]) == (False, "not_binary")


def test_safe_restore_errors_before_acting_are_recorded(box: Box) -> None:
    box.stage()
    (box.dir() / "request.json").write_text(json.dumps({"action": "binary"}))

    outcome = runner.safe_restore(TX)

    assert (outcome["acted"], outcome["reason"], outcome["error"]) == (False, "error", "KeyError")
    assert box.read("safe-restore.json") == outcome


def test_live_digests_reads_the_installed_and_the_running_binary(tmp_path: Path) -> None:
    installed = tmp_path / "traefik"
    installed.write_bytes(b"installed")

    class Fake:
        STATE_ROOT = LOCK = tmp_path

        def __init__(self, pid: int | Exception) -> None:
            self.pid = pid

        def main_pid(self) -> int:
            if isinstance(self.pid, Exception):
                raise self.pid
            return self.pid

        def digest(self, path: Path) -> str:
            assert path == Path("/proc/1234/exe")
            return "running"

    policy = {"binary_path": str(installed)}
    assert runner.live_digests(Fake(1234), policy) == (sha256(b"installed"), "running")  # type: ignore[arg-type]
    assert runner.live_digests(Fake(0), policy) == (sha256(b"installed"), None)  # type: ignore[arg-type]
    failing = Fake(engine.Refused("command failed: systemctl (exit 1)"))
    assert runner.live_digests(failing, {"binary_path": str(tmp_path / "gone")}) == (None, None)  # type: ignore[arg-type]


# -- poll and cleanup -----------------------------------------------------------------

M, R = f"traefik-tx-{TX}.service", f"traefik-tx-safe-restore@{TX}.service"


@pytest.mark.parametrize(
    ("args", "status"),
    [
        ((False, "inactive", ("loaded", "inactive"), False, False, None, False, False), "absent"),
        ((True, "inactive", ("loaded", "inactive"), False, False, None, False, False), "incomplete"),
        ((True, "inactive", ("loaded", "inactive"), True, False, None, False, False), "staged"),
        ((True, "activating", ("loaded", "inactive"), True, False, None, False, False), "running"),
        ((True, "active", ("loaded", "inactive"), True, True, None, False, False), "running"),
        (
            (True, "deactivating", ("loaded", "inactive"), True, True, {"restore_expected": False}, False, False),
            "running",
        ),
        ((True, "inactive", ("loaded", "inactive"), True, True, {"restore_expected": False}, False, False), "finished"),
        ((True, "inactive", ("loaded", "inactive"), True, True, {"restore_expected": True}, False, False), "restoring"),
        ((True, "inactive", ("loaded", "active"), True, True, {"restore_expected": True}, True, False), "restoring"),
        ((True, "inactive", ("loaded", "inactive"), True, True, {"restore_expected": True}, True, True), "finished"),
        ((True, "inactive", ("loaded", "inactive"), True, True, None, False, False), "restoring"),
        ((True, "inactive", ("loaded", "activating"), True, True, None, True, False), "restoring"),
        ((True, "inactive", ("loaded", "inactive"), True, True, None, True, True), "interrupted"),
        ((True, "inactive", ("loaded", "inactive"), True, True, None, True, False), "interrupted"),
        ((True, "inactive", ("not-found", "inactive"), True, True, None, False, False), "interrupted"),
        ((True, "failed", ("loaded", "inactive"), True, False, None, True, True), "interrupted"),
    ],
)
def test_classify(args: tuple[Any, ...], status: str) -> None:
    assert runner.classify(*args) == status


def test_poll_reports_the_files_and_units(box: Box) -> None:
    assert runner.poll(TX) == {
        "schema": 1,
        "id": TX,
        "status": "absent",
        "staged": False,
        "started": False,
        "result": None,
        "safe_restore": None,
    }
    assert box.commands == []  # an absent transaction asks systemd nothing

    box.stage()
    assert runner.poll(TX)["status"] == "staged"
    box.units[M] = ("loaded", "active")
    assert runner.poll(TX)["status"] == "running"
    box.units.clear()
    runner.run_transaction(TX)
    polled = runner.poll(TX)
    assert (polled["status"], polled["staged"], polled["started"]) == ("finished", True, True)
    assert polled["result"] == box.read("result.json")
    assert polled["safe_restore"] is None


def test_poll_after_a_kill_and_the_safe_restore(box: Box) -> None:
    run_killed(box, kill_engine(box))
    assert runner.poll(TX)["status"] == "restoring"
    box.units[R] = ("loaded", "active")
    assert runner.poll(TX)["status"] == "restoring"
    box.units.clear()
    runner.safe_restore(TX)

    polled = runner.poll(TX)

    assert polled["status"] == "finished"
    assert polled["safe_restore"] == box.read("safe-restore.json")


def test_poll_after_the_whole_unit_was_killed(box: Box) -> None:
    """The runner died with the engine: no result, then the safe-restore unit's outcome."""

    box.engine_run = kill_engine(box)
    box.stage()
    real = runner.write_json

    def write_json(path: Path, value: Any) -> None:
        if path.name == runner.RESULT:
            raise Killed
        real(path, value)

    with patch.object(runner, "write_json", write_json), pytest.raises(Killed):
        runner.run_transaction(TX)
    assert runner.poll(TX)["status"] == "restoring"

    runner.safe_restore(TX)

    polled = runner.poll(TX)
    assert (polled["status"], polled["result"]) == ("interrupted", None)
    assert polled["safe_restore"]["phase"] == "recovery"


def test_a_safe_restore_starting_during_the_poll_is_not_missed(box: Box) -> None:
    """The safe-restore unit starts right after the poll looked at the files: still restoring.

    Read the other way round (units first), the poll would see the safe-restore's start
    marker with an inactive unit and take it for a restore that ended, and cleanup
    would remove the files the starting restore still needs.
    """

    run_killed(box, kill_engine(box))

    def restore_starts(unit: str) -> None:
        if unit == R and not (box.dir() / runner.RESTORE_STARTED).exists():
            runner.write_json(box.dir() / runner.RESTORE_STARTED, {"schema": 1})

    box.on_show = restore_starts
    assert runner.poll(TX)["status"] == "restoring"
    box.units[R] = ("loaded", "active")
    with pytest.raises(runner.Refused, match=r"^transaction is still running or restoring$"):
        runner.cleanup(TX)
    assert box.dir().exists()


def test_cleanup_refuses_while_running_or_restoring(box: Box) -> None:
    assert runner.cleanup(TX) == {"schema": 1, "id": TX, "removed": False}
    run_killed(box, kill_engine(box))

    with pytest.raises(runner.Refused, match=r"^transaction is still running or restoring$"):
        runner.cleanup(TX)
    box.units[M] = ("loaded", "active")
    with pytest.raises(runner.Refused, match=r"^transaction is still running or restoring$"):
        runner.cleanup(TX)
    box.units.clear()
    runner.safe_restore(TX)

    assert runner.cleanup(TX) == {"schema": 1, "id": TX, "removed": True}
    assert not box.dir().exists()
    assert list(box.transport.iterdir()) == []


def test_cleanup_removes_a_staged_transaction(box: Box) -> None:
    box.stage()

    assert runner.cleanup(TX)["removed"] is True
    assert not box.dir().exists()


# -- inspect --------------------------------------------------------------------------


def test_inspect_runs_the_engine_read_only(box: Box) -> None:
    request = {"action": "inspect", "policy": box.host.policy()}
    before = freeze(box.host.root)

    found = runner.inspect(box.source(request))

    assert found == {
        "schema": 1,
        "engine_exit": 0,
        "response": {"identity": box.host.identity(box.host.policy()), "state": box.record()},
    }
    assert freeze(box.host.root) == before
    assert not box.transport.exists()


def test_inspect_refuses_other_actions(box: Box) -> None:
    with pytest.raises(runner.Refused, match=r"^only inspect runs in the foreground$"):
        runner.inspect(box.source())


# -- the program ----------------------------------------------------------------------

RUNNER_PATH = Path(runner.__file__)


def test_main_reports_refusals_and_unexpected_errors(box: Box, capsys: pytest.CaptureFixture[str]) -> None:
    previous = os.umask(0o022)
    try:
        assert runner.main(["start", TX, "900"]) == 1
        assert capsys.readouterr().err == "traefik tx: transaction is not staged\n"
        with patch.object(runner, "poll", side_effect=PermissionError(13, "denied", "/secret/path")):
            assert runner.main(["poll", TX]) == 1
        assert capsys.readouterr().err == "traefik tx: unexpected error (PermissionError)\n"
        box.stage()
        assert runner.main(["poll", TX]) == 0
        assert json.loads(capsys.readouterr().out)["status"] == "staged"
    finally:
        os.umask(previous)


def test_the_runner_is_a_standalone_standard_library_program(tmp_path: Path) -> None:
    """``python3 -I runner.py``: no package, no site directory, no script directory on the path."""

    tree = ast.parse(RUNNER_PATH.read_text(), feature_version=(3, 11))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert node.module is not None
            imported.add(node.module.partition(".")[0])
    assert imported - {"__future__"} <= sys.stdlib_module_names

    def call(*args: str) -> tuple[int, str, str]:
        result = subprocess.run(
            [sys.executable, "-I", str(RUNNER_PATH), *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=tmp_path,
        )
        return result.returncode, result.stdout, result.stderr

    assert call("poll", "not-an-id") == (1, "", "traefik tx: invalid transaction id\n")
    code, out, err = call("poll", TX)
    assert (code, err) == (0, "")
    assert json.loads(out)["status"] == "absent"
    if os.geteuid() != 0:
        assert call("stage", TX, str(tmp_path)) == (1, "", "traefik tx: root is required\n")


def test_load_engine_takes_the_file_it_is_given(tmp_path: Path) -> None:
    copy = tmp_path / "engine.py"
    copy.write_bytes(Path(engine.__file__).read_bytes() + b"\nMARKER = 'the staged copy'\n")

    loaded = runner.load_engine(copy)

    assert getattr(loaded, "MARKER") == "the staged copy"  # noqa: B009
    assert loaded is not engine
    assert loaded.STATE_ROOT == engine.STATE_ROOT
    assert sorted(p.name for p in tmp_path.iterdir()) == ["engine.py"]  # no __pycache__
