"""A fake host for the Traefik transaction engines: ours and ops-library's reference.

``ENGINES`` holds :mod:`ops_deploy.infra.traefik_tx.engine` and the reference engine,
vendored byte for byte from ops-library 3110a0f1 as ``parity/traefik_deploy/
traefik_transaction.py.txt`` (``.txt`` keeps lint, mypy and pytest away from it).

:class:`FakeHost` replaces, the same way in both engines, what a test cannot have
or must pin: systemd and the running process (``identity``, ``systemctl restart``,
``traefik version``), the probe programs, the ``tar`` backup, root (``geteuid``,
the root-owned state directory, ``trusted_file`` without the ownership check),
``validate_policy`` (it allows only the real host paths), and ``time`` and
``uuid4`` (fixed, so records compare byte for byte). The parity tests compare each
replaced function separately. Everything else runs for real on files below a
temporary root: state records, the lock, the transaction directory, the release
archive, the candidate, the binary replacement and its rollback. ``run_scenario``
drives one engine through one request and returns everything it left behind, so
two runs can be compared.
"""

from __future__ import annotations

import copy
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tarfile
import types
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path, PosixPath
from typing import Any
from unittest.mock import patch

from ops_deploy.infra.traefik_tx import engine as port

REFERENCE_PATH = Path(__file__).parent / "parity" / "traefik_deploy" / "traefik_transaction.py.txt"
REFERENCE_COMMIT = "3110a0f136320654dd7041a0f78e8d6fc629c3d9"
REFERENCE_SHA256 = "6c79b22af04290c76384bd0ba397097875f03cfef58099d8634bc526c3da6030"


def load_reference() -> types.ModuleType:
    """The vendored ops-library engine as a module of its own."""

    module = types.ModuleType("traefik_transaction_reference")
    module.__file__ = str(REFERENCE_PATH)
    exec(compile(REFERENCE_PATH.read_text(), str(REFERENCE_PATH), "exec", dont_inherit=True), module.__dict__)
    return module


reference = load_reference()
ENGINES: dict[str, types.ModuleType] = {"ops-deploy": port, "ops-library": reference}

NOW = 1_800_000_000
OLD, NEW = "3.7.14", "3.7.16"
MACHINE_ID = "0123456789abcdef0123456789abcdef"
UNIT = (
    "# /etc/systemd/system/traefik.service\n[Service]\n"
    "ExecStart=/usr/local/bin/traefik --configFile=/etc/traefik/traefik.toml\n"
)
PROBES = ("baseline", "acceptance", "cleanup")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fake_traefik(version: str) -> bytes:
    """A stand-in executable: a shell script that answers ``version`` like Traefik."""

    return f"#!/bin/sh\necho 'Version:      {version}'\necho 'Codename:     fixture'\n".encode()


def version_of(executable: bytes) -> str | None:
    match = re.search(rb"Version: +(\S+)'", executable)
    return None if match is None else match.group(1).decode()


def release_archive(path: Path, members: list[tuple[str, bytes | None]]) -> Path:
    """A ``tar.gz`` like Traefik's releases; a ``None`` member is a directory.

    The gzip header carries no time and no name, so the same members always give the
    same bytes: two engine runs that straddle a second still get the same checksum.
    """

    with (
        path.open("wb") as raw,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w") as bundle,
    ):
        for name, data in members:
            info = tarfile.TarInfo(name)
            if data is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                bundle.addfile(info)
            else:
                info.size, info.mode = len(data), 0o755
                bundle.addfile(info, io.BytesIO(data))
    return path


class RootOwnedPath(PosixPath):
    """A path whose ``stat`` reports root ownership: the engines require a root-owned state root."""

    def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        info = super().stat(follow_symlinks=follow_symlinks)
        fields = (info.st_mode, info.st_ino, info.st_dev, info.st_nlink, 0, 0, info.st_size)
        return os.stat_result((*fields, int(info.st_atime), int(info.st_mtime), int(info.st_ctime)))


def relaxed_trusted_file(path: Path) -> None:
    """``trusted_file`` without the root ownership, which a test cannot provide."""

    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise RuntimeError(f"fixture file not regular or writable by others: {path}")


class FakeClock:
    def __init__(self) -> None:
        self.sleeps: list[float] = []

    def time(self) -> float:
        return float(NOW)

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)


class FakeUuid:
    def __init__(self) -> None:
        self.count = 0

    def uuid4(self) -> uuid.UUID:
        self.count += 1
        return uuid.UUID(int=self.count)


@dataclass
class FakeHost:
    """Traefik on a temporary root, as both engines see it through the patched functions."""

    engine: types.ModuleType
    root: Path
    running: bytes | None = None
    calls: list[str] = field(default_factory=list)
    # The host record as it was on disk at each restart (the pending record, while it is live).
    records_at_restart: list[bytes] = field(default_factory=list)
    # probe name -> failures left (-1: always); a probe named in ``interrupt`` raises KeyboardInterrupt once.
    failing: dict[str, int] = field(default_factory=dict)
    interrupt: str = ""
    restart_failures: int = 0
    # Restarts that come up with a different identity than the binary on disk (a unit that does not settle).
    unsettled_restarts: int = 0
    unsettled: bool = False
    after_backup: Callable[[], None] | None = None
    euid: int = 0
    clock: FakeClock = field(default_factory=FakeClock)
    uuids: FakeUuid = field(default_factory=FakeUuid)

    @property
    def binary(self) -> Path:
        return self.root / "bin" / "traefik"

    @property
    def config(self) -> Path:
        return self.root / "etc" / "traefik.toml"

    @property
    def dynamic(self) -> Path:
        return self.root / "etc" / "dynamic"

    @property
    def state_root(self) -> Path:
        return self.root / "state"

    def probe(self, name: str) -> dict[str, Any]:
        path = self.root / "probes" / name
        return {"argv": [str(path), "--fixture"], "sha256": sha256(path.read_bytes())}

    def install(self, version: str = OLD) -> None:
        for directory in (self.binary.parent, self.dynamic, self.root / "probes"):
            directory.mkdir(parents=True, exist_ok=True)
        self.binary.write_bytes(fake_traefik(version))
        self.binary.chmod(0o755)
        self.config.write_text(f'[providers.file]\ndirectory = "{self.dynamic}"\nwatch = true\n')
        (self.dynamic / "app.yml").write_text("http:\n  routers: {}\n")
        for path in (self.config, self.dynamic / "app.yml"):
            path.chmod(0o644)
        for name in PROBES:
            probe = self.root / "probes" / name
            probe.write_text(f"#!/bin/sh\n# {name} probe fixture\n")
            probe.chmod(0o755)
        self.running = self.binary.read_bytes()

    def policy(self) -> dict[str, Any]:
        return {
            "host": "fixture",
            "binary_path": str(self.binary),
            "config_path": str(self.config),
            "dynamic_path": str(self.dynamic),
            "backup_paths": [str(self.binary), str(self.config)],
            "acme_paths": [],
            "alias_policy": {},
        }

    # -- what the engines call ------------------------------------------------------------

    def identity(self, policy: dict[str, Any]) -> dict[str, Any]:
        if self.running is None:
            raise self.engine.Refused("Traefik is not running")
        disk = Path(policy["binary_path"]).read_bytes()
        if self.running != disk:
            raise self.engine.Refused("running/installed executable hash drift")
        return {
            "machine_id": MACHINE_ID,
            "binary_path": policy["binary_path"],
            "binary_sha256": sha256(disk),
            "version": "0.0.0" if self.unsettled else str(version_of(disk)),
            "config_path": policy["config_path"],
            "config_sha256": sha256(Path(policy["config_path"]).read_bytes()),
            "dynamic_sha256": self.engine.inventory_tree(Path(policy["dynamic_path"])),
            "unit_sha256": sha256(UNIT.encode()),
        }

    def run(self, argv: list[str], timeout: int = 30, **kwargs: Any) -> str:
        if argv == ["systemctl", "restart", "traefik.service"]:
            self.calls.append("restart")
            self.records_at_restart.append((self.state_root / "state.json").read_bytes())
            if self.restart_failures:
                self.restart_failures -= 1
                raise self.engine.Refused("command failed: systemctl (exit 1)")
            self.running = self.binary.read_bytes()
            self.unsettled = self.unsettled_restarts > 0
            self.unsettled_restarts = max(0, self.unsettled_restarts - 1)
            return ""
        if len(argv) == 2 and argv[1] == "version":
            self.calls.append(f"version {Path(argv[0]).name}")
            found = version_of(Path(argv[0]).read_bytes())
            return "no version here\n" if found is None else f"Version:      {found}\nCodename:     fixture\n"
        raise AssertionError(f"unexpected command: {argv}")

    def check_probe(self, spec: dict[str, Any]) -> None:
        name = Path(spec["argv"][0]).name
        self.calls.append(f"probe {name}")
        if name == self.interrupt:
            self.interrupt = ""
            raise KeyboardInterrupt
        left = self.failing.get(name, 0)
        if left:
            self.failing[name] = left - 1 if left > 0 else left
            raise self.engine.Refused(f"command failed: {name} (exit 1)")

    def backup(self, policy: dict[str, Any], directory: Path) -> None:
        self.calls.append("backup")
        self.engine.atomic(directory / "prechange.tar.gz", b"fixture archive")
        self.engine.save(directory / "backup.json", {"paths": policy["backup_paths"], "sha256": "fixture"})
        if self.after_backup is not None:
            self.after_backup()

    @contextmanager
    def patched(self) -> Iterator[None]:
        engine = self.engine
        with ExitStack() as stack:
            for name, value in {
                "STATE_ROOT": RootOwnedPath(self.state_root),
                "LOCK": self.root / "lock",
                "validate_policy": lambda policy: None,
                "trusted_file": relaxed_trusted_file,
                "identity": self.identity,
                "run": self.run,
                "check_probe": self.check_probe,
                "backup": self.backup,
                "time": self.clock,
                "uuid": self.uuids,
            }.items():
                stack.enter_context(patch.object(engine, name, value))
            stack.enter_context(patch("os.geteuid", new=lambda: self.euid))
            yield


@dataclass
class Setup:
    """What a scenario may change before the engine runs: the host, the request, the record."""

    host: FakeHost
    request: dict[str, Any]
    state: dict[str, Any] | None
    state_dir_mode: int = 0o700
    hold_lock: bool = False


def enrolled_state(identity: dict[str, Any], **fields: Any) -> dict[str, Any]:
    """A clear record as an enrollment leaves it (fixed revision and time)."""

    record = {
        "schema": 1,
        "host": "fixture",
        "phase": "clear",
        "identity": identity,
        "revision": "11111111-2222-4333-8444-555555555555",
        "updated_at": NOW - 86400,
        "owner": "operator",
    }
    record.update(fields)
    return record


def base_setup(host: FakeHost, action: str) -> Setup:
    """A complete, valid request for ``action`` against a clear record."""

    policy = host.policy()
    live = host.identity(policy)
    candidate = fake_traefik(NEW)
    archive = release_archive(
        host.root / "release.tar.gz", [("LICENSE.md", b"license\n"), ("traefik", candidate), ("CHANGELOG.md", b"log\n")]
    )
    state = enrolled_state(live)
    request: dict[str, Any] = {
        "action": action,
        "policy": policy,
        "controller_state": state,
        "evidence": {
            "baseline": live,
            "verified_at": NOW - 60,
            "owner": "operator",
            "review_reference": "fixture review",
            "recovery_access": "fresh key-authenticated root SSH; binary-only",
            "independent_observer": "fixture controller",
            "observer_delivery_test": "fixture HTTP baseline",
            "observer_watch_active": True,
        },
        "baseline_probe": host.probe("baseline"),
        "acceptance_probe": host.probe("acceptance"),
        "cleanup_probe": host.probe("cleanup"),
        "compatibility": {
            "baseline": live,
            "architecture": os.uname().machine,
            "candidate_binary_sha256": sha256(candidate),
            "candidate_config_sha256": live["config_sha256"],
            "passed": True,
            "baseline_pair_passed": True,
            "report_reference": "fixture proof",
        },
        "release": {"version": NEW, "arch": "amd64", "sha256": sha256(archive.read_bytes())},
        "archive_path": str(archive),
    }
    if action == "resume":
        request["recovery_review_reference"] = "fixture reviewed recovery"
    return Setup(host=host, request=request, state=state)


def run_main(engine: types.ModuleType, root: Path, request: dict[str, Any]) -> dict[str, Any]:
    """``engine.main`` on ``request`` written to a file; ``main`` sets umask 077 and is given back the old one."""

    path = root / "request.json"
    path.write_text(json.dumps(request))
    output = io.StringIO()
    previous = os.umask(0o022)
    try:
        with patch("sys.argv", ["engine.py", "--request", str(path)]), redirect_stdout(output):
            code = engine.main()
    finally:
        os.umask(previous)
    return {"exit": code, "output": json.loads(output.getvalue())}


@dataclass
class Outcome:
    """Everything one engine run returned or left behind."""

    result: dict[str, Any] | None
    error: tuple[str, str] | None
    files: dict[str, tuple[int, bytes | None]]
    calls: list[str]
    sleeps: list[float]
    records_at_restart: list[bytes]

    @property
    def record(self) -> dict[str, Any] | None:
        """The host record left behind, if any."""

        data = self.files.get("state/state.json")
        return None if data is None or data[1] is None else dict(json.loads(data[1]))

    @property
    def saved(self) -> dict[str, Any]:
        """The host record left behind; there must be one."""

        record = self.record
        assert record is not None
        return record


def snapshot(root: Path) -> dict[str, tuple[int, bytes | None]]:
    """Mode and content of every entry below ``root`` (``None`` for directories)."""

    entries: dict[str, tuple[int, bytes | None]] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        content = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
        entries[str(path.relative_to(root))] = (stat.S_IMODE(info.st_mode), content)
    return entries


def run_scenario(
    engine: types.ModuleType, root: Path, scenario: Callable[[Setup], None], action: str, *, cli: bool = False
) -> Outcome:
    """Run ``engine`` on a fresh host at ``root`` (always the same path, so runs compare byte for byte).

    With ``cli`` the request goes through ``main`` as a file; the result is then the exit
    code and the printed JSON.
    """

    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    host = FakeHost(engine, root)
    host.install()
    result: dict[str, Any] | None = None
    error: tuple[str, str] | None = None
    with host.patched(), ExitStack() as stack:
        setup = base_setup(host, action)
        scenario(setup)
        if setup.state is not None:
            host.state_root.mkdir(mode=0o700)
            engine.save(host.state_root / "state.json", setup.state)
            host.state_root.chmod(setup.state_dir_mode)
        if setup.hold_lock:
            holder = stack.enter_context((root / "lock").open("a"))
            fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            result = run_main(engine, root, setup.request) if cli else engine.execute(copy.deepcopy(setup.request))
        except Exception as exc:
            error = (type(exc).__name__, str(exc))
    return Outcome(
        result=result,
        error=error,
        files=snapshot(root),
        calls=host.calls,
        sleeps=host.clock.sleeps,
        records_at_restart=host.records_at_restart,
    )
