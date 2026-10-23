"""Retention of the Traefik rollback set and the external rollback archive (Q4 of the patch design).

Retention runs in process on ``traefik_tx_fixtures.FakeHost`` (state directory, lock and
record below a temporary root); the external archive runs the engine's real ``backup``
with ``findmnt`` and ``tar`` replaced.
"""

from __future__ import annotations

import fcntl
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, redirect_stdout
from pathlib import Path, PosixPath
from typing import Any
from unittest.mock import patch

import pytest

from ops_deploy.infra.traefik_tx import engine, retention, runner, transport
from ops_deploy.infra.traefik_tx.transport import TransportError
from tests.test_traefik_tx_rebaseline import ArchivingHost, add_route, history
from tests.test_traefik_tx_transport import FakeRunner, blocks, ok
from tests.traefik_tx_fixtures import (
    NOW,
    FakeHost,
    enrolled_state,
    run_scenario,
    sha256,
    snapshot,
)

IDS = [f"00000000-0000-4000-8000-00000000000{n}" for n in range(1, 7)]  # oldest first


def transaction(host: FakeHost, tx: str, created: int, *, archive: bool = True, candidate: bool = True) -> Path:
    directory = host.state_root / tx
    directory.mkdir(mode=0o700)
    (directory / "request.json").write_text("{}\n")
    (directory / "backup.json").write_text("{}\n")
    (directory / "original").write_bytes(b"o" * 10)
    if candidate:
        (directory / "candidate").write_bytes(b"c" * 100)
    if archive:
        (directory / "prechange.tar.gz").write_bytes(b"a" * 1000)
    os.utime(directory / "request.json", (created, created))
    return directory


@contextmanager
def fake_host(tmp_path: Path, phase: str = "clear", protected: str | None = IDS[1]) -> Iterator[FakeHost]:
    """Six transactions (one an hour, IDS order), a record naming ``protected``, and a few other entries."""

    host = FakeHost(engine, tmp_path / "host")
    host.root.mkdir()
    host.install()
    with host.patched(), patch.object(retention, "time", host.clock):
        host.state_root.mkdir(mode=0o700)
        for index, tx in enumerate(IDS):
            transaction(host, tx, NOW - 3600 * (len(IDS) - index))
        fields: dict[str, Any] = {} if protected is None else {"transaction": str(host.state_root / protected)}
        record = enrolled_state(host.identity(host.policy()), **fields)
        record["phase"] = phase
        engine.save(host.state_root / "state.json", record)
        engine.save(host.state_root / engine.ROUTE_INVENTORY, {"files": []})
        (host.state_root / "notes").mkdir()
        (host.state_root / "ffffffff-ffff-4fff-8fff-ffffffffffff").symlink_to(host.state_root / IDS[0])
        yield host


def request(
    apply: bool = False, keep_minimal: int = 3, keep_full: int = 2, policy: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {"keep_minimal": keep_minimal, "keep_full": keep_full, "apply": apply, "policy": policy or {}}


def by_id(found: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in found["transactions"]}


# -- the plan ---------------------------------------------------------------------------------


def test_the_listing_plans_and_writes_nothing(tmp_path: Path) -> None:
    with fake_host(tmp_path) as host:
        before = snapshot(host.root)
        found = retention.retention(engine, request())
        assert snapshot(host.root) == before
        assert not (host.root / "lock").exists()  # no lock taken

    plan = by_id(found)
    assert [item["id"] for item in found["transactions"]] == IDS[::-1]
    assert {tx: plan[tx]["keep"] for tx in IDS} == {
        IDS[5]: "full",
        IDS[4]: "full",
        IDS[3]: "minimal",
        IDS[2]: "remove",
        IDS[1]: "minimal",  # the recorded transaction is always kept
        IDS[0]: "remove",
    }
    assert plan[IDS[5]]["remove"] == ["candidate"]
    assert plan[IDS[3]]["remove"] == ["candidate", "prechange.tar.gz"]
    assert plan[IDS[1]]["protected"] is True
    assert plan[IDS[0]]["remove"] == ["backup.json", "candidate", "original", "prechange.tar.gz", "request.json"]
    assert plan[IDS[0]]["free_bytes"] == 1000 + 100 + 10 + 3 + 3
    assert found["free_bytes"] == 2 * 100 + 2 * 1100 + 2 * 1116
    assert found["local_bytes"] == 6 * 1116
    assert found["apply"] is False
    assert found["applied"] is None
    assert found["phase"] == "clear"
    assert found["other"] == sorted(
        ["ffffffff-ffff-4fff-8fff-ffffffffffff", "notes", "route-inventory.json", "state.json"]
    )
    assert found["external"] == {"status": "not_configured", "archives": []}


def test_apply_removes_what_the_listing_names_and_keeps_the_rest(tmp_path: Path) -> None:
    with fake_host(tmp_path) as host:
        listed = retention.retention(engine, request())
        applied = retention.retention(engine, request(apply=True))
        left = {path.name for path in host.state_root.iterdir()}
        kept = {tx: sorted(p.name for p in (host.state_root / tx).iterdir()) for tx in IDS if tx in left}
        marker = json.loads((host.state_root / IDS[3] / "retention.json").read_text())
        again = retention.retention(engine, request(apply=True))
        # the recorded transaction's rollback artifact is intact
        assert (host.state_root / IDS[1] / "original").read_bytes() == b"o" * 10

    assert applied["transactions"] == listed["transactions"]
    assert sorted(applied["applied"]) == sorted([IDS[5], IDS[4], IDS[3], IDS[2], IDS[1], IDS[0]])
    assert left == {IDS[5], IDS[4], IDS[3], IDS[1], "notes", "route-inventory.json", "state.json",
                    "ffffffff-ffff-4fff-8fff-ffffffffffff"}  # fmt: skip
    full = ["backup.json", "original", "prechange.tar.gz", "request.json", "retention.json"]
    minimal = ["backup.json", "original", "request.json", "retention.json"]
    assert kept == {IDS[5]: full, IDS[4]: full, IDS[3]: minimal, IDS[1]: minimal}
    assert marker == {"schema": 1, "removed": ["candidate", "prechange.tar.gz"], "updated_at": NOW}
    # A second run finds nothing more to do.
    assert again["applied"] == []
    assert again["free_bytes"] == 0


def test_apply_refuses_while_the_transaction_lock_is_held(tmp_path: Path) -> None:
    with fake_host(tmp_path) as host, (host.root / "lock").open("a") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot(host.state_root)
        with pytest.raises(retention.Refused, match=r"^the transaction lock is held$"):
            retention.retention(engine, request(apply=True))
        assert snapshot(host.state_root) == before
        # The listing still works: it never takes the lock.
        assert retention.retention(engine, request())["phase"] == "clear"


@pytest.mark.parametrize("phase", ["pending", "recovery", "degraded"])
def test_apply_needs_a_clear_record(phase: str, tmp_path: Path) -> None:
    with fake_host(tmp_path, phase=phase) as host:
        before = snapshot(host.state_root)
        with pytest.raises(retention.Refused, match=r"^retention requires a clear host record$"):
            retention.retention(engine, request(apply=True))
        assert snapshot(host.state_root) == before
        assert retention.retention(engine, request())["phase"] == phase


def test_apply_needs_an_enrolled_host(tmp_path: Path) -> None:
    with fake_host(tmp_path) as host:
        (host.state_root / "state.json").unlink()
        with pytest.raises(retention.Refused, match=r"^missing host enrollment$"):
            retention.retention(engine, request(apply=True))


def test_without_a_recorded_transaction_only_the_counts_decide(tmp_path: Path) -> None:
    with fake_host(tmp_path, protected=None):
        plan = by_id(retention.retention(engine, request(keep_minimal=1, keep_full=0)))

    assert plan[IDS[5]]["keep"] == "minimal"
    assert all(plan[tx]["keep"] == "remove" for tx in IDS[:5])


def test_a_record_outside_the_state_directory_protects_nothing(tmp_path: Path) -> None:
    with fake_host(tmp_path) as host:
        record = json.loads((host.state_root / "state.json").read_text())
        record["transaction"] = f"/elsewhere/{IDS[0]}"
        engine.save(host.state_root / "state.json", record)
        plan = by_id(retention.retention(engine, request()))

    assert not any(item["protected"] for item in plan.values())


def test_without_a_state_directory_there_is_nothing(tmp_path: Path) -> None:
    host = FakeHost(engine, tmp_path / "host")
    host.root.mkdir()
    with host.patched():
        found = retention.retention(engine, request(apply=True))

    assert (found["transactions"], found["applied"], found["phase"]) == ([], [], None)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"keep_minimal": 0}, "keep_minimal must be an integer from 1 to 20"),
        ({"keep_minimal": 21}, "keep_minimal must be an integer from 1 to 20"),
        ({"keep_minimal": True}, "keep_minimal must be an integer from 1 to 20"),
        ({"keep_full": 4}, "keep_full must be an integer from 0 to keep_minimal"),
        ({"keep_full": -1}, "keep_full must be an integer from 0 to keep_minimal"),
        ({"apply": "yes"}, "apply must be true or false"),
        ({"policy": None}, "policy is required"),
    ],
)
def test_invalid_requests_are_refused(change: dict[str, Any], message: str, tmp_path: Path) -> None:
    with fake_host(tmp_path), pytest.raises(retention.Refused, match=f"^{message}$"):
        retention.retention(engine, {**request(), **change})


def test_only_root_runs_it(tmp_path: Path) -> None:
    with fake_host(tmp_path) as host:
        host.euid = 1000
        with pytest.raises(retention.Refused, match=r"^root is required$"):
            retention.retention(engine, request())


def test_an_unsafe_state_directory_is_refused(tmp_path: Path) -> None:
    with fake_host(tmp_path) as host:
        host.state_root.chmod(0o755)
        with pytest.raises(retention.Refused, match=r"^unsafe state directory$"):
            retention.retention(engine, request())


# -- external archives: listed, never removed -------------------------------------------------


def test_external_archives_are_listed_and_kept(tmp_path: Path) -> None:
    disk = tmp_path / "disk"
    archives = disk / "traefik-rollback"
    archives.mkdir(parents=True)
    (archives / f"{IDS[0]}.tar.gz").write_bytes(b"x" * 7)
    (archives / "unrelated.txt").write_text("x")
    policy = {"rollback_archive": {"root": str(archives), "mount": str(disk)}}
    with fake_host(tmp_path):
        with patch.object(engine, "archive_mounted", lambda mount: False):
            unmounted = retention.retention(engine, request(policy=policy))
        with patch.object(engine, "archive_mounted", lambda mount: mount == disk):
            listed = retention.retention(engine, request(policy=policy))
            retention.retention(engine, request(apply=True, policy=policy))

    assert unmounted["external"] == {"status": "not_mounted", "archives": []}
    assert listed["external"]["status"] == "mounted"
    assert [(item["name"], item["bytes"]) for item in listed["external"]["archives"]] == [(f"{IDS[0]}.tar.gz", 7)]
    assert (archives / f"{IDS[0]}.tar.gz").read_bytes() == b"x" * 7


# -- the program, the runner and the transport ------------------------------------------------


def test_the_program_reports_refusals_as_json(tmp_path: Path) -> None:
    path = tmp_path / "request.json"
    path.write_text(json.dumps(request(keep_minimal=0)))
    output = io.StringIO()
    with redirect_stdout(output):
        code = retention.main(["--request", str(path)])

    assert (code, json.loads(output.getvalue())) == (
        2,
        {"failed": True, "error": "keep_minimal must be an integer from 1 to 20"},
    )


def test_the_program_loads_the_engine_next_to_it() -> None:
    loaded = retention.load_engine()

    assert loaded.__file__ == str(Path(engine.__file__).resolve())
    assert loaded.STATE_ROOT == engine.STATE_ROOT
    assert loaded.LOCK == engine.LOCK


def test_retention_uses_the_standard_library_only() -> None:
    allowed = set(sys.stdlib_module_names) | {"__future__"}
    source = Path(retention.__file__).read_text()
    imports = {line.split()[1].split(".")[0] for line in source.splitlines() if line.startswith(("import ", "from "))}

    assert imports <= allowed


def source_dir(tmp_path: Path, body: dict[str, Any]) -> Path:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    shutil.copy(engine.__file__, source / runner.ENGINE)
    shutil.copy(retention.__file__, source / runner.RETENTION)
    (source / runner.REQUEST).write_text(json.dumps(body))
    return source


def test_the_runner_runs_the_program_next_to_its_request(tmp_path: Path) -> None:
    source = source_dir(tmp_path, {"action": "retention", **request(keep_minimal=0)})

    with patch.object(runner, "ROOT_UID", os.getuid()), patch.object(runner, "PYTHON", sys.executable):
        found = runner.retention(source)

    assert found == {
        "schema": 1,
        "engine_exit": 2,
        "response": {"failed": True, "error": "keep_minimal must be an integer from 1 to 20"},
    }


def test_the_runner_runs_only_retention_requests(tmp_path: Path) -> None:
    source = source_dir(tmp_path, {"action": "inspect", "policy": {}})

    with (
        patch.object(runner, "ROOT_UID", os.getuid()),
        pytest.raises(runner.Refused, match=r"^only retention runs here$"),
    ):
        runner.retention(source)


def test_the_transport_sends_engine_program_and_request() -> None:
    response = {"schema": 1, "apply": False, "transactions": []}
    fake = FakeRunner([ok({"schema": 1, "engine_exit": 0, "response": response})])
    policy = {"host": "fixture", "rollback_archive": {"root": "/mnt/disk/traefik", "mount": "/mnt/disk"}}

    found = transport.retention_host(fake, policy, keep_minimal=3, keep_full=0)

    assert found == transport.EngineRun(0, response)
    script, args, timeout = fake.calls[0]
    assert (args, timeout) == ([], 900)
    assert script.endswith('runner.py" retention "$dir"\n')
    sent = blocks(script)
    assert sorted(sent) == ["engine.py", "request.json", "retention.py", "runner.py"]
    assert sent["retention.py"] == Path(retention.__file__).read_bytes()
    assert json.loads(sent["request.json"]) == {
        "action": "retention",
        "policy": policy,
        "keep_minimal": 3,
        "keep_full": 0,
        "apply": False,
    }


def test_the_transport_refuses_an_unusable_answer() -> None:
    fake = FakeRunner([ok({"schema": 1, "engine_exit": 0})])

    with pytest.raises(TransportError, match=r"^retention: unusable result$"):
        transport.retention_host(fake, {}, keep_minimal=3, keep_full=2, apply=True)


# -- the external rollback archive ----------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "/mnt/disk",
        {"root": "/mnt/disk/traefik"},
        {"root": "/mnt/disk/traefik", "mount": "/mnt/disk", "extra": 1},
        {"root": "/mnt/disk", "mount": "/mnt/disk"},
        {"root": "/srv/traefik", "mount": "/mnt/disk"},
        {"root": "/mnt/disk/../traefik", "mount": "/mnt/disk"},
        {"root": "/mnt/disk/./traefik", "mount": "/mnt/disk"},
        {"root": "mnt/disk/traefik", "mount": "mnt/disk"},
        {"root": "/mnt/disk/traefik/", "mount": "/mnt/disk"},
        {"root": "/mnt/disk/.hidden", "mount": "/mnt/disk"},
    ],
)
def test_an_invalid_archive_setting_is_refused(value: Any) -> None:
    with pytest.raises(
        engine.Refused, match=r"^(invalid rollback_archive|rollback archive root must be below its mount)$"
    ):
        engine.archive_settings({"rollback_archive": value})


def test_without_an_archive_setting_the_archive_stays_local() -> None:
    assert engine.archive_settings({}) is None
    assert engine.archive_settings({"rollback_archive": None}) is None


@pytest.mark.parametrize(
    ("returncode", "stdout", "mounted"),
    [
        (0, "/mnt/disk rw,relatime\n", True),
        (0, "/mnt/disk ro,relatime\n", False),
        (0, "/ rw,relatime\n", False),
        (1, "", False),
        (0, "", False),
    ],
)
def test_findmnt_must_report_a_read_write_mount_there(returncode: int, stdout: str, mounted: bool) -> None:
    done = subprocess.CompletedProcess([], returncode, stdout, "")
    with patch("ops_deploy.infra.traefik_tx.engine.subprocess.run", return_value=done) as run:
        assert engine.archive_mounted(Path("/mnt/disk")) is mounted
    assert run.call_args.args[0][:3] == ["findmnt", "--mountpoint", "/mnt/disk"]


def test_a_failing_findmnt_is_not_mounted() -> None:
    with patch("ops_deploy.infra.traefik_tx.engine.subprocess.run", side_effect=OSError):
        assert engine.archive_mounted(Path("/mnt/disk")) is False


def fake_stat(dev: int, ino: int) -> os.stat_result:
    return os.stat_result((0o40755, ino, dev, 2, 0, 0, 0, 0, 0, 0))


@pytest.mark.parametrize(
    ("now", "parent", "findmnt", "root"),
    [
        ((7, 2), (1, 9), True, True),
        ((7, 2), (1, 9), False, False),  # findmnt does not see it
        ((7, 3), (1, 9), True, False),  # the path names another directory now
        ((7, 2), (7, 9), True, False),  # the same device as its parent: a directory on /
    ],
)
def test_the_opened_mount_point_must_be_the_mounted_root(
    now: tuple[int, int], parent: tuple[int, int], findmnt: bool, root: bool
) -> None:
    stats = {"/mnt/disk": fake_stat(*now), "/mnt": fake_stat(*parent)}

    def stat(path: Any, **kwargs: Any) -> os.stat_result:
        return stats[str(path)]

    with patch("os.stat", stat), patch.object(engine, "archive_mounted", lambda mount: findmnt):
        assert engine.mount_root(Path("/mnt/disk"), fake_stat(7, 2)) is root


class SystemPaths(PosixPath):
    """``/etc/traefik`` and the unit exist; ``/etc/letsencrypt`` and drop-ins do not (as on any test system)."""

    def exists(self, *, follow_symlinks: bool = True) -> bool:
        if str(self) in {"/etc/traefik", "/etc/systemd/system/traefik.service"}:
            return True
        if str(self) in {"/etc/letsencrypt", "/etc/systemd/system/traefik.service.d"}:
            return False
        return super().exists()


class Disk:
    """A temporary "external disk" for the engine's real ``backup``: the mount check and tar replaced."""

    def __init__(self, tmp_path: Path) -> None:
        self.mount = tmp_path / "disk"
        self.mount.mkdir()
        self.mount.chmod(0o755)
        self.root = self.mount / "traefik" / "rollback"
        self.mounted = True
        self.owner = os.getuid()
        self.host = FakeHost(engine, tmp_path / "host")
        self.host.root.mkdir()
        self.host.install()
        self.transaction = tmp_path / "state" / IDS[0]
        self.transaction.mkdir(parents=True, mode=0o700)
        self.tars: list[list[str]] = []
        self.during_tar: Callable[[], Any] = lambda: None
        self.tar_fails = False

    def policy(self, external: bool = True) -> dict[str, Any]:
        policy = {
            **self.host.policy(),
            "backup_paths": [str(self.host.binary), "/etc/traefik", "/etc/systemd/system/traefik.service"],
        }
        if external:
            policy["rollback_archive"] = {"root": str(self.root), "mount": str(self.mount)}
        return policy

    def mount_root(self, mount: Path, opened: os.stat_result) -> bool:
        info = os.stat(mount, follow_symlinks=False)
        return self.mounted and (info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino)

    def tar_to(self, stream: Any, paths: list[str]) -> None:
        self.tars.append(paths)
        self.during_tar()
        stream.write(b"archive")
        if self.tar_fails:
            raise engine.Refused("command failed: tar (exit 2)")

    def run(self, argv: list[str], timeout: int = 30) -> str:
        assert argv[:5] == ["tar", "--acls", "--xattrs", "--numeric-owner", "-czf"]
        self.tars.append(argv[6:])
        Path(argv[5]).write_bytes(b"local archive")
        return ""

    def backup(self, external: bool = True) -> None:
        with (
            patch.object(engine, "mount_root", self.mount_root),
            patch.object(engine, "tar_to", self.tar_to),
            patch.object(engine, "run", self.run),
            patch.object(engine, "ARCHIVE_OWNER", self.owner),
            patch.object(engine, "Path", SystemPaths),
        ):
            engine.backup(self.policy(external), self.transaction)


def test_the_full_archive_goes_to_the_mounted_disk(tmp_path: Path) -> None:
    disk = Disk(tmp_path)
    disk.backup()

    archive = disk.root / f"{IDS[0]}.tar.gz"
    assert archive.read_bytes() == b"archive"
    assert archive.stat().st_mode & 0o777 == 0o600
    assert disk.tars == [[str(disk.host.binary), "/etc/traefik", "/etc/systemd/system/traefik.service"]]
    assert not (disk.transaction / "prechange.tar.gz").exists()
    record = json.loads((disk.transaction / "backup.json").read_text())
    assert record == {"paths": disk.tars[0], "sha256": sha256(b"archive"), "archive": str(archive)}
    for directory in (disk.mount / "traefik", disk.root):
        assert directory.stat().st_mode & 0o777 == 0o700


def test_without_the_setting_the_archive_is_the_reference_engines(tmp_path: Path) -> None:
    disk = Disk(tmp_path)
    disk.backup(external=False)

    assert (disk.transaction / "prechange.tar.gz").read_bytes() == b"local archive"
    assert set(json.loads((disk.transaction / "backup.json").read_text())) == {"paths", "sha256"}
    assert not (disk.mount / "traefik").exists()


def unmounted(disk: Disk) -> None:
    disk.mounted = False


def missing_mount(disk: Disk) -> None:
    disk.mount.rmdir()


def symlinked_mount(disk: Disk) -> None:
    disk.mount.rename(disk.mount.with_name("real-disk"))
    disk.mount.symlink_to(disk.mount.with_name("real-disk"))


def shared_mount(disk: Disk) -> None:
    disk.mount.chmod(0o777)


def foreign_mount(disk: Disk) -> None:
    disk.owner = os.getuid() + 1


def symlinked_directory(disk: Disk) -> None:
    (disk.mount / "elsewhere").mkdir(mode=0o700)
    (disk.mount / "traefik").symlink_to(disk.mount / "elsewhere")


def shared_directory(disk: Disk) -> None:
    (disk.mount / "traefik").mkdir()
    (disk.mount / "traefik").chmod(0o777)


def file_in_the_way(disk: Disk) -> None:
    (disk.mount / "traefik").write_text("")


def readable_root(disk: Disk) -> None:
    disk.root.mkdir(parents=True, mode=0o700)
    disk.root.chmod(0o750)


def existing_archive(disk: Disk) -> None:
    disk.root.mkdir(parents=True, mode=0o700)
    (disk.root / f"{IDS[0]}.tar.gz").write_bytes(b"older")


def failing_tar(disk: Disk) -> None:
    disk.tar_fails = True


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (unmounted, "rollback archive mount is not mounted"),
        (missing_mount, "rollback archive mount is not mounted"),
        (symlinked_mount, "rollback archive mount is not mounted"),
        (shared_mount, "unsafe rollback archive mount: .*/disk"),
        (foreign_mount, "unsafe rollback archive mount: .*/disk"),
        (symlinked_directory, "unsafe rollback archive directory: .*/disk/traefik"),
        (shared_directory, "unsafe rollback archive directory: .*/disk/traefik"),
        (file_in_the_way, "unsafe rollback archive directory: .*/disk/traefik"),
        (readable_root, "rollback archive directory is not private: .*/disk/traefik/rollback"),
        (existing_archive, "rollback archive exists already"),
        (failing_tar, r"command failed: tar \(exit 2\)"),
    ],
)
def test_the_archive_never_lands_anywhere_else(change: Callable[[Disk], Any], message: str, tmp_path: Path) -> None:
    disk = Disk(tmp_path)
    change(disk)
    before = snapshot(tmp_path)

    with pytest.raises(engine.Refused, match=f"^{message}$"):
        disk.backup()

    assert not (disk.transaction / "backup.json").exists()
    if change is failing_tar:
        assert not (disk.root / f"{IDS[0]}.tar.gz").exists()  # the partial archive is removed
    else:
        assert disk.tars == []
    if "mount" in message:
        assert snapshot(tmp_path) == before  # nothing created below the mount point
    if change is existing_archive:
        assert (disk.root / f"{IDS[0]}.tar.gz").read_bytes() == b"older"


def unmount_during_tar(disk: Disk) -> Path:
    """The disk goes away after the checks and a directory of the same names appears on "/"."""

    moved = disk.mount.with_name("detached-disk")

    def swap() -> None:
        disk.mount.rename(moved)
        disk.root.mkdir(parents=True, mode=0o700)

    disk.during_tar = swap
    return moved / "traefik" / "rollback"


def symlink_during_tar(disk: Disk) -> Path:
    """A directory below the mount is replaced by a symlink after the checks."""

    moved = disk.mount / "traefik-moved"

    def swap() -> None:
        (disk.mount / "traefik").rename(moved)
        (disk.mount / "elsewhere" / "rollback").mkdir(parents=True)
        (disk.mount / "traefik").symlink_to(disk.mount / "elsewhere")

    disk.during_tar = swap
    return moved / "rollback"


@pytest.mark.parametrize("race", [unmount_during_tar, symlink_during_tar])
def test_the_checked_directory_is_the_one_written(race: Callable[[Disk], Path], tmp_path: Path) -> None:
    disk = Disk(tmp_path)
    written = race(disk)

    disk.backup()

    assert (written / f"{IDS[0]}.tar.gz").read_bytes() == b"archive"
    assert not (disk.root / f"{IDS[0]}.tar.gz").exists()


def external_archive(enable: bool) -> Callable[[Any], None]:
    def scenario(setup: Any) -> None:
        setup.request["policy"]["rollback_archive"] = {"root": "/mnt/disk/traefik", "mount": "/mnt/disk"}

    return scenario if enable else (lambda setup: None)


def test_an_unmounted_disk_refuses_the_transaction_before_anything_is_written(tmp_path: Path) -> None:
    with patch.object(engine, "archive_mounted", lambda mount: False):
        outcome = run_scenario(engine, tmp_path / "root", external_archive(True), "binary")

    assert outcome.error == ("Refused", "rollback archive mount is not mounted")
    assert outcome.calls == []  # not even the baseline probe
    assert [name for name in outcome.files if name.startswith("state/") and name.count("/") == 1] == [
        "state/state.json"
    ]


def test_a_mounted_disk_lets_the_transaction_run(tmp_path: Path) -> None:
    with patch.object(engine, "archive_mounted", lambda mount: True):
        outcome = run_scenario(engine, tmp_path / "root", external_archive(True), "binary")

    assert outcome.error is None
    assert outcome.saved["phase"] == "clear"
    assert "backup" in outcome.calls


# -- rebaseline reads the external archive -------------------------------------------------------


def moved_archive(tmp_path: Path, name: Callable[[str], str] | None = None) -> dict[str, Any]:
    """Enroll, update with a real archive, move it to the "disk" as ``backup.json`` names it, add a route."""

    host = ArchivingHost(engine, tmp_path / "host")
    host.install()
    step = history(host)
    from tests.traefik_tx_fixtures import reference

    step(reference, "enroll")
    directory = Path(step(engine, "binary")["state"]["transaction"])
    target = tmp_path / "disk" / ((name or (lambda tx: f"{tx}.tar.gz"))(directory.name))
    target.parent.mkdir()
    shutil.move(directory / "prechange.tar.gz", target)
    record = json.loads((directory / "backup.json").read_text())
    engine.save(directory / "backup.json", {**record, "archive": str(target)})
    with tarfile.open(target) as bundle:
        assert any(member.name.endswith("dynamic/app.yml") for member in bundle)
    add_route()(host)
    result: dict[str, Any] = step(engine, "rebaseline")["state"]
    return result


def test_rebaseline_names_the_changed_files_from_the_external_archive(tmp_path: Path) -> None:
    record = moved_archive(tmp_path)

    assert record["rebaseline"]["changed_files_basis"] == "prechange_archive"
    assert record["rebaseline"]["changed_files"] == {"added": ["new.yml"], "modified": [], "removed": []}


def test_an_external_archive_of_another_transaction_is_not_used(tmp_path: Path) -> None:
    record = moved_archive(tmp_path, lambda tx: f"{IDS[0]}.tar.gz")

    assert record["rebaseline"]["changed_files_basis"] == "unavailable"
    assert record["rebaseline"]["changed_files"] is None


@pytest.mark.skipif(sys.platform != "linux", reason="GNU tar with --acls/--xattrs, as on the hosts")
def test_tar_to_writes_a_gzip_tar_to_the_stream(tmp_path: Path) -> None:
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "traefik.toml").write_text("[entryPoints]\n")
    with (tmp_path / "out.tar.gz").open("w+b") as stream:
        engine.tar_to(stream, [str(tmp_path / "etc")])

    with tarfile.open(tmp_path / "out.tar.gz", "r:gz") as bundle:
        assert any(name.endswith("etc/traefik.toml") for name in bundle.getnames())
    with pytest.raises(engine.Refused, match=r"^command failed: tar \(exit 2\)$"), (tmp_path / "x").open("w+b") as out:
        engine.tar_to(out, [str(tmp_path / "missing")])
