"""The mount guard and local snapshots, run for real with a stub ``findmnt``.

The stub knows the mounts listed in ``FAKE_MOUNTS`` (``target|fstype|source|options``
per line); ``--target`` resolves symlinks and answers the longest mounted
prefix, or ``/``, as findmnt does.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from ops_deploy.backups import (
    MountMissingError,
    SnapshotError,
    SnapshotPolicy,
    SubprocessRunner,
    local_snapshot,
    local_snapshot_command,
    require_mount,
    require_mount_command,
)
from ops_deploy.backups.local_snapshot import SNAPSHOT_SCRIPT
from ops_deploy.backups.mounts import MOUNT_GUARD_SCRIPT
from ops_deploy.testing import fish_unsafe

FINDMNT = """#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
mounts = {}
for line in os.environ.get("FAKE_MOUNTS", "").splitlines():
    if line:
        target, fstype, source, options = line.split("|")
        mounts[target] = (target, fstype, source, options)
columns = args[args.index("--output") + 1].split(",")
if "--mountpoint" in args:
    entry = mounts.get(args[args.index("--mountpoint") + 1])
    if entry is None:
        sys.exit(1)
else:
    path = os.path.realpath(args[args.index("--target") + 1])
    best = max((t for t in mounts if path == t or path.startswith(t + "/")), key=len, default=None)
    entry = mounts[best] if best else ("/", "ext4", "/dev/root", "rw")
names = ["TARGET", "FSTYPE", "SOURCE", "OPTIONS"]
print(" ".join(entry[names.index(c)] for c in columns))
"""


class Host:
    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path.resolve()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        findmnt = bin_dir / "findmnt"
        findmnt.write_text(FINDMNT)
        findmnt.chmod(0o755)
        self.disk = self.root / "mnt" / "disk"
        self.disk.mkdir(parents=True)
        self.mounts = [f"{self.disk}|ext4|/dev/mapper/disk|rw,relatime"]
        self.path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"

    def env(self) -> dict[str, str]:
        return {**os.environ, "PATH": self.path, "FAKE_MOUNTS": "\n".join(self.mounts)}

    def runner(self) -> SubprocessRunner:
        return SubprocessRunner(env=self.env())

    def policy(self, **overrides: object) -> SnapshotPolicy:
        values: dict[str, object] = {"mountpoint": str(self.disk), "base_dir": f"{self.disk}/rollback", "keep": 3}
        values.update(overrides)
        return SnapshotPolicy(**values)  # type: ignore[arg-type]

    def source(self) -> str:
        src = self.root / "app" / "runtime"
        src.mkdir(parents=True, exist_ok=True)
        (src / "bin.txt").write_text("v1")
        return str(src)


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


# --- mount guard ----------------------------------------------------------------


def test_mounted_path_passes(host: Host) -> None:
    require_mount(host.runner(), str(host.disk))
    require_mount(host.runner(), str(host.disk), fstype="ext4", source="/dev/mapper/disk")


def test_missing_mount_fails(host: Host) -> None:
    host.mounts = []
    with pytest.raises(MountMissingError, match="is not mounted"):
        require_mount(host.runner(), str(host.disk))


def test_wrong_filesystem_fails(host: Host) -> None:
    with pytest.raises(MountMissingError, match="is ext4, expected btrfs"):
        require_mount(host.runner(), str(host.disk), fstype="btrfs")
    with pytest.raises(MountMissingError, match="mounted from /dev/mapper/disk"):
        require_mount(host.runner(), str(host.disk), source="/dev/sdz1")


def test_read_only_mount_fails_unless_allowed(host: Host) -> None:
    host.mounts = [f"{host.disk}|ext4|/dev/mapper/disk|ro,relatime"]
    with pytest.raises(MountMissingError, match="not mounted read-write"):
        require_mount(host.runner(), str(host.disk))
    require_mount(host.runner(), str(host.disk), writable=False)


def test_missing_findmnt_fails(host: Host) -> None:
    only_bash = host.root / "only-bash"
    only_bash.mkdir()
    (only_bash / "bash").symlink_to(shutil.which("bash") or "/bin/bash")
    runner = SubprocessRunner(env={**host.env(), "PATH": str(only_bash)})
    with pytest.raises(MountMissingError, match="findmnt not found"):
        require_mount(runner, str(host.disk))


@pytest.mark.parametrize("path", ["/", "relative", "/mnt/../etc", "/mnt/disk/", "/mnt/a b"])
def test_root_and_odd_paths_are_refused(host: Host, path: str) -> None:
    with pytest.raises(ValueError, match="mount point"):
        require_mount(host.runner(), path)


def test_pyinfra_command_form(host: Host) -> None:
    command = require_mount_command(str(host.disk))
    assert not fish_unsafe(command)
    assert subprocess.run(["sh", "-c", command], env=host.env(), check=False).returncode == 0
    host.mounts = []
    failed = subprocess.run(["sh", "-c", command], env=host.env(), capture_output=True, text=True, check=False)
    assert failed.returncode == 1
    assert "is not mounted" in failed.stderr


def test_scripts_carry_no_quotes_or_backslashes() -> None:
    for script in (MOUNT_GUARD_SCRIPT, SNAPSHOT_SCRIPT):
        assert "\\" not in script
        assert "'" not in script


# --- local snapshots --------------------------------------------------------------


def test_snapshot_writes_an_archive_on_the_disk(host: Host) -> None:
    source = host.source()
    result = local_snapshot(host.runner(), host.policy(), "homeassistant", "runtime", [source])
    archive = Path(result.path)
    assert archive.parent == host.disk / "rollback" / "homeassistant"
    assert archive.name.startswith("runtime-")
    assert archive.name.endswith("Z.tar.gz")
    assert result.size_bytes == archive.stat().st_size > 0
    assert result.pruned == ()
    assert oct(archive.parent.stat().st_mode & 0o777) == "0o700"
    assert oct(archive.stat().st_mode & 0o777) == "0o600"
    with tarfile.open(archive) as tar:
        assert f"{source.lstrip('/')}/bin.txt" in tar.getnames()
    assert not list(archive.parent.glob("*.partial"))


def test_snapshot_refuses_a_missing_mount_and_writes_nothing(host: Host) -> None:
    host.mounts = []
    with pytest.raises(MountMissingError, match="is not mounted"):
        local_snapshot(host.runner(), host.policy(), "homeassistant", "runtime", [host.source()])
    assert list(host.disk.iterdir()) == []


def test_snapshot_refuses_a_directory_that_leaves_the_disk(host: Host) -> None:
    outside = host.root / "rootfs-dir"
    outside.mkdir()
    (host.disk / "rollback").mkdir()
    (host.disk / "rollback" / "homeassistant").symlink_to(outside)
    with pytest.raises(SnapshotError, match="homeassistant is a symlink"):
        local_snapshot(host.runner(), host.policy(), "homeassistant", "runtime", [host.source()])
    assert list(outside.iterdir()) == []


def test_snapshot_refuses_a_symlink_to_a_sibling_on_the_same_disk(host: Host) -> None:
    sibling = host.disk / "other-data"
    sibling.mkdir()
    (host.disk / "rollback").mkdir()
    (host.disk / "rollback" / "ha").symlink_to(sibling)
    with pytest.raises(SnapshotError, match="ha is a symlink"):
        local_snapshot(host.runner(), host.policy(), "ha", "runtime", [host.source()])
    assert list(sibling.iterdir()) == []


def test_snapshot_creates_nothing_through_a_symlinked_base(host: Host) -> None:
    outside = host.root / "rootfs-dir"
    outside.mkdir()
    (host.disk / "rollback").symlink_to(outside)
    with pytest.raises(SnapshotError, match="rollback is a symlink"):
        local_snapshot(host.runner(), host.policy(), "ha", "runtime", [host.source()])
    assert list(outside.iterdir()) == []


def _fixed_date(host: Host) -> str:
    """Pin ``date`` so the archive name is known in advance."""

    stub = host.root / "bin" / "date"
    stub.write_text("#!/usr/bin/env bash\necho 20261022T120000Z\n")
    stub.chmod(0o755)
    return "20261022T120000Z"


def test_snapshot_refuses_a_dangling_symlink_at_the_archive_name(host: Host) -> None:
    stamp = _fixed_date(host)
    folder = host.disk / "rollback" / "ha"
    folder.mkdir(parents=True)
    target = host.root / "rootfs-file"
    (folder / f"runtime-{stamp}.tar.gz").symlink_to(target)
    with pytest.raises(SnapshotError, match="already exists"):
        local_snapshot(host.runner(), host.policy(), "ha", "runtime", [host.source()])
    assert not target.exists()
    assert [p.name for p in folder.iterdir()] == [f"runtime-{stamp}.tar.gz"]


def test_timed_out_snapshot_is_stopped_and_cleaned_up(host: Host) -> None:
    started = host.root / "tar-started"
    stub = host.root / "bin" / "tar"
    stub.write_text(f"#!/usr/bin/env bash\necho $$ >{started}\nprintf partial\nexec sleep 60\n")
    stub.chmod(0o755)
    with pytest.raises(SnapshotError, match="no result within 1s; stopped"):
        local_snapshot(host.runner(), host.policy(), "ha", "runtime", [host.source()], timeout=1)
    assert list((host.disk / "rollback" / "ha").iterdir()) == []
    pid = int(started.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_failing_retention_fails_the_run_but_keeps_the_archive(host: Host) -> None:
    stub = host.root / "bin" / "find"
    stub.write_text("#!/usr/bin/env bash\necho find: broken >&2\nexit 1\n")
    stub.chmod(0o755)
    with pytest.raises(SnapshotError, match="retention failed"):
        local_snapshot(host.runner(), host.policy(), "ha", "runtime", [host.source()])
    archives = list((host.disk / "rollback" / "ha").iterdir())
    assert len(archives) == 1
    assert archives[0].name.endswith(".tar.gz")


def test_snapshot_retention_by_count_and_age(host: Host) -> None:
    folder = host.disk / "rollback" / "ha"
    folder.mkdir(parents=True)
    names = [f"runtime-2026100{day}T000000Z.tar.gz" for day in range(1, 6)]
    for name in names:
        (folder / name).write_text("old")
    keep = ["other-20261001T000000Z.tar.gz", "runtime-notes.txt", "runtime-x-20261001T000000Z.tar.gz"]
    for name in keep:
        (folder / name).write_text("not ours")
    # Within the newest three by name, but older than max_age_days.
    subprocess.run(["touch", "-t", "202001010000", str(folder / names[4])], check=True)
    (folder / "runtime-20261005T000000Z.tar.gz.partial.AbC123").write_text("killed run")
    subprocess.run(
        ["touch", "-t", "202001010000", str(folder / "runtime-20261005T000000Z.tar.gz.partial.AbC123")], check=True
    )

    result = local_snapshot(host.runner(), host.policy(keep=3, max_age_days=14), "ha", "runtime", [host.source()])

    remaining = sorted(p.name for p in folder.iterdir())
    newest = Path(result.path).name
    # The new one and the two newest by name; runtime-20261005 is too old.
    assert remaining == sorted([newest, names[3], *keep])
    assert sorted(Path(p).name for p in result.pruned) == sorted(
        [*names[:3], names[4], "runtime-20261005T000000Z.tar.gz.partial.AbC123"]
    )


def test_retention_never_reads_names_with_a_newline(host: Host, tmp_path: Path) -> None:
    folder = host.disk / "rollback" / "ha"
    folder.mkdir(parents=True)
    odd = folder / "runtime-20200101T000000Z.tar.gz.partial.\nx\nxyz"
    odd.write_text("odd")
    subprocess.run(["touch", "-t", "202001010000", str(odd)], check=True)
    bystander = tmp_path / "x"
    bystander.write_text("keep me")
    runner = SubprocessRunner(env=host.env())
    cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        result = local_snapshot(runner, host.policy(), "ha", "runtime", [host.source()])
    finally:
        os.chdir(cwd)
    assert bystander.exists()
    assert odd.exists()
    assert result.pruned == ()


def test_snapshot_never_prunes_the_new_archive(host: Host) -> None:
    result = local_snapshot(host.runner(), host.policy(keep=1, max_age_days=1), "ha", "runtime", [host.source()])
    assert Path(result.path).exists()
    assert result.pruned == ()


def test_failed_snapshot_leaves_no_partial_file(host: Host) -> None:
    with pytest.raises(SnapshotError, match="does not exist"):
        local_snapshot(host.runner(), host.policy(), "ha", "runtime", [str(host.root / "missing")])
    folder = host.disk / "rollback" / "ha"
    assert list(folder.iterdir()) == []


def test_failed_tar_removes_its_partial_file(host: Host, tmp_path: Path) -> None:
    source = host.source()
    unreadable = Path(source) / "secret"
    unreadable.mkdir()
    unreadable.chmod(0)
    try:
        if os.access(unreadable, os.R_OK):
            pytest.skip("running as root: permissions do not stop tar")
        with pytest.raises(SnapshotError):
            local_snapshot(host.runner(), host.policy(), "ha", "runtime", [source])
    finally:
        unreadable.chmod(0o700)
    assert list((host.disk / "rollback" / "ha").iterdir()) == []


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"base_dir": "/srv/rollback"}, "not on the mount point"),
        ({"mountpoint": "/"}, "mount point"),
        ({"base_dir": "/mnt/disk/./rollback"}, "plain form"),
        ({"base_dir": "/mnt/disk//rollback"}, "plain form"),
        ({"keep": 0}, "at least 1"),
        ({"max_age_days": 0}, "at least 1"),
    ],
)
def test_policy_validation(host: Host, overrides: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        host.policy(**overrides)


@pytest.mark.parametrize(
    ("name", "prefix", "sources", "message"),
    [
        ("../x", "runtime", ["/srv/a"], "name"),
        ("ha", "run*", ["/srv/a"], "prefix"),
        ("ha", "runtime", [], "at least one"),
        ("ha", "runtime", ["/"], "source"),
        ("ha", "runtime", ["srv/a"], "source"),
    ],
)
def test_snapshot_argument_validation(host: Host, name: str, prefix: str, sources: list[str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        local_snapshot(host.runner(), host.policy(), name, prefix, sources)


def test_snapshot_pyinfra_command_form(host: Host) -> None:
    command = local_snapshot_command(host.policy(), "ha", "runtime", [host.source()])
    assert not fish_unsafe(command)
    done = subprocess.run(["sh", "-c", command], env=host.env(), capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.startswith("SNAPSHOT ")
    assert shlex.split(command)[:2] == ["bash", "-c"]
