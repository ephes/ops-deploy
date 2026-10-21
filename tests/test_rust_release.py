"""ops_deploy.helpers.rust_release: the pyinfra side of ops-library's rust_release_binary (F4).

Three layers:

- the host script (``templates/rust_release_host.py.txt`` after the vendored
  decisions) run locally against a temporary install root with fake release
  archives, as root would run it on a host (owner/group are the test user,
  ``--version`` runs without ``runuser``);
- the operations the helpers plan, against the fake connector;
- with ``OPS_LIBRARY_PATH`` (an ops-library checkout) and ``ansible-playbook``,
  the role ``rust_release_binary`` itself on a twin tree with the same steps:
  the trees must end up byte-identical (version directories, ``.archive-sha256``,
  current and ``.previous`` pins, modes) and prune must keep and remove the same
  versions, including ``protect`` entries and the fail-closed cases.
"""

from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pwd
import shlex
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import Config, Inventory, State, deploy
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.operations import run_ops

from ops_deploy.helpers.probes import FAILED
from ops_deploy.helpers.rust_release import HOST_SCRIPT, Install, install_release, pin_release, prune_releases
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

NAME = "demo-tool"
OWNER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
VENDORED = Path(__file__).parents[1] / "src/ops_deploy/helpers/templates/rust_release.py.txt"


def build_archive(
    path: Path,
    version: str,
    *,
    says: str | None = None,
    names: list[str] | None = None,
    symlink: str | None = None,
    directory: str | None = None,
    salt: str = "",
) -> str:
    """A fake release archive (a shell script that prints its version, and LICENSE); returns its sha256."""

    script = f"#!/bin/sh\n# {salt}\necho '{NAME} {says or version} (0123456789abcdef)'\n".encode()
    contents = {NAME: (script, 0o755), "LICENSE": (b"MIT License\n", 0o644)}
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name in names if names is not None else [NAME, "LICENSE"]:
            data, mode = contents.get(name.removeprefix("./"), (b"extra\n", 0o644))
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 1_700_000_000
            tar.addfile(info, io.BytesIO(data))
        if symlink:
            info = tarfile.TarInfo(symlink)
            info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tar.addfile(info)
        if directory:
            info = tarfile.TarInfo(directory)
            info.type, info.mode = tarfile.DIRTYPE, 0o755
            tar.addfile(info)
    path.write_bytes(buffer.getvalue())
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def host(action: str, root: Path, *options: str) -> subprocess.CompletedProcess[str]:
    """The host script as the helper runs it (``python3 -I -``, the script on stdin)."""

    argv = [sys.executable, "-I", "-", action, "--name", NAME, "--root", str(root), "--owner", OWNER, "--group", GROUP]
    return subprocess.run([*argv, *options], input=HOST_SCRIPT, capture_output=True, text=True, timeout=60, check=False)


def ok(action: str, root: Path, *options: str) -> str:
    result = host(action, root, *options)
    assert result.returncode == 0, result.stderr
    return result.stdout


class Host:
    """A temporary install root driven through the host script."""

    def __init__(self, base: Path) -> None:
        self.base = base
        self.root = base / "opt" / NAME
        self.archives: dict[str, tuple[Path, str]] = {}

    def archive(self, version: str, key: str | None = None, **kwargs: Any) -> tuple[Path, str]:
        key = key or version
        if key not in self.archives:
            path = self.base / f"{key}.tar.gz"
            self.archives[key] = (path, build_archive(path, version, **kwargs))
        return self.archives[key]

    def install(self, version: str, key: str | None = None, *extra: str) -> subprocess.CompletedProcess[str]:
        path, sha = self.archive(version, key)
        url = path.as_uri()
        return host(
            "install", self.root, "--version", version, "--sha256", sha, "--url", url, "--validate-user", "", *extra
        )

    def pin(self, consumer: str, version: str | None, *extra: str) -> str:
        what = ["--absent"] if version is None else ["--version", version]
        return ok("pin", self.root, "--consumer", consumer, *what, *extra)

    def prune(self, *extra: str) -> str:
        return ok("prune", self.root, *extra)

    def versions(self) -> list[str]:
        if not self.root.exists():
            return []
        return sorted(p.name for p in self.root.iterdir() if p.is_dir() and not p.is_symlink() and p.name[0] != ".")

    def pins(self) -> dict[str, str]:
        pins = self.root / ".pins"
        return {p.name: p.read_text() for p in sorted(pins.iterdir())} if pins.exists() else {}

    def age(self, *versions: str) -> None:
        """Give the version directories increasing mtimes in this order."""

        for index, version in enumerate(versions):
            stamp = 1_600_000_000 + index * 1000
            os.utime(self.root / version, (stamp, stamp))

    def hidden(self) -> list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.name.startswith(".") and p.name != ".pins")


@pytest.fixture
def box(tmp_path: Path) -> Host:
    return Host(tmp_path)


def test_host_script_starts_with_the_vendored_decisions() -> None:
    # tests/test_ops_library_drift.py compares the vendored copy with ops-library's.
    assert HOST_SCRIPT.startswith(VENDORED.read_text())
    assert "def rust_release_prune_plan(" in HOST_SCRIPT
    assert "\nimport ansible" not in HOST_SCRIPT


# -- install --------------------------------------------------------------------------


def test_install_layout_and_idempotent_validation(box: Host) -> None:
    _, sha = box.archive("1.0.0")
    first = box.install("1.0.0")
    assert first.returncode == 0, first.stderr
    version_dir = box.root / "1.0.0"
    assert first.stdout == f"installed {version_dir / NAME}\n"
    assert sorted(p.name for p in version_dir.iterdir()) == [".archive-sha256", "LICENSE", NAME]
    assert (version_dir / NAME).stat().st_mode & 0o7777 == 0o755
    assert (version_dir / "LICENSE").stat().st_mode & 0o7777 == 0o644
    assert (version_dir / ".archive-sha256").read_bytes() == f"{sha}\n".encode()
    assert (version_dir / ".archive-sha256").stat().st_mode & 0o7777 == 0o644
    assert version_dir.stat().st_mode & 0o7777 == 0o755
    assert box.root.stat().st_mode & 0o7777 == 0o755
    assert box.hidden() == []

    before = (version_dir / NAME).stat().st_mtime_ns
    again = box.install("1.0.0")
    assert again.returncode == 0, again.stderr
    assert again.stdout == f"validated {version_dir / NAME}\n"
    assert (version_dir / NAME).stat().st_mtime_ns == before


def test_extra_members_and_executables(box: Host) -> None:
    path = box.base / "multi.tar.gz"
    sha = build_archive(path, "1.0.0", names=[NAME, "LICENSE", "helper", "LICENSE-helper"])
    out = ok(
        "install",
        box.root,
        *("--version", "1.0.0", "--sha256", sha, "--url", path.as_uri(), "--validate-user", ""),
        *("--members", f"{NAME},helper,LICENSE,LICENSE-helper", "--executables", f"{NAME},helper"),
    )
    assert out.startswith("installed ")
    modes = {p.name: p.stat().st_mode & 0o777 for p in (box.root / "1.0.0").iterdir()}
    assert modes == {NAME: 0o755, "helper": 0o755, "LICENSE": 0o644, "LICENSE-helper": 0o644, ".archive-sha256": 0o644}


def test_a_different_archive_for_an_installed_version_is_refused(box: Host) -> None:
    assert box.install("1.0.0").returncode == 0
    box.archive("1.0.0", "other", salt="rebuilt")
    refused = box.install("1.0.0", "other")
    assert refused.returncode == 1
    assert "never replaced in place" in refused.stderr
    assert box.versions() == ["1.0.0"]
    assert (box.root / "1.0.0" / ".archive-sha256").read_text() == box.archives["1.0.0"][1] + "\n"


@pytest.mark.parametrize(
    "archive",
    [
        {"names": [NAME, "LICENSE", "extra"]},
        {"names": [NAME]},
        {"names": [NAME, "LICENSE", NAME]},
        {"names": [NAME, "sub/LICENSE"]},
        {"names": [NAME, "../LICENSE"]},
        {"symlink": "LICENSE", "names": [NAME]},
        {"directory": "share"},
        {"directory": "./"},
    ],
    ids=["extra", "missing", "duplicate", "nested", "dotdot", "symlink", "directory", "dot-directory"],
)
def test_archive_member_refusals_leave_nothing_behind(box: Host, archive: dict[str, Any]) -> None:
    box.archive("1.0.0", **archive)
    refused = box.install("1.0.0")
    assert refused.returncode == 1
    assert "must hold exactly the regular files" in refused.stderr
    assert box.versions() == []
    assert box.hidden() == []


def test_dot_slash_members_are_accepted(box: Host) -> None:
    box.archive("1.0.0", names=[f"./{NAME}", "./LICENSE"])
    assert box.install("1.0.0").returncode == 0
    assert sorted(p.name for p in (box.root / "1.0.0").iterdir()) == [".archive-sha256", "LICENSE", NAME]


def test_checksum_and_version_failures_remove_the_fresh_install(box: Host) -> None:
    assert box.install("1.0.0").returncode == 0
    path, _ = box.archive("2.0.0")
    wrong = host(
        "install", box.root, "--version", "2.0.0", "--sha256", "0" * 64, "--url", path.as_uri(), "--validate-user", ""
    )
    assert wrong.returncode == 1
    assert "has sha256" in wrong.stderr

    box.archive("3.0.0", says="9.9.9")
    lying = box.install("3.0.0")
    assert lying.returncode == 1
    assert "expected 'demo-tool 3.0.0 (<commit>)'" in lying.stderr
    assert box.versions() == ["1.0.0"]
    assert box.hidden() == []


def test_soft_failure_warns_and_exits_zero(box: Host) -> None:
    box.archive("1.0.0", says="0.0.1")
    soft = box.install("1.0.0", None, "--soft")
    assert soft.returncode == 0
    assert soft.stdout.startswith("failed ")
    assert "WARNING: demo-tool 1.0.0 failed installation or validation" in soft.stderr
    assert box.versions() == []
    # Invalid inputs only warn, too (the consumer's Python rollback is never blocked).
    invalid = host("install", box.root, "--version", "1.0", "--sha256", "x", "--soft")
    assert invalid.returncode == 0
    assert invalid.stdout.startswith("failed version must be a release version")


def test_upload_is_consumed_and_removed_on_failure(box: Host) -> None:
    path, sha = box.archive("1.0.0")
    box.root.mkdir(parents=True)
    upload = box.root / ".upload-1.0.0.tar.gz"
    shutil.copy(path, upload)
    ok("install", box.root, "--version", "1.0.0", "--sha256", sha, "--upload", str(upload), "--validate-user", "")
    assert not upload.exists()
    assert box.versions() == ["1.0.0"]

    shutil.copy(path, upload)
    refused = host(
        "install", box.root, "--version", "2.0.0", "--sha256", sha, "--upload", str(upload), "--validate-user", ""
    )
    assert refused.returncode == 1
    assert not upload.exists()
    assert box.versions() == ["1.0.0"]


def test_local_archive_checksum_must_match_the_pinned_one(box: Host) -> None:
    path, sha = box.archive("1.0.0")
    refused = host(
        "install",
        box.root,
        *("--version", "1.0.0", "--sha256", "a" * 64, "--archive-sha256", sha, "--url", path.as_uri()),
    )
    assert refused.returncode == 1
    assert "not the pinned" in refused.stderr


def test_an_installed_version_that_is_not_a_directory_is_refused(box: Host) -> None:
    box.root.mkdir(parents=True)
    (box.base / "elsewhere").mkdir()
    (box.root / "1.0.0").symlink_to(box.base / "elsewhere")
    refused = box.install("1.0.0")
    assert refused.returncode == 1
    assert "not a directory (or is a symlink)" in refused.stderr
    assert (box.root / "1.0.0").is_symlink()


@pytest.mark.parametrize("kind", ["symlink", "file"])
def test_a_staging_leftover_that_is_not_a_directory_is_never_followed(box: Host, kind: str) -> None:
    outside = box.base / "outside"
    outside.mkdir()
    (outside / "archive.tar.gz").write_text("keep me")
    (outside / "tree").mkdir()
    box.root.mkdir(parents=True)
    staging = box.root / ".staging-1.0.0"
    if kind == "symlink":
        staging.symlink_to(outside)
    else:
        staging.write_text("junk")
    assert box.install("1.0.0").returncode == 0
    assert (outside / "archive.tar.gz").read_text() == "keep me"
    assert sorted(p.name for p in outside.iterdir()) == ["archive.tar.gz", "tree"]
    assert box.hidden() == []
    assert box.versions() == ["1.0.0"]


def test_an_upload_that_is_not_a_regular_file_is_refused(box: Host) -> None:
    _, sha = box.archive("1.0.0")
    box.root.mkdir(parents=True)
    upload = box.root / ".upload-1.0.0.tar.gz"
    upload.symlink_to(box.archives["1.0.0"][0])
    refused = host("install", box.root, "--version", "1.0.0", "--sha256", sha, "--upload", str(upload))
    assert refused.returncode == 1
    assert "not a regular file" in refused.stderr
    assert box.versions() == []
    assert box.archives["1.0.0"][0].exists()


def test_refuse_fails_inside_the_guarded_step(box: Host) -> None:
    hard = host("install", box.root, "--version", "1.0.0", "--sha256", "a" * 64, "--refuse", "cannot read x")
    assert hard.returncode == 1
    assert "failed installation or validation: cannot read x" in hard.stderr
    soft = host("install", box.root, "--version", "1.0.0", "--sha256", "a" * 64, "--refuse", "cannot read x", "--soft")
    assert soft.returncode == 0
    assert soft.stdout == "failed cannot read x\n"
    assert not box.root.exists()


def test_a_staging_leftover_is_removed(box: Host) -> None:
    (box.root / ".staging-1.0.0" / "tree").mkdir(parents=True)
    (box.root / ".staging-1.0.0" / "tree" / "junk").write_text("x")
    assert box.install("1.0.0").returncode == 0
    assert box.hidden() == []


# -- pin ------------------------------------------------------------------------------


def test_pin_moves_and_rollback_sequence(box: Host) -> None:
    for version in ("1.0.0", "2.0.0", "3.0.0"):
        assert box.install(version).returncode == 0
    assert box.pin("svc", "1.0.0") == "current 1.0.0\nprevious -\n"
    assert box.pins() == {"svc": "1.0.0\n"}
    box.pin("svc", "2.0.0")
    assert box.pins() == {"svc": "2.0.0\n", "svc.previous": "1.0.0\n"}
    box.pin("svc", "1.0.0")  # roll back
    assert box.pins() == {"svc": "1.0.0\n", "svc.previous": "2.0.0\n"}
    box.pin("svc", "3.0.0")
    assert box.pins() == {"svc": "3.0.0\n", "svc.previous": "1.0.0\n"}
    assert ok("pin", box.root, "--consumer", "svc", "--version", "3.0.0", "--check") == ""
    box.pin("svc", None)  # switch to Python: the last Rust version stays the rollback pin
    assert box.pins() == {"svc.previous": "3.0.0\n"}
    box.pin("svc", None, "--no-keep-previous")
    assert box.pins() == {}
    box.pin("svc", "2.0.0", "--previous", "1.0.0")
    assert box.pins() == {"svc": "2.0.0\n", "svc.previous": "1.0.0\n"}
    for pin in (box.root / ".pins").iterdir():
        assert pin.stat().st_mode & 0o7777 == 0o644
    assert (box.root / ".pins").stat().st_mode & 0o7777 == 0o755
    assert box.hidden() == []


def test_pin_check_reports_without_changing(box: Host) -> None:
    assert box.install("1.0.0").returncode == 0
    box.pin("svc", "1.0.0")
    out = ok("pin", box.root, "--consumer", "svc", "--version", "2.0.0", "--check")
    pins = box.root / ".pins"
    assert out == f"change {pins}/svc.previous\nchange {pins}/svc\n"
    assert box.pins() == {"svc": "1.0.0\n"}
    os.chmod(pins / "svc", 0o600)
    assert ok("pin", box.root, "--consumer", "svc", "--version", "1.0.0", "--check") == f"change {pins}/svc\n"
    box.pin("svc", "1.0.0")
    assert (pins / "svc").stat().st_mode & 0o777 == 0o644


@pytest.mark.parametrize("breakage", ["garbage", "two-lines", "directory", "symlink"])
def test_unreadable_pins_fail_and_change_nothing(box: Host, breakage: str) -> None:
    for version in ("1.0.0", "2.0.0"):
        assert box.install(version).returncode == 0
    box.pin("svc", "1.0.0")
    current = box.root / ".pins" / "svc"
    current.unlink()
    if breakage == "garbage":
        current.write_text("garbage\n")
    elif breakage == "two-lines":
        current.write_text("1.0.0\n2.0.0\n")
    elif breakage == "directory":
        current.mkdir()
    else:
        current.symlink_to(box.root / "1.0.0")
    before = sorted(p.name for p in (box.root / ".pins").iterdir())
    failed = host("pin", box.root, "--consumer", "svc", "--version", "2.0.0")
    assert failed.returncode == 1
    assert sorted(p.name for p in (box.root / ".pins").iterdir()) == before
    assert not (box.root / ".pins" / "svc.previous").exists()


def test_pin_refuses_a_version_that_is_not_installed(box: Host) -> None:
    failed = host("pin", box.root, "--consumer", "svc", "--version", "1.0.0")
    assert failed.returncode == 1
    assert "is not installed" in failed.stderr
    # In check mode (while planning) a version this run installs is not there yet.
    out = ok("pin", box.root, "--consumer", "svc", "--version", "1.0.0", "--check")
    assert out == f"change {box.root}/.pins/svc\n"
    for bad in (["--consumer", "a.previous", "--version", "1.0.0"], ["--consumer", "svc", "--version", "v1"]):
        assert host("pin", box.root, *bad).returncode == 1


# -- prune ----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """An install root with 1.0.0 to 6.0.0, installed once by the host script (copied per test)."""

    box = Host(tmp_path_factory.mktemp("installed"))
    for version in ("1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"):
        assert box.install(version).returncode == 0, version
    return box.root


def install_all(box: Host, installed: Path, *versions: str) -> None:
    shutil.copytree(installed, box.root, symlinks=True)
    for extra in sorted(set(box.versions()) - set(versions)):
        shutil.rmtree(box.root / extra)
    box.age(*versions)


def test_prune_keeps_newest_pins_previous_pins_and_protect(box: Host, installed: Path) -> None:
    install_all(box, installed, "1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0")
    box.pin("a", "1.0.0")
    box.pin("a", "2.0.0")  # 1.0.0 becomes a's previous pin
    box.pin("b", "3.0.0")
    assert ok("prune", box.root, "--keep-versions", "1", "--protect", "4.0.0", "--check") == "remove 5.0.0\n"
    assert box.versions() == ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0"]
    assert box.prune("--keep-versions", "1", "--protect", "4.0.0") == "remove 5.0.0\n"
    assert box.versions() == ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "6.0.0"]
    assert box.prune("--keep-versions", "1", "--protect", "4.0.0") == ""


def test_prune_protects_running_executables_under_a_symlinked_root(box: Host, installed: Path) -> None:
    real = box.base / "srv" / NAME
    install_all(box, installed, "1.0.0", "2.0.0", "3.0.0", "4.0.0")
    real.parent.mkdir(parents=True)
    box.root.rename(real)
    box.root.symlink_to(real)
    protect = [
        "--protect", f"{real}/1.0.0/{NAME} (deleted)",
        "--protect", f"{box.root}/2.0.0/{NAME}",
        "--protect", "/usr/bin/python3.12",
    ]  # fmt: skip
    assert box.prune("--keep-versions", "1", *protect) == "remove 3.0.0\n"
    assert box.versions() == ["1.0.0", "2.0.0", "4.0.0"]


@pytest.mark.parametrize(
    "case",
    [
        "live-state-unknown",
        "garbage-pin",
        "empty-pin",
        "pin-directory",
        "pins-not-a-directory",
        "protect-staging-path",
        "protect-nested-path",
        "protect-binary-elsewhere",
        "protect-relative",
        "protect-not-normalised",
    ],
)
def test_prune_fails_closed(box: Host, installed: Path, case: str) -> None:
    install_all(box, installed, "1.0.0", "2.0.0", "3.0.0")
    pins = box.root / ".pins"
    extra: list[str] = []
    if case == "live-state-unknown":
        extra = ["--live-state-unknown"]
    elif case == "garbage-pin":
        pins.mkdir()
        (pins / "svc").write_text("garbage\n")
    elif case == "empty-pin":
        pins.mkdir()
        (pins / "svc").write_text("")
    elif case == "pin-directory":
        (pins / "sub").mkdir(parents=True)
    elif case == "pins-not-a-directory":
        pins.write_text("1.0.0\n")
    else:
        entry = {
            "protect-staging-path": f"{box.root}/.staging-1.0.0/tree/{NAME}",
            "protect-nested-path": f"{box.root}/1.0.0/sub/{NAME}",
            "protect-binary-elsewhere": f"/elsewhere/1.0.0/{NAME}",
            "protect-relative": f"1.0.0/{NAME}",
            "protect-not-normalised": f"{box.root}/../{NAME}/1.0.0/{NAME}",
        }[case]
        extra = ["--protect", entry]
    result = host("prune", box.root, "--keep-versions", "1", *extra)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("blocked ")
    assert "WARNING: not pruning" in result.stderr
    assert box.versions() == ["1.0.0", "2.0.0", "3.0.0"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_prune_fails_closed_on_an_unreadable_pin_directory(box: Host, installed: Path) -> None:
    install_all(box, installed, "1.0.0", "2.0.0")
    pins = box.root / ".pins"
    pins.mkdir()
    pins.chmod(0)
    try:
        out = box.prune("--keep-versions", "1")
    finally:
        pins.chmod(0o755)
    assert out.startswith("blocked ")
    assert box.versions() == ["1.0.0", "2.0.0"]


def test_prune_ignores_everything_that_is_not_a_version_directory(box: Host, installed: Path) -> None:
    install_all(box, installed, "1.0.0", "2.0.0")
    (box.root / "notes").mkdir()
    (box.root / "01.0.0").mkdir()
    (box.root / "9.0.0").symlink_to(box.root / "1.0.0")
    (box.root / ".hidden-9.9.9").mkdir()
    assert box.prune("--keep-versions", "1") == "remove 1.0.0\n"
    assert sorted(p.name for p in box.root.iterdir()) == [".hidden-9.9.9", "01.0.0", "2.0.0", "9.0.0", "notes"]


def test_prune_of_a_missing_root_does_nothing(box: Host) -> None:
    assert box.prune("--live-state-unknown") == ""
    assert not box.root.exists()


# -- the pyinfra operations -----------------------------------------------------------

ROOT = "/opt/metrics-httpd"
SHA = "b" * 64
PY = "/usr/bin/python3 -I -"


def run(body: Callable[[], Any], responses: dict[str, Any] | None = None) -> FakeRun:
    @deploy("Test")
    def _deploy() -> None:
        body()

    result = run_deploy_fake(_deploy, responses={**fakehost.LINUX, **(responses or {})})
    return result


def test_install_plans_one_install_with_the_script_on_stdin() -> None:
    result = run(lambda: install_release("metrics-httpd", "0.1.0", sha256=SHA, validate_user="metrics"))

    assert result.succeeded, result.error
    (command,) = result.executed_commands
    assert command == (
        f"{PY} install --name metrics-httpd --root {ROOT} --sha256 {SHA} --version 0.1.0 --validate-user metrics"
    )
    ((_, stdin),) = [s for s in result.stdin if s[0] == command]
    assert stdin == HOST_SCRIPT
    assert result.changed_ops == ["Test | Install metrics-httpd 0.1.0"]
    assert HOST_SCRIPT not in result.all_text()


def test_an_installed_version_is_validated_read_only() -> None:
    result = run(
        lambda: install_release("metrics-httpd", "0.1.0", sha256=SHA, fail_hard=False),
        fakehost.directory(f"{ROOT}/0.1.0"),
    )

    assert result.succeeded, result.error
    (command,) = result.executed_commands
    assert command.endswith(" --validate-user nobody --soft")
    assert result.ops[0].name == "Test | Validate metrics-httpd 0.1.0"
    assert result.ops[0].read_only
    assert result.mutating_changed_ops == []


def test_a_local_archive_is_uploaded_and_its_checksum_passed(tmp_path: Path) -> None:
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(b"archive")
    actual = hashlib.sha256(b"archive").hexdigest()
    result = run(
        lambda: install_release(
            "software-live",
            "1.2.3-rc.1",
            local_archive=archive,
            members=["software-live", "software-live-apt", "LICENSE"],
            executables=["software-live", "software-live-apt"],
            release_url="https://example.invalid/a.tar.gz",
        )
    )

    assert result.succeeded, result.error
    upload = "/opt/software-live/.upload-1.2.3-rc.1.tar.gz"
    assert result.upload(upload) == b"archive"
    command = result.executed_commands[-1]
    assert shlex.split(command)[3:] == [
        "install",
        *("--name", "software-live", "--root", "/opt/software-live", "--sha256", actual),
        *("--version", "1.2.3-rc.1", "--validate-user", "nobody"),
        *("--members", "software-live,software-live-apt,LICENSE", "--executables", "software-live,software-live-apt"),
        *("--url", "https://example.invalid/a.tar.gz", "--archive-sha256", actual, "--upload", upload),
    ]


def test_an_unreadable_local_archive(tmp_path: Path) -> None:
    missing = tmp_path / "missing.tar.gz"
    with pytest.raises(ValueError, match=r"cannot read the local archive of metrics-httpd 0\.1\.0"):
        run(lambda: install_release("metrics-httpd", "0.1.0", local_archive=missing))

    soft = run(lambda: install_release("metrics-httpd", "0.1.0", local_archive=missing, fail_hard=False))
    assert soft.succeeded, soft.error
    assert soft.uploaded_paths == []
    (command,) = soft.executed_commands
    argv = shlex.split(command)
    assert argv[argv.index("--refuse") + 1].startswith(f"cannot read the local archive {missing}: ")
    assert "--upload" not in argv
    assert "--soft" in argv


def test_a_later_pin_of_the_same_consumer_runs_after_an_earlier_one_changed() -> None:
    def body() -> None:
        pin_release("metrics-httpd", "svc", "1.0.0")
        pin_release("metrics-httpd", "svc", "2.0.0")
        pin_release("metrics-httpd", "other", "2.0.0")

    key = f"pin --name metrics-httpd --root {ROOT} --consumer"
    responses = {
        f"{key} svc --version 1.0.0 --check": [f"change {ROOT}/.pins/svc"],
        f"{key} svc --version 2.0.0 --check": [],
        f"{key} other --version 2.0.0 --check": [],
    }
    result = run(body, responses)
    assert result.succeeded, result.error
    assert [c.split()[-1] for c in result.executed_commands] == ["1.0.0", "2.0.0"]
    assert "other" not in " ".join(result.executed_commands)


def test_pin_gates_stay_per_host() -> None:
    """Two hosts plan the same pins; a gate never looks at the other host's operations."""

    @deploy("Pins")
    def pins() -> None:
        pin_release("metrics-httpd", "svc", "1.0.0")
        pin_release("metrics-httpd", "svc", "2.0.0")

    key = f"pin --name metrics-httpd --root {ROOT} --consumer svc --version"
    responses = {**fakehost.LINUX, f"{key} 1.0.0 --check": [], f"{key} 2.0.0 --check": []}
    data = {"fake_responses": responses, "fake_delay": 0, "fake_delay_jitter": 0}
    state = State(Inventory(([("@fake/one", dict(data)), ("@fake/two", dict(data))], {})), Config())
    connect_all(state)
    try:
        add_deploy(state, pins)
        run_ops(state)
    finally:
        disconnect_all(state)
    assert not state.failed_hosts
    for name in ("@fake/one", "@fake/two"):
        target = state.inventory.get_host(name)
        assert [state.get_op_meta(h).names for h in state.get_op_order() if h in state.ops[target]] == [
            {"Pins | Pin metrics-httpd for svc"}
        ] * 2


def test_pin_runs_only_when_its_probe_asks_for_a_change() -> None:
    probe_key = f"pin --name metrics-httpd --root {ROOT} --consumer svc --version 0.2.0 --check"
    converged = run(lambda: pin_release("metrics-httpd", "svc", "0.2.0"), {probe_key: []})
    assert converged.succeeded, converged.error
    assert converged.executed_commands == []
    assert converged.mutating_changed_ops == []

    change = run(lambda: pin_release("metrics-httpd", "svc", "0.2.0"), {probe_key: [f"change {ROOT}/.pins/svc"]})
    assert change.succeeded, change.error
    assert change.executed_commands == [f"{PY} pin --name metrics-httpd --root {ROOT} --consumer svc --version 0.2.0"]

    absent = run(lambda: pin_release("metrics-httpd", "svc", None, keep_previous=False))
    assert absent.succeeded, absent.error
    assert absent.fact_commands[-1].count("--absent --no-keep-previous --check") == 1


def test_a_failed_probe_runs_the_step_and_probes_again() -> None:
    probe_key = f"pin --name metrics-httpd --root {ROOT} --consumer svc --version 0.2.0 --check"
    result = run(lambda: pin_release("metrics-httpd", "svc", "0.2.0"), {probe_key: [FAILED]})
    assert result.succeeded, result.error
    pin, again = result.executed_commands
    assert pin == f"{PY} pin --name metrics-httpd --root {ROOT} --consumer svc --version 0.2.0"
    assert probe_key in again
    assert [op.name for op in result.ops] == [
        "Test | Pin metrics-httpd for svc",
        "Test | Probe again: Pin metrics-httpd for svc",
    ]


def test_prune_passes_protect_and_reruns_after_a_change() -> None:
    def body() -> None:
        installed = install_release("metrics-httpd", "0.2.0", sha256=SHA)
        prune_releases(
            "metrics-httpd",
            keep_versions=2,
            protect=[f"{ROOT}/0.1.0/metrics-httpd (deleted)", "0.0.9"],
            after=[installed],
        )

    result = run(body)
    assert result.succeeded, result.error
    prune = result.executed_commands[-1]
    assert shlex.split(prune)[3:] == [
        "prune",
        *("--name", "metrics-httpd", "--root", ROOT, "--keep-versions", "2"),
        *("--protect", f"{ROOT}/0.1.0/metrics-httpd (deleted)", "--protect", "0.0.9"),
    ]


def test_prune_is_skipped_after_a_failed_soft_install() -> None:
    def body() -> None:
        installed = install_release("metrics-httpd", "0.2.0", sha256=SHA, fail_hard=False)
        prune_releases("metrics-httpd", after=[installed])

    result = run(body, {"install --name metrics-httpd": {"stdout": ["failed bad archive"], "success": True}})
    assert result.succeeded, result.error
    assert [c.split()[3] for c in result.executed_commands] == ["install"]


def test_a_validated_install_gates_the_prune_but_is_no_change() -> None:
    def body() -> None:
        installed = install_release("metrics-httpd", "0.2.0", sha256=SHA, fail_hard=False)
        assert installed.validated
        prune_releases("metrics-httpd", after=[installed])

    prune_key = f"prune --name metrics-httpd --root {ROOT} --keep-versions 3 --check"
    converged = run(body, fakehost.directory(f"{ROOT}/0.2.0"))
    assert converged.succeeded, converged.error
    # Only the read-only validation runs: an installed version changes nothing to prune.
    assert [c.split()[3] for c in converged.executed_commands] == ["install"]
    assert converged.mutating_changed_ops == []

    pending = run(body, {**fakehost.directory(f"{ROOT}/0.2.0"), prune_key: [f"remove {ROOT}/0.0.1"]})
    assert [c.split()[3] for c in pending.executed_commands] == ["install", "prune"]

    failed = run(
        body,
        {
            **fakehost.directory(f"{ROOT}/0.2.0"),
            prune_key: [f"remove {ROOT}/0.0.1"],
            "install --name metrics-httpd": {"stdout": ["failed --version printed something else"]},
        },
    )
    assert failed.succeeded, failed.error
    assert [c.split()[3] for c in failed.executed_commands] == ["install"]


def test_a_fresh_install_is_not_validated() -> None:
    def body() -> None:
        assert not install_release("metrics-httpd", "0.2.0", sha256=SHA).validated

    assert run(body).succeeded


def test_prune_warns_while_planning_when_blocked(caplog: pytest.LogCaptureFixture) -> None:
    probe_key = f"prune --name metrics-httpd --root {ROOT} --keep-versions 3 --live-state-unknown --check"
    result = run(
        lambda: prune_releases("metrics-httpd", live_state_unknown=True),
        {probe_key: ["blocked the consumer marked its live state as unknown"]},
    )
    assert result.succeeded, result.error
    assert result.executed_commands == []
    assert "blocked the consumer marked its live state as unknown" in caplog.text


def test_install_failed_reads_the_operation_output() -> None:
    class Op:
        def __init__(self, ok: bool, lines: list[str]) -> None:
            self.ok, self.stdout_lines = ok, lines

        def did_succeed(self) -> bool:
            return self.ok

    assert not Install(Op(True, ["installed /opt/x/1.0.0/x"]), "").failed()  # type: ignore[arg-type]
    assert Install(Op(True, ["failed bad"]), "").failed()  # type: ignore[arg-type]
    assert Install(Op(False, []), "").failed()  # type: ignore[arg-type]


# -- the same files and decisions as ops-library's role ------------------------------

OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_role = pytest.mark.skipif(
    not OPS_LIBRARY or shutil.which("ansible-playbook") is None,
    reason="OPS_LIBRARY_PATH or ansible-playbook not set up",
)


def snapshot(root: Path) -> dict[str, Any]:
    """Every path below ``root`` with its type, mode and (for files) bytes."""

    tree: dict[str, Any] = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        kind = "link" if path.is_symlink() else "dir" if path.is_dir() else "file"
        tree[str(path.relative_to(root))] = (kind, info.st_mode & 0o7777, path.read_bytes() if kind == "file" else None)
    return tree


class Role:
    """``ansible-playbook`` runs of ops-library's rust_release_binary against localhost."""

    def __init__(self, base: Path, root: Path) -> None:
        assert OPS_LIBRARY is not None
        self.base, self.root, self.runs = base, root, 0
        collections = base / "collections/ansible_collections/local"
        collections.mkdir(parents=True)
        (collections / "ops_library").symlink_to(Path(OPS_LIBRARY).resolve())
        path = os.environ.get("PATH", "")
        probe = subprocess.run(["mv", "--version"], capture_output=True, text=True, check=False)
        if "GNU" not in probe.stdout:  # the role targets GNU coreutils (macOS: Homebrew's gmv)
            gmv = shutil.which("gmv")
            if gmv is None:
                pytest.skip("GNU mv (gmv) not found")
            (base / "gnu-bin").mkdir()
            (base / "gnu-bin" / "mv").symlink_to(gmv)
            path = f"{base / 'gnu-bin'}{os.pathsep}{path}"
        self.env = {
            **os.environ,
            "PATH": path,
            "ANSIBLE_COLLECTIONS_PATH": str(base / "collections"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_LOCALHOST_WARNING": "0",
            "ANSIBLE_INVENTORY_UNPARSED_WARNING": "0",
            "ANSIBLE_RETRY_FILES_ENABLED": "0",
            "ANSIBLE_LOCAL_TEMP": str(base / "ansible-local"),
            "ANSIBLE_REMOTE_TEMP": str(base / "ansible-remote"),
            "ANSIBLE_PYTHON_INTERPRETER": sys.executable,
        }

    def play(self, *tasks: dict[str, Any]) -> dict[str, Any]:
        self.runs += 1
        facts = self.base / f"facts-{self.runs}.json"
        dump = {
            "name": "dump",
            "ansible.builtin.copy": {
                "dest": str(facts),
                "content": "{{ rust_release_binary_prune | default(None) | to_json }}",
            },
        }
        play = {
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "rust_release_binary_name": NAME,
                "rust_release_binary_install_root": str(self.root),
                "rust_release_binary_owner": OWNER,
                "rust_release_binary_group": GROUP,
                "rust_release_binary_validate_user": "",
            },
            "tasks": [*tasks, dump],
        }
        path = self.base / f"play-{self.runs}.json"
        path.write_text(json.dumps([play]))  # JSON is YAML
        argv = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(path)]
        result = subprocess.run(argv, capture_output=True, text=True, env=self.env, timeout=600, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
        prune: dict[str, Any] = json.loads(facts.read_text()) or {}
        return prune

    @staticmethod
    def task(tasks_from: str, **params: Any) -> dict[str, Any]:
        return {
            "name": f"rust_release_binary {tasks_from}",
            "ansible.builtin.include_role": {"name": "local.ops_library.rust_release_binary", "tasks_from": tasks_from},
            "vars": {f"rust_release_binary_{k}": v for k, v in params.items()},
        }


@needs_role
def test_same_files_and_prune_decisions_as_the_role(tmp_path: Path) -> None:
    ours = Host(tmp_path / "pyinfra")
    ours.base.mkdir()
    theirs = tmp_path / "ansible" / "opt" / NAME
    role = Role(tmp_path, theirs)
    versions = ("1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0")
    archives = {v: ours.archive(v) for v in versions}

    # Install everything, then the pin moves: v1 -> v2 -> v1 (roll back) -> v3, a second consumer, a switch to Python.
    pins = [("a", "1.0.0"), ("a", "2.0.0"), ("a", "1.0.0"), ("a", "3.0.0"), ("b", "4.0.0"), ("c", "2.0.0"), ("c", None)]
    tasks = [
        Role.task("install", version=v, local_archive=str(archives[v][0]), sha256=archives[v][1]) for v in versions
    ]
    for consumer, version in pins:
        state = {"state": "absent"} if version is None else {"version": version}
        tasks.append(Role.task("pin", consumer=consumer, **state))
    role.play(*tasks)
    for version in versions:
        assert ours.install(version).returncode == 0
    for consumer, version in pins:
        ours.pin(consumer, version)
    assert snapshot(ours.root) == snapshot(theirs)
    assert ours.pins() == {"a": "3.0.0\n", "a.previous": "1.0.0\n", "b": "4.0.0\n", "c.previous": "2.0.0\n"}

    def age(root: Path) -> None:
        for index, version in enumerate(versions):
            if (root / version).exists():
                os.utime(root / version, (1_600_000_000 + index * 1000,) * 2)

    def both(prepare: Callable[[Path], None], protect: list[str], unknown: bool = False) -> dict[str, Any]:
        for root in (ours.root, theirs):
            age(root)
            prepare(root)
        params: dict[str, Any] = {"keep_versions": 1, "protect": protect, "live_state_unknown": unknown}
        reported = role.play(Role.task("prune", **params))
        options = [x for entry in protect for x in ("--protect", entry.replace(str(theirs), str(ours.root)))]
        out = ours.prune("--keep-versions", "1", *options, *(["--live-state-unknown"] if unknown else []))
        assert snapshot(ours.root) == snapshot(theirs)
        assert [line.removeprefix("remove ") for line in out.splitlines() if line.startswith("remove ")] == reported[
            "removed"
        ]
        assert bool(reported["skipped"]) == out.startswith("blocked ")
        return reported

    def nothing(root: Path) -> None:
        pass

    def garbage(root: Path) -> None:
        (root / ".pins" / "z").write_text("garbage\n")

    def clean(root: Path) -> None:
        (root / ".pins" / "z").unlink()

    # Fail closed first (nothing removed), then the real prune.
    assert both(nothing, [], unknown=True)["removed"] == []
    assert both(garbage, [])["removed"] == []
    assert both(clean, [f"{theirs}/1.0.0/sub/{NAME}"])["removed"] == []
    assert both(nothing, [f"/elsewhere/9.0.0/{NAME}"])["removed"] == []
    # Kept: 6.0.0 newest, 3.0.0/1.0.0 a's pins, 4.0.0 b's pin, 2.0.0 c's previous pin; 5.0.0 protected by path.
    assert both(nothing, [f"{theirs}/5.0.0/{NAME} (deleted)", "/usr/bin/python3"])["removed"] == []
    assert both(nothing, ["2.0.0"])["removed"] == ["5.0.0"]
    assert ours.versions() == ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "6.0.0"]
