"""Owned synthetic filesystem effects and refusal invariants, no inventory."""

from __future__ import annotations

import errno
import grp
import os
import pwd
import runpy
import stat
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

MODULE = runpy.run_path(str(files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py")))


def spec(path: Path, mode: int = 0o600, **extra: Any) -> dict[str, Any]:
    return {
        "path": str(path),
        "owner": pwd.getpwuid(os.getuid()).pw_name,
        "group": grp.getgrgid(os.getgid()).gr_name,
        "mode": mode,
        **extra,
    }


def metadata(path: Path) -> tuple[Any, ...]:
    info = path.lstat()
    return info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def test_directories_and_atomic_resource_repeat_preserve_existing_parents(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    root.chmod(0o755)
    parent_identity = (root.stat().st_ino, root.stat().st_mode, root.stat().st_uid, root.stat().st_gid)
    directory = spec(root / "prepared/owned", 0o750)
    assert MODULE["directory_matches"](directory) is False
    assert not (root / "prepared").exists()
    MODULE["ensure_directory"](directory)
    assert MODULE["directory_matches"](directory) is True
    assert (root.stat().st_ino, root.stat().st_mode, root.stat().st_uid, root.stat().st_gid) == parent_identity
    resource = spec(root / "prepared/owned/config.env", content="UNUSABLE-SYNTHETIC-CONTENT\n")
    MODULE["put_resource"](resource)
    target = Path(resource["path"])
    assert target.read_text() == resource["content"]
    before = metadata(target)
    MODULE["put_resource"](resource)
    MODULE["ensure_directory"](directory)
    assert metadata(target) == before
    assert not list(target.parent.glob(".daybook-sessions-*"))


def test_log_metadata_convergence_never_truncates_or_retimes_existing_log(tmp_path: Path) -> None:
    log = tmp_path.resolve() / "log"
    log.write_bytes(b"owned synthetic log\n")
    log.chmod(0o644)
    before = log.stat()
    declaration = spec(log, 0o640)
    MODULE["ensure_log"](declaration)
    after = log.stat()
    assert (after.st_ino, after.st_mtime_ns, after.st_size) == (before.st_ino, before.st_mtime_ns, before.st_size)
    assert stat.S_IMODE(after.st_mode) == 0o640
    assert log.read_bytes() == b"owned synthetic log\n"
    stable = metadata(log)
    MODULE["ensure_log"](declaration)
    assert metadata(log) == stable


def test_metadata_only_private_control_probe_does_not_read_synthetic_auth_body(tmp_path: Path) -> None:
    path = tmp_path.resolve() / "auth.json"
    path.write_text("UNUSABLE-SYNTHETIC-AUTH")
    path.chmod(0o600)
    before = metadata(path)
    with patch.object(MODULE["os"], "read", side_effect=AssertionError("metadata must not read body")):
        assert MODULE["file_matches"](spec(path), strict=True) is True
    assert metadata(path) == before


def test_unsafe_existing_private_directory_is_refused_before_adoption(tmp_path: Path) -> None:
    path = tmp_path.resolve() / "private"
    path.mkdir(mode=0o755)
    before = metadata(path)
    with pytest.raises(RuntimeError, match=r"^sessions_existing_private_directory_unsafe$"):
        MODULE["ensure_directory"](spec(path, 0o700, strict_existing=True))
    assert metadata(path) == before


def test_substituted_parent_is_never_followed_and_declared_legacy_link_only_is_removed(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    other = root / "other"
    other.mkdir()
    protected = other / "config"
    protected.write_text("owned protected body")
    before = metadata(protected)
    (root / "link").symlink_to(other, target_is_directory=True)
    with pytest.raises(OSError, match=rf"\[Errno ({errno.ELOOP}|{errno.ENOTDIR})\]"):
        MODULE["put_resource"](spec(root / "link/config", content="must not write"))
    assert metadata(protected) == before
    leaf = root / "legacy-link"
    leaf.symlink_to(protected)
    MODULE["remove_declared_file"](str(leaf))
    assert not leaf.is_symlink()
    assert metadata(protected) == before


def test_standard_mac_aliases_keep_original_declared_locations_without_arbitrary_links() -> None:
    path = MODULE["resource_path"]("/etc/daybook-sessions")
    assert path == Path("/private/etc/daybook-sessions" if sys.platform == "darwin" else "/etc/daybook-sessions")


def test_special_file_is_refused_without_blocking_or_reading_body(tmp_path: Path) -> None:
    import json
    import subprocess

    fifo = tmp_path.resolve() / "unexpected-fifo"
    os.mkfifo(fifo, 0o600)
    module = files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py")
    program = (
        "import json,runpy,sys;m=runpy.run_path(sys.argv[1]);"
        "\ntry:m['file_matches'](json.loads(sys.argv[2]))"
        "\nexcept RuntimeError as e:print(str(e));raise SystemExit(1)"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program, str(module), json.dumps(spec(fifo))],
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert result.returncode == 1
    assert result.stdout.strip() == "sessions_resource_file_invalid"
    assert result.stderr == ""
    assert stat.S_ISFIFO(fifo.stat().st_mode)
