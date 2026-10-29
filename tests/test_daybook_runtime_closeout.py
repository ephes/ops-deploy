"""Original closeout on owned files; no app, launchd, source or record calls."""

from __future__ import annotations

import grp
import importlib.resources
import os
import pwd
import sys
import types
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    fs = types.ModuleType("ops_closeout_filesystem")
    body = importlib.resources.files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py")
    exec(compile(body.read_bytes(), "<qualified-fs>", "exec"), fs.__dict__)
    monkeypatch.setitem(sys.modules, fs.__name__, fs)
    module = types.ModuleType("owned_runtime_closeout")
    body = importlib.resources.files("ops_deploy.services.daybook_operations_runtime").joinpath(
        "files/runtime_closeout.py"
    )
    exec(compile(body.read_bytes(), "<actual-closeout>", "exec"), module.__dict__)
    return module, fs.ResourceError


def metadata(path: Path) -> tuple[int, ...]:
    s = path.lstat()
    return s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns


@pytest.fixture
def data(tmp_path: Path) -> dict[str, str]:
    root = tmp_path.resolve()
    return {
        "legacy_plist": str(root / "saved.plist"),
        "marker": str(root / "closed-out"),
        "owner": pwd.getpwuid(os.getuid()).pw_name,
        "group": grp.getgrgid(root.stat().st_gid).gr_name,
    }


def test_first_removes_only_saved_command_repeat_preserves_marker_and_unrelated_files(
    helper: Any, data: dict[str, str]
) -> None:
    api, _ = helper
    saved, marker = Path(data["legacy_plist"]), Path(data["marker"])
    unrelated = marker.with_name("owned-unrelated-keeper.plist")
    unrelated.write_bytes(b"OWNED-KEEPER-COMMAND")
    before = metadata(unrelated)
    saved.write_bytes(b"bplist00OWNED-OLD-COMMAND")
    saved.chmod(0o644)
    saved_before = metadata(saved)
    assert api.closeout(data, "status") == "change"
    assert metadata(saved) == saved_before
    assert not marker.exists()
    assert api.closeout(data, "apply") == "changed"
    assert not saved.exists()
    assert marker.read_text() == api.MARKER
    state = metadata(marker)
    assert api.closeout(data, "verify") == "current"
    assert api.closeout(data, "status") == "current"
    assert api.closeout(data, "apply") == "current"
    assert metadata(marker) == state
    assert metadata(unrelated) == before
    assert unrelated.read_bytes() == b"OWNED-KEEPER-COMMAND"


@pytest.mark.parametrize("fault", ["linked-marker", "hardlinked-marker", "hardlinked-backup"])
def test_unsafe_declared_resource_refuses_before_deleting_backup_or_replacing_marker(
    helper: Any, data: dict[str, str], fault: str
) -> None:
    api, failure = helper
    saved, marker = Path(data["legacy_plist"]), Path(data["marker"])
    saved.write_bytes(b"OWNED-ORIGINAL")
    saved.chmod(0o644)
    protected = marker.with_name("owned-protected")
    protected.write_bytes(b"OWNED-PROTECTED")
    if fault == "linked-marker":
        marker.symlink_to(protected)
    elif fault == "hardlinked-marker":
        os.link(protected, marker)
    else:
        os.link(saved, marker.with_name("owned-backup-link"))
    before = metadata(saved)
    with pytest.raises((OSError, failure)):
        api.closeout(data, "apply")
    assert metadata(saved) == before
    assert saved.read_bytes() == b"OWNED-ORIGINAL"
    assert protected.read_bytes() == b"OWNED-PROTECTED"
