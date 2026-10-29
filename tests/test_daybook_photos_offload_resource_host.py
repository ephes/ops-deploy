"""Real owned GUI-user resource I/O, synthetic launchd/ACL/plutil controls."""

from __future__ import annotations

import grp
import os
import pwd
import runpy
import sys
import types
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest


@pytest.fixture
def component(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    fs = types.ModuleType("ops_photos_filesystem")
    fs.__dict__.update(
        runpy.run_path(str(files("ops_deploy.services.daybook_sessions").joinpath("files/resources_host.py")))
    )
    monkeypatch.setitem(sys.modules, "ops_photos_filesystem", fs)
    module = runpy.run_path(
        str(files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_resources.py"))
    )
    user = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    private = tmp_path / "private"
    launch = tmp_path / "LaunchAgents"
    logs = private / "logs"

    def spec(path: Path, mode: int) -> dict[str, Any]:
        return {"path": str(path), "owner": user, "group": group, "mode": mode}

    data = {
        "uid": os.getuid(),
        "directories": [spec(private, 0o700), spec(logs, 0o700), spec(launch, 0o755)],
        "logs": [spec(logs / "out.log", 0o600), spec(logs / "err.log", 0o600)],
        "resources": [
            {**spec(private / "reconcile.sh", 0o700), "content": "#!/bin/sh\n# OWNED fixture; never executed\n"},
            {**spec(launch / "owned.plist", 0o644), "content": "OWNED synthetic plist\n"},
        ],
        "plist": str(launch / "owned.plist"),
    }

    class Probes:
        def __init__(self) -> None:
            self.acls: set[str] = set()
            self.calls: list[list[str]] = []

        def acl_free(self, path: Any) -> bool:
            return str(path) not in self.acls

        def run(self, argv: list[str], *, user: bool = False) -> Any:
            assert user
            self.calls.append(argv)
            if argv[:2] == ["/bin/chmod", "-N"]:
                self.acls.discard(argv[2])
            return SimpleNamespace(returncode=0)

    class Controls:
        def __init__(self) -> None:
            self.quiet = True
            self.calls = 0

        def require_quiescent(self) -> None:
            self.calls += 1
            if not self.quiet:
                raise RuntimeError("owned not quiescent")

    return SimpleNamespace(module=module, data=data, probes=Probes(), controls=Controls(), private=private, logs=logs)


def test_status_creates_nothing_then_real_first_repeat_preserves_logs(component: Any) -> None:
    c = component
    assert c.module["directories_current"](c.data, c.probes) is False
    assert not c.private.exists()
    c.module["prepare_directories"](c.data, c.probes, c.controls)
    c.module["apply_resources"](c.data, c.probes, c.controls)
    log = c.logs / "out.log"
    log.write_text("OWNED private log body, never read by component\n")
    before = log.stat()
    c.module["prepare_directories"](c.data, c.probes, c.controls)
    c.module["apply_resources"](c.data, c.probes, c.controls)
    after = log.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    assert c.module["directories_current"](c.data, c.probes)
    assert c.module["resources_current"](c.data, c.probes)
    assert all(argv[0] in {"/usr/bin/plutil", "/bin/chmod"} for argv in c.probes.calls)


def test_quiescence_refuses_before_any_preparation(component: Any) -> None:
    c = component
    c.controls.quiet = False
    with pytest.raises(RuntimeError, match="not quiescent"):
        c.module["prepare_directories"](c.data, c.probes, c.controls)
    assert not c.private.exists()


def test_original_acl_convergence_is_managed_and_rechecked(component: Any) -> None:
    c = component
    c.probes.acls.add(str(c.private))
    assert c.module["directories_current"](c.data, c.probes) is False
    assert not c.probes.calls
    c.module["prepare_directories"](c.data, c.probes, c.controls)
    assert ["/bin/chmod", "-N", str(c.private)] in c.probes.calls
    assert c.module["directories_current"](c.data, c.probes)


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "wrong-user"])
def test_substitution_or_identity_refuses_real_publication(component: Any, fault: str) -> None:
    c = component
    c.module["prepare_directories"](c.data, c.probes, c.controls)
    destination = Path(c.data["resources"][0]["path"])
    outside = c.private.parent / "outside"
    outside.write_text("OWNED protected outside bytes")
    if fault == "symlink":
        destination.symlink_to(outside)
    elif fault == "hardlink":
        os.link(outside, destination)
    else:
        c.data["uid"] += 1
    before = outside.read_bytes()
    with pytest.raises((RuntimeError, ValueError, OSError)):
        c.module["apply_resources"](c.data, c.probes, c.controls)
    assert outside.read_bytes() == before


def test_second_resource_substitution_refuses_before_first_write(component: Any) -> None:
    c = component
    c.module["prepare_directories"](c.data, c.probes, c.controls)
    second = Path(c.data["resources"][1]["path"])
    second.symlink_to(c.private.parent)
    with pytest.raises((RuntimeError, OSError)):
        c.module["apply_resources"](c.data, c.probes, c.controls)
    assert not Path(c.data["resources"][0]["path"]).exists()
