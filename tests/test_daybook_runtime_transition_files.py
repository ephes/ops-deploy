"""Real owned filesystem command handoff; no application, Journal or host call."""

from __future__ import annotations

import grp
import importlib.resources
import os
import plistlib
import pwd
import sys
import types
from pathlib import Path
from typing import Any

import pytest

PACKAGE = "ops_deploy.services.daybook_operations_runtime"


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name, package, resource in (
        ("ops_daybook_observer", PACKAGE, "files/runtime_state.py"),
        ("ops_daybook_guards", PACKAGE, "guards.py"),
        ("ops_daybook_stage", PACKAGE, "files/runtime_stage.py"),
        ("ops_transition_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
    ):
        module = types.ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
        source = importlib.resources.files(package).joinpath(resource)
        exec(compile(source.read_bytes(), "<owned-installed-helper>", "exec"), module.__dict__)
    module = types.ModuleType("owned_transition_files")
    source = importlib.resources.files(PACKAGE).joinpath("files/runtime_transition.py")
    exec(compile(source.read_bytes(), "<actual-transition-files>", "exec"), module.__dict__)
    return module


@pytest.fixture
def driver(helper: Any, tmp_path: Path) -> Any:
    root = tmp_path.resolve()
    user, group = pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(root.stat().st_gid).gr_name
    live, saved = root / "live.plist", root / "saved.plist"
    original = plistlib.dumps({"Label": "owned.legacy", "ProgramArguments": ["/usr/bin/true"]}, fmt=plistlib.FMT_BINARY)
    desired = plistlib.dumps({"Label": "owned.runtime", "ProgramArguments": ["/usr/bin/true"]}).decode()
    live.write_bytes(original)
    live.chmod(0o644)
    data = {
        "user": user,
        "owner": "user",
        "group": group,
        "kinds": [],
        "label": "owned.runtime",
        "action": "cutover",
        "plist": str(live),
        "legacy_plist": str(saved),
        "closeout_marker": str(root / "closed-out"),
        "resources": [{"path": str(live), "owner": user, "group": group, "mode": 0o644, "content": desired}],
    }
    return helper.NativeTransition(data), original, desired


def metadata(path: Path) -> tuple[int, int, int, int]:
    info = path.lstat()
    return info.st_ino, info.st_mode, info.st_mtime_ns, info.st_ctime_ns


def test_original_binary_command_saved_once_and_rollback_preserves_exact_bytes(helper: Any, driver: Any) -> None:
    controller, original, desired = driver
    live, saved = Path(controller.data["plist"]), Path(controller.data["legacy_plist"])
    assert controller.select_command() is True
    assert saved.read_bytes() == original
    assert live.read_text() == desired
    before = metadata(saved)
    live_before = metadata(live)
    assert controller.select_command() is True
    assert metadata(saved) == before
    assert metadata(live) == live_before
    controller.data["action"] = "rollback"
    assert controller.select_command() is True
    assert live.read_bytes() == original
    assert saved.read_bytes() == original
    assert metadata(saved) == before
    restored = metadata(live)
    assert controller.select_command() is True
    assert metadata(live) == restored
    assert metadata(saved) == before


def test_existing_original_backup_is_never_overwritten_by_new_cutover(helper: Any, driver: Any) -> None:
    controller, _original, _desired = driver
    saved = Path(controller.data["legacy_plist"])
    saved.write_bytes(b"OWNED-FIRST-ORIGINAL-COMMAND")
    saved.chmod(0o644)
    before = metadata(saved)
    controller.select_command()
    assert saved.read_bytes() == b"OWNED-FIRST-ORIGINAL-COMMAND"
    assert metadata(saved) == before


def test_original_closeout_does_not_recreate_rollback_backup(helper: Any, driver: Any) -> None:
    controller, _original, desired = driver
    marker = Path(controller.data["closeout_marker"])
    marker.write_bytes(b"OWNED-CLOSED-OUT")
    marker.chmod(0o644)
    controller.select_command()
    assert not Path(controller.data["legacy_plist"]).exists()
    assert Path(controller.data["plist"]).read_text() == desired


def test_rollback_with_no_original_command_leaves_label_without_a_command(helper: Any, driver: Any) -> None:
    controller, _original, _desired = driver
    controller.data["action"] = "rollback"
    assert controller.select_command() is False
    assert not Path(controller.data["plist"]).exists()
    assert not Path(controller.data["legacy_plist"]).exists()


@pytest.mark.parametrize("fault", ["hardlink", "writable", "symlink"])
def test_unsafe_saved_command_refuses_without_replacing_live_or_backup(helper: Any, driver: Any, fault: str) -> None:
    controller, original, _desired = driver
    live, saved = Path(controller.data["plist"]), Path(controller.data["legacy_plist"])
    other = saved.with_name("owned-other")
    other.write_bytes(b"OWNED-PROTECTED-OTHER")
    other.chmod(0o644)
    if fault == "hardlink":
        os.link(other, saved)
    elif fault == "symlink":
        saved.symlink_to(other)
    else:
        saved.write_bytes(b"OWNED-UNSAFE")
        saved.chmod(0o666)
    before = metadata(live)
    with pytest.raises((OSError, helper.TransitionError)):
        controller.validate_commands()
    with pytest.raises((OSError, helper.TransitionError)):
        controller.select_command()
    assert live.read_bytes() == original
    assert metadata(live) == before
    assert other.read_bytes() == b"OWNED-PROTECTED-OTHER"
    assert not list(saved.parent.glob(".daybook-*"))


def test_native_transition_fixture_refuses_local_host_before_any_work(tmp_path: Path) -> None:
    import json
    import subprocess

    evidence = tmp_path / "evidence"
    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_transition_native_fixture.py"
    result = subprocess.run(
        [sys.executable, str(fixture)],
        capture_output=True,
        timeout=20,
        env={
            **os.environ,
            "GITHUB_ACTIONS": "false",
            "RUNNER_ENVIRONMENT": "local",
            "GITHUB_RUN_ID": "1",
            "IMPLEMENTATION_SHA": "a" * 40,
            "MAC_APPS_EVIDENCE_DIR": str(evidence),
        },
    )
    assert result.returncode != 0
    receipts = list(evidence.glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text())
    assert receipt["failure_type"] == "RefusedHost"
    assert "installed_resources" not in receipt
    assert "phases" not in receipt
    assert not list(tmp_path.glob("**/daybook"))


@pytest.mark.parametrize(
    ("success", "category", "accepted"),
    [
        (False, "runtime_transition_command_boundary_invalid", True),
        (True, "runtime_transition_command_boundary_invalid", False),
        (False, "runtime_transition_source_not_current", False),
        (False, "prefix runtime_transition_command_boundary_invalid", False),
    ],
)
def test_native_refusal_observer_requires_exact_actual_failed_category(
    monkeypatch: pytest.MonkeyPatch,
    success: bool,
    category: str,
    accepted: bool,
) -> None:
    import runpy
    from types import SimpleNamespace

    from pyinfra.api import StringCommand
    from pyinfra.connectors.ssh import SSHConnector
    from pyinfra.connectors.util import CommandOutput, OutputLine

    fixture = Path(__file__).resolve().parents[1] / "smoke/daybook_transition_native_fixture.py"
    monkeypatch.syspath_prepend(str(fixture.parent))
    module = runpy.run_path(str(fixture))
    monkeypatch.setattr(
        SSHConnector,
        "run_shell_command",
        lambda *_a, **_kw: (
            success,
            CommandOutput([OutputLine("stderr", category), OutputLine("stderr", "PRIVATE-DISCARDED")]),
        ),
    )

    def run(*_args: Any, **_kwargs: Any) -> Any:
        SSHConnector.run_shell_command(SSHConnector.__new__(SSHConnector), StringCommand("owned synthetic only"))
        return SimpleNamespace(succeeded=success)

    monkeypatch.setitem(module["refusal_run"].__globals__, "run_deploy_ssh", run)
    args = (None, None, None, None, "runtime_transition_command_boundary_invalid")
    if accepted:
        result = module["refusal_run"](*args)
        assert result.succeeded is False
        assert "PRIVATE" not in repr(result)
    else:
        with pytest.raises(AssertionError):
            module["refusal_run"](*args)
