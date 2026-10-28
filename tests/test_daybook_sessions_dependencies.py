"""Original prerequisites and synthetic model probe; never real inventory/model."""

from __future__ import annotations

import io
import json
import os
import pwd
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest

from tests.test_daybook_sessions_controls import RESOURCES, load_module
from tests.test_daybook_sessions_resources import config

with patch.dict(sys.modules, {"ops_sessions_resources": RESOURCES}):
    MODULE = load_module("ops_sessions_dependencies", "files/dependencies_host.py")


def declaration(**updates: Any) -> dict[str, Any]:
    return config(daybook_sessions_service_user=pwd.getpwuid(os.getuid()).pw_name, **updates).model_dump(mode="json")


def test_original_brew_installs_only_missing_and_never_upgrades_existing(tmp_path: Path) -> None:
    brew = tmp_path / "owned-brew"
    brew.touch()
    cfg = declaration(
        daybook_sessions_brew_bin=str(brew),
        daybook_sessions_brew_packages=["present", "missing"],
        daybook_sessions_brew_user=pwd.getpwuid(os.getuid()).pw_name,
    )
    deps = MODULE.Dependencies(cfg)
    calls: list[list[str]] = []
    installed: set[str] = {"present"}

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        if "install" in argv:
            installed.add(argv[-1])
        rc = int("--versions" in argv and argv[-1] not in installed)
        return subprocess.CompletedProcess(argv, rc, b"private synthetic child output", b"")

    with patch.object(deps, "run", side_effect=run):
        assert deps.inspect() == {"current": False}
        deps.apply()
        assert deps.inspect() == {"current": True}
        calls.clear()
        deps.apply()
        assert all("install" not in argv and "update" not in argv and "upgrade" not in argv for argv in calls)


def test_explicit_brew_update_precedes_missing_package_checks(tmp_path: Path) -> None:
    brew = tmp_path / "owned-brew"
    brew.touch()
    cfg = declaration(
        daybook_sessions_brew_bin=str(brew),
        daybook_sessions_brew_packages=["owned"],
        daybook_sessions_brew_update=True,
        daybook_sessions_brew_user=pwd.getpwuid(os.getuid()).pw_name,
    )
    deps = MODULE.Dependencies(cfg)
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    with patch.object(deps, "run", side_effect=run):
        assert deps.inspect() == {"current": False}
        calls.clear()
        deps.apply()
    assert calls[1:] == [[str(brew), "update"], [str(brew), "list", "--versions", "owned"]]


@pytest.mark.parametrize("field", ["uv", "install", "update"])
def test_prerequisite_failures_remain_genuine_and_do_not_echo_child_body(tmp_path: Path, field: str) -> None:
    brew = tmp_path / "owned-brew"
    brew.touch()
    deps = MODULE.Dependencies(
        declaration(
            daybook_sessions_brew_bin=str(brew),
            daybook_sessions_brew_packages=["owned"],
            daybook_sessions_brew_update=field == "update",
            daybook_sessions_brew_user=pwd.getpwuid(os.getuid()).pw_name,
        )
    )

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        fail = (field == "uv" and "--version" in argv) or (field in {"install", "update"} and field in argv)
        if "--versions" in argv and field == "install":
            fail = True
        return subprocess.CompletedProcess(argv, int(fail), b"UNUSABLE-PRIVATE-ERROR", b"UNUSABLE-PRIVATE-ERROR")

    with patch.object(deps, "run", side_effect=run), pytest.raises(RuntimeError, match=r"^sessions_") as caught:
        deps.apply()
    assert "UNUSABLE" not in str(caught.value)


def test_disabled_classifier_probe_does_not_start_a_process() -> None:
    deps = MODULE.Dependencies(declaration())
    with patch.object(MODULE.subprocess, "Popen", side_effect=AssertionError("disabled probe")):
        deps.probe()


def probe_cfg(tmp_path: Path, code: str, *, timeout: int = 5) -> dict[str, Any]:
    return declaration(
        daybook_archive_quote_classifier_enabled=True,
        daybook_archive_quote_classifier_cmd=shlex.join([sys.executable, "-I", "-B", "-c", code]),
        daybook_archive_quote_classifier_probe_enabled=True,
        daybook_archive_quote_classifier_probe_timeout_seconds=timeout,
        daybook_sessions_service_home=str(tmp_path.resolve()),
    )


def test_actual_owned_synthetic_probe_retains_exact_input_and_login_environment(tmp_path: Path) -> None:
    cfg = probe_cfg(
        tmp_path,
        "import os,sys;assert sys.stdin.read()=='Return exactly OK.\\n';"
        "assert os.environ['XDG_CONFIG_HOME']==os.environ['HOME']+'/.config';print('OK')",
    )
    MODULE.Dependencies(cfg).probe()
    assert list(tmp_path.iterdir()) == []


def test_actual_owned_probe_timeout_is_failure_and_terminates_its_group(tmp_path: Path) -> None:
    marker = tmp_path.resolve() / "owned-process-id"
    code = f"import os,pathlib,time;pathlib.Path({str(marker)!r}).write_text(str(os.getpid()));time.sleep(30)"
    cfg = probe_cfg(tmp_path, code, timeout=1)
    with pytest.raises(RuntimeError, match=r"^sessions_classifier_probe_timed_out$"):
        MODULE.Dependencies(cfg).probe()
    pid = int(marker.read_text())
    checked = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "state="], text=True, capture_output=True, timeout=3)
    assert checked.stdout.strip() in {"", "Z"}


def test_actual_owned_probe_wrong_or_private_output_is_fixed_failure(tmp_path: Path) -> None:
    cfg = probe_cfg(tmp_path, "print('UNUSABLE-PRIVATE-ERROR')")
    with pytest.raises(RuntimeError, match=r"^sessions_classifier_probe_failed$") as caught:
        MODULE.Dependencies(cfg).probe()
    assert "UNUSABLE" not in str(caught.value)


@pytest.mark.parametrize("wrong_group", [False, True])
def test_gui_deadline_proves_child_group_and_bounds_postkill_pipe_cleanup(wrong_group: bool) -> None:
    import signal

    child = Mock(pid=1234567)
    child.poll.return_value = None
    child.communicate.side_effect = [subprocess.TimeoutExpired("owned", 1), subprocess.TimeoutExpired("owned", 2)]
    child.wait.side_effect = subprocess.TimeoutExpired("owned", 1)
    output = io.StringIO()
    request = {"script": "owned synthetic command never executed", "environment": {}, "timeout": 1}
    with (
        patch.object(subprocess, "Popen", return_value=child),
        patch.object(os, "getpgid", return_value=7654321 if wrong_group else child.pid),
        patch.object(os, "getsid", return_value=child.pid),
        patch.object(os, "killpg") as signal_group,
        patch.object(sys, "stdin", io.StringIO(json.dumps(request))),
        patch.object(sys, "stdout", output),
        pytest.raises(SystemExit) as caught,
    ):
        exec(MODULE.PROBE_HELPER, {})
    assert caught.value.code == 1
    report = json.loads(output.getvalue().split("OPS_SESSIONS_PROBE=", 1)[1])
    assert report["reason"] == "cleanup_failed"
    assert report["ok"] is False
    assert report["owned_group"] is not wrong_group
    if wrong_group:
        signal_group.assert_not_called()
    else:
        signal_group.assert_called_once_with(child.pid, signal.SIGKILL)
    assert [call.kwargs["timeout"] for call in child.communicate.call_args_list] == [1, 2]
    child.wait.assert_called_once_with(timeout=1)
    child.stdout.close.assert_called_once()
    child.stderr.close.assert_called_once()


def test_absent_gui_report_bounds_outer_child_cleanup_without_signaling_any_group(tmp_path: Path) -> None:
    child = Mock()
    child.communicate.side_effect = [subprocess.TimeoutExpired("owned", 1), subprocess.TimeoutExpired("owned", 1)]
    child.wait.side_effect = subprocess.TimeoutExpired("owned", 1)
    cfg = probe_cfg(tmp_path, "print('OK')", timeout=1)
    with (
        patch.object(MODULE.subprocess, "Popen", return_value=child),
        patch.object(os, "killpg") as signal_group,
        pytest.raises(RuntimeError, match=r"^sessions_classifier_probe_cleanup_failed$"),
    ):
        MODULE.Dependencies(cfg).probe()
    child.kill.assert_called_once()
    signal_group.assert_not_called()
    assert [call.kwargs["timeout"] for call in child.communicate.call_args_list] == [6, 1]
    child.wait.assert_called_once_with(timeout=1)


def test_unqueryable_unreaped_zombie_retains_created_group_ownership_until_timeout() -> None:
    import signal

    child = Mock(pid=1234567, returncode=0)
    child.communicate.side_effect = [subprocess.TimeoutExpired("owned", 1), (b"", b"")]
    output = io.StringIO()
    request = {"script": "owned synthetic command never executed", "environment": {}, "timeout": 1}
    with (
        patch.object(subprocess, "Popen", return_value=child) as spawned,
        patch.object(os, "getpgid", side_effect=ProcessLookupError),
        patch.object(os, "killpg") as signal_group,
        patch.object(sys, "stdin", io.StringIO(json.dumps(request))),
        patch.object(sys, "stdout", output),
        pytest.raises(SystemExit) as caught,
    ):
        exec(MODULE.PROBE_HELPER, {})
    assert caught.value.code == 1
    assert spawned.call_args.kwargs["start_new_session"] is True
    report = json.loads(output.getvalue().split("OPS_SESSIONS_PROBE=", 1)[1])
    assert report == {"schema_version": 1, "ok": False, "reason": "timeout", "owned_group": True}
    signal_group.assert_called_once_with(child.pid, signal.SIGKILL)
    child.poll.assert_not_called()
    child.wait.assert_not_called()


def test_owned_timeout_stops_pipe_holding_descendant_after_group_leader_exits(tmp_path: Path) -> None:
    import signal

    marker = tmp_path.resolve() / "owned-descendant.json"
    background = (
        "import json,os,pathlib,time;"
        f"pathlib.Path({str(marker)!r}).write_text(json.dumps({{'pid':os.getpid(),'pgid':os.getpgrp(),'uid':os.geteuid()}}));"
        "time.sleep(30)"
    )
    code = (
        "import subprocess,sys;subprocess.Popen([sys.executable,'-I','-B','-c'," + repr(background) + "]);print('OK')"
    )
    cfg = probe_cfg(tmp_path, code, timeout=1)
    try:
        with pytest.raises(RuntimeError, match=r"^sessions_classifier_probe_timed_out$"):
            MODULE.Dependencies(cfg).probe()
        identity = json.loads(marker.read_text())
        assert identity["uid"] == os.geteuid()
        assert identity["pgid"] != os.getpgrp()
        checked = subprocess.run(
            ["/bin/ps", "-p", str(identity["pid"]), "-o", "state="], text=True, capture_output=True, timeout=3
        )
        assert checked.stdout.strip() in {"", "Z"}
    finally:
        # A surviving descendant fails the assertion first. Fixture backstop
        # signals only the declared synthetic PID in its original owned group.
        if marker.exists():
            identity = json.loads(marker.read_text())
            assert identity["uid"] == os.geteuid()
            try:
                if os.getpgid(identity["pid"]) == identity["pgid"] != os.getpgrp():
                    os.kill(identity["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
