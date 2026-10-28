"""Owned real files/Git and a production-script CLI; GUI probe stays synthetic."""

from __future__ import annotations

import grp
import hashlib
import io
import json
import os
import pwd
import runpy
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

SCRIPT = Path(str(files("ops_deploy.services.daybook_operations_runtime").joinpath("files/runtime_state.py")))
MODULE = runpy.run_path(str(SCRIPT))
observe = MODULE["observe"]
ObservationError = MODULE["ObservationError"]


def git(path: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(path), *arguments],
        capture_output=True,
        check=True,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        },
    ).stdout


@pytest.fixture
def payload(tmp_path: Path) -> dict[str, Any]:
    tmp_path = tmp_path.resolve()
    source = tmp_path / "source"
    source.mkdir()
    git(source, "init", "--quiet", "--template=")
    (source / "owned.py").write_text("# owned synthetic application source; never imported\n")
    git(source, "add", "owned.py")
    git(
        source,
        "-c",
        "user.name=Owned Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "--quiet",
        "-m",
        "owned",
    )
    for path in (tmp_path / "store", tmp_path / "store/halts", tmp_path / "store/deliveries"):
        path.mkdir(mode=0o700)
    policy = tmp_path / "operations.json"
    body = json.dumps({"schema": 5, "enabled": True, "workers": {"count": 3, "long": 2}})
    policy.write_text(body)
    policy.chmod(0o644)
    credential = tmp_path / "credential.json"
    secret = '{"token":"PRIVATE-FIXTURE-CREDENTIAL"}\n'
    credential.write_text(secret)
    credential.chmod(0o600)
    user = pwd.getpwuid(os.geteuid()).pw_name
    group = grp.getgrgid(os.getegid()).gr_name
    return {
        "user": user,
        "owner": "user",
        "group": group,
        "policy": str(policy),
        "checkout": str(source),
        "revision": git(source, "rev-parse", "HEAD").decode().strip(),
        "journal": str(tmp_path / "store"),
        "source_hashes": {"owned.py": hashlib.sha256((source / "owned.py").read_bytes()).hexdigest()},
        "resources": [
            {"path": str(policy), "owner": user, "group": group, "mode": 0o644, "content": body},
            {"path": str(credential), "owner": user, "group": group, "mode": 0o600, "content": secret},
        ],
    }


class Probes:
    def __init__(self, data: dict[str, Any], *, healthy: bool = True) -> None:
        self.data = data
        self.healthy = healthy

    def git(self, *arguments: str) -> bytes:
        return git(Path(self.data["checkout"]), *arguments)

    def health(self) -> tuple[bool, int | None]:
        return self.healthy, 6543 if self.healthy else None

    def runtime_current(self) -> bool:
        return True


def metadata(payload: dict[str, Any]) -> dict[str, tuple[int, ...]]:
    roots = [
        Path(payload["checkout"]),
        Path(payload["journal"]),
        Path(payload["policy"]),
        Path(payload["resources"][1]["path"]),
    ]
    paths = {path for root in roots for path in ([root, *root.rglob("*")] if root.is_dir() else [root])}
    result: dict[str, tuple[int, ...]] = {}
    for path in paths:
        info = path.lstat()
        result[str(path)] = (
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    return result


def test_real_git_files_and_credentials_repeat_without_managed_metadata_change(payload: dict[str, Any]) -> None:
    before = metadata(payload)
    for _ in range(2):
        result = observe(payload, Probes(payload))
        assert result == {
            "installed": True,
            "enabled": True,
            "source_current": True,
            "resources_current": True,
            "healthy": True,
            "keeper_pid": 6543,
            "schema": 5,
            "workers": {"count": 3, "long": 2},
            "halt_entries": 0,
            "delivery_entries": 0,
        }
        assert "PRIVATE-FIXTURE-CREDENTIAL" not in json.dumps(result)
    assert metadata(payload) == before


def test_records_are_counted_without_opening_or_constructing_journal(
    payload: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = Path(payload["journal"])
    (store / "halts/.halt.json").symlink_to("/not/read")
    (store / "deliveries/record.json").write_bytes(b"PRIVATE-FIXTURE-RECORD-BODY-DO-NOT-READ")
    original_open = os.open
    original_io_open = io.open

    def deny_record_body(path: Any) -> None:
        if isinstance(path, (str, bytes, os.PathLike)) and Path(os.fsdecode(path)).is_relative_to(store):
            pytest.fail("observer attempted a delivery/halt body read")

    def guarded_open(path: Any, *args: Any, **kwargs: Any) -> int:
        deny_record_body(path)
        return original_open(path, *args, **kwargs)

    def guarded_io_open(path: Any, *args: Any, **kwargs: Any) -> Any:
        deny_record_body(path)
        return original_io_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_open)
    monkeypatch.setattr(io, "open", guarded_io_open)
    before = metadata(payload)
    result = observe(payload, Probes(payload))
    assert result["healthy"] is False
    assert result["halt_entries"] == 1
    assert result["delivery_entries"] == 1
    assert "PRIVATE-FIXTURE-RECORD-BODY" not in json.dumps(result)
    assert metadata(payload) == before


def test_source_resource_health_and_policy_drifts_stay_distinct(payload: dict[str, Any]) -> None:
    changed = {**payload, "revision": "b" * 40}
    assert observe(changed, Probes(changed))["source_current"] is False
    credential = Path(payload["resources"][1]["path"])
    credential.write_text("changed-private-content")
    result = observe(payload, Probes(payload))
    assert result["resources_current"] is False
    assert result["source_current"] is True
    assert observe(payload, Probes(payload, healthy=False))["healthy"] is False


def test_malformed_profile_and_unsafe_store_fail_closed(payload: dict[str, Any]) -> None:
    Path(payload["journal"]).chmod(0o755)
    with pytest.raises(ObservationError, match="store_invalid"):
        observe(payload, Probes(payload))
    Path(payload["journal"]).chmod(0o700)
    Path(payload["policy"]).write_text('{"PRIVATE":"BODY"}')
    with pytest.raises(ObservationError, match="profile_invalid"):
        observe(payload, Probes(payload))


def test_real_script_cli_uses_stdin_and_emits_only_bounded_metadata(payload: dict[str, Any]) -> None:
    # Production observer and real Git/files; only GUI/interpreter probes are
    # synthetic here. Actual Darwin GUI proof is a separate native fixture.
    code = """import runpy,sys,json
m=runpy.run_path(sys.argv[1])
class Probes(m['NativeProbes']):
 def health(self):return True,6543
 def runtime_current(self):return True
data=json.load(sys.stdin)
print(json.dumps(m['observe'](data,Probes(data)),sort_keys=True))
"""
    before = metadata(payload)
    run = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(SCRIPT)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert run.returncode == 0, run.stderr
    assert json.loads(run.stdout)["resources_current"] is True
    assert "PRIVATE-FIXTURE-CREDENTIAL" not in run.stdout + run.stderr
    assert metadata(payload) == before


@pytest.mark.parametrize(("owner", "as_user"), [("root", False), ("user", True)])
def test_git_probe_uses_original_install_owner_without_safe_directory_bypass(
    payload: dict[str, Any], owner: str, as_user: bool
) -> None:
    data = {**payload, "owner": owner}
    probe = MODULE["NativeProbes"](data)
    probe.run = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=b"owned-revision\n"))
    assert probe.git("rev-parse", "HEAD") == b"owned-revision\n"
    assert probe.run.call_args.kwargs == {"user": as_user}
    assert "safe.directory" not in repr(probe.run.call_args)


def test_disabled_profile_without_store_source_or_gui_needs_disabled_install(payload: dict[str, Any]) -> None:
    from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime, normal_action
    from tests.test_daybook_runtime_contract import config

    Path(payload["policy"]).write_text(json.dumps({"schema": 5, "enabled": False, "workers": {"count": 3, "long": 2}}))
    payload["journal"] = "/nonexistent-owned-fixture-store"
    probes = Mock()
    result = observe(payload, probes)
    assert not probes.mock_calls
    assert result["enabled"] is False
    assert result["halt_entries"] is None
    assert (
        normal_action(
            config(), InstalledRuntime(result["enabled"], result["source_current"], result["resources_current"])
        )
        == "install_disabled"
    )


def test_current_unhealthy_runtime_stays_pure_verification(payload: dict[str, Any]) -> None:
    from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime, normal_action
    from tests.test_daybook_runtime_contract import config

    for halt in (False, True):
        if halt:
            (Path(payload["journal"]) / "halts/halt.json").write_text("unopened")
        result = observe(payload, Probes(payload, healthy=False))
        assert result["healthy"] is False
        assert result["source_current"] is True
        assert result["resources_current"] is True
        assert (
            normal_action(
                config(), InstalledRuntime(result["enabled"], result["source_current"], result["resources_current"])
            )
            == "pure_verify"
        )


@pytest.mark.parametrize("delegate", [False, True])
def test_metadata_probe_uses_public_cwd_and_inner_command_environment(
    payload: dict[str, Any], monkeypatch: pytest.MonkeyPatch, delegate: bool
) -> None:
    from types import SimpleNamespace

    account = SimpleNamespace(pw_uid=501, pw_dir="/Users/owned")
    monkeypatch.setattr(pwd, "getpwnam", lambda _: account)
    monkeypatch.setattr(os, "geteuid", lambda: 0 if delegate else 501)
    called = Mock(return_value=subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""))
    monkeypatch.setattr(subprocess, "run", called)
    probe = MODULE["NativeProbes"](payload)
    arguments = ["/usr/bin/owned-tmux", "-L", "owned", "has-session", "-t", "=host"]
    probe.run(arguments, user=True, extra={"TMUX_TMPDIR": "/owned/private-tmp"})
    argv = called.call_args.args[0]
    if delegate:
        assert argv[:7] == ["/usr/bin/sudo", "-n", "-H", "-u", payload["user"], "--", "/usr/bin/env"]
        assert "-i" not in argv
        assert "-s" not in argv
        assert "TMUX_TMPDIR=/owned/private-tmp" in argv[7:]
        assert "GIT_OPTIONAL_LOCKS=0" in argv[7:]
        assert "HOME=/Users/owned" in argv[7:]
        assert argv[-len(arguments) :] == arguments
    else:
        assert argv == arguments
        assert called.call_args.kwargs["env"]["TMUX_TMPDIR"] == "/owned/private-tmp"
    assert called.call_args.kwargs["cwd"] == "/"
    assert called.call_args.kwargs["timeout"] == 30
