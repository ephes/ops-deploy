"""Narrow lost-handler admission; fake process boundary is not SSH qualification."""

from __future__ import annotations

import copy
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.integration.paperless import ssh_recovery as recovery


def states() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], str]:
    unit = "MainPID=42\nActiveState=active\nUnitFileState=disabled\nActiveEnterTimestampMonotonic=100\n"
    before: dict[str, Any] = {"files": {recovery.DROPIN: None}, "public_program_hashes": {}, "units": {"ssh": unit}}
    after = copy.deepcopy(before)
    after["files"][recovery.DROPIN] = {"mode": 0o100644, "uid": 0, "gid": 0, "inode": 12, "mtime_ns": 1234}
    after["public_program_hashes"][recovery.DROPIN] = "fixture-body-sha"
    prepared = {"after": {"unit": {"MainPID": "42"}}}
    log = "TASK [local.ops_library.paperless_deploy : Deploy scanner SSH configuration]"
    return before, after, copy.deepcopy(after), prepared, log


def test_exact_new_dropin_and_unchanged_prepared_daemon_admitted() -> None:
    recovery.admit_lost_handler(*states())


@pytest.mark.parametrize(
    "bad",
    [
        "existing",
        "changed_body",
        "changed_file",
        "different_pid",
        "restarted",
        "inactive",
        "foreign_owner",
        "wrong_mode",
        "handler_ran",
        "missing_task",
    ],
)
def test_unknown_or_not_lost_handler_refuses(bad: str) -> None:
    before, after, current, prepared, log = states()
    if bad == "existing":
        before["files"][recovery.DROPIN] = after["files"][recovery.DROPIN]
    elif bad == "changed_body":
        current["public_program_hashes"][recovery.DROPIN] = "other"
    elif bad == "changed_file":
        current["files"][recovery.DROPIN]["inode"] = 13
    elif bad == "different_pid":
        prepared["after"]["unit"]["MainPID"] = "43"
    elif bad == "restarted":
        current["units"]["ssh"] = current["units"]["ssh"].replace("=42", "=43")
    elif bad == "inactive":
        for item in (before, after, current):
            item["units"]["ssh"] = item["units"]["ssh"].replace("active", "inactive")
    elif bad == "foreign_owner":
        after["files"][recovery.DROPIN]["uid"] = 1000
        current["files"][recovery.DROPIN]["uid"] = 1000
    elif bad == "wrong_mode":
        after["files"][recovery.DROPIN]["mode"] = 0o100666
        current["files"][recovery.DROPIN]["mode"] = 0o100666
    elif bad == "handler_ran":
        log += "\nRUNNING HANDLER [local.ops_library.paperless_deploy : restart ssh]"
    elif bad == "missing_task":
        log = ""
    with pytest.raises(AssertionError):
        recovery.admit_lost_handler(before, after, current, prepared, log)


@pytest.mark.parametrize(
    "error", ["Permission denied", "Connection refused", "bad ownership or modes", "", "Connection closed\nunknown"]
)
def test_unrelated_sftp_failure_never_requests_handler(monkeypatch: pytest.MonkeyPatch, error: str) -> None:
    monkeypatch.setattr(recovery, "sftp_diagnostic", lambda h: {})
    monkeypatch.setattr(recovery, "scanner_sftp", lambda *args: subprocess.CompletedProcess([], 255, "", error))
    h = SimpleNamespace(OWNED_ADMITTED=True, write=Mock(), command=Mock())
    with pytest.raises(AssertionError):
        recovery.complete_pending_handler(h)
    h.command.assert_not_called()


def test_working_sftp_never_requests_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(recovery, "sftp_diagnostic", lambda h: {})
    monkeypatch.setattr(recovery, "scanner_sftp", lambda *args: subprocess.CompletedProcess([], 0, "pwd", ""))
    h = SimpleNamespace(OWNED_ADMITTED=True, write=Mock(), command=Mock())
    recovery.complete_pending_handler(h)
    h.command.assert_not_called()
    h.write.assert_called_with("owned-ssh-pending-handler.json", {"required": False, "probe_exit": 0})


@pytest.mark.parametrize("handler_exit", [0, 1])
def test_complete_handler_uses_exact_source_task_and_retains_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, handler_exit: int
) -> None:
    import gzip
    import hashlib
    import json

    import yaml

    before_original, after_original, current, prepared, log = states()
    label = "00b-original-install-after-fixture-cache-recovery"

    def write(name: str, data: Any) -> None:
        (tmp_path / name).write_text(json.dumps(data))

    def recorded(name: str, value: Any) -> dict[str, Any]:
        raw = json.dumps(value).encode()
        body = gzip.compress(raw)
        (tmp_path / name).write_bytes(body)
        return {"file": name, "raw_size": len(raw), "sha256": hashlib.sha256(body).hexdigest()}

    write("owned-original-index-prerequisite-started.json", {"failed_original": label})
    write("owned-ssh-prerequisite.json", prepared)
    write(
        label + ".json",
        {
            "exit": 2,
            "before": recorded("before.json.gz", before_original),
            "after": recorded("after.json.gz", after_original),
        },
    )
    (tmp_path / (label + ".log")).write_text(log)
    source = tmp_path / "roles/paperless_deploy/handlers/main.yml"
    source.parent.mkdir(parents=True)
    source.write_text(yaml.safe_dump([recovery.HANDLER]))
    updated = copy.deepcopy(current)
    updated["units"]["ssh"] = updated["units"]["ssh"].replace("MainPID=42", "MainPID=43").replace("disabled", "enabled")
    snapshots = [
        SimpleNamespace(public=current, private={"owned": b"synthetic"}),
        SimpleNamespace(public=updated, private={"owned": b"synthetic"}),
    ]
    probes = Mock(
        side_effect=[
            subprocess.CompletedProcess([], 255, "", "Connection closed\n"),
            subprocess.CompletedProcess([], 0, "Remote working directory: /", ""),
        ]
    )
    monkeypatch.setattr(recovery, "scanner_sftp", probes)
    monkeypatch.setattr(recovery, "sftp_diagnostic", lambda h: {})

    def command(*args: str, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert args[:6] == (
            "/opt/paperless-ansible/bin/ansible-playbook",
            "-i",
            "localhost,",
            "-c",
            "local",
            str(tmp_path / "owned-pending-ssh-handler.yml"),
        )
        play = yaml.safe_load((tmp_path / "owned-pending-ssh-handler.yml").read_text())
        assert play == [
            {"hosts": "localhost", "connection": "local", "gather_facts": False, "tasks": [recovery.HANDLER]}
        ]
        return subprocess.CompletedProcess(args, handler_exit, "owned handler output", "")

    h = SimpleNamespace(
        OWNED_ADMITTED=True,
        EVIDENCE=tmp_path,
        ROOT=tmp_path,
        LIBRARY=tmp_path,
        write=write,
        command=command,
        snapshot=Mock(side_effect=snapshots),
        snapshot_receipt=lambda label, side, value: {"side": side},
    )
    if handler_exit:
        with pytest.raises(AssertionError):
            recovery.complete_pending_handler(h)
        assert probes.call_count == 1
    else:
        recovery.complete_pending_handler(h)
        assert probes.call_count == 2
    receipt = json.loads((tmp_path / "owned-ssh-pending-handler.json").read_text())
    assert receipt["handler_exit"] == handler_exit
    assert receipt["only_ssh_unit_changed"] is True
    assert not (tmp_path / "owned-pending-ssh-handler.yml").exists()
