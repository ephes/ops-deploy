"""Owned fixture controls only; fake mc execution is not exact-binary native proof."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).parent / "integration/minio"


def module(name: str) -> ModuleType:
    path = ROOT / "maintenance" / name
    spec = importlib.util.spec_from_file_location("owned_maintenance_" + name.replace("-", "_"), path)
    assert spec is not None
    assert spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.mark.parametrize("action", ["info", "detach", "remove"])
def test_fault_selection_exact_command_and_policy_only(action: str) -> None:
    fault = module("fault-mc.py")
    argv = ["--json", "--config-dir", "/owned", "admin", "policy", action, "local", "owned-policy-a"]
    assert fault.selected_action(argv, "owned-policy-a") == action
    assert fault.selected_action(argv, "owned-policy") is None
    assert fault.selected_action(["alias", "import", "local"], "owned-policy-a") is None
    assert (
        fault.selected_action(["admin", "policy", "entities", "local", "--policy", "owned-policy-a"], "owned-policy-a")
        is None
    )


@pytest.mark.parametrize(
    ("mode", "action", "removed", "expected_rc", "real_called"),
    [
        ("none", "detach", False, 0, True),
        ("detach-before", "detach", False, 1, False),
        ("detach-before", "info", False, 0, True),
        ("detach-after", "detach", False, 1, True),
        ("remove-before", "remove", False, 1, False),
        ("info-before", "info", False, 1, False),
        ("info-after-remove", "info", False, 0, True),
        ("info-after-remove", "info", True, 1, False),
        ("info-after-remove", "remove", False, 0, True),
    ],
)
def test_actual_fault_wrapper_delegate_and_partial_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    action: str,
    removed: bool,
    expected_rc: int,
    real_called: bool,
) -> None:
    fault = module("fault-mc.py")
    root = tmp_path / "owned"
    root.mkdir()
    marker = tmp_path / "marker.json"
    marker.write_text(json.dumps({"run": "owned-run", "machine": "owned-machine"}))
    owned_id = tmp_path / "owned-id"
    owned_id.write_text("owned-run")
    machine = tmp_path / "machine-id"
    machine.write_text("owned-machine")
    paths = {"/var/tmp/minio-owned-guest.json": marker, "/etc/ops-minio-owned-id": owned_id, "/etc/machine-id": machine}
    monkeypatch.setattr(fault, "Path", lambda path: paths.get(str(path), Path(path)))
    monkeypatch.setattr(fault, "ROOT", root)
    (root / "fault.json").write_text(json.dumps({"mode": mode, "policy": "owned-policy-a"}))
    if removed:
        (root / "removed").write_text("removed")
    capture = tmp_path / "real-call.json"
    fake = tmp_path / "fake-mc"
    fake.write_text(
        f"#!{sys.executable}\nimport sys,json\nfrom pathlib import Path\n"
        f"Path({str(capture)!r}).write_text(json.dumps({{'args':sys.argv[1:],'stdin':sys.stdin.read()}}))\n"
        "print(json.dumps({'status':'success'}))\n"
    )
    fake.chmod(0o700)
    monkeypatch.setattr(fault, "REAL", str(fake))
    argv = ["fault", "--json", "--config-dir", "/owned", "admin", "policy", action, "local", "owned-policy-a"]
    monkeypatch.setattr(sys, "argv", argv)
    stdin = tmp_path / "synthetic-input"
    stdin.write_text("owned synthetic protected input")
    with stdin.open() as stream:
        monkeypatch.setattr(sys, "stdin", stream)
        assert fault.main() == expected_rc
    output = capsys.readouterr()
    assert "owned synthetic protected input" not in output.out + output.err
    assert capture.exists() is real_called
    if real_called:
        actual = json.loads(capture.read_text())
        assert actual == {"args": argv[1:], "stdin": "owned synthetic protected input"}
    if action == "remove" and real_called:
        assert (root / "removed").read_text() == "removed\n"


@pytest.mark.parametrize("component", ["normal", "policy-rollback", "invalid", "policy-rollback;touch /outside"])
def test_actual_bootstrap_selector_rejects_before_any_bootstrap(tmp_path: Path, component: str) -> None:
    # Execute the actual selector source prefix, ending BEFORE any bootstrap
    # prerequisites. This isolates enum admission without architecture/root or
    # host paths making a positive test accidentally execute bootstrap work.
    source = (ROOT / "kvm/prepare-rootfs.sh").read_text()
    prefix = source.split("[[ $SHA =~", 1)[0]
    assert 'case "$COMPONENT"' in prefix
    observed = tmp_path / "selector-accepted"
    selected = tmp_path / "actual-selector.sh"
    selected.write_text(prefix + 'printf accepted > "$4"\n')
    result = subprocess.run(
        ["/bin/bash", str(selected), "a" * 40, "b" * 16, component, str(observed)],
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ["PATH"]},
    )
    accepted = component in {"normal", "policy-rollback"}
    assert result.returncode == (0 if accepted else 2)
    assert observed.exists() is accepted


def test_original_task_oracle_and_no_added_holder_document_gate() -> None:
    tasks: list[dict[str, Any]] = yaml.safe_load((ROOT / "maintenance/original-rollback.yml").read_text())
    assert len(tasks) == 9
    commands = [task["ansible.builtin.command"]["argv"] for task in tasks if "ansible.builtin.command" in task]
    assert [argv[3] for argv in commands] == ["info", "detach", "entities", "remove", "info"]
    assert all(argv[0] == "/usr/local/bin/mc" for argv in commands)
    assert tasks[2]["failed_when"] is False
    assert "aws_access_key_id not in" in tasks[4]["ansible.builtin.assert"]["that"][0]
    assert tasks[-1]["ansible.builtin.file"]["state"] == "absent"
    assert "replacement" not in json.dumps(tasks)


@pytest.mark.parametrize("outcome", ["healthy", "matrix-failed", "numeric-success", "guest-failed"])
def test_actual_maintenance_summary_through_tooling_main(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    """Exercise real producer/consumer completion code with no guest/process launch."""
    from unittest.mock import Mock

    harness = module("harness.py")
    spec = importlib.util.spec_from_file_location("owned_maintenance_tooling", ROOT / "kvm/tooling.py")
    assert spec is not None
    assert spec.loader is not None
    tooling = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tooling)
    generated = tmp_path / "generated"
    generated.mkdir()
    closed = []
    monkeypatch.setattr(harness, "admission", lambda evidence: None)
    monkeypatch.setattr(harness.Fixture, "close", lambda self: closed.append(True))
    monkeypatch.setattr(sys, "argv", ["harness", str(generated)])

    def matrix(fixture: Any) -> None:
        fixture.phases.append({"label": "owned-completion-control"})
        if outcome == "matrix-failed":
            fixture.write("summary.json", {"success": False, "phases": fixture.phases})
            raise RuntimeError("owned matrix failure")

    monkeypatch.setattr(harness, "matrix", matrix)
    if outcome == "matrix-failed":
        with pytest.raises(RuntimeError, match="owned matrix failure"):
            harness.main()
    else:
        harness.main()
    assert closed == [True]
    summary = json.loads((generated / "summary.json").read_text())
    if outcome != "matrix-failed":
        assert summary["component"] == "policy-rollback"
    if outcome == "numeric-success":
        summary["success"] = 1
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    guest = evidence / "guest/minio-evidence"
    guest.mkdir(parents=True)
    (guest / "summary.json").write_text(json.dumps(summary))
    (guest / "guest-exit.json").write_text(json.dumps({"exit": 1 if outcome == "guest-failed" else 0}))
    monkeypatch.setenv("MINIO_OWNED_ID", "a" * 16)
    monkeypatch.setattr(tooling, "Path", lambda value: evidence if value == "/evidence" else Path(value))
    process = Mock(returncode=0)
    process.poll.return_value = 0
    launcher = Mock(return_value=process)
    monkeypatch.setattr(tooling.subprocess, "Popen", launcher)
    monkeypatch.setattr(tooling.socket, "socket", lambda *args: Mock(__enter__=Mock(), __exit__=Mock()))
    monkeypatch.setattr(tooling, "query_kvm", lambda stream: {"enabled": True, "present": True})
    monkeypatch.setattr(tooling, "extract_evidence", lambda destination: None)
    if outcome == "healthy":
        tooling.main()
    else:
        with pytest.raises(RuntimeError, match=r"owned (MinIO fixture|guest entry) failed"):
            tooling.main()
    launcher.assert_called_once()
    assert (evidence / "qemu-exit").read_text() == "0\n"
