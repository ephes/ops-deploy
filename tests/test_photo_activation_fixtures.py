"""Local refusal and disarmed-proxy admission before any owned launchctl call."""

from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("fixture", ["photos", "archive"])
def test_fixture_refuses_local_before_provenance_keys_or_host_work(tmp_path: Path, fixture: str) -> None:
    evidence = tmp_path / "evidence"
    script = Path(__file__).resolve().parents[1] / f"smoke/daybook_{fixture}_native_fixture.py"
    result = subprocess.run(
        [sys.executable, str(script)],
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
    assert "transport" not in receipt
    assert "installed_resources" not in receipt


def test_archive_rescue_without_proxy_admission_never_reaches_even_a_fake_activate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "smoke"))
    helper = importlib.import_module("photo_activation_helpers")
    marker = tmp_path / "activation-would-have-run"
    # This direct program guard test uses a harmless class; no real launchctl
    # implementation or owner/Root escalation exists in this child.
    body = (
        "from pathlib import Path\nclass PhotosControlError(RuntimeError): pass\n"
        "class PhotosControls:\n def __init__(self,data): pass\n"
        " def activate(self):\n  Path(" + repr(str(marker)) + ").touch()\n  raise PhotosControlError('fake')\n"
    ).encode()
    request = {
        "case": "owned-guard",
        "expected_uid": os.geteuid(),
        "uid": os.getuid(),
        "module_alias": "ops_archive_controls",
        "label": "com.example.ops-mac-apps.owned",
        "owned_suffix": "owned",
        "owned_root": str(tmp_path),
        "plist": str(tmp_path / "owned.plist"),
        "class_source": base64.b64encode(body).decode(),
        "class_sha256": hashlib.sha256(body).hexdigest(),
        "cleanup_fault": "none",
    }
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", helper.CASE_PROGRAM],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=20,
    )
    assert result.returncode != 0
    assert not marker.exists()
    assert not result.stdout
    assert "KeyError: 'archive_launcher'" in result.stderr


def test_rescue_uses_exact_installed_unchanged_control_blob(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "smoke"))
    helper = importlib.import_module("photo_activation_helpers")
    assert hashlib.sha256(helper.class_bytes()).hexdigest() == helper.EXPECTED_CONTROLS_SHA256


@pytest.mark.parametrize("kind", ["photos-access-disarmed", "archive-execute-disarmed"])
def test_archive_proxy_records_but_never_executes_its_requested_data_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "smoke"))
    fixture = importlib.import_module("daybook_archive_native_fixture")
    # Unit-only ownership stand-in; the native fixture admits actual root-0755
    # ownership on the disposable VM before starting any RunAtLoad=true job.
    monkeypatch.setattr(fixture.os, "chown", lambda *_args: None)
    proxy, digest, events = fixture.timeout_proxy(SimpleNamespace(root=tmp_path), tmp_path)
    marker = tmp_path / "data-command-must-not-execute"
    argv = [sys.executable, "-c", "from pathlib import Path;Path(" + repr(str(marker)) + ").touch()"]
    if kind == "archive-execute-disarmed":
        argv = [str(marker), "photos", "archive-sync", "--execute"]
    result = subprocess.run(
        [sys.executable, str(proxy), "--signal=TERM", "--kill-after=5", "30", *argv],
        capture_output=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert fixture.disarmed_events(events, os.getuid()) == [{"kind": kind, "uid": os.getuid(), "forwarded": False}]
    assert hashlib.sha256(proxy.read_bytes()).hexdigest() == digest
