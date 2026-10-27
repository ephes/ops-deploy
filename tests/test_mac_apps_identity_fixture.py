"""Evidence failure behavior without real OpenSSH, service or native-host fixtures."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest


def fixture_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "smoke/mac_apps_identity_fixture.py"
    spec = importlib.util.spec_from_file_location("owned_identity_fixture", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_failed_guard_writes_honest_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = fixture_module()
    monkeypatch.setenv("MAC_APPS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("IMPLEMENTATION_SHA", "a" * 40)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(RuntimeError, match="disposable hosted runner"):
        fixture.main()
    receipt = json.loads((tmp_path / "evidence/identity-proof.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["cleanup"] is True
    assert receipt["failure_type"] == "RuntimeError"
    assert receipt["limitations"]


def test_failed_probe_and_cleanup_are_both_recorded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = fixture_module()
    root = tmp_path / "owned-unit-fixture"
    root.mkdir()
    monkeypatch.setenv("MAC_APPS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("IMPLEMENTATION_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setattr(fixture.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(fixture.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(fixture.os, "geteuid", lambda: 501)
    monkeypatch.setattr(fixture.tempfile, "mkdtemp", lambda **kwargs: str(root))

    def fail_generation(*args: object, **kwargs: object) -> None:
        raise ValueError("synthetic generation failure")

    def fail_cleanup(path: Path) -> None:
        raise PermissionError("synthetic cleanup failure")

    monkeypatch.setattr(fixture.subprocess, "run", fail_generation)
    monkeypatch.setattr(fixture.shutil, "rmtree", fail_cleanup)
    with pytest.raises(ValueError, match="synthetic generation failure"):
        fixture.main()
    text = (tmp_path / "evidence/identity-proof.json").read_text()
    receipt = json.loads(text)
    assert receipt["status"] == "failed"
    assert receipt["cleanup"] is False
    assert receipt["failure_type"] == "ValueError"
    assert receipt["cleanup_error_type"] == "PermissionError"
    assert "synthetic generation failure" not in text
    assert "synthetic cleanup failure" not in text
