"""Invalid standalone SSH candidates cannot replace the live drop-in."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

SPEC = importlib.util.spec_from_file_location(
    "paperless_scanner_ssh", Path(__file__).parents[1] / "src/ops_deploy/services/paperless/files/scanner_ssh.py"
)
assert SPEC is not None
assert SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_rejected_candidate_preserves_original_and_cleans_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "scanner.conf"
    target.write_text("original\n")
    before = target.stat()
    monkeypatch.setattr(MODULE, "TARGET", target)

    def reject(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        assert argv[:3] == ["sshd", "-t", "-f"]
        assert Path(argv[3]).read_text() == "invalid\n"
        assert Path(argv[3]).stat().st_mode & 0o777 == 0o600
        return SimpleNamespace(returncode=255)

    monkeypatch.setattr(MODULE.subprocess, "run", reject)
    with pytest.raises(MODULE.Refusal, match="validation failed"):
        MODULE.reconcile({"content": "invalid\n", "apply": True})
    assert target.read_text() == "original\n"
    after = target.stat()
    assert (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_ino,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    assert list(tmp_path.iterdir()) == [target]


def test_current_candidate_never_runs_validator_or_writer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(MODULE, "current", lambda content: True)
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **k: pytest.fail("healthy validator executed"))
    assert MODULE.reconcile({"content": "current\n", "apply": True}) == "current"


def test_symlink_dropin_refused_without_following(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    foreign = tmp_path / "foreign"
    foreign.write_text("untouched\n")
    target = tmp_path / "scanner.conf"
    target.symlink_to(foreign)
    monkeypatch.setattr(MODULE, "TARGET", target)
    with pytest.raises(OSError, match=r"Too many levels|symbolic link"):
        MODULE.reconcile({"content": "new\n", "apply": True})
    assert foreign.read_text() == "untouched\n"
