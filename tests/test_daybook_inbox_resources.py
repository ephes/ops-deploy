"""Owned filesystem publication: private expectations, preserved logs, no app calls."""

from __future__ import annotations

import grp
import importlib.util
import os
import pwd
import sys
import types
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE
from ops_deploy.services.daybook_voice_memo_inbox.resource_payload import resource_payload
from tests.test_daybook_inbox_controls import DATA, Probes
from tests.test_daybook_inbox_declaration import config, secrets


@pytest.fixture
def helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    for name, package, resource in (
        ("ops_inbox_controls", PACKAGE, "files/inbox_controls.py"),
        ("ops_inbox_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
    ):
        module = types.ModuleType(name)
        monkeypatch.setitem(sys.modules, name, module)
        source = files(package).joinpath(resource)
        exec(compile(source.read_bytes(), str(source), "exec"), module.__dict__)
    spec = importlib.util.spec_from_file_location(
        "owned_inbox_resources", str(files(PACKAGE).joinpath("files/inbox_resources.py"))
    )
    assert spec
    assert spec.loader
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def declared(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path.resolve() / "owned"
    owner, group = pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name

    def row(name: str, mode: int, **extra: Any) -> dict[str, Any]:
        return {"path": str(root / name), "owner": owner, "group": group, "mode": mode, **extra}

    rows = [
        row("policy.json", 0o644, content='{"owned": true}\n'),
        row("credentials.json", 0o600, content="UNUSABLE-FAKE-AUTH\n"),
    ]
    return {
        **DATA,
        "directories": [row(".", 0o700), row("logs", 0o700)],
        "logs": [row("logs/ingest.log", 0o600)],
        "resources": rows,
        "final_resources": [*rows[:-1], {**rows[-1], "content": "UNUSABLE-FAKE-FINAL-EXPECTATION\n"}],
        "retired_long_plist": str(root / "retired.plist"),
    }


def snapshot(root: Path) -> dict[str, tuple[int, int, int, int, int]]:
    return {
        str(path): (
            path.stat().st_ino,
            path.stat().st_mtime_ns,
            path.stat().st_ctime_ns,
            path.stat().st_mode,
            path.stat().st_size,
        )
        for path in [root, *root.rglob("*")]
    }


def test_owned_filesystem_first_and_repeat_preserve_log_bodies_and_metadata(
    helper: Any, declared: dict[str, Any]
) -> None:
    assert helper.directories_current(declared) is False
    helper.prepare_directories(declared, Probes())
    log = Path(declared["logs"][0]["path"])
    log.write_bytes(b"OWNED-LOG-NEVER-READ-OR-TRUNCATED")
    before_log = log.stat()
    helper.apply_resources(declared, Probes())
    assert helper.resources_current(declared) is True
    assert log.read_bytes() == b"OWNED-LOG-NEVER-READ-OR-TRUNCATED"
    assert (log.stat().st_ino, log.stat().st_mtime_ns, log.stat().st_ctime_ns) == (
        before_log.st_ino,
        before_log.st_mtime_ns,
        before_log.st_ctime_ns,
    )
    root = Path(declared["directories"][0]["path"])
    before = snapshot(root)
    helper.prepare_directories(declared, Probes())
    helper.apply_resources(declared, Probes())
    assert snapshot(root) == before


def test_private_content_drift_is_compared_in_memory_without_digest_or_repr(
    helper: Any, declared: dict[str, Any], capsys: Any
) -> None:
    helper.prepare_directories(declared, Probes())
    helper.apply_resources(declared, Probes())
    target = Path(declared["resources"][1]["path"])
    target.write_text("OTHER-UNUSABLE-FAKE-AUTH\n")
    before = snapshot(target.parent)
    assert helper.resources_current(declared) is False
    assert snapshot(target.parent) == before
    assert capsys.readouterr() == ("", "")


def test_final_keeper_projection_is_observation_only_and_installer_keeps_original(
    helper: Any, declared: dict[str, Any]
) -> None:
    helper.prepare_directories(declared, Probes())
    helper.apply_resources(declared, Probes())
    assert helper.resources_current(declared, final=True) is False
    target = Path(declared["resources"][1]["path"])
    assert target.read_text() == declared["resources"][1]["content"]
    assert declared["final_resources"][1]["content"] != target.read_text()


@pytest.mark.parametrize("action", ["prepare_directories", "apply_resources"])
def test_keeper_guard_refuses_before_any_filesystem_mutation(
    helper: Any, declared: dict[str, Any], action: str
) -> None:
    controls = sys.modules["ops_inbox_controls"]
    with pytest.raises(controls.InboxError, match="runtime_still_running"):
        getattr(helper, action)(declared, Probes(keeper=(0, b"\thost-keep\n")))
    assert not Path(declared["directories"][0]["path"]).exists()


@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_linked_private_resource_is_not_followed_or_replaced(helper: Any, declared: dict[str, Any], link: str) -> None:
    helper.prepare_directories(declared, Probes())
    target = Path(declared["resources"][1]["path"])
    original = target.with_name("other-owned-file")
    original.write_bytes(b"OWNED-PROTECTED")
    if link == "symlink":
        target.symlink_to(original)
    else:
        os.link(original, target)
    with pytest.raises((OSError, sys.modules["ops_inbox_filesystem"].ResourceError)):
        helper.apply_resources(declared, Probes())
    assert original.read_bytes() == b"OWNED-PROTECTED"
    assert target.is_symlink() if link == "symlink" else target.stat().st_nlink == 2
    assert not list(target.parent.glob(".daybook-sessions-*"))


def test_retired_long_plist_removal_is_explicit_quiesced_managed_work(helper: Any, declared: dict[str, Any]) -> None:
    helper.prepare_directories(declared, Probes())
    helper.apply_resources(declared, Probes())
    retired = Path(declared["retired_long_plist"])
    retired.write_bytes(b"OWNED-RETIRED-CODE")
    assert helper.resources_current(declared) is False
    assert retired.exists()
    helper.apply_resources(declared, Probes())
    assert not retired.exists()
    assert helper.resources_current(declared) is True


def test_payload_retains_original_secret_values_only_for_protected_stdin() -> None:
    cfg = config(daybook_voice_memo_inbox_long_label_enabled=False)
    data = resource_payload(cfg, secrets(), uid=501)
    assert len(data["directories"]) == 6
    assert len(data["logs"]) == 4
    assert data["resources"] == data["final_resources"]
    assert all(set(row) == {"path", "owner", "group", "mode", "content"} for row in data["resources"])
    assert "ledger" not in data
    assert "source_dir" not in data
    assert "activation" not in data
    assert data["retired_long_plist"] == cfg.daybook_voice_memo_inbox_long_plist_path
