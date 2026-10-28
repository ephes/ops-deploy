"""Disabled-first filesystem convergence and fail-before-write runtime guards."""

from __future__ import annotations

import errno
import json
import os
import pwd
import runpy
import subprocess
import sys
import types
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.daybook_operations_runtime import guards
from ops_deploy.services.daybook_operations_runtime.stage import stage_command
from tests.test_daybook_runtime_observer import Probes, payload  # noqa: F401

PACKAGE = files("ops_deploy.services.daybook_operations_runtime")
observer = types.ModuleType("ops_daybook_observer")
observer.__dict__.update(runpy.run_path(str(PACKAGE.joinpath("files/runtime_state.py"))))
sys.modules["ops_daybook_observer"] = observer
sys.modules["ops_daybook_guards"] = guards
MODULE = runpy.run_path(str(PACKAGE.joinpath("files/runtime_stage.py")))


class StageProbes(Probes):
    def __init__(self, data: dict[str, Any]) -> None:
        super().__init__(data)
        self.account = pwd.getpwnam(data["user"])
        self.loaded = False
        self.serving = False

    def run(self, argv: list[str]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            argv, (0 if self.loaded else 113) if argv[0].endswith("launchctl") else (0 if self.serving else 1), b"", b""
        )


@pytest.fixture
def staging(
    payload: dict[str, Any],  # noqa: F811 - imported pytest fixture
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, Any], StageProbes, list[str]]:
    policy = Path(payload["policy"])
    previous = {
        "schema": 5,
        "enabled": False,
        "api_url": "https://owned.invalid",
        "journal": payload["journal"],
        "kinds": [{"adapter": "voice_memos.ingest.v1"}],
    }
    policy.write_text(json.dumps(previous))
    payload["resources"][0]["content"] = json.dumps(previous)
    payload.update(
        action="install",
        confirmed=False,
        kinds=previous["kinds"],
        api_url=previous["api_url"],
        label="owned-never-probed",
        plist=str(policy.parent / "live.plist"),
        credential=payload["resources"][1]["path"],
        closeout_marker=str(policy.parent / "closed-out"),
    )
    candidate = {**payload["resources"][0], "path": str(policy.parent / "staged.plist"), "content": "owned candidate"}
    payload["resources"].append(candidate)
    validation: list[str] = []
    monkeypatch.setitem(MODULE["stage"].__globals__, "validate_client", lambda *_, **__: validation.append("client"))
    return payload, StageProbes(payload), validation


def snapshot(root: Path) -> dict[str, tuple[Any, ...]]:
    return {
        str(p): (
            s.st_ino,
            s.st_uid,
            s.st_gid,
            s.st_mode,
            s.st_size,
            s.st_mtime_ns,
            s.st_ctime_ns,
            p.read_bytes() if p.is_file() and not p.is_symlink() else None,
        )
        for p in [root, *root.rglob("*")]
        if ".git" not in p.parts
        for s in [p.lstat()]
    }


def test_disabled_install_first_then_repeat_without_source_activation_or_store_churn(
    staging: tuple[dict[str, Any], StageProbes, list[str]],
) -> None:
    data, probes, validations = staging
    Path(data["policy"]).unlink()
    root = Path(data["policy"]).parent
    assert MODULE["stage"](data, "status", probes) == "change"
    assert MODULE["stage"](data, "apply", probes) == "changed"
    assert json.loads(Path(data["policy"]).read_text())["enabled"] is False
    assert not Path(data["plist"]).exists()
    assert validations == ["client"]
    before = snapshot(root)
    assert MODULE["stage"](data, "status", probes) == "current"
    assert MODULE["stage"](data, "verify", probes) == "current"
    assert MODULE["stage"](data, "apply", probes) == "current"
    assert snapshot(root) == before
    assert validations == ["client"] * 3


@pytest.mark.parametrize("fault", ["enabled", "source", "loaded", "serving", "delivery", "halt", "identity", "schema"])
def test_original_stage_guard_refuses_before_any_resource_write(
    staging: tuple[dict[str, Any], StageProbes, list[str]],
    fault: str,
) -> None:
    data, probes, _ = staging
    previous = json.loads(Path(data["policy"]).read_text())
    if fault == "enabled":
        previous["enabled"] = True
    elif fault == "source":
        data["revision"] = "0" * 40
    else:
        data.update(action="replace", confirmed=True)
        if fault == "loaded":
            probes.loaded = True
        elif fault == "serving":
            probes.serving = True
        elif fault in {"delivery", "halt"}:
            (Path(data["journal"]) / ("deliveries" if fault == "delivery" else "halts") / ".owned.json").write_text(
                "not read"
            )
        elif fault == "identity":
            previous["api_url"] = "https://other.invalid"
        elif fault == "schema":
            previous["schema"] = 6
    Path(data["policy"]).write_text(json.dumps(previous))
    root = Path(data["policy"]).parent
    before = snapshot(root)
    category = {
        "enabled": "runtime_install_over_enabled_refused",
        "source": "runtime_stage_source_not_current",
        "loaded": "runtime_replace_requires_quiescence",
        "serving": "runtime_replace_requires_quiescence",
        "delivery": "runtime_old_store_not_drained",
        "halt": "runtime_old_store_not_drained",
        "identity": "runtime_profile_identity_changed",
        "schema": "runtime_previous_schema_unknown",
    }[fault]
    with pytest.raises(RuntimeError, match="^" + category + "$"):
        MODULE["stage"](data, "apply", probes)
    assert snapshot(root) == before


def test_replacement_stays_disabled_after_real_empty_store_guard(
    staging: tuple[dict[str, Any], StageProbes, list[str]],
) -> None:
    data, probes, _ = staging
    previous = json.loads(Path(data["policy"]).read_text())
    previous["enabled"] = True
    Path(data["policy"]).write_text(json.dumps(previous))
    data.update(action="replace", confirmed=True)
    assert MODULE["stage"](data, "apply", probes) == "changed"
    assert json.loads(Path(data["policy"]).read_text())["enabled"] is False


def test_client_rejection_is_rechecked_on_verify_without_a_success_marker(
    staging: tuple[dict[str, Any], StageProbes, list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, probes, _ = staging

    def rejected(*_: object, **__: object) -> None:
        raise RuntimeError("owned client rejection")

    monkeypatch.setitem(MODULE["stage"].__globals__, "validate_client", rejected)
    with pytest.raises(RuntimeError, match="owned client rejection"):
        MODULE["stage"](data, "apply", probes)
    with pytest.raises(RuntimeError, match="owned client rejection"):
        MODULE["stage"](data, "verify", probes)


def test_real_encoded_stage_entrypoint_refuses_invalid_input_before_host_probe() -> None:
    import shlex

    argv = shlex.split(stage_command("status"))
    argv[0] = sys.executable
    private = "UNUSABLE-OWNED-STAGE-INPUT"
    result = subprocess.run(argv, input=json.dumps({"private": private}), capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "runtime_stage_failed"
    assert private not in result.stdout + result.stderr


@pytest.mark.parametrize("context", ["pure", "same-user", "login"])
def test_actual_client_validation_context_and_fixed_failure(
    monkeypatch: pytest.MonkeyPatch,
    context: str,
) -> None:
    from unittest.mock import Mock

    account = types.SimpleNamespace(pw_uid=os.geteuid() + (context == "login"))
    probe = types.SimpleNamespace(account=account, run=Mock(return_value=subprocess.CompletedProcess([], 0, b"", b"")))
    runner = Mock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
    monkeypatch.setattr(subprocess, "run", runner)
    data = {"python": "/owned/python", "policy": "/owned/policy", "owner": "user", "user": "owned"}
    validate = MODULE["validate_client"]
    validate(data, probe, pure=context == "pure")
    used = probe.run if context == "pure" else runner
    argv = used.call_args.args[0]
    expected = [
        "/owned/python",
        "-I",
        "-B",
        "-c",
        "import sys;from daybook.operations_runtime import Config;Config.load(sys.argv[1],sys.argv[2])",
        "/owned/policy",
        "user",
    ]
    if context == "login":
        expected = ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", "owned", "--", *expected]
    assert argv == expected
    if context == "pure":
        assert used.call_args.kwargs == {"user": True}
    else:
        assert "timeout" not in used.call_args.kwargs
    used.return_value = subprocess.CompletedProcess([], 1, b"UNUSABLE-SYNTHETIC-ERROR", b"UNUSABLE-SYNTHETIC-ERROR")
    with pytest.raises(RuntimeError, match=r"^runtime_stage_client_rejected_profile$"):
        validate(data, probe, pure=context == "pure")


def test_write_descriptors_refuse_directory_links_even_after_preflight(tmp_path: Path) -> None:
    target = tmp_path / "protected"
    target.mkdir(mode=0o755)
    original = target.stat()
    alias = tmp_path / "managed"
    alias.symlink_to(target, target_is_directory=True)
    with pytest.raises(OSError, match=rf"\[Errno ({errno.ENOTDIR}|{errno.ELOOP})\]"):
        MODULE["make_directory"](alias, os.getuid(), os.getgid())
    assert (target.stat().st_mode, target.stat().st_ctime_ns) == (original.st_mode, original.st_ctime_ns)
    resource = {
        "path": str(alias / "file"),
        "owner": pwd.getpwuid(os.getuid()).pw_name,
        "group": "staff",
        "mode": 0o600,
        "content": "owned",
    }
    with pytest.raises(RuntimeError, match="linked_parent"):
        MODULE["put"](resource)
    assert list(target.iterdir()) == []


def test_legacy_slot_body_is_not_read_by_preflight_but_required_by_managed_apply(
    staging: tuple[dict[str, Any], StageProbes, list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, probes, _ = staging
    previous = {"schema": 1, "enabled": False, "api_url": data["api_url"], "journal": data["journal"]}
    Path(data["policy"]).write_text(json.dumps(previous))
    slot = Path(data["journal"]) / "delivery.json"
    slot.write_text(json.dumps({"phase": "idle"}))
    data.update(action="replace", confirmed=True)
    reads = []
    original = MODULE["prepare"].__globals__["safe_file"]

    def observed(path: object) -> Any:
        if Path(str(path)) == slot:
            reads.append("slot")
        return original(path)

    monkeypatch.setitem(MODULE["prepare"].__globals__, "safe_file", observed)
    assert MODULE["stage"](data, "status", probes) == "change"
    assert reads == []
    assert MODULE["stage"](data, "apply", probes) == "changed"
    assert reads == ["slot"]


def test_missing_unmanaged_resource_parent_fails_before_private_directory_creation(
    staging: tuple[dict[str, Any], StageProbes, list[str]],
) -> None:
    data, probes, _ = staging
    root = Path(data["policy"]).parent
    data["resources"][-1]["path"] = str(root / "missing-parent/staged.plist")
    before = snapshot(root)
    with pytest.raises(FileNotFoundError):
        MODULE["stage"](data, "apply", probes)
    assert snapshot(root) == before


def test_directory_swap_after_successful_preflight_cannot_harden_its_destination(
    staging: tuple[dict[str, Any], StageProbes, list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data, probes, _ = staging
    root = Path(data["policy"]).parent
    target = root / "unmanaged-directory"
    target.mkdir(mode=0o755)
    before = snapshot(target)
    journal = Path(data["journal"])
    scope = MODULE["stage"].__globals__
    original = scope["prepare"]
    injected: list[bool] = []

    def swap_after_preflight(*args: Any, **kwargs: Any) -> Any:
        result = original(*args, **kwargs)
        if not injected:
            journal.rename(root / "original-store")
            journal.symlink_to(target, target_is_directory=True)
            injected.append(True)
        return result

    monkeypatch.setitem(scope, "prepare", swap_after_preflight)
    with pytest.raises(OSError, match=rf"\[Errno ({errno.ENOTDIR}|{errno.ELOOP})\]"):
        MODULE["stage"](data, "apply", probes)
    assert injected == [True]
    assert snapshot(target) == before


def test_parent_swap_at_temporary_creation_cannot_redirect_atomic_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "managed"
    parent.mkdir()
    target = tmp_path / "unmanaged"
    target.mkdir()
    before = snapshot(target)
    original_open = os.open
    injected: list[bool] = []

    def swap_at_create(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if flags & os.O_CREAT and ".daybook-stage-" in str(path) and not injected:
            parent.rename(tmp_path / "original-parent")
            parent.symlink_to(target, target_is_directory=True)
            injected.append(True)
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", swap_at_create)
    resource = {
        "path": str(parent / "file"),
        "owner": pwd.getpwuid(os.getuid()).pw_name,
        "group": __import__("grp").getgrgid(os.getgid()).gr_name,
        "mode": 0o600,
        "content": "owned",
    }
    MODULE["put"](resource)
    assert injected == [True]
    assert snapshot(target) == before
    assert (tmp_path / "original-parent/file").read_text() == "owned"
