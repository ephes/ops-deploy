"""Original control-object invariants on owned synthetic paths only."""

from __future__ import annotations

import grp
import importlib.util
import json
import os
import pwd
import sys
import types
from importlib.resources import files
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tests.test_daybook_sessions_resources import studio


def load_module(name: str, relative: str) -> types.ModuleType:
    path = files("ops_deploy.services.daybook_sessions").joinpath(relative)
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {name: module}):
        spec.loader.exec_module(module)
    return module


RESOURCES = load_module("ops_sessions_resources", "files/resources_host.py")
with patch.dict(sys.modules, {"ops_sessions_resources": RESOURCES}):
    CONTROLS = load_module("ops_sessions_controls", "files/controls_host.py")


@pytest.fixture
def controls(tmp_path: Path) -> dict[str, Any]:
    home = tmp_path.resolve() / "home"
    home.mkdir()
    daybook = home / ".daybook"
    daybook.mkdir()
    profile = daybook / "archive-browser"
    profile.mkdir(mode=0o700)
    browser = home / "owned-browser"
    browser.write_text("# owned code fixture\n")
    browser.chmod(0o755)
    authroot = home / ".config/automation"
    authroot.mkdir(parents=True, mode=0o700)
    (authroot / "auth.json").write_text("UNUSABLE-OWNED-AUTH")
    (authroot / "auth.json").chmod(0o600)
    runtime = daybook / "weeknotes"
    runtime.mkdir(mode=0o700)
    agent = runtime / "pi-agent"
    agent.mkdir(mode=0o700)
    (agent / "auth.json").write_text("UNUSABLE-PRESERVED-REFRESH")
    (agent / "auth.json").chmod(0o600)
    cfg = studio().model_dump(mode="json")
    cfg.update(
        daybook_sessions_service_user=pwd.getpwuid(os.getuid()).pw_name,
        daybook_sessions_service_group=grp.getgrgid(os.getgid()).gr_name,
        daybook_sessions_service_home=str(home),
        daybook_archive_browser_user_data_dir=str(profile),
        daybook_archive_browser_executable=str(browser),
        daybook_weeknotes_reconcile_runtime_dir=str(runtime),
        daybook_weeknotes_reconcile_pi_agent_dir=str(agent),
        daybook_weeknotes_reconcile_pi_auth_source_root=str(authroot),
        daybook_weeknotes_reconcile_pi_auth_source=str(authroot / "auth.json"),
    )
    return {"config": cfg}


def test_existing_refreshed_auth_is_preserved_without_any_body_read(controls: dict[str, Any]) -> None:
    cfg = controls["config"]
    dest = Path(cfg["daybook_weeknotes_reconcile_pi_agent_dir"]) / "auth.json"
    before = dest.stat()
    with (
        patch.dict(sys.modules, {"ops_sessions_resources": RESOURCES}),
        patch.object(CONTROLS.os, "read", side_effect=AssertionError("no auth body read")),
    ):
        CONTROLS.seed_auth(controls, None)
    assert dest.stat() == before
    assert dest.read_text() == "UNUSABLE-PRESERVED-REFRESH"


def test_missing_auth_is_seeded_privately_and_repeat_preserves_refresh(controls: dict[str, Any]) -> None:
    cfg = controls["config"]
    dest = Path(cfg["daybook_weeknotes_reconcile_pi_agent_dir"]) / "auth.json"
    dest.unlink()
    with patch.dict(sys.modules, {"ops_sessions_resources": RESOURCES}):
        CONTROLS.seed_auth(controls, None)
        assert dest.read_text() == "UNUSABLE-OWNED-AUTH"
        assert dest.stat().st_nlink == 1
        assert dest.stat().st_mode & 0o777 == 0o600
        dest.write_text("UNUSABLE-REFRESHED-AUTH")
        before = dest.stat()
        CONTROLS.seed_auth(controls, None)
        assert dest.stat() == before
        assert dest.read_text() == "UNUSABLE-REFRESHED-AUTH"
    assert list(dest.parent.iterdir()) == [dest]


@pytest.mark.parametrize("state", [{"loaded": True, "disabled": True}, {"loaded": False, "disabled": False}])
def test_explicit_auth_rotation_requires_original_disabled_and_unloaded_state(
    controls: dict[str, Any], state: dict[str, bool]
) -> None:
    from unittest.mock import Mock

    cfg = controls["config"]
    cfg["daybook_weeknotes_reconcile_pi_auth_rotate"] = True
    dest = Path(cfg["daybook_weeknotes_reconcile_pi_agent_dir"]) / "auth.json"
    before = dest.stat()
    with (
        patch.dict(sys.modules, {"ops_sessions_resources": RESOURCES}),
        pytest.raises(RuntimeError, match="sessions_auth_rotation_requires_quiescence"),
    ):
        CONTROLS.seed_auth(controls, Mock(state=Mock(return_value=state)))
    assert dest.stat() == before


def test_no_replace_publication_does_not_overwrite_a_concurrent_refreshed_auth(tmp_path: Path) -> None:
    from tests.test_daybook_sessions_filesystem import spec

    path = tmp_path.resolve() / "owned-auth"
    path.write_bytes(b"UNUSABLE-CONCURRENT-REFRESH")
    path.chmod(0o600)
    before = path.stat()
    RESOURCES.put_bytes(spec(path), b"UNUSABLE-SEED", replace=False)
    assert path.read_bytes() == b"UNUSABLE-CONCURRENT-REFRESH"
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert list(path.parent.iterdir()) == [path]


def test_pure_gui_probe_uses_explicit_direct_metadata_context_and_protected_stdin(controls: dict[str, Any]) -> None:
    import subprocess

    cfg = controls["config"]
    account = pwd.getpwnam(cfg["daybook_sessions_service_user"])
    request = b"UNUSABLE-PRIVATE-STDIN"
    with (
        patch.object(CONTROLS.os, "geteuid", return_value=account.pw_uid + 10000),
        patch.object(CONTROLS.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"fixed", b"")) as run,
    ):
        assert CONTROLS.gui_command(cfg, ["/bin/test", "-x", "/owned/path"], payload=request) == b"fixed"
    argv = run.call_args.args[0]
    assert argv[:7] == ["/usr/bin/sudo", "-n", "-H", "-u", account.pw_name, "--", "/usr/bin/env"]
    assert "-i" not in argv
    assert all("UNUSABLE" not in part for part in argv)
    assert run.call_args.kwargs["input"] == request
    assert run.call_args.kwargs["cwd"] == "/"
    assert run.call_args.kwargs["env"]["HOME"] == account.pw_dir
    assert run.call_args.kwargs["env"]["PYTHONDONTWRITEBYTECODE"] == "1"


def snapshot(root: Path) -> dict[str, tuple[Any, ...]]:
    return {
        str(p.relative_to(root)): (s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        for p in root.rglob("*")
        for s in [p.lstat()]
    }


def test_preflight_never_reads_auth_browser_or_state_bodies(controls: dict[str, Any]) -> None:
    cfg = controls["config"]
    root = Path(cfg["daybook_sessions_service_home"])
    before = snapshot(root)
    with patch.object(CONTROLS.os, "read", side_effect=AssertionError("no body reads")):
        assert CONTROLS.preflight(controls) == os.getuid()
    assert snapshot(root) == before


@pytest.mark.parametrize("field", ["runtime", "pi_agent"])
def test_unsafe_existing_private_directory_is_not_adopted(controls: dict[str, Any], field: str) -> None:
    path = Path(controls["config"][f"daybook_weeknotes_reconcile_{field}_dir"])
    path.chmod(0o755)
    before = path.stat()
    with pytest.raises(RuntimeError, match="sessions_private_control_unsafe"):
        CONTROLS.preflight(controls)
    assert path.stat() == before


@pytest.mark.parametrize("kind", ["state", "lock", "auth", "extra", "linked_auth"])
def test_existing_private_objects_and_isolated_auth_names_are_strict(controls: dict[str, Any], kind: str) -> None:
    cfg = controls["config"]
    runtime = Path(cfg["daybook_weeknotes_reconcile_runtime_dir"])
    agent = Path(cfg["daybook_weeknotes_reconcile_pi_agent_dir"])
    path = {
        "state": runtime / "state.json",
        "lock": runtime / ".state.json.lock",
        "auth": agent / "auth.json",
        "extra": agent / "settings.json",
        "linked_auth": agent / "auth.json",
    }[kind]
    if kind == "linked_auth":
        path.unlink()
        path.symlink_to(cfg["daybook_weeknotes_reconcile_pi_auth_source"])
    else:
        path.write_text("owned synthetic object")
        path.chmod(0o644)
    before = snapshot(Path(cfg["daybook_sessions_service_home"]))
    with pytest.raises(RuntimeError, match=r"sessions_(private_control_unsafe|auth_directory_not_isolated)"):
        CONTROLS.preflight(controls)
    assert snapshot(Path(cfg["daybook_sessions_service_home"])) == before


def test_missing_private_runtime_is_observed_without_implicit_creation(controls: dict[str, Any]) -> None:
    cfg = controls["config"]
    runtime = Path(cfg["daybook_weeknotes_reconcile_runtime_dir"])
    (runtime / "pi-agent/auth.json").unlink()
    (runtime / "pi-agent").rmdir()
    runtime.rmdir()
    CONTROLS.preflight(controls)
    assert not runtime.exists()


def test_nonempty_browser_profile_needs_existing_owned_marker(controls: dict[str, Any]) -> None:
    profile = Path(controls["config"]["daybook_archive_browser_user_data_dir"])
    protected = profile / "owned-profile-entry"
    protected.write_text("owned synthetic protected data never read by guard")
    before = snapshot(profile)
    with pytest.raises(RuntimeError, match="sessions_browser_profile_unmarked"):
        CONTROLS.preflight(controls)
    assert snapshot(profile) == before
    (profile / ".daybook-archive-browser-profile").touch()
    with patch.object(CONTROLS.os, "read", side_effect=AssertionError("no body reads")):
        CONTROLS.preflight(controls)


@pytest.mark.parametrize("kind", ["ancestor", "marker", "executable"])
def test_browser_substitution_refuses_without_following(controls: dict[str, Any], kind: str) -> None:
    cfg = controls["config"]
    profile = Path(cfg["daybook_archive_browser_user_data_dir"])
    if kind == "ancestor":
        path = Path(cfg["daybook_sessions_service_home"]) / "substitute"
        path.symlink_to(profile.parent, target_is_directory=True)
        cfg["daybook_archive_browser_user_data_dir"] = str(path / profile.name)
    elif kind == "marker":
        (profile / ".daybook-archive-browser-profile").symlink_to(cfg["daybook_archive_browser_executable"])
    else:
        path = Path(cfg["daybook_archive_browser_executable"])
        path.unlink()
        path.symlink_to("/bin/sh")
    with pytest.raises(RuntimeError, match="sessions_browser_"):
        CONTROLS.preflight(controls)


def test_identity_json_is_bounded_private_and_not_logged(controls: dict[str, Any]) -> None:
    root = Path(controls["config"]["daybook_weeknotes_reconcile_runtime_dir"])
    path = root / "owned-seed.json"
    path.write_text('{"synthetic":"PRIVATE-OWNED-INTENT"}')
    path.chmod(0o600)
    assert CONTROLS.read_private_json(str(path), os.getuid()) == {"synthetic": "PRIVATE-OWNED-INTENT"}
    path.write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(RuntimeError, match="sessions_identity_metadata_unsafe"):
        CONTROLS.read_private_json(str(path), os.getuid())


def identity_case(controls: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    cfg = controls["config"]
    root = Path(cfg["daybook_weeknotes_reconcile_runtime_dir"])
    for field in ("seed", "plan", "attestation"):
        path = root / (field + ".json")
        path.write_text("{}")
        path.chmod(0o600)
        cfg["daybook_weeknotes_identity_" + field + "_path"] = str(path)
    cfg.update(daybook_sessions_repo_ref="b" * 40, daybook_sessions_checkout_path=str(root / "owned-checkout"))
    data = {
        **controls,
        "identity": {
            "required": True,
            "seed_intent": {"owned": "private intent"},
            "helper_sha256": "c" * 64,
            "module_hashes": {},
        },
        "resources": [
            {"path": cfg["daybook_weeknotes_identity_" + field + "_path"], "owner": "root", "mode": 0o755}
            for field in ("helper", "launcher")
        ],
    }
    proof = {
        "schema_version": 1,
        "identity_epoch": "monday-after-v1",
        "plan_hash": "a" * 64,
        "daybook_repo_ref": "d" * 40,
    }
    return data, proof


@pytest.mark.parametrize("fault", ["none", "intent", "proof", "ancestry", "untracked", "helper", "child"])
def test_bound_identity_parent_proves_original_gate_order_and_sanitized_result(
    controls: dict[str, Any], fault: str
) -> None:
    data, proof = identity_case(controls)
    calls: list[list[str]] = []
    cfg = data["config"]
    proof_path = cfg["daybook_weeknotes_identity_activation_proof_path"]

    def private_json(path: str, uid: int) -> dict[str, Any]:
        if path == proof_path:
            assert uid == 0
            return {**proof, "plan_hash": "e" * 64} if fault == "proof" else proof
        assert uid == os.getuid()
        return {} if fault == "intent" else data["identity"]["seed_intent"]

    def command(_cfg: dict[str, Any], argv: list[str], *, payload: bytes | None = None) -> bytes:
        calls.append(argv)
        if payload:
            request = json.loads(payload)
            assert request["helper_sha256"] == "c" * 64
            assert argv[-5:-2] == ["-I", "-B", "-S"]
            assert "\n" not in argv[-1]
            assert "base64.b64decode" in argv[-1]
            return json.dumps(
                {"schema_version": 1, "status": "failed"}
                if fault == "child"
                else {"schema_version": 1, "status": "attestation_verified", "plan_hash": "a" * 64}
            ).encode()
        assert "--no-optional-locks" in argv
        assert "core.fsmonitor=false" in argv
        if argv[-2:] == ["rev-parse", "HEAD"]:
            return ("b" * 40 + "\n").encode()
        if argv[-2:] == ["rev-parse", "--show-toplevel"]:
            return str(cfg["daybook_sessions_checkout_path"]).encode()
        if "status" in argv:
            return b"?? unexpected\n" if fault == "untracked" else b""
        assert argv[-4:] == ["merge-base", "--is-ancestor", "d" * 40, "HEAD"]
        if fault == "ancestry":
            raise RESOURCES.ResourceError("sessions_identity_verification_failed")
        return b""

    with (
        patch.object(CONTROLS, "read_private_json", side_effect=private_json),
        patch.object(CONTROLS, "gui_command", side_effect=command),
        patch.object(RESOURCES, "file_matches", return_value=fault != "helper"),
        patch.dict(sys.modules, {"ops_sessions_resources": RESOURCES}),
    ):
        if fault == "none":
            assert CONTROLS.identity_gate(data, "owned-loader") == {"schema_version": 1, "identity_verified": True}
            assert len(calls) == 5
        else:
            with pytest.raises(RuntimeError, match="sessions_identity_"):
                CONTROLS.identity_gate(data, "owned-loader")
            if fault in {"intent", "helper"}:
                assert calls == []
            if fault in {"proof", "child"}:
                assert len(calls) == 4  # real verification before proof, no ancestry after invalid proof
