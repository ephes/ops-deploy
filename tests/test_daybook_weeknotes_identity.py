"""Original operator declaration, managed SDK boundary and synthetic host rails."""

from __future__ import annotations

import hashlib
import importlib
import importlib.resources
import json
import os
import pwd
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.services.daybook_weeknotes_identity import IdentityMove, WeeknotesIdentityConfig, run_weeknotes_identity
from ops_deploy.services.daybook_weeknotes_identity.config import APPLY_PHRASE
from ops_deploy.services.daybook_weeknotes_identity.deploy import operator_payload, template_values
from ops_deploy.testing import run_deploy_fake

MOVE = {
    "week": "2026-W01",
    "audience": "public",
    "blog_id": 1,
    "post_id": 2,
    "expected_revision_id": 3,
    "from_title": "Weeknotes 2025-12-22",
    "from_slug": "weeknotes-2025-12-22",
}


def cfg(action: Any = "prepare", **extra: Any) -> WeeknotesIdentityConfig:
    return WeeknotesIdentityConfig(
        **{
            "owner": "fixture",
            "action": action,
            "required_revision": "a" * 40,
            "moves": [MOVE],
            "confirmation": APPLY_PHRASE if action == "apply" else "",
            **extra,
        }
    )


@pytest.mark.parametrize(
    "change",
    [
        {"owner": "root"},
        {"state": "/tmp/other"},
        {"checkout": "/tmp/other"},
        {"uv_bin": "/tmp/uv"},
        {"scheduler_label": "other"},
        {"required_revision": "main"},
        {"action": "activate"},
    ],
)
def test_original_scope_cannot_be_retargeted(change: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        cfg(**change)


def test_apply_phrase_and_exact_private_intent_are_not_general_deploy_defaults() -> None:
    with pytest.raises(ValidationError):
        cfg("apply", confirmation="yes")
    with pytest.raises(ValidationError):
        cfg(moves=[])
    assert cfg("status", moves=[]).moves == ()
    with pytest.raises(ValidationError):
        IdentityMove(**{**MOVE, "blog_id": True})
    with pytest.raises(ValidationError) as error:
        IdentityMove(**{**MOVE, "post_id": "PRIVATE_INVALID_ID"})
    assert "PRIVATE_INVALID_ID" not in str(error.value)
    assert "from_title" not in repr(cfg())


def test_render_mapping_needs_no_sessions_storage_credentials_and_pairs_actual_role() -> None:
    selected = cfg()
    values = template_values(selected)
    assert values["daybook_weeknotes_reconcile_state_path"] == selected.runtime + "/state.json"
    assert not any("aws" in key or "token" in key for key in values)
    payload = operator_payload(selected, 501)
    assert set(payload["expected_code"]) == {"helper", "launcher"}
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("Actual owned collection rendering is qualified separately")
    import jinja2

    role = Path(source) / "roles/daybook_sessions_deploy/templates"
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(role),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters.update(importlib.import_module("ansible.plugins.filter.core").FilterModule().filters())
    for key, name in (("helper", "weeknotes-identity-ops.py.j2"), ("launcher", "weeknotes-identity-ops.sh.j2")):
        body = env.get_template(name).render(values).encode()
        assert payload["expected_code"][key] == {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}


@pytest.mark.parametrize("action", ["prepare", "dry-run", "apply", "verify", "status"])
def test_actual_sdk_two_managed_sequences_every_repeat_no_upload_or_inherited_privilege(
    action: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = FakeConnector.run_shell_command
    calls = []

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        calls.append(True)
        return original(connector, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", shell)
    for _ in range(2):
        result = run_deploy_fake(
            run_weeknotes_identity,
            cfg(action),
            responses={"uname -s": ["Darwin"], "/usr/bin/id -u fixture": ["501"], "/usr/bin/id -u": ["0"]},
            _sudo=True,
            _sudo_user="root",
            _su_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
        )
        assert result.succeeded, result.error
        assert len(result.mutating_changed_ops) == 2
        assert result.uploaded_paths == []
        assert not any("identity_operator" in command for command in result.fact_commands)
    assert calls


def test_wrong_connecting_identity_refuses_before_any_managed_work() -> None:
    result = run_deploy_fake(
        run_weeknotes_identity, cfg("status"), responses={"uname -s": ["Darwin"], "/usr/bin/id -u": ["501"]}
    )
    assert not result.succeeded
    assert result.mutating_changed_ops == []


@pytest.fixture
def rail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    if os.getuid() == 0:
        pytest.skip("Unprivileged unit filesystem; real root ownership is exercised in native proof")
    account = pwd.getpwuid(os.getuid())
    fs = types.ModuleType("ops_identity_filesystem")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_sessions")
        .joinpath("files/resources_host.py")
        .read_text()
    )
    exec(compile(body, "owned_identity_fs", "exec"), fs.__dict__)
    monkeypatch.setitem(sys.modules, fs.__name__, fs)
    host = types.ModuleType("owned_identity_operator")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_weeknotes_identity")
        .joinpath("files/identity_operator_host.py")
        .read_text()
    )
    exec(compile(body, "owned_identity_operator", "exec"), host.__dict__)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    root = tmp_path.resolve()
    checkout, runtime, config = root / "checkout", root / "runtime", root / "config"
    for path in (checkout, checkout / ".git", runtime, config):
        path.mkdir()
        path.chmod(0o700)
    data: dict[str, Any] = {
        "owner": account.pw_name,
        "uid": account.pw_uid,
        "action": "prepare",
        "required_revision": "a" * 40,
        "confirmation": "",
        "moves": [MOVE],
        "checkout": str(checkout),
        "runtime": str(runtime),
    }
    expected = {}
    for key, name, content, mode in (
        ("helper", "helper.py", b"OWNED inert helper", 0o755),
        ("launcher", "launcher.sh", b"OWNED inert launcher", 0o755),
        ("env_file", "operator.env", b"OWNED_AUTH=not-a-credential\n", 0o600),
    ):
        file = config / name
        file.write_bytes(content)
        file.chmod(mode)
        data[key] = str(file)
        if key != "env_file":
            expected[key] = {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
    checksum = config / "operator.env.sha256"
    checksum.write_text(
        hashlib.sha256(Path(data["env_file"]).read_bytes()).hexdigest() + "  " + data["env_file"] + "\n"
    )
    checksum.chmod(0o644)
    data.update(
        env_checksum=str(checksum),
        expected_code=expected,
        proof=str(config / "proof.json"),
        seed=str(runtime / "seed.json"),
    )
    protected = []
    for name in ("plan.json", "attestation.json", "state.json", ".state.lock", "auth.json", "stdout.log"):
        file = runtime / name
        file.write_bytes(b"OWNED protected synthetic private bytes")
        file.chmod(0o600)
        protected.append(file)
    # Unit-only simulation of root file ownership. All modes, links, bodies,
    # descriptors and publications are real; native proof checks actual uid0.
    root_files = {data[key] for key in ("helper", "launcher", "env_checksum", "proof")}
    original_read, original_put = host.read_control, fs.put_bytes

    def read(name: str, uid: int, mode: int, **kwargs: Any) -> Any:
        return original_read(name, account.pw_uid if uid == 0 and name in root_files else uid, mode, **kwargs)

    def put(spec: dict[str, Any], body: bytes, **kwargs: Any) -> Any:
        import grp

        spec = {**spec, "owner": account.pw_name, "group": grp.getgrgid(os.getgid()).gr_name}
        return original_put(spec, body, **kwargs)

    monkeypatch.setattr(host, "read_control", read)
    monkeypatch.setattr(host, "put_bytes", put)
    calls = []
    faults: dict[str, Any] = {}

    def run(_data: Any, argv: list[str]) -> Any:
        calls.append(argv)
        if argv[0] == "/usr/bin/git":
            text = "a" * 40 if argv[-1] == "HEAD" else str(checkout) if argv[-1] == "--show-toplevel" else ""
            if faults.get("dirty") and argv[-1] == "--untracked-files=all":
                text = "?? OWNED-untracked"
            return subprocess.CompletedProcess(argv, 0, text.encode(), b"")
        action = argv[-1]
        if faults.get(action):
            return subprocess.CompletedProcess(argv, 1, b"PRIVATE_UNTRUSTED_BODY", b"PRIVATE_DIAGNOSTIC")
        if action in {"prepare", "verify"}:
            value: dict[str, Any] = {
                "schema_version": 1,
                "status": "plan_prepared" if action == "prepare" else "attestation_verified",
                "plan_hash": "c" * 64,
            }
        elif action == "status":
            value = {"schema_version": 2, "weeks": {}}
            if faults.get("unknown_status"):
                value["raw_body"] = "PRIVATE_UNTRUSTED_BODY"
        else:
            apply = action == "apply"
            value = {
                "schema_version": 1,
                "identity_epoch": "monday-after-v1",
                "plan_hash": "c" * 64,
                "dry_run": not apply,
                "applied": apply,
                "status": "applied" if apply else "dry_run_validated",
                "reason_code": None,
                "moves": [
                    {
                        "week": "2026-W01",
                        "audience": "public",
                        "blog_id": 1,
                        "post_id": 2,
                        "from_or_already_target": "from",
                        "result": "moved" if apply else "would_move",
                        "new_revision_id": 4 if apply else None,
                        "reason_code": None,
                    }
                ],
            }
        return subprocess.CompletedProcess(argv, 0, json.dumps(value).encode(), b"")

    return types.SimpleNamespace(host=host, data=data, protected=protected, calls=calls, faults=faults, run=run)


def metadata(paths: list[Path]) -> dict[Path, os.stat_result]:
    return {path: path.stat() for path in paths}


def test_prepare_preserves_existing_seed_and_all_unrelated_private_metadata(rail: Any) -> None:
    before = metadata(rail.protected)
    first = rail.host.execute(rail.data, run=rail.run)
    seed = Path(rail.data["seed"])
    stamp = seed.stat()
    again = rail.host.execute(rail.data, run=rail.run)
    assert first["seed_checked"] is True
    assert again["seed_checked"] is True
    assert seed.stat() == stamp
    assert metadata(rail.protected) == before
    assert "c" * 64 not in json.dumps(first)
    assert [call[-1] for call in rail.calls if call[0] == rail.data["launcher"]] == ["prepare", "prepare"]


@pytest.mark.parametrize("fault", ["wrong_intent", "linked_seed", "helper_bytes", "env_checksum", "dirty"])
def test_original_admission_faults_refuse_before_any_app_and_preserve_files(rail: Any, fault: str) -> None:
    rail.host.execute(rail.data, run=rail.run)
    rail.calls.clear()
    seed = Path(rail.data["seed"])
    if fault == "wrong_intent":
        seed.write_text('{"schema_version":1,"identity_epoch":"monday-after-v1","moves":[]}')
    elif fault == "linked_seed":
        seed.unlink()
        seed.symlink_to(rail.protected[0])
    elif fault == "helper_bytes":
        Path(rail.data["helper"]).write_bytes(b"changed")
    elif fault == "env_checksum":
        Path(rail.data["env_file"]).write_bytes(b"changed")
    else:
        rail.faults["dirty"] = True
    before = metadata(rail.protected)
    with pytest.raises((rail.host.OperatorError, OSError)):
        rail.host.execute(rail.data, run=rail.run)
    assert not any(call[0] == rail.data["launcher"] for call in rail.calls)
    assert metadata(rail.protected) == before


def test_apply_requires_postverify_before_root_proof_and_repeat_preserves_proof(rail: Any) -> None:
    rail.host.execute(rail.data, run=rail.run)
    rail.data.update(action="apply", confirmation=APPLY_PHRASE)
    rail.faults["verify"] = True
    with pytest.raises(rail.host.OperatorError) as error:
        rail.host.execute(rail.data, run=rail.run)
    assert "PRIVATE" not in str(error.value)
    proof = Path(rail.data["proof"])
    assert not proof.exists()
    rail.faults.clear()
    first = rail.host.execute(rail.data, run=rail.run)
    assert first["proof_written"] is True
    assert json.loads(proof.read_text())["plan_hash"] == "c" * 64
    before = proof.stat()
    repeat = rail.host.execute(rail.data, run=rail.run)
    assert repeat["proof_written"] is False
    assert proof.stat() == before
    assert "c" * 64 not in json.dumps(repeat)


def test_status_needs_no_seed_and_rejects_extra_raw_report_fields(rail: Any) -> None:
    rail.data.update(action="status", moves=[])
    result = rail.host.execute(rail.data, run=rail.run)
    assert result["report"] == {"schema_version": 2, "weeks": {}}
    assert not Path(rail.data["seed"]).exists()
    rail.faults["unknown_status"] = True
    with pytest.raises(rail.host.OperatorError):
        rail.host.execute(rail.data, run=rail.run)


def test_apply_and_verify_must_bind_the_same_plan_before_proof(rail: Any) -> None:
    rail.host.execute(rail.data, run=rail.run)
    rail.data.update(action="apply", confirmation=APPLY_PHRASE)

    def mismatched(data: Any, argv: Any) -> Any:
        result = rail.run(data, argv)
        if argv == [data["launcher"], "verify"]:
            value = json.loads(result.stdout)
            value["plan_hash"] = "d" * 64
            result.stdout = json.dumps(value).encode()
        return result

    with pytest.raises(rail.host.OperatorError, match="plan_mismatch"):
        rail.host.execute(rail.data, run=mismatched)
    assert not Path(rail.data["proof"]).exists()
