"""Fixed admission, managed SDK scope and actual activation failure sequencing."""

from __future__ import annotations

import importlib.resources
import io
import json
import sys
import types
from typing import Any

import pytest
from pydantic import ValidationError
from pyinfra.connectors.fake import FakeConnector

from ops_deploy.services.daybook_weeknotes_activation import WeeknotesActivationConfig, activate_weeknotes_schedule
from ops_deploy.services.daybook_weeknotes_activation.config import ENABLE_PHRASE
from ops_deploy.services.daybook_weeknotes_identity import WeeknotesIdentityConfig
from ops_deploy.services.daybook_weeknotes_identity.config import APPLY_PHRASE
from ops_deploy.testing import run_deploy_fake


def config(**updates: Any) -> WeeknotesActivationConfig:
    identity = WeeknotesIdentityConfig(
        owner="fixture",
        action="apply",
        required_revision="a" * 40,
        confirmation=APPLY_PHRASE,
        moves=[
            {
                "week": "2026-W01",
                "audience": "public",
                "blog_id": 1,
                "post_id": 2,
                "expected_revision_id": 3,
                "from_title": "OWNED",
                "from_slug": "owned",
            }
        ],
    )
    return WeeknotesActivationConfig(**{"identity": identity, "confirmation": ENABLE_PHRASE, **updates})


@pytest.mark.parametrize(
    "updates",
    [
        {"retired": True},
        {"retired": "false"},
        {"retired": None},
        {"confirmation": "yes"},
        {"launchctl_bin": "/tmp/control"},
        {"reconcile_launcher": "/tmp/launcher"},
    ],
)
def test_retired_or_retargeted_requests_are_refused(updates: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**updates)


def test_fresh_apply_is_mandatory_and_private_intent_hidden() -> None:
    with pytest.raises(ValidationError):
        config(identity=config().identity.model_copy(update={"action": "verify"}))
    assert "OWNED" not in repr(config())
    assert "from_title" not in repr(config())


def test_sdk_first_repeat_are_two_managed_direct_sequences(monkeypatch: pytest.MonkeyPatch) -> None:
    original = FakeConnector.run_shell_command

    def direct(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        return original(connector, *args, **kwargs)

    monkeypatch.setattr(FakeConnector, "run_shell_command", direct)
    for _ in range(2):
        result = run_deploy_fake(
            activate_weeknotes_schedule,
            config(),
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
        assert not any("activation" in command for command in result.fact_commands)
    wrong = run_deploy_fake(
        activate_weeknotes_schedule, config(), responses={"uname -s": ["Darwin"], "/usr/bin/id -u": ["501"]}
    )
    assert not wrong.succeeded
    assert wrong.mutating_changed_ops == []


@pytest.fixture
def rail(monkeypatch: pytest.MonkeyPatch) -> Any:
    cfg = config()
    data = cfg.identity.model_dump(mode="json")
    data.update(uid=501, activation=cfg.model_dump(mode="json", exclude={"identity"}))
    verified = {"plan_hash": "c" * 64}
    proof = {
        "schema_version": 1,
        "identity_epoch": "monday-after-v1",
        "plan_hash": "c" * 64,
        "daybook_repo_ref": "a" * 40,
    }
    bodies = {
        data["env_file"]: b"DAYBOOK_WEEKNOTES_POST_IDENTITY_EPOCH=monday-after-v1\n",
        data["proof"]: json.dumps(proof).encode(),
    }
    reads = []

    def read(path: str, uid: int, mode: int) -> bytes:
        reads.append((path, uid, mode))
        return bodies.get(path, b"OWNED public code/checksum/plist")

    identity: Any = types.ModuleType("ops_weeknotes_identity")
    identity.read_control = read
    identity.strict_json = json.loads
    monkeypatch.setitem(sys.modules, identity.__name__, identity)
    module = types.ModuleType("owned_activation")
    body = (
        importlib.resources.files("ops_deploy.services.daybook_weeknotes_activation")
        .joinpath("files/activation_host.py")
        .read_bytes()
    )
    exec(compile(body, "<owned activation>", "exec"), module.__dict__)
    state = {"disabled": True, "loaded": False, "fault": ""}
    calls = []

    def control(_data: Any, *argv: str) -> Any:
        calls.append(argv)
        if argv[0] == "print":
            status = (
                2
                if state["fault"] == "unavailable"
                else (1 if state["fault"] == "postverify" else 0)
                if state["loaded"]
                else 113
            )
            return types.SimpleNamespace(returncode=status, stdout=b"")
        if argv[0] == "print-disabled":
            return types.SimpleNamespace(
                returncode=0,
                stdout=(
                    f'"{data["scheduler_label"]}" => ' + ("true" if state["disabled"] else "false") + "\n"
                ).encode(),
            )
        if argv[0] == "enable":
            state["disabled"] = False
        if argv[0] == "bootstrap":
            if state["fault"] == "bootstrap":
                return types.SimpleNamespace(returncode=1, stdout=b"PRIVATE synthetic failure")
            state["loaded"] = True
        return types.SimpleNamespace(returncode=0, stdout=b"")

    return types.SimpleNamespace(
        module=module,
        data=data,
        verified=verified,
        proof=proof,
        bodies=bodies,
        reads=reads,
        calls=calls,
        state=state,
        control=control,
    )


def test_exact_original_metadata_epoch_proof_and_enable_bootstrap_order(rail: Any) -> None:
    rail.module.activate(rail.data, rail.verified, control=rail.control)
    assert rail.state["loaded"]
    assert not rail.state["disabled"]
    assert [call[0] for call in rail.calls] == [
        "print",
        "print-disabled",
        "enable",
        "bootstrap",
        "print",
        "print-disabled",
    ]
    assert not any("kickstart" in call for call in rail.calls)
    assert (rail.data["env_file"], 501, 0o600) in rail.reads
    assert (rail.data["proof"], 0, 0o600) in rail.reads
    assert (rail.data["scheduler_plist"], 0, 0o644) in rail.reads
    assert (rail.data["activation"]["reconcile_launcher"], 0, 0o755) in rail.reads


@pytest.mark.parametrize("fault", ["epoch", "proof", "loaded", "enabled", "unavailable"])
def test_admission_failure_never_enables(rail: Any, fault: str) -> None:
    if fault == "epoch":
        rail.bodies[rail.data["env_file"]] = b"OWNED no epoch"
    if fault == "proof":
        rail.bodies[rail.data["proof"]] = json.dumps({**rail.proof, "plan_hash": "d" * 64}).encode()
    if fault == "loaded":
        rail.state["loaded"] = True
    if fault == "enabled":
        rail.state["disabled"] = False
    if fault == "unavailable":
        rail.state["fault"] = "unavailable"
    with pytest.raises(rail.module.ActivationError):
        rail.module.activate(rail.data, rail.verified, control=rail.control)
    assert not any(call[0] == "enable" for call in rail.calls)


@pytest.mark.parametrize(
    ("fault", "reason", "loaded"),
    [("bootstrap", "enabled_bootstrap_failed", False), ("postverify", "loaded_verification_failed", True)],
)
def test_post_enable_failure_reports_actual_phase_without_invented_rollback(
    rail: Any, fault: str, reason: str, loaded: bool
) -> None:
    rail.state["fault"] = fault
    with pytest.raises(rail.module.ActivationError, match=reason):
        rail.module.activate(rail.data, rail.verified, control=rail.control)
    assert not rail.state["disabled"]
    assert rail.state["loaded"] is loaded
    assert not any(call[0] in {"disable", "bootout"} for call in rail.calls)


@pytest.mark.parametrize("change", [{"retired": True}, {"confirmation": "wrong"}, {"action": "verify"}])
def test_host_side_execute_refuses_before_identity_work(
    rail: Any, monkeypatch: pytest.MonkeyPatch, change: dict[str, Any]
) -> None:
    calls = []
    monkeypatch.setattr(rail.module.identity, "execute", lambda *_a, **_k: calls.append(True), raising=False)
    if "action" in change:
        rail.data.update(change)
    else:
        rail.data["activation"].update(change)
    with pytest.raises(rail.module.ActivationError, match="request_refused"):
        rail.module.execute(rail.data)
    assert calls == []


@pytest.mark.parametrize(
    "reason",
    [
        "weeknotes_activation_enabled_bootstrap_failed",
        "weeknotes_activation_loaded_verification_failed",
        "identity-private-error",
    ],
)
def test_main_preserves_fixed_partial_failure_codes_without_private_output(
    rail: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], reason: str
) -> None:
    monkeypatch.setattr(rail.module.identity, "MAX_PRIVATE", 1024, raising=False)
    monkeypatch.setattr(rail.module.sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"{}")))

    def fail(_data: Any) -> None:
        if reason == "identity-private-error":
            raise RuntimeError("PRIVATE_UNTRUSTED_BODY " + "c" * 64)
        raise rail.module.ActivationError(reason)

    monkeypatch.setattr(rail.module, "execute", fail)
    with pytest.raises(SystemExit) as error:
        rail.module.main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert not output.out
    report = json.loads(output.err)
    assert report["reason_code"] == (
        "weeknotes_activation_before_enable_failed" if reason == "identity-private-error" else reason
    )
    assert "PRIVATE_UNTRUSTED_BODY" not in output.err
    assert "c" * 64 not in output.err
