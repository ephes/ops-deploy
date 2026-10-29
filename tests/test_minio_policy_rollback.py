"""Synthetic response/state tests of the original named-policy maintenance path."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1] / "src/ops_deploy/services/minio/files"
SPEC = importlib.util.spec_from_file_location("minio_rollback_fixture", ROOT / "iam_host.py")
assert SPEC
assert SPEC.loader
HOST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HOST)
exec(compile((ROOT / "policy_rollback.py").read_bytes(), "<rollback-fixture>", "exec"), HOST.__dict__)
PAYLOAD = {"alias": "owned", "policy": "owned-policy", "access": "owned-user"}


def success(**values: Any) -> Any:
    return HOST.Reply(0, json.dumps({"status": "success", **values}), "")


def absent(code: str = "XMinioAdminNoSuchPolicy") -> Any:
    return HOST.Reply(1, json.dumps({"status": "error", "error": {"cause": {"error": {"Code": code}}}}), "")


class Client:
    def __init__(self, *, present: bool = True, users: set[str] | None = None) -> None:
        self.present = present
        self.users = {"owned-user"} if users is None else users
        self.calls: list[tuple[str, ...]] = []
        self.detach_fail = False
        self.detach_effect = True
        self.remove_fail = False
        self.final_present = False
        self.unknown_info = False

    def call(self, *args: str) -> Any:
        self.calls.append(args)
        action = args[2]
        if action == "info":
            if self.unknown_info:
                return absent("AccessDenied")
            # No document gate: original explicit name selection is authority.
            return success(policyInfo={"Policy": {"arbitrary": "synthetic"}}) if self.present else absent()
        if action == "detach":
            if self.detach_effect:
                self.users.discard("owned-user")
            return absent("SyntheticDetachFailure") if self.detach_fail else success()
        if action == "entities":
            return success(
                result={"policyMappings": [{"policy": "owned-policy", "users": sorted(self.users), "groups": []}]}
            )
        if action == "remove":
            if self.remove_fail:
                return absent("SyntheticRemoveFailure")
            self.present = self.final_present
            return success()
        raise AssertionError(args)


def progress() -> dict[str, Any]:
    return {"phase": "input", "detach_attempted": False, "detach_failed": False, "remove_attempted": False}


def test_first_and_repeat_and_exact_commands() -> None:
    client = Client()
    report = progress()
    assert HOST.rollback_policy(client, PAYLOAD, report)
    assert report == {"phase": "complete", "detach_attempted": True, "detach_failed": False, "remove_attempted": True}
    assert [row[2] for row in client.calls] == ["info", "detach", "entities", "remove", "info"]
    client.calls.clear()
    assert not HOST.rollback_policy(client, PAYLOAD, progress())
    assert [row[2] for row in client.calls] == ["info", "info"]


def test_absent_always_gets_independent_final_verification() -> None:
    client = Client(present=False)
    assert not HOST.rollback_policy(client, PAYLOAD, progress())
    assert len(client.calls) == 2


def test_failed_detach_requires_actual_absence() -> None:
    for effect in (False, True):
        client = Client()
        client.detach_fail = True
        client.detach_effect = effect
        report = progress()
        if effect:
            assert HOST.rollback_policy(client, PAYLOAD, report)
        else:
            with pytest.raises(HOST.Refused, match="remains attached"):
                HOST.rollback_policy(client, PAYLOAD, report)
            assert not report["remove_attempted"]
            assert client.present
        assert report["detach_failed"]


def test_other_holder_uses_actual_server_removal_behavior() -> None:
    client = Client(users={"owned-user", "foreign-user"})
    client.remove_fail = True
    report = progress()
    with pytest.raises(HOST.Refused, match="successful result"):
        HOST.rollback_policy(client, PAYLOAD, report)
    assert client.users == {"foreign-user"}  # Real partial detach, not zero mutation.
    assert report["remove_attempted"]
    assert report["phase"] == "remove"
    client.remove_fail = False
    assert HOST.rollback_policy(client, PAYLOAD, progress())  # No invented holder gate.


def test_detached_policy_still_attempts_original_detach_then_removal() -> None:
    client = Client(users=set())
    client.detach_fail = True
    assert HOST.rollback_policy(client, PAYLOAD, progress())


def test_unknown_inspection_refuses_before_any_mutation() -> None:
    client = Client()
    client.unknown_info = True
    report = progress()
    with pytest.raises(HOST.Refused):
        HOST.rollback_policy(client, PAYLOAD, report)
    assert len(client.calls) == 1
    assert not report["detach_attempted"]


def test_failed_final_verification_is_not_success_or_zero_change() -> None:
    client = Client()
    client.final_present = True
    report = progress()
    with pytest.raises(HOST.Refused, match="remains after"):
        HOST.rollback_policy(client, PAYLOAD, report)
    assert report["remove_attempted"]
    assert report["phase"] == "verify-absence"
    assert client.users == set()


def test_typed_rollback_uses_only_scoped_actions_and_protected_stdin() -> None:
    from pydantic import SecretStr

    from ops_deploy.services.minio.policy_rollback import (
        MinioPolicyRollbackConfig,
        MinioPolicyRollbackCredentials,
        host_command,
        rollback_minio_policy,
    )
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    cfg = MinioPolicyRollbackConfig(policy="owned-policy")
    credentials = MinioPolicyRollbackCredentials(
        root_user=SecretStr("synthetic-root"),
        root_password=SecretStr("synthetic-root-value"),
        access=SecretStr("synthetic-access"),
    )
    responses = {**fakehost.UBUNTU, **fakehost.stat(cfg.policy_file), host_command("check"): ['{"pending":true}']}
    result = run_deploy_fake(rollback_minio_policy, cfg, credentials, responses=responses)
    assert result.succeeded, result.error
    assert len(result.mutating_changed_ops) == 2
    assert len([op for op in result.ops if op.changed and op.read_only]) == 1
    assert not result.uploads
    assert result.executed_commands[-1] == f"rm -rf {cfg.policy_file}"
    assert all("synthetic-root-value" not in command for command in result.executed_commands)
    assert any("synthetic-root-value" in stdin for _, stdin in result.stdin)


def test_typed_absent_repeat_retains_independent_readonly_proof() -> None:
    from pydantic import SecretStr

    from ops_deploy.services.minio.policy_rollback import (
        MinioPolicyRollbackConfig,
        MinioPolicyRollbackCredentials,
        host_command,
        rollback_minio_policy,
    )
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    cfg = MinioPolicyRollbackConfig(policy="owned-policy")
    credentials = MinioPolicyRollbackCredentials(
        root_user=SecretStr("synthetic-root"),
        root_password=SecretStr("synthetic-root-value"),
        access=SecretStr("synthetic-access"),
    )
    result = run_deploy_fake(
        rollback_minio_policy,
        cfg,
        credentials,
        responses={**fakehost.UBUNTU, host_command("check"): ['{"pending":false}']},
    )
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert len([op for op in result.ops if op.changed and op.read_only]) == 1
    assert result.uploads == []


@pytest.mark.parametrize("answer", ['{"pending":1}', '{"pending":false,"foreign":true}', "not json"])
def test_typed_unknown_refuses_without_any_operation(answer: str) -> None:
    from pydantic import SecretStr

    from ops_deploy.services.minio.policy_rollback import (
        MinioPolicyRollbackConfig,
        MinioPolicyRollbackCredentials,
        host_command,
        rollback_minio_policy,
    )
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    result = run_deploy_fake(
        rollback_minio_policy,
        MinioPolicyRollbackConfig(policy="owned-policy"),
        MinioPolicyRollbackCredentials(
            root_user=SecretStr("root-fixture"),
            root_password=SecretStr("value-fixture"),
            access=SecretStr("user-fixture"),
        ),
        responses={**fakehost.UBUNTU, host_command("check"): [answer]},
    )
    assert result.error is not None
    assert result.executed_commands == []
    assert result.uploads == []


def test_actual_encoded_helper_uses_private_alias_and_retains_absence(tmp_path: Path) -> None:
    import os
    import shlex
    import subprocess
    import sys

    from ops_deploy.services.minio.policy_rollback import host_command

    state = tmp_path / "state.json"
    state.write_text(json.dumps({"present": True, "users": ["owned-user"]}))
    calls = tmp_path / "calls.jsonl"
    client = tmp_path / "synthetic-mc"
    client.write_text(
        "#!"
        + sys.executable
        + "\n"
        + "import json,sys,pathlib\n"
        + f"state=pathlib.Path({str(state)!r}); calls=pathlib.Path({str(calls)!r})\n"
        + "args=sys.argv[1:]; assert args[:2]==['--json','--config-dir']\n"
        + "directory=pathlib.Path(args[2]); command=args[3:]\n"
        + "record={'command':command,'directory':str(directory)}\n"
        + "with calls.open('a') as stream: stream.write(json.dumps(record)+'\\n')\n"
        + "value=json.loads(state.read_text()); result={'status':'success'}; code=0\n"
        + "if command[:2]==['alias','import']:\n"
        + " material=json.load(sys.stdin); (directory/'config.json').write_text(json.dumps(material))\n"
        + "elif command[:3]==['admin','policy','info']:\n"
        + " if value['present']: result['policyInfo']={'Policy':{'arbitrary':'synthetic'}}\n"
        + " else: result={'status':'error','error':{'cause':{'error':{'Code':'XMinioAdminNoSuchPolicy'}}}}; code=1\n"
        + "elif command[:3]==['admin','policy','detach']: value['users']=[]; state.write_text(json.dumps(value))\n"
        + "elif command[:3]==['admin','policy','entities']:\n"
        + " result['result']={'policyMappings':[{'policy':'owned-policy','users':value['users'],'groups':[]}]}\n"
        + "elif command[:3]==['admin','policy','remove']: value['present']=False; state.write_text(json.dumps(value))\n"
        + "else: raise AssertionError('unexpected fixture command')\n"
        + "print(json.dumps(result)); sys.exit(code)\n"
    )
    client.chmod(0o755)
    data = {
        **PAYLOAD,
        "mc": str(client),
        "endpoint": "http://127.0.0.1:1",
        "root_user": "fixture-root",
        "root_password": "fixture-secret-value",
    }
    results = []
    for action in ("check", "apply", "verify", "check", "apply"):
        completed = subprocess.run(
            shlex.split(host_command(action)),
            input=json.dumps(data),
            capture_output=True,
            text=True,
            timeout=30,
            env=dict(os.environ),
        )
        assert completed.returncode == 0, completed.stderr
        assert "fixture-secret-value" not in completed.stdout + completed.stderr
        results.append(json.loads(completed.stdout))
    assert results[0] == {"pending": True}
    assert results[1]["changed"] is True
    assert results[2] == {"absent": True}
    assert results[3] == {"pending": False}
    assert results[4]["changed"] is False
    recorded = [json.loads(line) for line in calls.read_text().splitlines()]
    assert all(not Path(call["directory"]).exists() for call in recorded)
    assert all(call["directory"] != "/root/.mc" for call in recorded)
    assert sum(call["command"][:3] == ["admin", "policy", "remove"] for call in recorded) == 1


@pytest.mark.parametrize("initially_present", [False, True])
def test_actual_execution_absence_failure_preserves_local_document(initially_present: bool) -> None:
    from pydantic import SecretStr

    from ops_deploy.services.minio.policy_rollback import (
        MinioPolicyRollbackConfig,
        MinioPolicyRollbackCredentials,
        host_command,
        rollback_minio_policy,
    )
    from ops_deploy.testing import run_deploy_fake
    from tests import fakehost

    cfg = MinioPolicyRollbackConfig(policy="owned-policy")
    result = run_deploy_fake(
        rollback_minio_policy,
        cfg,
        MinioPolicyRollbackCredentials(
            root_user=SecretStr("root-fixture"),
            root_password=SecretStr("value-fixture"),
            access=SecretStr("user-fixture"),
        ),
        responses={
            **fakehost.UBUNTU,
            **fakehost.stat(cfg.policy_file),
            host_command("check"): [json.dumps({"pending": initially_present})],
            host_command("verify"): {"success": False, "stderr": "synthetic independent absence failure"},
        },
    )
    assert not result.succeeded
    assert host_command("verify") in result.executed_commands
    assert not any(command.startswith("rm ") for command in result.executed_commands)
    assert (host_command("apply") in result.executed_commands) is initially_present
    assert not result.uploads
