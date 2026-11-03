"""Listed-user retirement: typed refusals, the host helper against a fake client, plan shape."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.services.minio.user_retirement import (
    MinioUserRetirementConfig,
    MinioUserRetirementCredentials,
    host_command,
    retire_minio_users,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

ROOT_VALUE = "fixture-root-value"  # pragma: allowlist secret
PROTECTED_VALUE = "fixture-protected-access"
CREDENTIALS = MinioUserRetirementCredentials(
    root_user=SecretStr("fixture-root"),
    root_password=SecretStr(ROOT_VALUE),
    protected_access=(SecretStr(PROTECTED_VALUE),),
)
CONFIG = MinioUserRetirementConfig(users=("legacy-one", "legacy-two"), protected=("named-keeper",))

# A stand-in for mc; tests/integration/minio/user_retirement runs the real client and server.
FAKE_CLIENT = """#!{python}
import json, pathlib, sys
state_path = pathlib.Path({state!r})
args = sys.argv[1:]
assert args[:2] == ["--json", "--config-dir"]
command = args[3:]
state = json.loads(state_path.read_text())
state["calls"].append(command)


def finish(state, rows, code=0):
    state_path.write_text(json.dumps(state))
    for row in rows:
        print(json.dumps(row))
    sys.exit(code)


def missing():
    error = {{"cause": {{"error": {{"Code": "XMinioAdminNoSuchUser"}}}}}}
    finish(state, [{{"status": "error", "error": error}}], 1)


ok = {{"status": "success"}}
if command[:2] == ["alias", "import"]:
    json.load(sys.stdin)
    finish(state, [ok])
if command[:2] == ["admin", "info"]:
    if state["health"] == "down":
        finish(state, [{{"status": "error", "error": "connection refused", "info": {{}}}}])
    finish(state, [{{**ok, "info": {{"mode": state["health"]}}}}])
if command[:3] == ["admin", "user", "info"]:
    user = command[4]
    if user not in state["users"]:
        missing()
    finish(state, [{{**ok, "accessKey": user, **state["users"][user]}}])
if command[:3] == ["admin", "user", "list"]:
    finish(state, [{{**ok, "accessKey": user, **row}} for user, row in state["users"].items()])
if command[:4] == ["admin", "user", "svcacct", "list"]:
    finish(state, [{{**ok, "accessKey": key}} for key in state["svcacct"].get(command[5], [])])
if command[:3] == ["admin", "user", "remove"]:
    user = command[4]
    if state["remove_fails"]:
        missing()
    if not state["remove_sticks"]:
        state["users"].pop(user)
    if state["remove_side_effect"]:
        state["policies"]["surprise"] = {{}}
    finish(state, [{{**ok, "accessKey": user}}])
if command[:3] == ["admin", "policy", "list"]:
    finish(state, [{{**ok, "policy": name}} for name in state["policies"]])
if command[:3] == ["admin", "policy", "info"]:
    finish(state, [{{**ok, "policyInfo": state["policies"][command[4]]}}])
if command[:3] == ["admin", "group", "list"]:
    finish(state, [{{**ok, "groups": list(state["groups"])}} if state["groups"] else ok])
if command[:3] == ["admin", "group", "info"]:
    finish(state, [{{**ok, "members": state["groups"][command[4]]}}])
if command[0] == "ls":
    finish(state, [{{**ok, "key": bucket}} for bucket in state["buckets"]])
raise AssertionError("unexpected fixture command")
"""


class Host:
    def __init__(self, tmp_path: Path, **overrides: Any) -> None:
        self.path = tmp_path / "state.json"
        self.state: dict[str, Any] = {
            "health": "online",
            "users": {
                "legacy-one": {"userStatus": "enabled", "policyName": "readwrite"},
                "keeper-user": {"userStatus": "enabled", "policyName": "keeper"},
            },
            "svcacct": {},
            "policies": {"readwrite": {"Statement": []}, "keeper": {"Statement": []}},
            "groups": {},
            "buckets": ["kept/"],
            "remove_fails": False,
            "remove_sticks": False,
            "remove_side_effect": False,
            "calls": [],
            **overrides,
        }
        self.path.write_text(json.dumps(self.state))
        self.client = tmp_path / "fake-mc"
        self.client.write_text(FAKE_CLIENT.format(python=sys.executable, state=str(self.path)))
        self.client.chmod(0o755)

    def run(self, action: str, **payload: Any) -> tuple[int, dict[str, Any]]:
        data = {
            "mc": str(self.client),
            "alias": "local",
            "endpoint": "http://127.0.0.1:1",
            "users": ["legacy-one", "legacy-two"],
            "protected": [],
            "root_user": "fixture-root",
            "root_password": ROOT_VALUE,
            **payload,
        }
        completed = subprocess.run(
            shlex.split(host_command(action)),  # type: ignore[arg-type]
            input=json.dumps(data),
            capture_output=True,
            text=True,
            timeout=60,
            env=dict(os.environ),
        )
        assert ROOT_VALUE not in completed.stdout + completed.stderr
        assert completed.stderr == ""
        return completed.returncode, json.loads(completed.stdout)

    def read(self) -> dict[str, Any]:
        state: dict[str, Any] = json.loads(self.path.read_text())
        return state

    def removals(self) -> list[list[str]]:
        return [call for call in self.read()["calls"] if call[:3] == ["admin", "user", "remove"]]


def test_removes_a_present_user_proves_absence_then_repeats_as_a_noop(tmp_path: Path) -> None:
    host = Host(tmp_path)
    assert host.run("check") == (0, {"pending": True})
    code, applied = host.run("apply")
    assert code == 0
    assert applied == {"changed": True, "phase": "complete", "removed": 1, "remove_attempted": True}
    assert host.run("verify") == (0, {"absent": True})
    assert host.removals() == [["admin", "user", "remove", "local", "legacy-one"]]
    state = host.read()
    assert list(state["users"]) == ["keeper-user"]
    assert list(state["policies"]) == ["readwrite", "keeper"]
    # The repeat run: nothing pending, and nothing removed again.
    assert host.run("check") == (0, {"pending": False})
    code, repeat = host.run("apply")
    assert code == 0
    assert repeat == {"changed": False, "phase": "complete", "removed": 0, "remove_attempted": False}
    assert host.run("verify") == (0, {"absent": True})
    assert len(host.removals()) == 1


def test_no_credential_reaches_the_client_argv(tmp_path: Path) -> None:
    host = Host(tmp_path)
    host.run("check")
    host.run("apply")
    host.run("verify")
    calls = json.dumps(host.read()["calls"])
    assert ROOT_VALUE not in calls
    assert "fixture-root" not in calls


def test_empty_answers_are_not_failures(tmp_path: Path) -> None:
    # The real client prints nothing for an empty list, also when the last user goes.
    host = Host(tmp_path, users={"legacy-one": {"userStatus": "enabled"}}, policies={}, buckets=[])
    assert host.run("apply")[1]["changed"] is True
    assert host.run("verify") == (0, {"absent": True})


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ({"users": []}, "the user list is empty"),
        ({"users": "legacy-one"}, "the user list is empty"),
        ({"users": ["-flag"]}, "a listed user name is invalid"),
        ({"users": ["a/b"]}, "a listed user name is invalid"),
        ({"users": ["legacy-one\n"]}, "a listed user name is invalid"),
        ({"users": ["legacy-one", "legacy-one"]}, "the user list has duplicates"),
        ({"users": ["fixture-root"]}, "a listed user is protected"),
        ({"protected": ["legacy-one"]}, "a listed user is protected"),
    ],
)
def test_bad_lists_refuse_before_any_client_call(tmp_path: Path, payload: dict[str, Any], reason: str) -> None:
    host = Host(tmp_path)
    assert host.run("check", **payload) == (0, {"refused": reason})
    code, applied = host.run("apply", **payload)
    assert code == 1
    assert applied["reason"] == reason
    assert host.read()["calls"] == []


@pytest.mark.parametrize("health", ["down", "safemode"])
def test_unhealthy_alias_refuses_without_any_removal(tmp_path: Path, health: str) -> None:
    host = Host(tmp_path, health=health)
    assert host.run("check") == (0, {"refused": "the admin alias is not healthy"})
    code, applied = host.run("apply")
    assert code == 1
    assert applied["reason"] == "the admin alias is not healthy"
    assert applied["remove_attempted"] is False
    assert host.run("verify")[0] == 1
    assert host.removals() == []


def test_group_member_refuses_for_the_whole_list(tmp_path: Path) -> None:
    users = {
        "legacy-one": {"userStatus": "enabled"},
        "legacy-two": {"userStatus": "enabled", "memberOf": [{"name": "kept-group"}]},
    }
    host = Host(tmp_path, users=users)
    assert host.run("check")[1] == {"refused": "a listed user belongs to a group; removing it would change the group"}
    assert host.run("apply")[0] == 1
    assert host.removals() == []


def test_service_account_owner_refuses(tmp_path: Path) -> None:
    host = Host(tmp_path, svcacct={"legacy-one": ["owned-svc"]})
    assert host.run("check")[1] == {"refused": "a listed user owns service accounts; removing it would delete them"}
    assert host.run("apply")[0] == 1
    assert host.removals() == []


def test_unknown_inspection_is_not_absence(tmp_path: Path) -> None:
    host = Host(tmp_path)
    source = host.client.read_text().replace(
        'if user not in state["users"]:\n        missing()',
        'finish(state, [{"status": "error", "error": {"cause": {"error": {"Code": "AccessDenied"}}}}], 1)',
    )
    host.client.write_text(source)
    assert "refused" in host.run("check")[1]
    assert host.run("apply")[0] == 1
    assert host.removals() == []


def test_failed_removal_reports_the_attempt_and_changes_nothing_else(tmp_path: Path) -> None:
    host = Host(tmp_path, remove_fails=True)
    code, applied = host.run("apply")
    assert code == 1
    assert applied["remove_attempted"] is True
    assert applied["removed"] == 0
    assert applied["phase"] == "remove"


def test_user_that_survives_removal_fails(tmp_path: Path) -> None:
    host = Host(tmp_path, remove_sticks=True)
    code, applied = host.run("apply")
    assert code == 1
    assert applied["reason"] == "a listed user remains after removal"
    assert applied["phase"] == "verify-absence"


def test_other_state_changing_fails_after_the_removal(tmp_path: Path) -> None:
    host = Host(tmp_path, remove_side_effect=True)
    code, applied = host.run("apply")
    assert code == 1
    assert applied["reason"] == "state outside the listed users changed during the removal"
    assert applied["removed"] == 1


def test_policy_action_order_is_not_a_change(tmp_path: Path) -> None:
    # The real server returned builtin action lists in a different order on each read.
    host = Host(tmp_path)
    before = host.client.read_text()
    source = before.replace(
        '{**ok, "policyInfo": state["policies"][command[4]]}',
        '{**ok, "policyInfo": {"Policy": {"Statement": [{"Action": '
        'sorted("ab", reverse="legacy-one" in state["users"])}]}}}',
    )
    assert source != before
    host.client.write_text(source)
    code, applied = host.run("apply")
    assert code == 0, applied
    assert applied["changed"] is True


def conditioned(host: Host, policy_info: str) -> None:
    before = host.client.read_text()
    source = before.replace('{**ok, "policyInfo": state["policies"][command[4]]}', policy_info)
    assert source != before
    host.client.write_text(source)


def test_condition_value_order_is_not_a_change(tmp_path: Path) -> None:
    # The real server returned one policy's Condition values in a different order between reads.
    host = Host(tmp_path)
    conditioned(
        host,
        """{**ok, "policyInfo": {"Policy": {"Statement": [{"Action": ["s3:ListBucket"], "Condition": {
            "StringLike": {"s3:prefix": sorted(["a/*", "b/*", "c/*"], reverse="legacy-one" in state["users"])}
        }}]}}}""",
    )
    code, applied = host.run("apply")
    assert code == 0, applied
    assert applied["changed"] is True


def test_condition_order_does_not_reorder_statements(tmp_path: Path) -> None:
    # Statements are sorted on their text, so a Condition's order alone could swap two of them.
    host = Host(tmp_path)
    conditioned(
        host,
        """{**ok, "policyInfo": {"Policy": {"Statement": [
            {"Action": ["s3:ListBucket"], "Condition": {"StringLike": {
                "s3:prefix": sorted(["a/*", "z/*"], reverse="legacy-one" in state["users"])}}},
            {"Action": ["s3:ListBucket"], "Condition": {"StringLike": {"s3:prefix": ["m/*", "n/*"]}}}
        ]}}}""",
    )
    code, applied = host.run("apply")
    assert code == 0, applied
    assert applied["changed"] is True


@pytest.mark.parametrize(
    "changed",
    [
        '["a/*", "b/*"] if state["users"].get("legacy-one") else ["a/*", "c/*"]',
        '["a/*", "b/*"] if state["users"].get("legacy-one") else ["a/*"]',
        '["a/*", "a/*"] if state["users"].get("legacy-one") else ["a/*", "b/*"]',
        '"a/*" if state["users"].get("legacy-one") else "b/*"',
    ],
)
def test_real_condition_value_change_still_fails(tmp_path: Path, changed: str) -> None:
    host = Host(tmp_path)
    conditioned(
        host,
        '{**ok, "policyInfo": {"Policy": {"Statement": [{"Action": ["s3:ListBucket"], '
        f'"Condition": {{"StringLike": {{"s3:prefix": {changed}}}}}}}]}}}}}}',
    )
    code, applied = host.run("apply")
    assert code == 1, applied
    assert applied["reason"] == "state outside the listed users changed during the removal"
    assert applied["removed"] == 1


def test_real_condition_key_change_still_fails(tmp_path: Path) -> None:
    host = Host(tmp_path)
    conditioned(
        host,
        """{**ok, "policyInfo": {"Policy": {"Statement": [{"Action": ["s3:ListBucket"], "Condition": {
            "StringLike" if state["users"].get("legacy-one") else "StringEquals": {"s3:prefix": ["a/*"]}
        }}]}}}""",
    )
    code, applied = host.run("apply")
    assert code == 1, applied
    assert applied["reason"] == "state outside the listed users changed during the removal"


def test_unknown_action_fails() -> None:
    completed = subprocess.run(
        [*shlex.split(host_command("check"))[:-1], "other"],
        input="{}",
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 1
    assert json.loads(completed.stdout)["reason"] == "unknown user retirement action"


@pytest.mark.parametrize(
    "fields",
    [
        {"users": ()},
        {"users": ("ab",)},
        {"users": ("-flag",)},
        {"users": ("a b c",)},
        {"users": ("legacy-one", "legacy-one")},
        {"users": ("legacy-one",), "protected": ("legacy-one",)},
        {"users": ("legacy-one",), "endpoint": "http://user:value@127.0.0.1:9001"},
        {"users": ("legacy-one",), "mc_bin_path": "/usr/../bin/mc"},
    ],
)
def test_config_refuses(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MinioUserRetirementConfig(**fields)


def test_config_requires_a_list() -> None:
    with pytest.raises(ValidationError):
        MinioUserRetirementConfig()  # type: ignore[call-arg]


def test_typed_removal_uses_stdin_and_one_managed_operation() -> None:
    result = run_deploy_fake(
        retire_minio_users,
        CONFIG,
        CREDENTIALS,
        responses={**fakehost.UBUNTU, host_command("check"): ['{"pending":true}']},
    )
    assert result.succeeded, result.error
    assert len(result.mutating_changed_ops) == 1
    assert len([op for op in result.ops if op.changed and op.read_only]) == 1
    assert not result.uploads
    assert result.executed_commands == [host_command("apply"), host_command("verify")]
    assert all(ROOT_VALUE not in command for command in result.executed_commands)
    assert all(PROTECTED_VALUE not in command for command in result.executed_commands)
    assert any(ROOT_VALUE in stdin for _, stdin in result.stdin)


def test_typed_repeat_changes_nothing_and_keeps_the_proof() -> None:
    result = run_deploy_fake(
        retire_minio_users,
        CONFIG,
        CREDENTIALS,
        responses={**fakehost.UBUNTU, host_command("check"): ['{"pending":false}']},
    )
    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert result.executed_commands == [host_command("verify")]


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        ('{"refused":"the admin alias is not healthy"}', "the admin alias is not healthy"),
        ('{"refused":"<script>"}', "Cannot prove"),
        ('{"refused":1}', "Cannot prove"),
        ('{"pending":1}', "Cannot prove"),
        ('{"pending":false,"foreign":true}', "Cannot prove"),
        ("not json", "Cannot prove"),
    ],
)
def test_typed_refusal_runs_nothing_and_names_the_reason(answer: str, message: str) -> None:
    result = run_deploy_fake(
        retire_minio_users,
        CONFIG,
        CREDENTIALS,
        responses={**fakehost.UBUNTU, host_command("check"): [answer]},
    )
    assert result.error is not None
    assert message in str(result.error)
    assert result.executed_commands == []


@pytest.mark.parametrize("secret_name", ["fixture-root", PROTECTED_VALUE])
def test_typed_secret_protected_name_refuses_before_the_host(secret_name: str) -> None:
    result = run_deploy_fake(
        retire_minio_users,
        MinioUserRetirementConfig(users=(secret_name,)),
        CREDENTIALS,
        responses={**fakehost.UBUNTU},
    )
    assert result.error is not None
    assert "protected" in str(result.error)
    assert result.executed_commands == []
    assert secret_name not in str(result.error)


def test_failed_probe_refuses() -> None:
    result = run_deploy_fake(
        retire_minio_users,
        CONFIG,
        CREDENTIALS,
        responses={**fakehost.UBUNTU, host_command("check"): {"success": False, "stderr": "synthetic"}},
    )
    assert result.error is not None
    assert result.executed_commands == []


def test_normal_deploy_never_reaches_the_component() -> None:
    root = Path(__file__).parents[1] / "src/ops_deploy/services/minio"
    for name in ("deploy.py", "__init__.py", "render.py", "config.py", "policy_rollback.py"):
        assert "user_retirement" not in (root / name).read_text()
