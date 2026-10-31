"""Exercise unchanged original provisioning decisions with owned fake MinIO state."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import types
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def module() -> types.ModuleType:
    path = str(files("ops_deploy.services.daybook_voice_memo_attention_reader").joinpath("files/provision_reader.py"))
    spec = importlib.util.spec_from_file_location("owned_attention_reader", path)
    assert spec is not None
    assert spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def request_value(tmp_path: Path) -> dict[str, str]:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    return {
        "access_key": "OwnedAttentionReader123456",
        "secret_key": "owned-secret-" * 4,
        "mc_bin": "/owned/mc",
        "alias": "local",
        "state_dir": str(root),
    }


class MC:
    def __init__(self, module: Any, request: dict[str, str]) -> None:
        self.module = module
        self.request = request
        self.policy: dict[str, Any] | None = None
        self.user: dict[str, Any] | None = None
        self.mappings: dict[str, Any] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fault = ""

    def call(self, command: str, **kwargs: Any) -> Any:
        self.calls.append((command, kwargs))
        if command == self.fault:
            raise self.module.Refused("owned_fault")
        if command == "policy info":
            return None if self.policy is None else {"policyInfo": {"Policy": copy.deepcopy(self.policy)}}
        if command == "user info":
            return copy.deepcopy(self.user)
        if command == "policy entities":
            return {"result": copy.deepcopy(self.mappings)}
        if command == "policy create":
            self.policy = json.loads(Path(kwargs["path"]).read_text())
        elif command == "user add":
            assert kwargs["stdin"] == self.request["access_key"] + "\n" + self.request["secret_key"] + "\n"
            self.user = {
                "accessKey": self.request["access_key"],
                "userStatus": "enabled",
                "memberOf": [],
                "policyName": "",
            }
        elif command == "policy attach":
            assert self.user is not None
            self.user["policyName"] = self.module.POLICY_NAME
            self.mappings = {
                "userMappings": [{"user": self.request["access_key"], "policies": [self.module.POLICY_NAME]}]
            }
        else:
            raise AssertionError(command)
        return {"status": "success"}

    def mutations(self) -> list[str]:
        return [command for command, _ in self.calls if command in {"policy create", "user add", "policy attach"}]


def create(module: Any, request: dict[str, str]) -> MC:
    mc = MC(module, request)
    assert module.provision(request, mc) == {"changed": True, "category": "exact_reader_created"}
    return mc


def test_fresh_exact_order_private_marker_then_genuine_unchanged_repeat(
    module: Any, request_value: dict[str, str]
) -> None:
    mc = create(module, request_value)
    assert mc.mutations() == ["policy create", "user add", "policy attach"]
    root = Path(request_value["state_dir"])
    marker = root / "identity.json"
    before = marker.read_bytes(), marker.stat()
    assert json.loads(before[0]) == module.credentials(request_value)
    for path in (marker, root / "policy.json", root / "provision.lock"):
        assert path.stat().st_uid == os.getuid()
        assert path.stat().st_mode & 0o777 == 0o600
    mc.calls.clear()
    assert module.provision(request_value, mc) == {"changed": False, "category": "exact_reader_verified"}
    assert [command for command, _ in mc.calls] == ["policy info", "user info", "policy entities"]
    assert not mc.mutations()
    assert marker.read_bytes() == before[0]
    assert marker.stat() == before[1]


@pytest.mark.parametrize(
    "fault",
    [
        "disabled",
        "group",
        "policy_name",
        "extra_attachment",
        "broader_policy",
        "unrestricted_listing",
        "wrong_prefix",
        "broader_resource",
        "missing_policy",
        "missing_user",
        "changed_secret",
        "foreign_marker",
    ],
)
def test_existing_drift_refuses_without_reactivation_or_iam_mutation(
    module: Any, request_value: dict[str, str], fault: str
) -> None:
    mc = create(module, request_value)
    assert mc.user is not None
    assert mc.policy is not None
    assert mc.mappings is not None
    if fault == "disabled":
        mc.user["userStatus"] = "disabled"
    elif fault == "group":
        mc.user["memberOf"] = ["foreign"]
    elif fault == "policy_name":
        mc.user["policyName"] = "foreign"
    elif fault == "extra_attachment":
        mc.mappings["userMappings"][0]["policies"].append("foreign")
    elif fault == "broader_policy":
        mc.policy["Statement"][1]["Action"].append("s3:PutObject")
    elif fault == "unrestricted_listing":
        del mc.policy["Statement"][0]["Condition"]
    elif fault == "wrong_prefix":
        mc.policy["Statement"][0]["Condition"]["StringEquals"]["s3:prefix"] = ["Inbox/"]
    elif fault == "broader_resource":
        mc.policy["Statement"][1]["Resource"] = ["arn:aws:s3:::obsidian/*"]
    elif fault == "missing_policy":
        mc.policy = None
    elif fault == "missing_user":
        mc.user = None
    elif fault == "changed_secret":
        request_value["secret_key"] += "different"
    else:
        (Path(request_value["state_dir"]) / "identity.json").unlink()
    snapshot = copy.deepcopy((mc.policy, mc.user, mc.mappings))
    mc.calls.clear()
    with pytest.raises(module.Refused):
        module.provision(request_value, mc)
    assert not mc.mutations()
    assert (mc.policy, mc.user, mc.mappings) == snapshot


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "public_mode"])
def test_unsafe_owned_marker_refuses_before_mc(module: Any, request_value: dict[str, str], unsafe: str) -> None:
    mc = create(module, request_value)
    marker = Path(request_value["state_dir"]) / "identity.json"
    if unsafe == "symlink":
        saved = marker.with_name("saved.json")
        marker.rename(saved)
        marker.symlink_to(saved)
    elif unsafe == "hardlink":
        os.link(marker, marker.with_name("other.json"))
    else:
        marker.chmod(0o644)
    mc.calls.clear()
    with pytest.raises(module.Refused, match="unsafe_ownership_marker"):
        module.provision(request_value, mc)
    assert not mc.calls


def test_partial_creation_is_retained_and_never_silently_upserted(module: Any, request_value: dict[str, str]) -> None:
    mc = MC(module, request_value)
    mc.fault = "policy attach"
    with pytest.raises(module.Refused, match="owned_fault"):
        module.provision(request_value, mc)
    assert mc.user is not None
    assert not (Path(request_value["state_dir"]) / "identity.json").exists()
    mc.fault = ""
    mc.calls.clear()
    with pytest.raises(module.Refused, match="existing_identity_not_owned"):
        module.provision(request_value, mc)
    assert not mc.mutations()


def test_mc_remote_identifier_argv_and_secret_stdin_are_original(
    module: Any, request_value: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def run(argv: list[str], **kwargs: Any) -> types.SimpleNamespace:
        calls.append((argv, kwargs))
        return types.SimpleNamespace(returncode=0, stdout='{"status":"success"}', stderr="")

    monkeypatch.setattr(module.subprocess, "run", run)
    mc = module.MC(request_value["mc_bin"], "local")
    mc.call("user info", identity=request_value["access_key"])
    mc.call("user add", stdin=request_value["access_key"] + "\n" + request_value["secret_key"] + "\n")
    assert calls[0][0][-1] == request_value["access_key"]
    assert all(request_value["secret_key"] not in str(argv) for argv, _ in calls)
    assert calls[1][1]["input"].endswith(request_value["secret_key"] + "\n")


@pytest.mark.parametrize(("response", "code"), [("not-json", 0), ('{"status":"error"}', 0), ('{"error":{}}', 1)])
def test_mc_ambiguous_response_never_proves_absence(
    module: Any, request_value: dict[str, str], monkeypatch: pytest.MonkeyPatch, response: str, code: int
) -> None:
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=code, stdout=response, stderr="private output"),
    )
    with pytest.raises(module.Refused):
        module.MC(request_value["mc_bin"], "local").call(
            "user info", identity=request_value["access_key"], missing="XMinioAdminNoSuchUser"
        )


def test_real_original_helper_stdin_and_fake_mc_subprocesses(tmp_path: Path) -> None:
    import shutil
    import subprocess
    import sys

    root = tmp_path / "native-mechanism"
    root.mkdir(mode=0o700)
    fake = root / "mc"
    shutil.copyfile(Path(__file__).parent / "integration/daybook_attention_reader/fake_mc.py", fake)
    fake.chmod(0o700)
    access, secret = "OwnedNativeSubprocess123", "owned-subprocess-fixture-" * 3
    state = {"access": access, "secret": secret, "policy": None, "user": None, "mappings": None}
    (root / "iam.json").write_text(json.dumps(state))
    request = {
        "access_key": access,
        "secret_key": secret,
        "mc_bin": str(fake),
        "alias": "local",
        "state_dir": str(root),
    }
    helper = files("ops_deploy.services.daybook_voice_memo_attention_reader").joinpath("files/provision_reader.py")
    for changed in (True, False):
        result = subprocess.run(
            [sys.executable, str(helper)], input=json.dumps(request), text=True, capture_output=True, timeout=30
        )
        assert result.returncode == 0, result.stderr + result.stdout
        assert json.loads(result.stdout)["changed"] is changed
        assert access not in result.stdout + result.stderr
        assert secret not in result.stdout + result.stderr
    trace = [json.loads(line)["command"] for line in (root / "commands.jsonl").read_text().splitlines()]
    assert trace[-3:] == ["policy info", "user info", "policy entities"]
    assert trace.count("user add") == 1


def test_prefix_policy_has_only_the_declared_reader_capabilities(module: Any) -> None:
    assert module.POLICY_NAME == "daybook-voice-memo-attention-read"
    assert module.POLICY == {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": ["arn:aws:s3:::obsidian"],
                "Condition": {"StringEquals": {"s3:prefix": ["Inbox/Voice Memos/"]}},
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::obsidian/Inbox/Voice Memos/*"],
            },
        ],
    }
