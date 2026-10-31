"""Disposable Linux proof: actual file/lock/helper/stdin, synthetic IAM only."""

from __future__ import annotations

import copy
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import ops_deploy
from ops_deploy.services.daybook_work_source_access import (
    DaybookWorkSourceAccessConfig,
    DaybookWorkSourceCredentials,
    install_daybook_work_source_access,
)
from ops_deploy.testing import run_deploy_ssh

ACCESS = "OwnedNativeWorkSource12345"
SECRET = "owned-native-fixture-only-" * 3
MUTATIONS = {"policy create", "user add", "policy attach"}


def main() -> None:
    assert os.geteuid() == 0
    assert sys.platform == "linux"
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    run_id = os.environ["GITHUB_RUN_ID"]
    sha = os.environ["IMPLEMENTATION_SHA"]
    assert run_id.isdigit()
    assert re.fullmatch(r"[0-9a-f]{40}", sha)
    source = Path(__file__).resolve().parents[3]
    root = Path("/var/lib/daybook-work-source-fixture-" + run_id)
    evidence = Path("/var/tmp/daybook-work-source-evidence")
    assert not root.exists()
    evidence.mkdir(mode=0o700)
    installed = Path(ops_deploy.__file__).resolve().parent
    direct = json.loads(importlib.metadata.distribution("ops-deploy").read_text("direct_url.json") or "{}")
    assert direct.get("vcs_info", {}).get("commit_id") == sha
    assert not direct.get("dir_info", {}).get("editable", False)
    tracked = subprocess.check_output(
        ["git", "-C", str(source), "ls-tree", "-r", "--name-only", sha, "src/ops_deploy/"], text=True
    ).splitlines()
    resources = {}
    for name in tracked:
        member = name.removeprefix("src/ops_deploy/")
        raw = subprocess.check_output(["git", "-C", str(source), "show", sha + ":" + name])
        assert (installed / member).read_bytes() == raw
        assert not (installed / member).is_symlink()
        resources[member] = hashlib.sha256(raw).hexdigest()
    actual = {
        str(p.relative_to(installed))
        for p in installed.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }
    assert actual == set(resources)
    (evidence / "installed.json").write_text(
        json.dumps({"implementation": sha, "direct_url": direct, "resources": resources}, indent=2)
    )
    phases: list[dict[str, Any]] = []
    try:
        root.mkdir(mode=0o700)
        fake = root / "mc"
        shutil.copyfile(Path(__file__).with_name("fake_mc.py"), fake)
        fake.chmod(0o700)
        iam = root / "iam.json"
        commands = root / "commands.jsonl"
        initial = {"access": ACCESS, "secret": SECRET, "policy": None, "user": None, "mappings": None}
        iam.write_text(json.dumps(initial))
        cfg = DaybookWorkSourceAccessConfig(mc_bin=str(fake), state_dir=str(root))
        credentials = DaybookWorkSourceCredentials(access_key=ACCESS, secret_key=SECRET)

        def run(name: str, success: bool, expected_managed: int | None = None) -> list[str]:
            commands.write_text("")
            result = run_deploy_ssh(
                install_daybook_work_source_access, cfg, credentials=credentials, host_name="@local", host_data={}
            )
            trace = [json.loads(line)["command"] for line in commands.read_text().splitlines()]
            phase = {
                "name": name,
                "succeeded": result.succeeded,
                "managed": result.mutating_changed_ops,
                "mc_commands": trace,
            }
            phases.append(phase)
            (evidence / "phases.json").write_text(json.dumps(phases, indent=2))
            assert result.succeeded is success, name
            if expected_managed is not None:
                assert len(result.mutating_changed_ops) == expected_managed, phase
            assert ACCESS not in repr(result.ops)
            assert SECRET not in repr(result.ops)
            return trace

        trace = run("fresh", True, 2)  # Existing fixture root; helper put + managed provisioning.
        assert [c for c in trace if c in MUTATIONS] == ["policy create", "user add", "policy attach"]
        marker = root / "identity.json"
        protected = [marker, root / "policy.json", root / "provision.lock"]
        for path in protected:
            assert path.stat().st_uid == 0
            assert path.stat().st_mode & 0o777 == 0o600
        baseline = {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in protected}
        assert run("repeat", True, 1) == ["policy info", "user info", "policy entities"]
        assert baseline == {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in protected}
        healthy = json.loads(iam.read_text())
        for name in ("disabled", "policy_drift", "extra_attachment", "foreign_marker"):
            state = copy.deepcopy(healthy)
            if name == "disabled":
                state["user"]["userStatus"] = "disabled"
            elif name == "policy_drift":
                state["policy"]["Statement"][1]["Action"].append("s3:PutObject")
            elif name == "extra_attachment":
                state["mappings"]["userMappings"][0]["policies"].append("foreign")
            else:
                marker.unlink()
            iam.write_text(json.dumps(state))
            before = iam.read_bytes()
            expected = {
                "disabled": ["policy info", "user info"],
                "policy_drift": ["policy info"],
                "extra_attachment": ["policy info", "user info", "policy entities"],
                "foreign_marker": ["policy info", "user info"],
            }
            assert run(name, False) == expected[name]
            assert iam.read_bytes() == before
            if name == "foreign_marker":
                marker.write_bytes(baseline["identity.json"][0])
                marker.chmod(0o600)
        # Real partial user creation must not be silently upserted by another invocation.
        marker.unlink()
        state = copy.deepcopy(initial)
        state["fault"] = "policy attach"
        iam.write_text(json.dumps(state))
        assert run("partial_attach_failure", False) == [
            "policy info",
            "user info",
            "policy create",
            "policy info",
            "user add",
            "policy attach",
        ]
        assert not marker.exists()
        state = json.loads(iam.read_text())
        state.pop("fault")
        iam.write_text(json.dumps(state))
        assert run("partial_repeat_refusal", False) == ["policy info", "user info"]
        assert not marker.exists()
    finally:
        if root.exists():
            shutil.rmtree(root)  # Exact newly-created disposable owned fixture, never inventory.
        (evidence / "cleanup.json").write_text(json.dumps({"owned_fixture_absent": not root.exists()}))


if __name__ == "__main__":
    main()
