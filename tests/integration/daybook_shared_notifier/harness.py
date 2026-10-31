"""Disposable hosted Linux proof of the fixed notifier installer, with no send."""

from __future__ import annotations

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

from pyinfra.api import DeployError

import ops_deploy
from ops_deploy.services.daybook_voice_memo_attention_notifier import (
    DaybookVoiceMemoAttentionNotifierConfig,
    DaybookVoiceMemoAttentionNotifierPins,
    install_daybook_voice_memo_attention_notifier,
)
from ops_deploy.testing import run_deploy_ssh

SCRIPT = Path("/usr/local/libexec/daybook-attention-notify.py")
CONFIG = Path("/etc/daybook-attention-notify.json")
KEYS = Path("/root/.ssh/authorized_keys")


def owned_hardlink(source: Path, destination: Path) -> None:
    assert source.stat().st_dev == destination.parent.stat().st_dev
    os.link(source, destination)


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
    root = Path("/tmp/daybook-shared-notifier-fixture-" + run_id)
    evidence = Path("/var/tmp/daybook-shared-notifier-evidence")
    assert not root.exists()
    # Never borrow or replace preexisting server authorization/config/script.
    assert all(not os.path.lexists(path) for path in (SCRIPT, CONFIG, KEYS))
    created_directories = [p for p in (SCRIPT.parent, KEYS.parent) if not p.exists()]
    for path in (SCRIPT.parent, KEYS.parent):
        if path.exists():
            assert path.is_dir()
            assert not path.is_symlink()
            assert path.stat().st_uid == path.stat().st_gid == 0
            assert path.stat().st_mode & 0o777 == (0o700 if path == KEYS.parent else 0o755)
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
        script = root / "work_notify.py"
        sentinel = root / "application-was-executed"
        script.write_text(
            "from pathlib import Path\nPath("
            + repr(str(sentinel))
            + ").touch()\nraise RuntimeError('must not execute')\n"
        )
        cfg = DaybookVoiceMemoAttentionNotifierConfig(script_src=str(script))
        pins = DaybookVoiceMemoAttentionNotifierPins(
            public_key="ssh-ed25519 " + "A" * 68 + " owned", native_host="owned-host", recipient="123456789"
        )

        def snapshot() -> dict[str, Any]:
            return {str(p): (p.read_bytes(), p.stat()) for p in (SCRIPT, CONFIG, KEYS)}

        def run(name: str, success: bool) -> None:
            result = None
            try:
                result = run_deploy_ssh(
                    install_daybook_voice_memo_attention_notifier, cfg, pins=pins, host_name="@local", host_data={}
                )
                succeeded = result.succeeded
            except DeployError:
                succeeded = False
            phase = {
                "name": name,
                "succeeded": succeeded,
                "managed": [] if result is None else result.mutating_changed_ops,
                "source_not_executed": not sentinel.exists(),
                "private_values_not_in_operation_repr": result is None or "123456789" not in repr(result.ops),
            }
            phases.append(phase)
            (evidence / "phases.json").write_text(json.dumps(phases, indent=2))
            assert succeeded is success, phase
            assert not sentinel.exists()
            assert phase["private_values_not_in_operation_repr"]
            if success:
                assert result is not None
                assert len(result.mutating_changed_ops) == 1
            else:
                assert result is None or not result.mutating_changed_ops

        run("fresh", True)
        for path, mode in ((SCRIPT, 0o755), (CONFIG, 0o600), (KEYS, 0o600)):
            assert path.stat().st_uid == path.stat().st_gid == 0
            assert path.stat().st_mode & 0o777 == mode
        baseline = snapshot()
        run("repeat", True)
        assert snapshot() == baseline
        CONFIG.write_text(json.dumps(json.loads(CONFIG.read_text()), indent=4) + "\n\n")
        KEYS.write_bytes(b"# owned administrator\nssh-ed25519 " + b"B" * 68 + b" admin\n\n" + KEYS.read_bytes())
        protected = snapshot()
        script.write_text(script.read_text() + "# bounded shared source update\n")
        run("formatted_config_admin_keys_source_update", True)
        assert snapshot()[str(CONFIG)] == protected[str(CONFIG)]
        assert snapshot()[str(KEYS)] == protected[str(KEYS)]
        assert SCRIPT.read_bytes() == script.read_bytes()
        baseline = snapshot()
        for fault in ("conflicting_key_options", "foreign_notifier_marker", "symlink", "hardlink", "invalid_source"):
            if fault == "conflicting_key_options":
                KEYS.write_text("ssh-ed25519 " + "A" * 68 + " owned\n")
            elif fault == "foreign_notifier_marker":
                KEYS.write_text("ssh-ed25519 " + "C" * 68 + " daybook-attention-notifier\n")
            elif fault == "symlink":
                CONFIG.unlink()
                CONFIG.symlink_to(root / "absent-config")
            elif fault == "hardlink":
                owned_hardlink(CONFIG, root / "config-link")
            else:
                script.write_text("if invalid syntax")
            protected_script = SCRIPT.read_bytes(), SCRIPT.stat()
            run(fault, False)
            assert (SCRIPT.read_bytes(), SCRIPT.stat()) == protected_script
            if os.path.lexists(CONFIG):
                CONFIG.unlink()
            if (root / "config-link").exists():
                (root / "config-link").unlink()
            CONFIG.write_bytes(baseline[str(CONFIG)][0])
            CONFIG.chmod(0o600)
            KEYS.write_bytes(baseline[str(KEYS)][0])
            KEYS.chmod(0o600)
        assert len(phases) == 8
    finally:
        for path in (SCRIPT, CONFIG, KEYS):
            if os.path.lexists(path):
                path.unlink()
        for path in reversed(created_directories):
            path.rmdir()
        if root.exists():
            shutil.rmtree(root)
        (evidence / "cleanup.json").write_text(
            json.dumps(
                {
                    "owned_fixture_absent": not root.exists(),
                    "owned_fixed_files_absent": all(not os.path.lexists(p) for p in (SCRIPT, CONFIG, KEYS)),
                    "owned_created_directories_absent": all(not p.exists() for p in created_directories),
                }
            )
        )


if __name__ == "__main__":
    main()
