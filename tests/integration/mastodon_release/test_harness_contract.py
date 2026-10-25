"""Local checks of fixture construction; these do not claim real Linux execution."""

from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).parent


def load_harness() -> Any:
    spec = importlib.util.spec_from_file_location("mastodon_linux_harness", HERE / "harness.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_candidate_contract_reads_both_real_git_migration_trees(tmp_path: Path) -> None:
    harness = load_harness()
    harness.fixture(tmp_path, "4.0.5", "24.17")
    (tmp_path / "Gemfile.lock").write_text("fixture source contract only\n")
    (tmp_path / "yarn.lock").write_text("fixture source contract only\n")
    post = tmp_path / "db/post_migrate/20250103000000_post.rb"
    post.parent.mkdir()
    post.write_text("# candidate post migration\n")
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    commit = harness.git_commit(tmp_path, "candidate fixture")
    cfg = harness.config(tmp_path, tmp_path.as_uri(), "HEAD")
    assert cfg["source_commit"] == commit
    assert cfg["migration_versions"] == ["20250101000000", "20250103000000"]
    assert "db/post_migrate/20250103000000_post.rb" in cfg["source_tracked_paths"]
    assert set(cfg["source_files"]) == {"Gemfile.lock", "yarn.lock", "package.json", ".ruby-version", ".nvmrc"}
    assert cfg["runtime_tool_commits"]["ruby_build"] == harness.RUBY_BUILD


def test_host_runner_refuses_before_provisioning_outside_owned_vm() -> None:
    env = dict(os.environ, GITHUB_ACTIONS="false", RUNNER_ENVIRONMENT="")
    result = subprocess.run(["bash", str(HERE / "run.sh")], env=env, capture_output=True, check=False)
    assert result.returncode != 0
    assert b"OWNED_VM_PROVISION_START" not in result.stdout


def test_direct_harness_rejects_self_hosted_before_destructive_steps(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = load_harness()
    monkeypatch.setattr(harness.os, "getuid", lambda: 0)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    with pytest.raises(SystemExit, match="self-hosted runner forbidden"):
        harness.assert_owned_vm()


@pytest.mark.parametrize("flags", [[], ["-O"]])
def test_direct_execution_guards_survive_optimization(flags: list[str]) -> None:
    import sys

    code = (
        "import os,runpy,sys; "
        "module=runpy.run_path(sys.argv[1]); os.getuid=lambda:0; "
        "os.environ['GITHUB_ACTIONS']='true'; os.environ['RUNNER_ENVIRONMENT']='self-hosted'; "
        "module['assert_owned_vm']()"
    )
    result = subprocess.run(
        [sys.executable, *flags, "-c", code, str(HERE / "harness.py")], capture_output=True, check=False
    )
    assert result.returncode != 0
    assert b"self-hosted runner forbidden" in result.stderr


def test_marker_is_private_exclusive_and_preserves_umask(tmp_path: Path) -> None:
    import stat

    harness = load_harness()
    marker = tmp_path / "marker.json"
    previous = os.umask(0o027)
    try:
        harness.create_vm_marker(marker, "123", "fixture-machine")
        after = os.umask(0o027)
        assert after == 0o027
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600
        with pytest.raises(FileExistsError):
            harness.create_vm_marker(marker, "456", "other-machine")
    finally:
        os.umask(previous)


def test_operation_invariants_survive_optimization() -> None:
    import sys

    code = (
        "import runpy,sys; module=runpy.run_path(sys.argv[1]); "
        "module['services'].__globals__['command']=lambda *args:'inactive'; module['services']()"
    )
    result = subprocess.run(
        [sys.executable, "-O", "-c", code, str(HERE / "harness.py")], capture_output=True, check=False
    )
    assert result.returncode != 0
    assert b"AssertionError" in result.stderr


@pytest.mark.parametrize("existing", ["absent", "empty", "nonempty", "symlink"])
def test_image_nvm_leaf_preserved_without_deleting_or_following(tmp_path: Path, existing: str) -> None:
    import json

    harness = load_harness()
    home = tmp_path / "home"
    home.mkdir()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = home / ".nvm"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "untouched").write_text("keep outside target")
    if existing == "symlink":
        target.symlink_to(outside, target_is_directory=True)
    elif existing != "absent":
        target.mkdir()
        if existing == "nonempty":
            (target / "keep").write_text("preserve actual bytes")
    saved = harness.preserve_runner_nvm(home, evidence, os.getuid())
    proof = json.loads((evidence / "image-nvm.json").read_text())
    assert not target.exists()
    assert not target.is_symlink()
    assert (outside / "untouched").read_text() == "keep outside target"
    if existing == "absent":
        assert saved is None
        assert proof["present"] is False
    else:
        assert saved is not None
        assert saved.name == proof["preserved_as"]
        if existing == "symlink":
            assert saved.is_symlink()
            assert proof["entries"] == []
        elif existing == "nonempty":
            assert (saved / "keep").read_text() == "preserve actual bytes"


def test_image_nvm_refuses_unverified_home_owner(tmp_path: Path) -> None:
    harness = load_harness()
    with pytest.raises(SystemExit, match="HOME must belong"):
        harness.preserve_runner_nvm(tmp_path, tmp_path, os.getuid() + 1000)


def test_diagnostic_upload_permissions_survive_missing_journal(tmp_path: Path) -> None:
    import stat

    import yaml

    workflow = yaml.load(
        (HERE.parents[2] / ".github/workflows/mastodon-release-integration.yml").read_text(), Loader=yaml.BaseLoader
    )
    steps = workflow["jobs"]["real-linux"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Capture diagnostic service state")
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    journal = tmp_path / "journal"
    script = script.replace("/var/tmp/mastodon-release-evidence", '"$TEST_EVIDENCE"')
    script = script.replace("/tmp/mastodon-journal.txt", '"$TEST_JOURNAL"')
    fake_sudo = 'sudo() { if [[ "$1" == journalctl ]]; then echo "No service journal" >&2; return 1; fi; "$@"; }\n'
    result = subprocess.run(
        ["bash", "-e", "-c", fake_sudo + script],
        env=dict(os.environ, TEST_EVIDENCE=str(evidence), TEST_JOURNAL=str(journal)),
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "No service journal" in (evidence / "journal.log").read_text()
    assert stat.S_IMODE(evidence.stat().st_mode) & 0o005 == 0o005


def test_command_failure_reports_real_tool_stdout_without_fixture_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    import sys

    harness = load_harness()
    monkeypatch.setattr(harness, "HOME", tmp_path)
    private_value = "generated-vapid-value-for-test"
    (tmp_path / "vapid.json").write_text(json.dumps({"vapid_private_key": private_value}))
    script = (
        "import sys; print('YN0028: lockfile would be created'); "
        "print('DB_PASS=fixture-database-only'); print('" + private_value + "'); "
        "print('Authorization: Bearer fixture-only',file=sys.stderr); sys.exit(17)"
    )
    with pytest.raises(RuntimeError) as error:
        harness.command(sys.executable, "-c", script)
    output = str(error.value)
    assert "failed (17)" in output
    assert "YN0028: lockfile would be created" in output
    assert "DB_PASS=" not in output
    assert "Authorization" not in output
    assert "fixture-database-only" not in output
    assert private_value not in output


@pytest.mark.parametrize("metadata", ["missing", "invalid", "directory"])
def test_bad_diagnostic_metadata_preserves_primary_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, metadata: str
) -> None:
    import sys

    harness = load_harness()
    monkeypatch.setattr(harness, "HOME", tmp_path)
    if metadata == "invalid":
        (tmp_path / "vapid.json").write_text("not json")
    elif metadata == "directory":
        (tmp_path / "vapid.json").mkdir()
    with pytest.raises(RuntimeError, match=r"failed \(19\)") as error:
        harness.command(sys.executable, "-c", "import sys; print('original tool failure'); sys.exit(19)")
    assert "tool output withheld" in str(error.value)
    assert "original tool failure" not in str(error.value)


def test_tool_failure_output_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = load_harness()
    monkeypatch.setattr(harness, "HOME", tmp_path)
    (tmp_path / "vapid.json").write_text("{}")
    output = harness.fixture_failure_output("x" * 10000, "y" * 10000)
    assert len(output) <= 4020


def test_fixture_vapid_keys_are_valid_private_and_exclusive(tmp_path: Path) -> None:
    import json
    import stat
    from base64 import urlsafe_b64decode

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    harness = load_harness()
    target = tmp_path / "vapid.json"
    harness.generate_fixture_keys(target)
    values = json.loads(target.read_text())
    private = urlsafe_b64decode(values["vapid_private_key"] + "=")
    public = urlsafe_b64decode(values["vapid_public_key"] + "===")
    key = ec.derive_private_key(int.from_bytes(private, "big"), ec.SECP256R1())
    assert key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint) == public
    assert len(private) == 32
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    before = target.read_bytes()
    with pytest.raises(FileExistsError):
        harness.generate_fixture_keys(target)
    assert target.read_bytes() == before


def test_service_commands_start_in_accessible_home_outside_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = load_harness()
    home, controller, build = (tmp_path / name for name in ("service-home", "controller", "build"))
    for path in (home, controller, build):
        path.mkdir()
    monkeypatch.setattr(harness, "HOME", home)
    real_run = subprocess.run

    def execute_without_uid_switch(argv: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        # Ordinary tests cannot switch UID. Preserve the actual env/Bash command
        # and process cwd; only remove runuser's privilege-switch prefix.
        assert argv[:4] == ["runuser", "-u", "mastodon", "--"]
        return real_run(argv[4:], **options)

    monkeypatch.setattr(harness.subprocess, "run", execute_without_uid_switch)
    monkeypatch.chdir(controller)
    try:
        controller.chmod(0)
        output = harness.command(
            "bash", "-c", 'set -e; pushd "$1" >/dev/null; popd >/dev/null; pwd -P', "fixture", str(build), user=True
        )
    finally:
        controller.chmod(0o700)
    assert output == str(home.resolve())


def test_service_environment_ignores_runner_hooks_and_cache_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    import sys

    harness = load_harness()
    home = tmp_path / "service-home"
    home.mkdir()
    monkeypatch.setattr(harness, "HOME", home)
    marker = tmp_path / "foreign-hook-executed"
    hook = tmp_path / "runner-bash-env"
    hook.write_text('touch "' + str(marker) + '"\n')
    inherited = ("GEM_HOME", "GEM_PATH", "NPM_CONFIG_PREFIX", "COREPACK_HOME", "TMPDIR", "GIT_CONFIG_GLOBAL")
    for name in (*inherited, "HOME", "RBENV_ROOT", "NVM_DIR"):
        monkeypatch.setenv(name, str(tmp_path / "foreign-runner-root"))
    monkeypatch.setenv("BASH_ENV", str(hook))
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    real_run = subprocess.run

    def execute_without_uid_switch(argv: list[str], **options: Any) -> subprocess.CompletedProcess[str]:
        assert argv[:4] == ["runuser", "-u", "mastodon", "--"]
        return real_run(argv[4:], **options)

    monkeypatch.setattr(harness.subprocess, "run", execute_without_uid_switch)
    keys = ("HOME", "RBENV_ROOT", "NVM_DIR", "CI", "GITHUB_ACTIONS", "BASH_ENV", *inherited)
    code = "import json,os; print(json.dumps({key:os.environ.get(key) for key in " + repr(keys) + "}))"
    output = harness.command("bash", "-c", 'exec "$1" -c "$2"', "fixture", sys.executable, code, user=True)
    actual = json.loads(output)
    assert actual["HOME"] == str(home)
    assert actual["RBENV_ROOT"] == str(home / ".rbenv")
    assert actual["NVM_DIR"] == str(home / ".nvm")
    assert actual["CI"] == actual["GITHUB_ACTIONS"] == "true"
    assert all(actual[name] is None for name in ("BASH_ENV", *inherited))
    assert not marker.exists()
