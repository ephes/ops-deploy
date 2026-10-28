"""Real Git/bundle guards with synthetic uv/process boundaries, no inventory."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import runpy
import shutil
import subprocess
import sys
import types
import uuid
from collections.abc import Iterator
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

import pytest

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime import guards
from ops_deploy.services.daybook_sessions.source import source_command, source_payload, verify_controller_bundle
from tests.test_daybook_sessions_resources import config

RUNTIME = files("ops_deploy.services.daybook_operations_runtime")
for name, resource in (
    ("ops_daybook_observer", "files/runtime_state.py"),
    ("ops_daybook_stage", "files/runtime_stage.py"),
):
    if name == "ops_daybook_stage":
        sys.modules["ops_daybook_guards"] = guards
    module = types.ModuleType(name)
    module.__dict__.update(runpy.run_path(str(RUNTIME.joinpath(resource))))
    sys.modules[name] = module
MODULE = runpy.run_path(str(files("ops_deploy.services.daybook_sessions").joinpath("files/source_host.py")))


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        },
    ).stdout.strip()


@pytest.fixture
def checkout(tmp_path: Path) -> Iterator[tuple[dict[str, Any], Path, SourceTree]]:
    root = tmp_path.resolve()
    source = root / "controller"
    source.mkdir()
    git(source, "init", "--quiet", "--template=", "-b", "main")
    (source / "src/daybook").mkdir(parents=True)
    (source / "src/daybook/__init__.py").write_text("# synthetic source never imported\n")
    (source / "pyproject.toml").write_text('[project]\nname="owned-daybook"\nversion="0.0.0"\n')
    git(source, "add", ".")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "old")
    dest = root / "checkout"
    subprocess.run(["/usr/bin/git", "clone", "--quiet", str(source), str(dest)], check=True)
    (source / "src/daybook/__init__.py").write_text("# synthetic desired Main\n")
    git(source, "add", ".")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "new")
    commit = git(source, "rev-parse", "HEAD")
    bundle = root / "controller.bundle"
    git(source, "bundle", "create", str(bundle), "refs/heads/main")
    user = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    cfg = config(
        daybook_sessions_service_user=user,
        daybook_sessions_service_group=group,
        daybook_sessions_repo_ref=commit,
        daybook_sessions_checkout_path=str(dest),
        daybook_sessions_repo_bundle_path=str(root / "target.bundle"),
        daybook_sessions_uv_bin=str(root / "owned-uv"),
        daybook_sessions_launchd_path="/usr/bin:/bin",
        daybook_sessions_repo_update=False,
        daybook_sessions_launchd_scope="user",
    )
    data = source_payload(cfg, SourceTree(source, commit))
    try:
        yield data, bundle, SourceTree(source, commit)
    finally:
        if data.get("transfer_dir"):
            shutil.rmtree(data["transfer_dir"], ignore_errors=True)


def stage_transfer(data: dict[str, Any], content: Path | bytes) -> None:
    parent = "/private/var/tmp" if sys.platform == "darwin" else "/tmp"
    data["transfer_dir"] = parent + "/ops-deploy-daybook-source-" + uuid.uuid4().hex
    data["bundle_path"] = data["transfer_dir"] + "/source.bundle"
    MODULE["prepare_transfer"](data)
    Path(data["bundle_path"]).write_bytes(content.read_bytes() if isinstance(content, Path) else content)
    Path(data["bundle_path"]).chmod(0o600)
    data["staged_bundle"] = True


class Probes:
    def __init__(self, data: dict[str, Any]) -> None:
        self.native = MODULE["SourceProbes"](data)
        self.data = data
        self.account = self.native.account
        self.ready = False
        self.fail_sync = False
        self.syncs: list[list[str]] = []

    def run(self, argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "/usr/bin/pgrep":
            raise AssertionError("Checkout-only Sessions convergence must not query unrelated supervisors")
        return cast(subprocess.CompletedProcess[bytes], self.native.run(argv, **kwargs))

    def git(self, *args: str) -> bytes:
        return cast(bytes, self.native.git(*args))

    def git_command(self, *args: str) -> list[str]:
        return cast(list[str], self.native.git_command(*args))

    def runtime_current(self) -> bool:
        return self.ready

    def managed(self, argv: list[str]) -> None:
        if argv[0] == self.data["uv_bin"]:
            self.syncs.append(argv)
            if self.fail_sync:
                raise MODULE["SourceError"]("sessions_source_command_failed")
            self.ready = True
        else:
            self.native.managed(argv)


def snapshot(path: Path) -> dict[str, tuple[Any, ...]]:
    return {
        str(p.relative_to(path)): (
            s.st_ino,
            s.st_uid,
            s.st_gid,
            s.st_mode,
            s.st_size,
            s.st_mtime_ns,
            s.st_ctime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None,
        )
        for p in [path, *path.rglob("*")]
        for s in [p.lstat()]
    }


def test_real_missing_commit_bundle_first_and_repeat_with_actual_git_bytes(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, source = checkout
    probes = Probes(data)
    assert MODULE["inspect"](data, probes)["needs_bundle"] is True
    stage_transfer(data, bundle)
    MODULE["apply"](data, probes)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert (Path(data["checkout"]) / "src/daybook/__init__.py").read_bytes() == (
        source.path / "src/daybook/__init__.py"
    ).read_bytes()
    assert not Path(data["bundle_path"]).exists()
    assert len(probes.syncs) == 1
    before = snapshot(Path(data["checkout"]))
    assert MODULE["inspect"](data, probes)["current"] is True
    data["staged_bundle"] = False
    MODULE["apply"](data, probes)
    assert snapshot(Path(data["checkout"])) == before
    assert len(probes.syncs) == 1


def test_checkout_only_source_change_never_queries_unrelated_supervisors(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, source = checkout
    probes = Probes(data)
    stage_transfer(data, bundle)
    MODULE["apply"](data, probes)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert len(probes.syncs) == 1
    assert not Path(data["transfer_dir"]).exists()


def test_status_can_plan_explicit_source_parent_preparation_without_creating_it(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, source = checkout
    root = source.path.parent / "explicitly-prepared-parent"
    data.update(allow_create=True, checkout=str(root / "checkout"), python=str(root / "checkout/.venv/bin/python"))
    probes = Probes(data)
    state = MODULE["inspect"](data, probes, planning=True)
    assert state["current"] is False
    assert state["needs_bundle"] is True
    assert not root.exists()
    with pytest.raises(RuntimeError, match="sessions_source_parent_required"):
        MODULE["inspect"](data, probes)
    assert not root.exists()
    root.mkdir()  # explicitly managed preparation boundary in the full role
    stage_transfer(data, bundle)
    MODULE["apply"](data, probes)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert MODULE["inspect"](data, probes)["current"] is True


@pytest.mark.parametrize("fault", ["untracked", "tracked", "linked", "missing"])
def test_original_no_fetch_shape_cleanliness_guards_preserve_tree(
    checkout: tuple[dict[str, Any], Path, SourceTree],
    fault: str,
) -> None:
    data, _, _ = checkout
    probes = Probes(data)
    root = Path(data["checkout"])
    if fault == "untracked":
        (root / "untracked").write_text("owned")
    elif fault == "tracked":
        data["force"] = False
        (root / "src/daybook/__init__.py").write_text("owned dirty")
    elif fault == "linked":
        other = root.with_name("actual")
        root.rename(other)
        root.symlink_to(other, target_is_directory=True)
    else:
        shutil.rmtree(root)
    expected = {
        "untracked": "untracked_files_refused",
        "tracked": "tracked_changes_refused",
        "linked": "linked_checkout",
        "missing": "preexisting_checkout_required",
    }[fault]
    with pytest.raises(RuntimeError, match=r"^sessions_source_" + expected + "$"):
        MODULE["inspect"](data, probes)
    assert probes.syncs == []


def test_bad_bundle_and_failed_uv_are_genuine_failures_with_bundle_cleanup(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, _ = checkout
    probes = Probes(data)
    stage_transfer(data, b"owned wrong bundle")
    before = snapshot(Path(data["checkout"]))
    with pytest.raises(RuntimeError, match=r"^sessions_source_bundle_mismatch$"):
        MODULE["apply"](data, probes)
    assert snapshot(Path(data["checkout"])) == before
    assert not Path(data["bundle_path"]).exists()
    stage_transfer(data, bundle)
    probes.fail_sync = True
    with pytest.raises(RuntimeError, match=r"^sessions_source_command_failed$"):
        MODULE["apply"](data, probes)
    assert not Path(data["bundle_path"]).exists()
    # Original checkout precedes sync: a failed build is not a successful or
    # rolled-back source deployment. No invented rollback is claimed.
    assert MODULE["inspect"](data, probes)["current"] is False


def test_controller_bundle_and_manifest_bind_same_resolved_main(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    _data, bundle, source = checkout
    verify_controller_bundle(bundle, source.commit)
    with pytest.raises(ValueError, match="declared commit"):
        verify_controller_bundle(bundle, "0" * 40)
    cfg = config(daybook_sessions_repo_ref="0" * 40)
    with pytest.raises(ValueError, match="same once-resolved Main"):
        source_payload(cfg, source)


def test_actual_encoded_source_entrypoint_refuses_invalid_request_without_body() -> None:
    import shlex

    argv = shlex.split(source_command("status"))
    argv[0] = sys.executable
    private = "UNUSABLE-OWNED-SOURCE-INPUT"
    result = subprocess.run(argv, input=json.dumps({"private": private}), capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "sessions_source_failed"
    assert private not in result.stdout + result.stderr


def test_fresh_checkout_uses_controller_bundle_without_host_network(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, source = checkout
    shutil.rmtree(data["checkout"])
    data["allow_create"] = True
    stage_transfer(data, bundle)
    probes = Probes(data)
    MODULE["apply"](data, probes)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert git(Path(data["checkout"]), "remote", "get-url", "origin") == data["repo_url"]
    assert not Path(data["bundle_path"]).exists()
    assert MODULE["inspect"](data, probes)["current"] is True
    before = snapshot(Path(data["checkout"]))
    MODULE["apply"](data, probes)
    assert snapshot(Path(data["checkout"])) == before
    assert len(probes.syncs) == 1


@pytest.mark.parametrize(
    "argument",
    [
        "--project=/outside",
        "--directory=/outside",
        "--active",
        "-p",
        "--python=3.15.0",
        "-p3.15",
        "--python-preference=system",
        "--no-managed-python",
        "--managed-python",
        "--config-file=/other",
        "--no-config",
    ],
)
def test_sync_arguments_cannot_escape_declared_target_or_python(
    checkout: tuple[dict[str, Any], Path, SourceTree],
    argument: str,
) -> None:
    _data, _bundle, source = checkout
    cfg = config(
        daybook_sessions_repo_ref=source.commit,
        daybook_sessions_uv_sync_args=["sync", "--frozen", "--no-dev", "--python", "3.14.7", argument],
    )
    with pytest.raises(ValueError, match="declared checkout and Python"):
        source_payload(cfg, source)


@pytest.mark.parametrize(("current", "delegate"), [(True, False), (False, True), (False, False)])
def test_normal_source_api_defers_reconcile_readiness_until_execution(
    checkout: tuple[dict[str, Any], Path, SourceTree],
    current: bool,
    delegate: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ops_deploy.services.daybook_sessions import install_sessions_source
    from ops_deploy.services.daybook_sessions import source as source_module
    from ops_deploy.testing import run_deploy_fake

    data, bundle, source = checkout
    cfg = config(
        daybook_sessions_repo_ref=source.commit,
        daybook_sessions_checkout_path=data["checkout"],
        daybook_sessions_repo_bundle_path=data["bundle_path"],
    )
    state = {
        "current": current,
        "needs_bundle": not current,
        "delegate": delegate,
        "reconcile_ready": False,
    }
    # The generic fake recorder deliberately refuses stream fact stdin. Keep
    # production's protected stream path; this test covers operation planning.
    # Actual encoded CLI/owned SSH tests cover the real input/transport boundary.
    monkeypatch.setattr(source_module, "inspect_sessions_source", lambda *_: state)
    run = run_deploy_fake(install_sessions_source, cfg, source, bundle, responses={"uname -s": ["Darwin"]})
    assert run.succeeded, run.error
    assert len(run.uploaded_paths) == int(not current)
    assert len(run.mutating_changed_ops) == (0 if current else 3)
    assert run.fish_unsafe_commands == []


def test_transfer_prep_never_adopts_existing_directory_and_publish_checks_mode(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, _ = checkout
    stage_transfer(data, bundle)
    before = Path(data["transfer_dir"]).stat()
    with pytest.raises(FileExistsError):
        MODULE["prepare_transfer"](data)
    assert Path(data["transfer_dir"]).stat().st_ctime_ns == before.st_ctime_ns
    Path(data["bundle_path"]).chmod(0o644)
    with pytest.raises(RuntimeError, match=r"^sessions_source_transfer_file_invalid$"):
        MODULE["publish_transfer"](data, Probes(data))
    MODULE["cleanup_transfer"](data)
    assert not Path(data["transfer_dir"]).exists()


def test_failed_upload_uses_existing_state_callback_cleanup_without_relabeling_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io
    from types import SimpleNamespace

    from pyinfra.api.operation import OperationMeta

    from ops_deploy.services.daybook_sessions import source as api

    handlers: list[Any] = []
    recorded = []
    monkeypatch.setattr(api, "host", SimpleNamespace(state=SimpleNamespace(add_callback_handler=handlers.append)))
    prep, upload, apply = (OperationMeta(name, True) for name in ("prep", "upload", "apply"))
    api.register_transfer_cleanup({"transfer_dir": "/owned-only-metadata"}, prep, upload, apply)
    callback = handlers[0]

    def operation(_host: object, key: str) -> object:
        return SimpleNamespace(operation_meta={"prep": prep, "upload": upload, "apply": apply}[key])

    state = SimpleNamespace(get_op_data_for_host=operation)

    def shell(command: str, **kwargs: Any) -> tuple[bool, object]:
        assert isinstance(kwargs["_stdin"], io.StringIO)
        recorded.append(json.loads(kwargs["_stdin"].getvalue()))
        return True, object()

    target = SimpleNamespace(run_shell_command=shell)
    callback.operation_host_error(state, target, "upload")
    assert recorded == []  # prep did not succeed; never remove an unowned path
    callback.operation_host_success(state, target, "prep")
    callback.operation_host_error(state, target, "upload")
    assert recorded == [{"transfer_dir": "/owned-only-metadata"}]
    callback.operation_host_error(state, target, "upload")
    assert len(recorded) == 1


@pytest.mark.parametrize("failure", ["bundle", "fetch", "origin"])
def test_fresh_unborn_checkout_recovers_after_original_failed_attempt(
    checkout: tuple[dict[str, Any], Path, SourceTree],
    failure: str,
) -> None:
    data, bundle, source = checkout
    shutil.rmtree(data["checkout"])
    data["allow_create"] = True
    probes = Probes(data)
    original_managed = probes.managed
    if failure in {"fetch", "origin"}:

        def managed(argv: list[str]) -> None:
            if (failure == "fetch" and "fetch" in argv) or (failure == "origin" and "remote" in argv):
                raise MODULE["SourceError"]("sessions_source_command_failed")
            original_managed(argv)

        probes.managed = managed  # type: ignore[method-assign]
    stage_transfer(data, b"owned invalid bundle" if failure == "bundle" else bundle)
    with pytest.raises(RuntimeError, match=r"sessions_source_(bundle_mismatch|command_failed)"):
        MODULE["apply"](data, probes)
    assert Path(data["checkout"], ".git").is_dir()
    assert not Path(data["transfer_dir"]).exists()
    assert MODULE["inspect"](data, probes)["current"] is False
    probes.managed = original_managed  # type: ignore[method-assign]
    stage_transfer(data, bundle)
    MODULE["apply"](data, probes)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert MODULE["inspect"](data, probes)["current"] is True
    assert git(Path(data["checkout"]), "remote", "get-url", "origin") == data["repo_url"]
    assert not Path(data["transfer_dir"]).exists()


def test_update_mode_preserves_unrelated_untracked_files(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, source = checkout
    data["allow_create"] = True
    extra = Path(data["checkout"], "unrelated")
    extra.write_text("owned metadata only")
    before = extra.stat()
    stage_transfer(data, bundle)
    probes = Probes(data)
    MODULE["apply"](data, probes)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert (extra.stat().st_ino, extra.stat().st_mtime_ns, extra.read_text()) == (
        before.st_ino,
        before.st_mtime_ns,
        "owned metadata only",
    )
    assert MODULE["inspect"](data, probes)["current"] is True


@pytest.mark.parametrize(
    ("loaded", "marker", "allowed"),
    [(0, "true", False), (113, "false", False), (113, "", False), (113, "true", True), (113, "disabled", True)],
)
def test_source_drift_requires_original_system_reconcile_disabled_unloaded(
    checkout: tuple[dict[str, Any], Path, SourceTree],
    loaded: int,
    marker: str,
    allowed: bool,
) -> None:
    data, _bundle, _source = checkout
    data["require_reconcile_quiescence"] = True
    probes = Probes(data)
    original_run = probes.run
    commands: list[list[str]] = []

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "/bin/launchctl":
            commands.append(argv)
            if argv[1] == "print":
                return subprocess.CompletedProcess(argv, loaded, b"", b"")
            return subprocess.CompletedProcess(
                argv, 0, ('"de.wersdoerfer.daybook.weeknotes-reconcile" => ' + marker + "\n").encode(), b""
            )
        return original_run(argv, **kwargs)

    probes.run = run  # type: ignore[method-assign]
    before = snapshot(Path(data["checkout"]))
    state = MODULE["inspect"](data, probes)
    assert state["current"] is False
    assert state["reconcile_ready"] is allowed
    if allowed:
        MODULE["require_reconcile_quiescent"](state)
    else:
        with pytest.raises(RuntimeError, match=r"^sessions_source_requires_reconcile_disabled_unloaded$"):
            MODULE["require_reconcile_quiescent"](state)
    assert commands
    assert all(argv[1] in {"print", "print-disabled"} for argv in commands)
    assert snapshot(Path(data["checkout"])) == before
    assert probes.syncs == []


def test_no_fetch_refuses_unborn_repository_without_adoption(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, _bundle, _source = checkout
    shutil.rmtree(data["checkout"])
    subprocess.run(["/usr/bin/git", "init", "--quiet", "--template=", data["checkout"]], check=True)
    before = snapshot(Path(data["checkout"]))
    with pytest.raises(RuntimeError, match=r"^sessions_source_preexisting_head_required$"):
        MODULE["inspect"](data, Probes(data))
    assert snapshot(Path(data["checkout"])) == before


def test_original_earlier_quiesce_can_satisfy_fresh_apply_after_status(
    checkout: tuple[dict[str, Any], Path, SourceTree],
) -> None:
    data, bundle, source = checkout
    data["require_reconcile_quiescence"] = True
    probes = Probes(data)
    original_run = probes.run
    quiesced = False

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if argv[0] == "/bin/launchctl":
            if argv[1] == "print":
                return subprocess.CompletedProcess(argv, 113 if quiesced else 0, b"", b"")
            return subprocess.CompletedProcess(argv, 0, b'"de.wersdoerfer.daybook.weeknotes-reconcile" => true\n', b"")
        return original_run(argv, **kwargs)

    probes.run = run  # type: ignore[method-assign]
    assert MODULE["inspect"](data, probes)["reconcile_ready"] is False
    before = snapshot(Path(data["checkout"]))
    stage_transfer(data, bundle)
    with pytest.raises(RuntimeError, match=r"^sessions_source_requires_reconcile_disabled_unloaded$"):
        MODULE["apply"](data, probes)
    assert snapshot(Path(data["checkout"])) == before
    assert not Path(data["transfer_dir"]).exists()
    # Represents the original earlier managed operation having completed after
    # plan-time status collection. Apply must obtain a fresh readiness state.
    quiesced = True
    stage_transfer(data, bundle)
    MODULE["apply"](data, probes)
    assert git(Path(data["checkout"]), "rev-parse", "HEAD") == source.commit
    assert not Path(data["transfer_dir"]).exists()


@pytest.mark.parametrize("failure", [True, False])
def test_bundle_upload_normalizes_only_setup_failure_into_failed_operation(failure: bool) -> None:
    from types import SimpleNamespace
    from unittest.mock import Mock

    from pyinfra.api.exceptions import ConnectError

    from ops_deploy.services.daybook_sessions.source import BundleUploadCommand

    upload = Mock(side_effect=ConnectError("unusable owned private diagnostic") if failure else None, return_value=True)
    target = SimpleNamespace(put_file=upload)
    state = SimpleNamespace(print_output=False, print_input=False)
    command = BundleUploadCommand("/owned/source.bundle", "/owned/private/target.bundle")
    assert command.execute(cast(Any, state), cast(Any, target), {}) is (not failure)
    upload.assert_called_once_with(
        "/owned/source.bundle",
        "/owned/private/target.bundle",
        remote_temp_filename=None,
        print_output=False,
        print_input=False,
    )
