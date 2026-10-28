"""Owned Inbox root/GUI/SFTP component proof; inert app and fake credentials.

Fixed original declarations/templates have paired-role tests. This mechanism
case substitutes only owned paths, unique labels and inert prerequisite tools
via explicit fixture-only model copies. No inventory or private app is reached.
"""

from __future__ import annotations

import importlib.resources
import json
import os
import plistlib
import pwd
import stat
import sys
import types
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import patch

import paramiko
import pytest
from daybook_resources_native_fixture import provenance, wait
from daybook_runtime_native_fixture import snapshot
from mac_apps_owned import OwnedMac, command, job_pid
from pyinfra.api.exceptions import ConnectError, PyinfraError
from pyinfra.connectors.ssh import SSHConnector

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime.decision import InstalledRuntime
from ops_deploy.services.daybook_operations_runtime.render import render_resource
from ops_deploy.services.daybook_voice_memo_inbox import DaybookInboxConfig, install_daybook_inbox
from ops_deploy.services.daybook_voice_memo_inbox.config import PACKAGE
from ops_deploy.services.daybook_voice_memo_inbox.deploy import component_payload
from ops_deploy.services.daybook_voice_memo_inbox.render import SECRET_DEFAULTS
from ops_deploy.testing import run_deploy_ssh

APP = """import sys,time

def main():
    if sys.argv[1:3] == ['voice-memos','--help']:
        print('owned inert help')
        return 0
    if sys.argv[1:3] == ['operations','serve']:
        time.sleep(10000)
        return 0
    raise RuntimeError('owned fixture forbids other app commands')
"""


def helpers() -> dict[str, Any]:
    result = {}
    for name, package, resource in (
        ("ops_daybook_observer", "ops_deploy.services.daybook_operations_runtime", "files/runtime_state.py"),
        ("ops_inbox_filesystem", "ops_deploy.services.daybook_sessions", "files/resources_host.py"),
        ("ops_inbox_controls", PACKAGE, "files/inbox_controls.py"),
        ("ops_inbox_python", PACKAGE, "files/inbox_python.py"),
        ("ops_inbox_transfer", PACKAGE, "files/inbox_transfer.py"),
    ):
        module = types.ModuleType(name)
        sys.modules[name] = module
        body = importlib.resources.files(package).joinpath(resource).read_bytes()
        exec(compile(body, "<installed-owned-helper>", "exec"), module.__dict__)
        result[name] = module
    return result


def configuration(
    owned: Any, source: SourceTree, bundle: Path, uv: str, actor: Any, *, name: str
) -> DaybookInboxConfig:
    base = owned.root / name / "Daybook"
    install = base / "voice-memo-inbox"
    home = owned.root / name / "home"
    state = home / ".local/state/daybook/voice-memo-inbox"
    logs = state / "logs"
    label = "com.example.ops-mac-apps.inbox-" + name + "." + owned.suffix
    long_label = "com.example.ops-mac-apps.inbox-long-" + name + "." + owned.suffix
    # Validate original semantic declarations first. Only disposable locations,
    # unique labels and prerequisite paths are then substituted, with no product flag.
    cfg = DaybookInboxConfig(
        daybook_voice_memo_inbox_enabled=True,
        daybook_voice_memo_inbox_service_user=actor.pw_name,
        daybook_voice_memo_inbox_repo_ref=source.commit,
        daybook_voice_memo_inbox_repo_bundle_src=str(bundle),
        daybook_voice_memo_inbox_bucket="owned-inert-bucket",
        daybook_voice_memo_inbox_s3_endpoint_url="https://unused.example.test",
        daybook_voice_memo_inbox_long_label_enabled=False,
    )
    values = {
        "install_root": str(install),
        "checkout_path": str(install / "daybook"),
        "repo_bundle_path": str(install / "source.bundle"),
        "uv_bin": uv,
        "python_install_dir": str(base / "python"),
        "python": str(install / "daybook/.venv/bin/python"),
        "service_home": str(home),
        "runtime_dir": str(state),
        "source_dir": str(home / "owned-recordings"),
        "activation_marker_path": str(install / "activation.json"),
        "activation_proof_path": str(install / "activation-proven.json"),
        "state_path": str(state / "ledger.json"),
        "lock_path": str(state / "ingest.lock"),
        "log_dir": str(logs),
        "stdout_log": str(logs / "ingest.log"),
        "stderr_log": str(logs / "ingest.err.log"),
        "long_stdout_log": str(logs / "ingest-long.log"),
        "long_stderr_log": str(logs / "ingest-long.err.log"),
        "credential_dir": str(home / ".config/daybook-voice-memo-inbox"),
        "credential_path": str(home / ".config/daybook-voice-memo-inbox/credentials.json"),
        "policy_path": str(install / "policy.json"),
        "launchd_label": label,
        "long_launchd_label": long_label,
        "plist_path": str(home / "Library/LaunchAgents" / (label + ".plist")),
        "long_plist_path": str(home / "Library/LaunchAgents" / (long_label + ".plist")),
        "ffprobe_path": "/usr/bin/true",
        "ffmpeg_path": "/usr/bin/true",
    }
    return cfg.model_copy(update={"daybook_voice_memo_inbox_" + key: value for key, value in values.items()})


def source_tree(owned: OwnedMac, uv: str) -> tuple[SourceTree, Path]:
    root = owned.root / "controller-source"
    (root / "src/daybook").mkdir(parents=True)
    (root / "src/daybook/__init__.py").write_text("# owned inert Daybook\n")
    (root / "src/daybook/cli.py").write_text(APP)
    (root / "pyproject.toml").write_text(
        '[project]\nname="daybook"\nversion="0.0.0"\nrequires-python=">=3.14.7"\n'
        'dependencies=[]\n[build-system]\nrequires=["uv_build>=0.13.0,<0.14.0"]\nbuild-backend="uv_build"\n'
    )
    (root / ".python-version").write_text("3.14.7\n")
    (root / ".gitignore").write_text(".venv/\n__pycache__/\n*.pyc\n")
    environment = {
        **os.environ,
        "HOME": "/var/root",
        "UV_PYTHON_INSTALL_DIR": str(owned.root / "fixture-python"),
        "UV_PYTHON_PREFERENCE": "only-managed",
        "UV_CACHE_DIR": str(owned.root / "fixture-cache"),
    }
    command(uv, "--directory", str(root), "lock", "--python", "3.14.7", env=environment)
    command("/usr/bin/git", "-C", str(root), "init", "--quiet", "--template=")
    command("/usr/bin/git", "-C", str(root), "add", ".")
    command(
        "/usr/bin/git",
        "-C",
        str(root),
        "-c",
        "user.name=Owned",
        "-c",
        "user.email=owned@example.test",
        "commit",
        "-qm",
        "owned",
    )
    revision = command("/usr/bin/git", "-C", str(root), "rev-parse", "HEAD").stdout.strip()
    command("/usr/bin/git", "-C", str(root), "update-ref", "refs/remotes/origin/main", revision)
    bundle = owned.root / "controller-source.bundle"
    command("/usr/bin/git", "-C", str(root), "bundle", "create", str(bundle), "refs/remotes/origin/main")
    return SourceTree(root, revision), bundle


def run(
    owned: OwnedMac,
    transport: dict[str, Any],
    cfg: DaybookInboxConfig,
    secret: dict[str, str],
    source: SourceTree,
    bundle: Path,
    *,
    fail_setup: bool = False,
    runtime: Any = None,
    installed: Any = None,
) -> tuple[Any, dict[str, Any]]:
    counts: dict[str, Any] = {"attempted": 0, "succeeded": 0, "paths": []}
    original = paramiko.SFTPClient.putfo

    def observed(client: Any, stream: Any, destination: str, *args: Any, **kwargs: Any) -> Any:
        path = Path(destination)
        assert path.parent.parent == Path("/private/var/tmp")
        assert path.parent.name.startswith("ops-deploy-daybook-inbox-")
        assert path.name == "source.bundle"
        counts["attempted"] += 1
        counts["paths"].append(destination)
        result = original(client, stream, destination, *args, **kwargs)
        counts["succeeded"] += 1
        return result

    with ExitStack() as stack:
        stack.enter_context(patch.object(paramiko.SFTPClient, "putfo", observed))
        injected = None
        if fail_setup:
            injected = stack.enter_context(
                patch.object(
                    SSHConnector, "get_file_transfer_connection", side_effect=ConnectError("owned setup fault")
                )
            )
        result = run_deploy_ssh(
            install_daybook_inbox,
            cfg,
            secret,
            source,
            bundle,
            host_name="owned-inbox",
            host_data=transport,
            runtime=runtime,
            installed=installed,
            _env={"UV_CACHE_DIR": str(owned.root / "fixture-cache")},
        )
        if injected is not None:
            counts["setup_attempted"] = injected.call_count
    assert all(not Path(path).parent.exists() for path in counts["paths"])
    return result, counts


def phase(owned: OwnedMac, name: str, result: Any, counts: dict[str, Any]) -> None:
    owned.report.setdefault("phases", {})[name] = {
        "succeeded": result.succeeded,
        "managed": len(result.mutating_changed_ops),
        "ops": [
            {"name": row.name, "changed": row.changed, "read_only": row.read_only, "succeeded": row.succeeded}
            for row in result.ops
        ],
        "sftp": counts,
        "error_type": type(result.error).__name__ if result.error is not None else None,
    }


def main() -> None:
    owned = OwnedMac("daybook-inbox")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        uv = str(Path(sys.executable).parent / "uv")
        assert command(uv, "--version").stdout.startswith("uv 0.13.5 ")
        source, bundle = source_tree(owned, uv)
        transport = owned.ssh_transport()
        secret = dict.fromkeys(SECRET_DEFAULTS, "UNUSABLE-OWNED-CREDENTIAL")
        cfg = configuration(owned, source, bundle, uv, actor, name="healthy")
        for label in (cfg.daybook_voice_memo_inbox_launchd_label, cfg.daybook_voice_memo_inbox_long_launchd_label):
            owned.adopt_gui_label(actor.pw_uid, label)
        first, counts = run(owned, transport, cfg, secret, source, bundle)
        phase(owned, "first", first, counts)
        assert first.succeeded, str(first.error)
        assert len(first.mutating_changed_ops) == 8
        assert counts["succeeded"] == 1
        python = Path(cfg.daybook_voice_memo_inbox_python)
        info = python.lstat()
        assert stat.S_ISREG(info.st_mode)
        assert info.st_uid == 0
        assert info.st_nlink == 1
        assert stat.S_IMODE(info.st_mode) == 0o755
        paths = [Path(cfg.daybook_voice_memo_inbox_install_root), Path(cfg.daybook_voice_memo_inbox_service_home)]
        before = snapshot(paths)
        repeat, counts = run(owned, transport, cfg, secret, source, bundle)
        phase(owned, "repeat", repeat, counts)
        assert repeat.succeeded
        assert not repeat.mutating_changed_ops
        assert counts["attempted"] == 0
        assert snapshot(paths) == before
        owned.report["repeat_metadata_exact"] = True

        modules = helpers()
        data = component_payload(cfg, secret, source, bundle, uid=actor.pw_uid)
        probes = modules["ops_daybook_observer"].NativeProbes(data)
        modules["ops_inbox_controls"].NativeControls()
        python_helper = modules["ops_inbox_python"]
        pinned, _digest = python_helper.interpreter_source(data, probes)
        prior = snapshot([python])
        with pytest.raises(python_helper.InboxPythonError, match=r"^inbox_python_source_changed_during_copy$"):
            python_helper.copy_interpreter(data, pinned, b"\x00" * 32, probes)
        assert snapshot([python]) == prior
        assert not list(python.parent.glob(".inbox-python-*"))
        pth = Path(data["checkout"]) / ".venv/owned-unsafe.pth"
        pth.write_bytes(b'raise AssertionError("must not execute")\n')
        pth.chmod(0o666)
        with pytest.raises(python_helper.InboxPythonError, match=r"^inbox_python_root_inputs_unsafe$"):
            python_helper.require_root_inputs(data)
        pth.unlink()
        owned.report["root_faults"] = [
            "copy digest refusal preserves destination and removes temp",
            "writable pth refused before UV",
        ]

        runtime = DaybookRuntimeConfig(user=actor.pw_name, revision=source.commit).model_copy(
            update={
                "home": PurePosixPath(cfg.daybook_voice_memo_inbox_service_home),
                "install_root": PurePosixPath(cfg.daybook_voice_memo_inbox_install_root),
                "python": PurePosixPath(cfg.daybook_voice_memo_inbox_python),
                "importer_policy": PurePosixPath(cfg.daybook_voice_memo_inbox_policy_path),
                "label": cfg.daybook_voice_memo_inbox_launchd_label,
                "plist": PurePosixPath(cfg.daybook_voice_memo_inbox_plist_path),
                "policy": PurePosixPath(cfg.daybook_voice_memo_inbox_install_root + "/owned-operations.json"),
            }
        )
        profile_path = Path(str(runtime.policy))
        profile = json.loads(render_resource(runtime, "policy.json.j2"))
        profile["enabled"] = True  # Explicit owned baseline, not a migrated real profile.
        profile_path.write_text(json.dumps(profile, sort_keys=True) + "\n")
        profile_path.chmod(0o644)
        profile_before = snapshot([profile_path])
        plist = Path(cfg.daybook_voice_memo_inbox_plist_path)
        body = render_resource(runtime, "runtime.plist.j2")
        assert plistlib.loads(body.encode())["ProgramArguments"][-4:-2] != ["voice-memos", "ingest"]
        modules["ops_inbox_filesystem"].put_resource(
            {"path": str(plist), "owner": "root", "group": "wheel", "mode": 0o644, "content": body}
        )
        service = "gui/" + str(actor.pw_uid) + "/" + runtime.label
        command("/bin/launchctl", "enable", service)
        command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(plist))
        wait(lambda: job_pid(service) is not None)
        pid = job_pid(service)
        before = snapshot(paths)
        current, counts = run(
            owned, transport, cfg, secret, source, bundle, runtime=runtime, installed=InstalledRuntime(True, True, True)
        )
        phase(owned, "enabled-current", current, counts)
        assert current.succeeded
        assert not current.mutating_changed_ops
        assert counts["attempted"] == 0
        assert job_pid(service) == pid
        assert snapshot(paths) == before
        drift, counts = run(
            owned,
            transport,
            cfg,
            dict.fromkeys(SECRET_DEFAULTS, "OTHER-UNUSABLE-OWNED"),
            source,
            bundle,
            runtime=runtime,
            installed=InstalledRuntime(True, True, True),
        )
        phase(owned, "enabled-drift-refusal", drift, counts)
        assert not drift.succeeded
        assert not drift.ops
        assert drift.error is not None
        assert "original operations runtime stop/update" in str(drift.error)
        assert counts["attempted"] == 0
        assert job_pid(service) == pid
        assert snapshot(paths) == before
        command("/bin/launchctl", "bootout", service)
        wait(lambda: job_pid(service) is None)
        command("/bin/launchctl", "disable", service)
        owned.report["keeper_pid_preserved_during_current_and_refusal"] = pid
        assert json.loads(profile_path.read_text())["enabled"] is True
        stopped, counts = run(
            owned,
            transport,
            cfg,
            dict.fromkeys(SECRET_DEFAULTS, "OTHER-UNUSABLE-OWNED"),
            source,
            bundle,
            runtime=runtime,
            installed=InstalledRuntime(True, True, True),
        )
        phase(owned, "stopped-enabled-resource-handoff", stopped, counts)
        assert stopped.succeeded
        assert len(stopped.mutating_changed_ops) == 1
        assert counts["attempted"] == 0
        assert snapshot([profile_path]) == profile_before
        assert json.loads(profile_path.read_text())["enabled"] is True
        assert job_pid(service) is None
        owned.report["stopped_enabled_handoff"] = (
            "Original disabled-first set verified; profile enabled unchanged; subsequent cutover not invoked."
        )

        fault_cfg = configuration(owned, source, bundle, uv, actor, name="setup-fault")
        for label in (
            fault_cfg.daybook_voice_memo_inbox_launchd_label,
            fault_cfg.daybook_voice_memo_inbox_long_launchd_label,
        ):
            owned.adopt_gui_label(actor.pw_uid, label)
        failed, counts = run(owned, transport, fault_cfg, secret, source, bundle, fail_setup=True)
        phase(owned, "sftp-setup-fault", failed, counts)
        assert type(failed.error) is PyinfraError
        assert str(failed.error) == "No hosts remaining!"
        assert counts["setup_attempted"] == 1
        assert counts["attempted"] == 0
        assert not Path(fault_cfg.daybook_voice_memo_inbox_checkout_path).exists()
        assert not list(Path("/private/var/tmp").glob("ops-deploy-daybook-inbox-*"))
        owned.report.update(
            status="passed",
            scope=(
                "Owned root/GUI/real-SSH component mechanisms only; paired original declarations separate. "
                "No private app, inventory, recordings, ledger, activation, model or TCC/auth changes."
            ),
            fixture_source=source.commit,
        )
    except BaseException as error:
        failure = error
    finally:
        reset = []
        for service in owned.labels:
            if service.startswith("gui/"):
                command("/bin/launchctl", "bootout", service, check=False)
                command("/bin/launchctl", "enable", service, check=False)
                reset.append(service)
        owned.report["owned_unique_disabled_entries_reset_enabled"] = reset
        owned.report["cleanup_limit"] = (
            "OS may retain unique enabled rows; controller/workflow setup outside fixture root. "
            "No global zero-I/O claim."
        )
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
