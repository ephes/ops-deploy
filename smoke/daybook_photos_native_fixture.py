"""Disposable Photos mechanism: root source, real GUI UV/resources and SFTP.

Model copies substitute only owned paths/unique labels after validating the
original declaration. The library is an empty owned directory. No real Photos,
ledger, media, model, credentials, inventory or TCC surface is reached.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import pwd
import stat
import sys
import uuid
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

import paramiko
from daybook_resources_native_fixture import provenance, wait
from daybook_runtime_native_fixture import snapshot
from mac_apps_owned import OwnedMac, command, job_pid
from pyinfra.api import deploy
from pyinfra.api.exceptions import ConnectError, PyinfraError
from pyinfra.connectors.ssh import SSHConnector

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_photos_offload import (
    DaybookPhotosOffloadConfig,
    install_daybook_photos_offload,
)
from ops_deploy.services.daybook_photos_offload import deploy as api
from ops_deploy.services.daybook_photos_offload.payload import component_payload
from ops_deploy.testing import run_deploy_ssh


def configuration(owned: OwnedMac, source: SourceTree, bundle: Path, uv: str, actor: Any) -> DaybookPhotosOffloadConfig:
    install = owned.root / "Daybook/photos-offload"
    home = owned.root / "home"
    runtime = home / ".daybook/photos-offload"
    config = home / ".config/daybook-photos-offload"
    label = "com.example.ops-mac-apps.photos." + owned.suffix
    cfg = DaybookPhotosOffloadConfig(
        daybook_photos_offload_service_user=actor.pw_name,
        daybook_photos_offload_repo_ref=source.commit,
        daybook_photos_offload_repo_bundle_src=str(bundle),
        daybook_photos_offload_repo_url="/Library/Application Support/Daybook/photos-offload/source.bundle",
    )
    paths = {
        "service_home": str(home),
        "checkout_path": str(install / "daybook"),
        "checkout_attestation_path": str(install / "managed-v1"),
        "repo_bundle_path": str(install / "source.bundle"),
        "repo_url": str(install / "source.bundle"),
        "venv_path": str(install / "daybook/.venv"),
        "uv_bin": uv,
        "library_path": str(home / "Pictures/Owned.photoslibrary"),
        "runtime_dir": str(runtime),
        "state_path": str(runtime / "ledger.json"),
        "config_dir": str(config),
        "launcher_path": str(config / "reconcile.sh"),
        "log_dir": str(runtime / "logs"),
        "stdout_log": str(runtime / "logs/reconcile.log"),
        "stderr_log": str(runtime / "logs/reconcile.err.log"),
        "launchd_label": label,
        "launchd_plist_path": str(home / "Library/LaunchAgents" / (label + ".plist")),
    }
    return cfg.model_copy(update={"daybook_photos_offload_" + key: value for key, value in paths.items()})


def source_tree(owned: OwnedMac, uv: str) -> tuple[SourceTree, Path]:
    root = owned.root / "controller-source"
    (root / "src/daybook").mkdir(parents=True)
    (root / "src/daybook/__init__.py").write_text("raise AssertionError('Photos fixture must never import app')\n")
    (root / "pyproject.toml").write_text(
        '[project]\nname="owned-photos"\nversion="0.0.0"\nrequires-python=">=3.14.7"\ndependencies=[]\n'
    )
    (root / ".python-version").write_text("3.14.7\n")
    (root / ".gitignore").write_text(".venv/\n")
    environment = {
        **os.environ,
        "HOME": "/var/root",
        "UV_PYTHON_INSTALL_DIR": str(owned.root / "controller-python"),
        "UV_CACHE_DIR": str(owned.root / "controller-cache"),
        "UV_PYTHON_PREFERENCE": "only-managed",
    }
    command(uv, "--directory", str(root), "lock", "--python", "3.14.7", env=environment)
    command("/usr/bin/git", "-C", str(root), "init", "--quiet", "--template=", "-b", "main")
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
        "owned inert Photos",
    )
    return bundle_source(owned, root)


def bundle_source(owned: OwnedMac, root: Path) -> tuple[SourceTree, Path]:
    revision = command("/usr/bin/git", "-C", str(root), "rev-parse", "HEAD").stdout.strip()
    bundle = owned.root / ("controller-" + revision + ".bundle")
    command("/usr/bin/git", "-C", str(root), "bundle", "create", str(bundle), "refs/heads/main")
    return SourceTree(root, revision), bundle


def run(
    owned: OwnedMac,
    transport: dict[str, Any],
    cfg: DaybookPhotosOffloadConfig,
    source: SourceTree,
    bundle: Path,
    *,
    name: str,
    bad_digest: bool = False,
) -> Any:
    counts = {"attempted": 0, "succeeded": 0}
    paths: list[str] = []
    original_putfo = paramiko.SFTPClient.putfo
    original_payload = component_payload

    def sftp(client: Any, stream: Any, destination: str, *args: Any, **kwargs: Any) -> Any:
        path = Path(destination)
        assert path.parent.parent == Path("/private/var/tmp")
        assert path.parent.name.startswith("ops-deploy-daybook-photos-")
        assert path.name == "source.bundle"
        paths.append(destination)
        counts["attempted"] += 1
        value = original_putfo(client, stream, destination, *args, **kwargs)
        counts["succeeded"] += 1
        return value

    def payload(*args: Any, **kwargs: Any) -> dict[str, Any]:
        data = original_payload(*args, **kwargs)
        if bad_digest:
            data["bundle_sha256"] = "f" * 64
        return data

    with ExitStack() as stack:
        stack.enter_context(patch.object(paramiko.SFTPClient, "putfo", sftp))
        stack.enter_context(patch.object(api, "component_payload", payload))
        result = run_deploy_ssh(
            install_daybook_photos_offload, cfg, source, bundle, host_name="owned-photos", host_data=transport
        )
    assert all(not Path(path).parent.exists() for path in paths)
    owned.report.setdefault("phases", {})[name] = {
        "succeeded": result.succeeded,
        "managed": len(result.mutating_changed_ops),
        "ops": [
            {"name": op.name, "changed": op.changed, "read_only": op.read_only, "succeeded": op.succeeded}
            for op in result.ops
        ],
        "actual_sftp": counts,
        "transfer_cleanup": all(not Path(path).parent.exists() for path in paths),
        "error_type": type(result.error).__name__ if result.error is not None else None,
    }
    return result


def connecting_identity_case(owned: OwnedMac, transport: dict[str, Any], bundle: Path, *, fail_setup: bool) -> None:
    """Actual SDK all-flags inheritance: only the login identity may execute."""
    transfer = "/private/var/tmp/ops-deploy-daybook-photos-" + uuid.uuid4().hex
    owned.created_outside_root(Path(transfer))
    data: dict[str, Any] = {
        "transfer_dir": transfer,
        "uploaded_bundle": transfer + "/source.bundle",
        "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
    }
    seen = {"shell": 0, "upload": 0, "sftp": 0}
    flags = ("_sudo", "_doas", "_dzdo")
    users = ("_sudo_user", "_doas_user", "_dzdo_user", "_su_user")

    def assert_direct(kwargs: dict[str, Any]) -> None:
        assert all(kwargs.get(key) is False or kwargs.get(key) is None for key in flags)
        assert all(kwargs.get(key) in {"", None} for key in users)

    original_shell, original_put = SSHConnector.run_shell_command, SSHConnector.put_file
    original_sftp = paramiko.SFTPClient.putfo

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert_direct(kwargs)
        seen["shell"] += 1
        return original_shell(connector, *args, **kwargs)

    def put(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert_direct(kwargs)
        seen["upload"] += 1
        return original_put(connector, *args, **kwargs)

    def sftp(client: Any, stream: Any, destination: str, *args: Any, **kwargs: Any) -> Any:
        assert destination == data["uploaded_bundle"], "no shared temporary upload allowed"
        seen["sftp"] += 1
        return original_sftp(client, stream, destination, *args, **kwargs)

    @deploy("Owned connecting-identity handoff under every inherited privilege path")
    def handoff() -> None:
        data["transfer_uid"] = api._connecting_uid()
        prepared = api._transfer_operation(data)
        uploaded = api.upload_photos_bundle(src=str(bundle), dest=data["uploaded_bundle"])
        cleanup = api._transfer_operation(data, cleanup=True)
        api.transfer_cleanup(data, prepared, uploaded, cleanup)

    with ExitStack() as stack:
        stack.enter_context(patch.object(SSHConnector, "run_shell_command", shell))
        stack.enter_context(patch.object(SSHConnector, "put_file", put))
        stack.enter_context(patch.object(paramiko.SFTPClient, "putfo", sftp))
        injected = None
        if fail_setup:
            injected = stack.enter_context(
                patch.object(
                    SSHConnector, "get_file_transfer_connection", side_effect=ConnectError("owned setup fault")
                )
            )
        result = run_deploy_ssh(
            handoff,
            host_name="owned-all-escalation",
            host_data=transport,
            _sudo=True,
            _sudo_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
            _su_user="root",
        )
        if injected is not None:
            assert injected.call_count == 1
    assert not Path(transfer).exists()
    assert seen["shell"] >= 2
    assert seen["upload"] == 1
    if fail_setup:
        assert type(result.error) is PyinfraError
        assert str(result.error) == "No hosts remaining!"
        assert seen["sftp"] == 0
    else:
        assert result.succeeded
        assert seen["sftp"] == 1
        assert len(result.mutating_changed_ops) == 3
    owned.report.setdefault("connecting_identity_inherited_all", []).append(
        {
            "inherited": [*flags, *users],
            "actual_sdk_escalation_executed": 0,
            "observed": seen,
            "genuine_failed_setup": fail_setup,
            "failed": not result.succeeded,
            "owned_transfer_cleanup": not Path(transfer).exists(),
        }
    )


def keeper(owned: OwnedMac, actor: Any) -> tuple[str, Path, int]:
    label = "com.example.ops-mac-apps.photos-unrelated-keeper." + owned.suffix
    owned.adopt_gui_label(actor.pw_uid, label)
    plist = owned.root / "unrelated-keeper.plist"
    plist.write_bytes(plistlib.dumps({"Label": label, "ProgramArguments": ["/bin/sleep", "10000"], "RunAtLoad": True}))
    service = "gui/" + str(actor.pw_uid) + "/" + label
    command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(plist))
    wait(lambda: job_pid(service) is not None)
    pid = job_pid(service)
    assert pid is not None
    return service, plist, pid


def main() -> None:
    owned = OwnedMac("daybook-photos")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        uv = str(Path(sys.executable).parent / "uv")
        assert command(uv, "--version").stdout.startswith("uv 0.13.5 ")
        source, bundle = source_tree(owned, uv)
        cfg = configuration(owned, source, bundle, uv, actor)
        home = Path(cfg.daybook_photos_offload_service_home)
        home.mkdir(mode=0o700)
        os.chown(home, actor.pw_uid, actor.pw_gid)
        library = Path(cfg.daybook_photos_offload_library_path)
        library.mkdir(parents=True)
        # Fixture-only setup of the declared fake library, no personal contents.
        os.chown(library.parent, actor.pw_uid, actor.pw_gid)
        os.chown(library, actor.pw_uid, actor.pw_gid)
        owned.adopt_gui_label(actor.pw_uid, cfg.daybook_photos_offload_launchd_label)
        service, keeper_plist, pid = keeper(owned, actor)
        protected = snapshot([keeper_plist])
        transport = owned.ssh_transport()
        connecting_identity_case(owned, transport, bundle, fail_setup=False)
        connecting_identity_case(owned, transport, bundle, fail_setup=True)
        first = run(owned, transport, cfg, source, bundle, name="first")
        assert first.succeeded, str(first.error)
        assert len(first.mutating_changed_ops) == 7
        install = Path(cfg.daybook_photos_offload_checkout_path)
        venv = Path(cfg.daybook_photos_offload_venv_path)
        assert install.stat().st_uid == 0
        assert (install / ".git").stat().st_uid == 0
        assert venv.stat().st_uid == actor.pw_uid
        assert stat.S_IMODE(venv.stat().st_mode) == 0o700
        assert Path(cfg.daybook_photos_offload_launcher_path).stat().st_uid == actor.pw_uid
        assert job_pid(service) == pid
        assert snapshot([keeper_plist]) == protected
        before = snapshot([install.parent, home])
        repeat = run(owned, transport, cfg, source, bundle, name="repeat")
        assert repeat.succeeded
        assert not repeat.mutating_changed_ops
        assert snapshot([install.parent, home]) == before
        assert job_pid(service) == pid
        assert snapshot([keeper_plist]) == protected
        owned.report["repeat_metadata_exact"] = True

        # Existing untrusted checkout refuses before prep/upload and preserves
        # all source/environment/resource bytes and the unrelated keeper.
        attestation = Path(cfg.daybook_photos_offload_checkout_attestation_path)
        original = attestation.read_bytes()
        attestation.unlink()
        before = snapshot([install, home])
        refused = run(owned, transport, cfg, source, bundle, name="missing-attestation-refusal")
        assert not refused.succeeded
        assert not refused.ops
        assert snapshot([install, home]) == before
        attestation.write_bytes(original)
        attestation.chmod(0o600)

        # Managed root recreation, not execution of a wrong user interpreter.
        python = venv / "bin/python"
        python.unlink()
        python.symlink_to("/usr/bin/python3")
        marker = venv / "owned-stale"
        marker.write_text("owned state-free env marker")
        code_before = (install / "src/daybook/__init__.py").read_bytes()
        fixed = run(owned, transport, cfg, source, bundle, name="wrong-python-rebuild")
        assert fixed.succeeded
        assert len(fixed.mutating_changed_ops) == 1
        assert not marker.exists()
        assert (install / "src/daybook/__init__.py").read_bytes() == code_before
        assert job_pid(service) == pid
        assert snapshot([keeper_plist]) == protected

        # Original existing protected checkout Main update must retain its Git
        # identity and already-correct GUI environment (never Inbox-style rmtree).
        git_inode, environment_inode = (install / ".git").stat().st_ino, venv.stat().st_ino
        logs = [Path(cfg.daybook_photos_offload_stdout_log), Path(cfg.daybook_photos_offload_stderr_log)]
        logs_before = snapshot(logs)
        (source.path / "src/daybook/__init__.py").write_text(
            "raise AssertionError('updated inert Photos app must not import')\n"
        )
        command("/usr/bin/git", "-C", str(source.path), "add", ".")
        command(
            "/usr/bin/git",
            "-C",
            str(source.path),
            "-c",
            "user.name=Owned",
            "-c",
            "user.email=owned@example.test",
            "commit",
            "-qm",
            "next owned Main",
        )
        source, bundle = bundle_source(owned, source.path)
        cfg = cfg.model_copy(
            update={
                "daybook_photos_offload_repo_ref": source.commit,
                "daybook_photos_offload_repo_bundle_src": str(bundle),
            }
        )
        updated = run(owned, transport, cfg, source, bundle, name="existing-Main-update")
        assert updated.succeeded
        assert len(updated.mutating_changed_ops) == 5
        assert (install / ".git").stat().st_ino == git_inode
        assert venv.stat().st_ino == environment_inode
        assert snapshot(logs) == logs_before
        assert job_pid(service) == pid
        assert snapshot([keeper_plist]) == protected
        owned.report["existing_Main_git_and_environment_inode_preserved"] = True

        # A distinct next-Main bundle triggers real source drift. Its deliberately
        # wrong transfer digest fails publication without modifying old source.
        fault_root = owned.root / "fault-controller-source"
        command("/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(source.path), str(fault_root))
        (fault_root / "src/daybook/__init__.py").write_text("raise AssertionError('owned fault app never imported')\n")
        command("/usr/bin/git", "-C", str(fault_root), "add", ".")
        command(
            "/usr/bin/git",
            "-C",
            str(fault_root),
            "-c",
            "user.name=Owned",
            "-c",
            "user.email=owned@example.test",
            "commit",
            "-qm",
            "owned faulty transfer next Main",
        )
        fault_source, fault_bundle = bundle_source(owned, fault_root)
        fault_cfg = cfg.model_copy(
            update={
                "daybook_photos_offload_repo_ref": fault_source.commit,
                "daybook_photos_offload_repo_bundle_src": str(fault_bundle),
            }
        )
        source_before = snapshot([install])
        bundle_before = Path(cfg.daybook_photos_offload_repo_bundle_path).read_bytes()
        failed = run(
            owned, transport, fault_cfg, fault_source, fault_bundle, name="digest-publication-fault", bad_digest=True
        )
        assert not failed.succeeded
        assert source_before == snapshot([install])
        assert Path(cfg.daybook_photos_offload_repo_bundle_path).read_bytes() == bundle_before
        assert job_pid(service) == pid
        assert snapshot([keeper_plist]) == protected
        final = run(owned, transport, cfg, source, bundle, name="final-repeat")
        assert final.succeeded
        assert not final.mutating_changed_ops
        owned.report.update(
            status="passed",
            unrelated_keeper_pid=pid,
            unrelated_keeper_preserved=True,
            source=source.commit,
            library_entries_by_construction=0,
            library_observation_limit=(
                "Only an empty owned directory was constructed; entry reads are not instrumented."
            ),
            application_import_sentinel="Inert app raises if imported; no process-wide app-call counter is claimed.",
            scope=(
                "Disposable original Photos mechanisms only; paired private declarations separate; "
                "no inventory/default/activation claim."
            ),
        )
    except BaseException as error:
        failure = error
    finally:
        reset = []
        for label in owned.labels:
            if label.startswith("gui/"):
                command("/bin/launchctl", "bootout", label, check=False)
                command("/bin/launchctl", "enable", label, check=False)
                reset.append(label)
        owned.report["owned_unique_disabled_entries_reset_enabled"] = reset
        owned.report["cleanup_limit"] = (
            "Unique enabled rows may remain; transient UV/cache setup is not global-zero IO."
        )
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
