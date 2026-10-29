"""Owned direct GUI-user SSH archive mechanism; no real photo/archive calls."""

from __future__ import annotations

import os
import plistlib
import pwd
import socket
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

import paramiko
from daybook_resources_native_fixture import provenance, wait
from daybook_runtime_native_fixture import snapshot
from mac_apps_owned import OwnedMac, command, job_pid, port

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_photos_archive_sync import DaybookPhotosArchiveSyncConfig
from ops_deploy.services.daybook_photos_archive_sync import deploy as api
from ops_deploy.testing import run_deploy_ssh


def user_transport(owned: OwnedMac, actor: Any) -> dict[str, Any]:
    key, host_key = owned.root / "user-key", owned.root / "host-key"
    for path in (key, host_key):
        command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path))
    # Never change the runner's existing SSH authorizations. This unique path
    # exists only on the disposable VM and is registered for owned cleanup.
    auth = Path(actor.pw_dir) / (".ops-mac-apps-archive-" + owned.suffix)
    owned.created_outside_root(auth)
    auth.mkdir(mode=0o700)
    os.chown(auth, actor.pw_uid, actor.pw_gid)
    authorized = auth / "authorized_keys"
    authorized.write_text(key.with_suffix(".pub").read_text())
    authorized.chmod(0o600)
    os.chown(authorized, actor.pw_uid, actor.pw_gid)
    selected_port = port()
    config = owned.root / "sshd.conf"
    config.write_text(
        f"Port {selected_port}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
        f"PidFile {owned.root}/sshd.pid\nAuthorizedKeysFile {authorized}\n"
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\n"
        f"AllowUsers {actor.pw_name}\nStrictModes yes\nLogLevel INFO\nSubsystem sftp internal-sftp\n"
    )
    command("/usr/sbin/sshd", "-t", "-f", str(config))
    child = owned.spawn(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], owned.evidence / "user-sshd.log")
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", selected_port), 0.1):
                break
        except OSError:
            assert child.poll() is None
            time.sleep(0.1)
    else:
        raise RuntimeError("owned user SSH transport did not start")
    known = owned.root / "known_hosts"
    known.write_text(
        f"[127.0.0.1]:{selected_port} " + " ".join(host_key.with_suffix(".pub").read_text().split()[:2]) + "\n"
    )
    owned.report["transport"] = {
        "user": actor.pw_name,
        "uid": actor.pw_uid,
        "loopback_only": True,
        "system_SSH_keys_sudoers_unchanged": True,
    }
    return {
        "ssh_hostname": "127.0.0.1",
        "ssh_port": selected_port,
        "ssh_user": actor.pw_name,
        "ssh_key": str(key),
        "ssh_known_hosts_file": str(known),
        "ssh_strict_host_key_checking": "yes",
    }


def source(owned: OwnedMac, uv: str, runtime: Path) -> tuple[SourceTree, Path]:
    root = owned.root / "controller-source"
    (root / "src/daybook").mkdir(parents=True)
    counter = str(runtime / "owned-import-count")
    cli_counter = str(runtime / "owned-cli-count")
    (root / "src/daybook/__init__.py").write_text(
        "from pathlib import Path\np=Path("
        + repr(counter)
        + ")\np.write_text(str(int(p.read_text())+1) if p.exists() else '1')\n"
    )
    (root / "src/daybook/cli.py").write_text(
        "from pathlib import Path\nimport sys\ndef main():\n"
        " assert sys.argv[1:]==['--help'], 'owned fixture must never execute archival app'\n"
        " p=Path(" + repr(cli_counter) + ")\n p.write_text(str(int(p.read_text())+1) if p.exists() else '1')\n"
    )
    (root / "pyproject.toml").write_text(
        '[project]\nname="daybook"\nversion="0.0.0"\nrequires-python=">=3.14.7"\ndependencies=[]\n'
        '[project.scripts]\ndaybook="daybook.cli:main"\n'
        '[build-system]\nrequires=["uv_build==0.13.5"]\nbuild-backend="uv_build"\n'
    )
    (root / ".python-version").write_text("3.14.7\n")
    (root / ".gitignore").write_text(".venv/\n__pycache__/\n")
    command(
        uv,
        "--directory",
        str(root),
        "lock",
        "--python",
        "3.14.7",
        env={
            **os.environ,
            "UV_PYTHON_INSTALL_DIR": str(owned.root / "controller-uv/python"),
            "UV_CACHE_DIR": str(owned.root / "controller-cache"),
        },
    )
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
        "owned",
    )
    return bundle(owned, root)


def bundle(owned: OwnedMac, root: Path) -> tuple[SourceTree, Path]:
    revision = command("/usr/bin/git", "-C", str(root), "rev-parse", "HEAD").stdout.strip()
    path = owned.root / (revision + ".bundle")
    command("/usr/bin/git", "-C", str(root), "bundle", "create", str(path), "refs/heads/main")
    return SourceTree(root, revision), path


def run(
    owned: OwnedMac, transport: Any, cfg: Any, tree: SourceTree, artifact: Path, phase: str, *, fault: bool = False
) -> Any:
    counts = {"attempted": 0, "succeeded": 0}
    original_put, original_payload = paramiko.SFTPClient.putfo, api.payload

    def upload(client: Any, stream: Any, destination: str, *args: Any, **kwargs: Any) -> Any:
        counts["attempted"] += 1
        value = original_put(client, stream, destination, *args, **kwargs)
        counts["succeeded"] += 1
        return value

    def data(*args: Any, **kwargs: Any) -> Any:
        value = original_payload(*args, **kwargs)
        if fault:
            value["bundle_sha256"] = "f" * 64
        return value

    with patch.object(paramiko.SFTPClient, "putfo", upload), patch.object(api, "payload", data):
        result = run_deploy_ssh(
            api.install_daybook_photos_archive_sync,
            cfg,
            tree,
            artifact,
            host_name="owned-archive-user",
            host_data=transport,
            _env={
                "UV_PYTHON_INSTALL_DIR": cfg.daybook_photos_archive_sync_service_home + "/uv/python",
                "UV_CACHE_DIR": cfg.daybook_photos_archive_sync_service_home + "/cache",
            },
            _sudo=True,
            _sudo_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
            _su_user="root",
        )
    owned.report.setdefault("phases", {})[phase] = {
        "succeeded": result.succeeded,
        "managed": len(result.mutating_changed_ops),
        "actual_sftp": counts,
        "error_type": type(result.error).__name__ if result.error else None,
    }
    assert job_pid(owned.report["keeper_service"]) == owned.report["keeper_pid"]
    return result


def main() -> None:
    owned = OwnedMac("daybook-archive")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        uv = str(Path(sys.executable).parent / "uv")
        if not Path("/opt/homebrew/bin/exiftool").is_file() or not Path("/opt/homebrew/bin/gtimeout").is_file():
            command(
                "/usr/bin/sudo",
                "-H",
                "-u",
                actor.pw_name,
                "/opt/homebrew/bin/brew",
                "install",
                "coreutils",
                "exiftool",
                env={**os.environ, "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1"},
            )
            owned.report["limitations"].append("Homebrew GNU timeout/ExifTool installed as fixture prerequisites.")
        home = owned.root / "home"
        home.mkdir(mode=0o700)
        os.chown(home, actor.pw_uid, actor.pw_gid)
        runtime = home / ".daybook/owned-archive"
        tree, artifact = source(owned, uv, runtime)
        cfg = DaybookPhotosArchiveSyncConfig(
            inventory_hostname="owned-writer",
            daybook_photos_archive_sync_enabled=True,
            daybook_photos_archive_sync_service_user=actor.pw_name,
            daybook_photos_archive_sync_repo_ref=tree.commit,
            daybook_photos_archive_sync_repo_bundle_src=str(artifact),
            daybook_photos_archive_sync_expected_smb_server="nas.example.invalid",
            daybook_photos_archive_sync_expected_writer_host="owned-writer",
        )
        install = home / ".local/share/owned-archive"
        label = "com.example.ops-mac-apps.archive." + owned.suffix
        paths = {
            "service_home": str(home),
            "install_root": str(install),
            "repo_bundle_path": str(install / "source.bundle"),
            "checkout_path": str(install / "daybook"),
            "venv_path": str(install / "daybook/.venv"),
            "uv_bin": uv,
            "timeout_bin": "/opt/homebrew/bin/gtimeout",
            "runtime_dir": str(runtime),
            "state_path": str(runtime / "ledger.json"),
            "folder_map_path": str(runtime / "folder-map.json"),
            "log_dir": str(runtime / "logs"),
            "stdout_log": str(runtime / "logs/archive-sync.log"),
            "stderr_log": str(runtime / "logs/archive-sync.err.log"),
            "config_dir": str(home / ".config/owned-archive"),
            "launcher_path": str(home / ".config/owned-archive/archive.sh"),
            "launchd_label": label,
            "launchd_plist_path": str(home / "Library/LaunchAgents" / (label + ".plist")),
            "library_path": str(home / "Pictures/Owned.photoslibrary"),
            "source_root": str(home / "Pictures/Owned Nikon"),
            "mount_point": str(owned.root / "Volumes/Owned"),
        }
        cfg = cfg.model_copy(update={"daybook_photos_archive_sync_" + key: value for key, value in paths.items()})
        owned.report["configuration_validation"] = {
            "original_declaration_validated": True,
            "owned_path_substitutions_use_model_copy": True,
            "substituted_paths_revalidated": False,
            "scope": (
                "Mechanism proof after deliberate owned-path substitution; "
                "public /Users and /Volumes validation is covered separately by source tests."
            ),
        }
        owned.adopt_gui_label(actor.pw_uid, label)
        keeper_label = "com.example.ops-mac-apps.archive-keeper." + owned.suffix
        owned.adopt_gui_label(actor.pw_uid, keeper_label)
        keeper = owned.root / "keeper.plist"
        keeper.write_bytes(
            plistlib.dumps({"Label": keeper_label, "ProgramArguments": ["/bin/sleep", "600"], "RunAtLoad": True})
        )
        command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(keeper))
        keeper_service = "gui/" + str(actor.pw_uid) + "/" + keeper_label
        wait(lambda: job_pid(keeper_service) is not None)
        owned.report.update(keeper_service=keeper_service, keeper_pid=job_pid(keeper_service))
        transport = user_transport(owned, actor)
        first = run(owned, transport, cfg, tree, artifact, "first")
        assert first.succeeded, type(first.error).__name__
        assert (runtime / "owned-import-count").read_text() == "1"
        assert (runtime / "owned-cli-count").read_text() == "1"
        protected_paths = [
            Path(cfg.daybook_photos_archive_sync_state_path),
            Path(cfg.daybook_photos_archive_sync_folder_map_path),
            Path(cfg.daybook_photos_archive_sync_stdout_log),
            Path(cfg.daybook_photos_archive_sync_stderr_log),
        ]
        for path in protected_paths:
            path.write_text("OWNED retained synthetic data " + path.name)
            os.chown(path, actor.pw_uid, actor.pw_gid)
        protected = snapshot(protected_paths)
        repeat = run(owned, transport, cfg, tree, artifact, "repeat")
        assert repeat.succeeded
        assert len(repeat.mutating_changed_ops) == 1
        assert owned.report["phases"]["repeat"]["actual_sftp"]["attempted"] == 0
        assert (runtime / "owned-cli-count").read_text() == "2"
        assert (runtime / "owned-import-count").read_text() == "2"
        checkout, venv = (
            Path(cfg.daybook_photos_archive_sync_checkout_path),
            Path(cfg.daybook_photos_archive_sync_venv_path),
        )
        continuity = (checkout / ".git").stat().st_ino, venv.stat().st_ino
        (tree.path / "src/daybook/cli.py").write_text(
            (tree.path / "src/daybook/cli.py").read_text() + "# owned Main update\n"
        )
        command("/usr/bin/git", "-C", str(tree.path), "add", ".")
        command(
            "/usr/bin/git",
            "-C",
            str(tree.path),
            "-c",
            "user.name=Owned",
            "-c",
            "user.email=owned@example.test",
            "commit",
            "-qm",
            "owned update",
        )
        next_tree, next_artifact = bundle(owned, tree.path)
        next_cfg = cfg.model_copy(
            update={
                "daybook_photos_archive_sync_repo_ref": next_tree.commit,
                "daybook_photos_archive_sync_repo_bundle_src": str(next_artifact),
            }
        )
        before = snapshot([checkout, home / ".config", home / "Library/LaunchAgents"])
        refused = run(owned, transport, next_cfg, next_tree, next_artifact, "genuine-digest-failure", fault=True)
        assert not refused.succeeded
        assert snapshot([checkout, home / ".config", home / "Library/LaunchAgents"]) == before
        assert (runtime / "owned-cli-count").read_text() == "2"
        updated = run(owned, transport, next_cfg, next_tree, next_artifact, "Main-update-recovery")
        assert updated.succeeded
        assert ((checkout / ".git").stat().st_ino, venv.stat().st_ino) == continuity
        assert (runtime / "owned-cli-count").read_text() == "3"
        python = venv / "bin/python"
        python.unlink()
        python.symlink_to(owned.root / "nonexistent-python")
        rebuilt = run(owned, transport, next_cfg, next_tree, next_artifact, "nonstarting-interpreter")
        assert rebuilt.succeeded
        assert (runtime / "owned-cli-count").read_text() == "4"
        final = run(owned, transport, next_cfg, next_tree, next_artifact, "final-repeat")
        assert final.succeeded
        assert len(final.mutating_changed_ops) == 1
        assert (runtime / "owned-cli-count").read_text() == "5"
        assert (runtime / "owned-import-count").read_text() == "5"
        assert snapshot(protected_paths) == protected
        owned.report.update(
            status="passed",
            actual_inert_managed_help_calls=5,
            source_Git_and_environment_inode_preserved=True,
            synthetic_data_metadata_preserved=True,
            real_media_library_model_financial_body_calls=False,
            scope_limits=(
                "Empty owned library declaration; no whole-process app/library syscall counter claimed; "
                "UV/cache/fixture bookkeeping is not globalzeroIO."
            ),
        )
    except BaseException as error:
        failure = error
        owned.fail(error)
    finally:
        try:
            owned.cleanup()
        except BaseException as error:
            failure = failure or error
        owned.receipt()
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
