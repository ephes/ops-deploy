"""Disposable user SSH/code/managed-Python proof; no inventory or app imports."""

from __future__ import annotations

import os
import plistlib
import pwd
import shlex
import socket
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch

from daybook_resources_native_fixture import provenance, wait
from daybook_runtime_native_fixture import snapshot
from daybook_transition_native_fixture import phase
from mac_apps_owned import OwnedMac, command, job_pid, port
from pyinfra.api import deploy
from pyinfra.connectors.ssh import SSHConnector
from pyinfra.connectors.util import CommandOutput, OutputLine
from pyinfra.operations import server

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime import DaybookRuntimeConfig
from ops_deploy.services.daybook_operations_runtime import code as api
from ops_deploy.testing import run_deploy_ssh


def git(root: Path, *args: str) -> str:
    return command(
        "/usr/bin/env",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_SYSTEM=/dev/null",
        "GIT_OPTIONAL_LOCKS=0",
        "/usr/bin/git",
        "-C",
        str(root),
        *args,
    ).stdout.strip()


def user_transport(owned: OwnedMac, actor: Any) -> dict[str, Any]:
    key, hostkey = owned.root / "user-key", owned.root / "user-host-key"
    for path in (key, hostkey):
        command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path))
    keys = Path(actor.pw_dir) / (".ops-source-fixture-" + owned.suffix)
    owned.created_outside_root(keys)
    keys.mkdir(mode=0o700)
    os.chown(keys, actor.pw_uid, actor.pw_gid)
    authorized = keys / "authorized_keys"
    authorized.write_text(key.with_suffix(".pub").read_text())
    authorized.chmod(0o600)
    os.chown(authorized, actor.pw_uid, actor.pw_gid)
    selected = port()
    config = owned.root / "source-sshd.conf"
    config.write_text(
        f"Port {selected}\nListenAddress 127.0.0.1\nHostKey {hostkey}\n"
        f"PidFile {owned.root}/source-sshd.pid\nAuthorizedKeysFile {authorized}\n"
        f"AllowUsers {actor.pw_name}\nPermitRootLogin no\nStrictModes yes\n"
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n"
        "Subsystem sftp internal-sftp\nLogLevel INFO\n"
    )
    command("/usr/sbin/sshd", "-t", "-f", str(config))
    child = owned.spawn(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], owned.evidence / "source-sshd.log")
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", selected), 0.1):
                break
        except OSError:
            assert child.poll() is None
            time.sleep(0.1)
    else:
        raise RuntimeError("owned_user_sshd_unavailable")
    known = owned.root / "user-known-hosts"
    known.write_text(f"[127.0.0.1]:{selected} " + " ".join(hostkey.with_suffix(".pub").read_text().split()[:2]) + "\n")
    result = command(
        "/usr/bin/ssh",
        "-p",
        str(selected),
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=" + str(known),
        actor.pw_name + "@127.0.0.1",
        "/usr/bin/id -u",
        check=False,
    )
    owned.report["user_transport"] = {
        "probe_exit": result.returncode,
        "observed_uid": result.stdout.strip(),
        "expected_uid": actor.pw_uid,
        "loopback_only": True,
        "isolated_fixture_key": True,
        "system_ssh_and_existing_keys_modified": False,
    }
    assert result.returncode == 0
    assert result.stdout.strip() == str(actor.pw_uid)
    return {
        "ssh_hostname": "127.0.0.1",
        "ssh_port": selected,
        "ssh_user": actor.pw_name,
        "ssh_key": str(key),
        "ssh_known_hosts_file": str(known),
        "ssh_strict_host_key_checking": "yes",
        "_sudo": True,
        "_sudo_user": "root",
        "_doas": True,
        "_doas_user": "root",
        "_dzdo": True,
        "_dzdo_user": "root",
        "_su_user": "root",
    }


def main() -> None:
    owned = OwnedMac("runtime-code")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        transport = user_transport(owned, actor)
        positive_handoffs: list[dict[str, Any]] = []

        @deploy("Owned unsafe inheritance positive control")
        def unsafe_control() -> None:
            server.shell(commands="/usr/bin/true")

        def blocked_control(_connector: Any, *_args: Any, **kwargs: Any) -> Any:
            # Observe the real SDK handoff, then refuse before the connector
            # can execute ANY privileged command. No actual escalation occurs.
            keys = ("_sudo", "_sudo_user", "_doas", "_doas_user", "_dzdo", "_dzdo_user", "_su_user")
            fields = {key: kwargs.get(key) for key in keys}
            assert all(fields[key] is True for key in ("_sudo", "_doas", "_dzdo"))
            assert all(fields[key] == "root" for key in ("_sudo_user", "_doas_user", "_dzdo_user", "_su_user"))
            positive_handoffs.append(fields)
            return False, CommandOutput([OutputLine("stderr", "owned_escalation_control_blocked")])

        with patch.object(SSHConnector, "run_shell_command", blocked_control):
            positive = run_deploy_ssh(unsafe_control, host_name="owned-positive-control", host_data=transport)
        assert not positive.succeeded
        assert positive_handoffs
        owned.report["canonical_inherited_positive_control"] = {
            "actual_SDK_handoffs": positive_handoffs,
            "blocked_before_actual_privilege_command": True,
        }
        controller_uv = str(Path(sys.executable).parent / "uv")
        root = owned.root / "actor"
        root.mkdir(mode=0o755)
        os.chown(root, actor.pw_uid, actor.pw_gid)
        home = root / "home"
        home.mkdir(mode=0o700)
        os.chown(home, actor.pw_uid, actor.pw_gid)
        wrapper = root / "owned-uv"
        # Only the configured owned binary is shimmed: real UV/Python/build and
        # SDK execute unchanged, while installation/cache stays disposable.
        wrapper.write_text(
            "#!/bin/sh\nexport UV_PYTHON_INSTALL_DIR="
            + shlex.quote(str(root / "uv/python"))
            + "\nexport UV_CACHE_DIR="
            + shlex.quote(str(root / "uv/cache"))
            + "\nexec "
            + shlex.quote(controller_uv)
            + ' "$@"\n'
        )
        wrapper.chmod(0o755)
        os.chown(wrapper, actor.pw_uid, actor.pw_gid)
        repository = owned.root / "controller-source"
        repository.mkdir()
        git(repository, "init", "--quiet", "--template=", "-b", "main")
        (repository / "src/daybook").mkdir(parents=True)
        marker = root / "forbidden-app-import"
        inert = (
            "import pathlib\npathlib.Path("
            + repr(str(marker))
            + ").write_text('owned import')\nraise RuntimeError('owned application must never import')\n"
        )
        (repository / "src/daybook/__init__.py").write_text(inert)
        (repository / ".gitignore").write_text(".venv/\n")
        (repository / "pyproject.toml").write_text(
            '[project]\nname="owned-runtime-source"\nversion="0.0.0"\nrequires-python=">=3.11"\n'
            '[build-system]\nrequires=["hatchling"]\nbuild-backend="hatchling.build"\n'
            '[tool.hatch.build.targets.wheel]\npackages=["src/daybook"]\n'
        )
        command(controller_uv, "--directory", str(repository), "lock", "--python", sys.executable)
        git(repository, "add", ".")
        git(repository, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned first")
        revision = git(repository, "rev-parse", "HEAD")
        bundle = owned.root / "first.bundle"
        git(repository, "bundle", "create", str(bundle), "refs/heads/main")
        source = SourceTree(repository, revision)
        label = owned.label("runtime-code")
        cfg = DaybookRuntimeConfig(
            user=actor.pw_name,
            owner="user",
            revision=revision,
            home=str(home),
            install_root=str(root / "install"),
            uv_bin=str(wrapper),
            label=label,
        )
        transfers: list[Path] = []
        original_uuid = uuid.uuid4
        uploads = 0
        failures = 0
        handoffs: list[dict[str, Any]] = []
        original_shell, original_put = SSHConnector.run_shell_command, SSHConnector.put_file

        def next_uuid() -> Any:
            value = original_uuid()
            path = Path("/private/var/tmp/ops-deploy-daybook-source-" + value.hex)
            owned.created_outside_root(path)
            transfers.append(path)
            return value

        def check(arguments: Any) -> None:
            fields = {
                name: arguments.get(name)
                for name in ("_sudo", "_sudo_user", "_doas", "_doas_user", "_dzdo", "_dzdo_user", "_su_user")
            }
            assert all(fields[key] is False for key in ("_sudo", "_doas", "_dzdo"))
            assert all(fields[key] in {None, ""} for key in ("_sudo_user", "_doas_user", "_dzdo_user", "_su_user"))
            handoffs.append(fields)

        def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal failures
            check(kwargs)
            success, output = original_shell(connector, *args, **kwargs)
            if not success:
                failures += sum(
                    line.buffer_name == "stderr" and line.line == "runtime_code_or_environment_in_use"
                    for line in output
                )
            return success, output

        def put(connector: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal uploads
            check(kwargs)
            uploads += 1
            return original_put(connector, *args, **kwargs)

        def run(name: str, selected: Any, tree: Any, archive: Path) -> Any:
            previous = uploads
            with (
                patch.object(uuid, "uuid4", next_uuid),
                patch.object(SSHConnector, "run_shell_command", shell),
                patch.object(SSHConnector, "put_file", put),
            ):
                result = run_deploy_ssh(
                    api.install_daybook_runtime_code,
                    selected,
                    tree,
                    archive,
                    host_name="owned-user-code",
                    host_data=transport,
                )
            phase(owned, name, result)
            owned.report["phases"][name]["actual_SFTP"] = uploads - previous
            assert all(not path.exists() for path in transfers)
            return result

        first = run("user-source-first", cfg, source, bundle)
        assert first.succeeded
        assert uploads == 1
        target = Path(str(cfg.install_root))
        before = snapshot([target])
        repeat = run("user-source-repeat", cfg, source, bundle)
        assert repeat.succeeded
        assert not repeat.mutating_changed_ops
        assert uploads == 1
        assert snapshot([target]) == before
        owned.adopt_gui_label(actor.pw_uid, label)
        plist = owned.root / "owned-sleep.plist"
        plist.write_bytes(
            plistlib.dumps({"Label": label, "ProgramArguments": ["/bin/sleep", "10000"], "RunAtLoad": True})
        )
        plist.chmod(0o644)
        command("/bin/launchctl", "bootstrap", f"gui/{actor.pw_uid}", str(plist))
        service = f"gui/{actor.pw_uid}/{label}"
        wait(lambda: job_pid(service) is not None)
        pid = job_pid(service)
        before = snapshot([target])
        current = run("current-code-keeps-owned-keeper", cfg, source, bundle)
        assert current.succeeded
        assert not current.mutating_changed_ops
        assert job_pid(service) == pid
        assert uploads == 1
        assert snapshot([target]) == before
        (repository / "src/daybook/__init__.py").write_text("# owned second Main\n" + inert)
        git(repository, "add", ".")
        git(repository, "-c", "user.name=Owned", "-c", "user.email=owned@example.test", "commit", "-qm", "owned second")
        second = git(repository, "rev-parse", "HEAD")
        second_bundle = owned.root / "second.bundle"
        git(repository, "bundle", "create", str(second_bundle), "refs/heads/main")
        desired = cfg.model_copy(update={"revision": second})
        changed_source = SourceTree(repository, second)
        before = snapshot([target])
        refused = run("in-use-source-refuses-before-transfer", desired, changed_source, second_bundle)
        assert not refused.succeeded
        assert failures == 1
        assert uploads == 1
        assert snapshot([target]) == before
        assert job_pid(service) == pid
        command("/bin/launchctl", "bootout", service)
        wait(lambda: job_pid(service) is None)
        updated = run("quiescent-source-replacement", desired, changed_source, second_bundle)
        assert updated.succeeded
        assert uploads == 2
        before = snapshot([target])
        final = run("replacement-repeat", desired, changed_source, second_bundle)
        assert final.succeeded
        assert not final.mutating_changed_ops
        assert uploads == 2
        assert snapshot([target]) == before
        for relative in ("src/daybook/__init__.py", "pyproject.toml", "uv.lock"):
            assert (target / "daybook" / relative).read_bytes() == (repository / relative).read_bytes()
        version = command(
            "/usr/bin/sudo",
            "-n",
            "-H",
            "-u",
            actor.pw_name,
            "--",
            str(cfg.python),
            "-I",
            "-B",
            "-S",
            "-c",
            "import sys;print('%d.%d.%d'%sys.version_info[:3])",
        ).stdout.strip()
        assert version == cfg.python_version
        assert not marker.exists()
        owned.report.update(
            status="passed",
            actual_user_python=version,
            actual_uploads=uploads,
            exact_expected_failures=failures,
            no_application_import_or_API=True,
            inherited_handoffs=handoffs,
            fixture_uv_install_root=str(root / "uv/python"),
            UV_path_scope=(
                "configured owned wrapper; actual UV/Python and original selectors; no global user tree changes"
            ),
        )
    except BaseException as error:
        failure = error
    finally:
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
