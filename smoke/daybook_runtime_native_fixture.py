"""Owned Darwin GUI/SSH stop proof with synthetic Daybook code and metadata.

Never run on inventory. The existing OwnedMac guard confines every resource to a
fresh hosted ARM VM; its exact process/session cleanup is fixture work only.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.resources
import json
import os
import pwd
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from mac_apps_owned import OwnedMac, command, job_pid

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime import (
    DaybookRuntimeConfig,
    RuntimeStopPolicy,
    RuntimeStopWindow,
    stop_daybook_runtime,
)
from ops_deploy.services.daybook_operations_runtime.inspect import verify_daybook_runtime
from ops_deploy.services.daybook_operations_runtime.render import credential_text, render_resource
from ops_deploy.services.daybook_operations_runtime.status import SourceStatus
from ops_deploy.testing import run_deploy_ssh

APP = """import json,pathlib,subprocess,sys,time

def main():
    args=sys.argv[1:]
    def option(name):return args[args.index(name)+1]
    root=pathlib.Path(option('--policy')).parent
    if args[:2]==['operations','status']:
        marker=root/'native-status-count'
        with marker.open('a') as stream:stream.write('managed status\\n')
        mode=(root/'native-mode').read_text().strip()
        if mode=='unanswered':return 1
        print(json.dumps({'enabled':True,'server':{'active_state':'assigned' if mode=='busy' else None}}))
        return 0
    assert args[:2]==['operations','host-keep']
    tmux=option('--tmux');socket=option('--socket')
    while True:
        if subprocess.run([tmux,'-L',socket,'has-session','-t','=supervisor'],capture_output=True).returncode:
            code='import time'
            if (root/'native-mode').read_text().strip()=='ignore-term':
                code='import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN)'
            code+=';time.sleep(10000)'
            import shlex
            child=shlex.join([sys.executable,'-I','-B','-c',code,'operations','serve'])
            subprocess.run([tmux,'-L',socket,'new-session','-d','-s','supervisor',child],check=True,capture_output=True)
        time.sleep(.1)
"""


def snapshot(paths: list[Path]) -> dict[str, tuple[Any, ...]]:
    all_paths = {item for root in paths for item in ([root, *root.rglob("*")] if root.is_dir() else [root])}
    return {
        str(path): (
            s.st_dev,
            s.st_ino,
            s.st_uid,
            s.st_gid,
            s.st_mode,
            s.st_size,
            s.st_mtime_ns,
            s.st_ctime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else "",
        )
        for path in all_paths
        for s in [path.lstat()]
    }


def wait(predicate: Any) -> None:
    for _ in range(100):
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("owned native readiness did not converge")


def main() -> None:
    owned = OwnedMac("daybook-runtime")
    failure: BaseException | None = None
    try:
        owned.verify_implementation()
        # Strengthen this new fixture's provenance: enumerate actual package
        # files too, rather than claiming a Git-derived expected map proves extras.
        package = Path(str(importlib.resources.files("ops_deploy")))
        installed = {
            str(p.relative_to(package))
            for p in package.rglob("*")
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
        }
        assert installed == set(owned.report["installed_resources"])
        direct = json.loads(importlib.metadata.distribution("ops-deploy").read_text("direct_url.json") or "{}")
        assert not direct.get("dir_info", {}).get("editable")
        assert direct.get("vcs_info", {}).get("commit_id") == os.environ["IMPLEMENTATION_SHA"]
        owned.report["installed_root"] = str(package)
        owned.report["distribution_root"] = str(importlib.metadata.distribution("ops-deploy").locate_file(""))
        owned.report["actual_direct_url_commit"] = direct["vcs_info"]["commit_id"]
        owned.report["actual_installed_resource_set_equal"] = True
        owned.report["limitations"].append(
            "Workflow controller/action caches and checkout are disposable-VM setup, outside fixture cleanup; "
            "fixture app interpreter/cache are entirely under owned.root."
        )
        owned.report["native_provenance"] = (
            "actual package full set/bytes equal immutable clean Git; "
            "noneditable Git direct_url commit independently checked"
        )
        actor = pwd.getpwnam("runner")
        uv = shutil.which("uv")
        assert uv
        tmux = "/opt/homebrew/bin/tmux"
        assert Path(tmux).is_file()
        controller = owned.root / "controller-source"
        (controller / "src/daybook").mkdir(parents=True)
        (controller / "src/daybook/__init__.py").write_text("")
        (controller / "src/daybook/cli.py").write_text(APP)
        (controller / ".gitignore").write_text(".venv/\n__pycache__/\n")
        (controller / ".python-version").write_text("3.14.7\n")
        (controller / "pyproject.toml").write_text(
            '[project]\nname="daybook"\nversion="0.0.0"\nrequires-python=">=3.12"\n'
            '[build-system]\nrequires=["uv_build>=0.13.0,<0.14.0"]\nbuild-backend="uv_build"\n'
        )
        command(
            uv,
            "--directory",
            str(controller),
            "lock",
            "--python",
            sys.executable,
            env={
                **os.environ,
                "UV_CACHE_DIR": str(owned.root / "controller-uv-cache"),
                "UV_PYTHON_INSTALL_DIR": str(owned.root / "controller-uv-python"),
            },
        )
        command("/usr/bin/git", "-C", str(controller), "init", "--quiet", "--template=")
        command("/usr/bin/git", "-C", str(controller), "add", ".")
        command(
            "/usr/bin/git",
            "-C",
            str(controller),
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "--quiet",
            "-m",
            "owned synthetic Daybook",
        )
        revision = command("/usr/bin/git", "-C", str(controller), "rev-parse", "HEAD").stdout.strip()
        root = owned.root / "runtime"
        root.mkdir(mode=0o755)
        # The real uv, its managed Python and cache all stay under owned.root.
        # The /uv/python/ segment retains the production base-prefix predicate.
        uv_wrapper = root / "uv-owned"
        uv_wrapper.write_text(
            "#!/bin/sh\nexec /usr/bin/env "
            + shlex.join(
                [
                    "UV_PYTHON_INSTALL_DIR=" + str(root / "uv/python"),
                    "UV_CACHE_DIR=" + str(root / "uv/cache"),
                    uv,
                ]
            )
            + ' "$@"\n'
        )
        uv_wrapper.chmod(0o755)
        checkout = root / "daybook"
        command("/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(controller), str(checkout))
        command("/usr/sbin/chown", "-R", "runner:staff", str(root))
        command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            "runner",
            "--",
            str(uv_wrapper),
            "--directory",
            str(checkout),
            "sync",
            "--frozen",
            "--no-dev",
            "--python",
            "3.14.7",
        )
        tmpdir = root / "tmux"
        tmpdir.mkdir(mode=0o700)
        journal = root / "store"
        for path in (journal, journal / "deliveries", journal / "halts"):
            path.mkdir(mode=0o700)
        label = "com.example.ops-mac-apps.daybook." + owned.suffix
        owned.adopt_gui_label(actor.pw_uid, label)
        cfg = DaybookRuntimeConfig(
            user="runner",
            revision=revision,
            owner="user",
            mode="host",
            home=Path(actor.pw_dir),
            install_root=root,
            python=checkout / ".venv/bin/python",
            uv_bin=uv_wrapper,
            policy=root / "operations.json",
            credential=root / "credential.json",
            journal=journal,
            label=label,
            plist=root / "agent.plist",
            staged_plist=root / "staged.plist",
            host_lock=root / "host.lock",
            importer_policy=root / "importer.json",
            legacy_plist=root / "legacy.plist",
            closeout_marker=root / "closed-out",
            host_socket="db",
            host_tmux=Path(tmux),
            host_tmpdir=tmpdir,
            quiet_retries=1,
            quiet_delay=0,
            poll_delay=1,
            stop_timeout=2,
        )
        (root / "operations.json").write_text(
            render_resource(cfg.model_copy(update={"action": "cutover"}), "policy.json.j2")
        )
        for path in (root / "agent.plist", root / "staged.plist"):
            path.write_text(render_resource(cfg, "runtime.plist.j2"))
        executor = "owned-native-executor-" + "x" * 40
        (root / "credential.json").write_text(credential_text(executor))
        (root / "credential.json").chmod(0o600)
        (root / "native-mode").write_text("idle")
        (root / "native-status-count").write_text("")
        command("/usr/sbin/chown", "-R", "runner:staff", str(root))
        owned.spawn(
            [
                "/usr/bin/sudo",
                "-H",
                "-u",
                "runner",
                "--",
                "/usr/bin/env",
                "TMUX_TMPDIR=" + str(tmpdir),
                tmux,
                "-D",
                "-f",
                "/dev/null",
                "-L",
                cfg.host_socket,
            ]
        )
        # -D takes no command. Wait for its owned socket before a separate
        # client creates the capability-host session; the server stays in our
        # spawned process tree for exact descendant cleanup.
        wait(lambda: (tmpdir / ("tmux-" + str(actor.pw_uid)) / cfg.host_socket).is_socket())
        command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            "runner",
            "--",
            "/usr/bin/env",
            "TMUX_TMPDIR=" + str(tmpdir),
            tmux,
            "-L",
            cfg.host_socket,
            "new-session",
            "-d",
            "-s",
            "host",
            "/bin/sleep 10000",
        )
        wait(
            lambda: (
                command(
                    "/usr/bin/sudo",
                    "-H",
                    "-u",
                    "runner",
                    "--",
                    "/usr/bin/env",
                    "TMUX_TMPDIR=" + str(tmpdir),
                    tmux,
                    "-L",
                    cfg.host_socket,
                    "has-session",
                    "-t",
                    "=host",
                    check=False,
                ).returncode
                == 0
            )
        )
        service = "gui/" + str(actor.pw_uid) + "/" + label
        command("/bin/launchctl", "enable", service)
        command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(root / "agent.plist"))
        wait(lambda: job_pid(service) is not None)
        wait(
            lambda: (
                command(
                    "/usr/bin/sudo",
                    "-H",
                    "-u",
                    "runner",
                    "--",
                    "/usr/bin/env",
                    "TMUX_TMPDIR=" + str(tmpdir),
                    tmux,
                    "-L",
                    cfg.host_socket,
                    "has-session",
                    "-t",
                    "=supervisor",
                    check=False,
                ).returncode
                == 0
            )
        )
        host_data = owned.ssh_transport()

        def capability_present() -> bool:
            return (
                command(
                    "/usr/bin/sudo",
                    "-H",
                    "-u",
                    "runner",
                    "--",
                    "/usr/bin/env",
                    "TMUX_TMPDIR=" + str(tmpdir),
                    tmux,
                    "-L",
                    cfg.host_socket,
                    "has-session",
                    "-t",
                    "=host",
                    check=False,
                ).returncode
                == 0
            )

        protected = [
            checkout,
            uv_wrapper,
            journal,
            root / "operations.json",
            root / "credential.json",
            root / "agent.plist",
            root / "staged.plist",
        ]
        source = SourceTree(controller, revision)
        statuses = (SourceStatus("regular", True, None, False, 0, False),)
        token = dict(executor_token=executor)
        # Actual readonly API through loopback SSH, keeping the real GUI PID.
        before = snapshot(protected)
        pid = job_pid(service)
        for index in range(2):
            result = run_deploy_ssh(
                verify_daybook_runtime,
                cfg,
                token,
                source,
                statuses=statuses,
                host_name="owned-daybook",
                host_data=host_data,
            )
            assert result.succeeded, str(result.error)
            assert result.mutating_changed_ops == []
            assert job_pid(service) == pid
            assert snapshot(protected) == before
            assert capability_present()
            owned.report["repeats"]["pure-" + str(index)] = []
        stop_cfg = cfg.model_copy(update={"action": "stop", "confirmed": True})
        clock = command("/bin/date", "+%H:%M", env={**os.environ, "TZ": "Europe/Berlin"}).stdout.strip()
        assert clock < "23:58", "Owned full-day window fault needs a bounded midnight margin"
        window = RuntimeStopPolicy(windows=(RuntimeStopWindow(start="00:01", end="23:59"),), lead_minutes=1)
        counter_before = (root / "native-status-count").read_bytes()
        denied = run_deploy_ssh(
            stop_daybook_runtime, stop_cfg, policy=window, host_name="owned-daybook", host_data=host_data
        )
        assert not denied.succeeded
        assert job_pid(service) == pid
        assert snapshot(protected) == before
        assert capability_present()
        assert (root / "native-status-count").read_bytes() == counter_before
        owned.report["actual_window_denial_before_executor_pid_preserved"] = True
        halt = journal / "halts/.owned.json"
        halt.write_text("owned synthetic halt marker")
        halted = snapshot(protected)
        denied = run_deploy_ssh(
            stop_daybook_runtime, stop_cfg, policy=RuntimeStopPolicy(), host_name="owned-daybook", host_data=host_data
        )
        assert not denied.succeeded
        assert job_pid(service) == pid
        assert snapshot(protected) == halted
        halt.unlink()  # remove only this fixture's deliberate fault marker
        # Parent directory metadata changed by deliberate fault setup/removal.
        before = snapshot(protected)
        owned.report["halt_denial_pid_preserved"] = True
        for mode in ("busy", "unanswered"):
            (root / "native-mode").write_text(mode)
            result = run_deploy_ssh(
                stop_daybook_runtime,
                stop_cfg,
                policy=RuntimeStopPolicy(),
                host_name="owned-daybook",
                host_data=host_data,
            )
            assert not result.succeeded
            assert job_pid(service) == pid
            assert snapshot(protected) == before
            assert capability_present()
            owned.report[mode + "_refused_pid_preserved"] = True
        (root / "native-mode").write_text("idle")
        result = run_deploy_ssh(
            stop_daybook_runtime, stop_cfg, policy=RuntimeStopPolicy(), host_name="owned-daybook", host_data=host_data
        )
        assert result.succeeded, str(result.error)
        assert len(result.mutating_changed_ops) == 1
        assert job_pid(service) is None
        assert snapshot(protected) == before
        assert capability_present()
        # Explicit stop recovery remains managed because it still invokes the
        # original executor status. This is not a default-service repeat claim.
        repeat = run_deploy_ssh(
            stop_daybook_runtime, stop_cfg, policy=RuntimeStopPolicy(), host_name="owned-daybook", host_data=host_data
        )
        assert repeat.succeeded, str(repeat.error)
        assert len(repeat.mutating_changed_ops) == 1
        assert snapshot(protected) == before
        assert capability_present()
        # Fresh owned setup for genuine post-TERM timeout/restoration proof.
        # This is fixture setup, never a repair/restart on inventory.
        (root / "native-mode").write_text("ignore-term")
        command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(root / "agent.plist"))
        wait(lambda: job_pid(service) is not None)
        fault_pid = job_pid(service)
        wait(
            lambda: (
                command(
                    "/usr/bin/sudo",
                    "-H",
                    "-u",
                    "runner",
                    "--",
                    "/usr/bin/env",
                    "TMUX_TMPDIR=" + str(tmpdir),
                    tmux,
                    "-L",
                    cfg.host_socket,
                    "has-session",
                    "-t",
                    "=supervisor",
                    check=False,
                ).returncode
                == 0
            )
        )
        failed = run_deploy_ssh(
            stop_daybook_runtime, stop_cfg, policy=RuntimeStopPolicy(), host_name="owned-daybook", host_data=host_data
        )
        assert not failed.succeeded
        wait(lambda: job_pid(service) is not None)
        assert job_pid(service) != fault_pid
        assert snapshot(protected) == before
        assert capability_present()
        owned.report["genuine_exit_timeout_keeper_restored"] = True
        owned.report["synthetic_monitor_rows_only"] = True
        owned.report["capability_host_preserved_each_phase"] = True
        owned.report["original_managed_status_invocations"] = len(
            (root / "native-status-count").read_text().splitlines()
        )
        owned.report["stop_expected_target_pid_removed"] = pid
        owned.report["scope_not_inventory_or_default_qualification"] = True
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
    finally:
        failure = owned.finish(failure)
    if failure is not None:
        raise failure
    print("owned native Daybook pure/stop/failure/recovery proof passed; fixture removed")


if __name__ == "__main__":
    main()
