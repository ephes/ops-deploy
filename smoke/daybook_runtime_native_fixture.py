"""Owned Darwin GUI/SSH stop proof with synthetic Daybook code and metadata.

Never run on inventory. The existing OwnedMac guard confines every resource to a
fresh hosted ARM VM; its exact process/session cleanup is fixture work only.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import importlib.resources
import io
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
    stage_daybook_runtime,
    stop_daybook_runtime,
)
from ops_deploy.services.daybook_operations_runtime.inspect import SCRIPT, observation_payload, verify_daybook_runtime
from ops_deploy.services.daybook_operations_runtime.render import credential_text, render_resource
from ops_deploy.services.daybook_operations_runtime.status import SourceStatus
from ops_deploy.services.daybook_sessions import DaybookSessionsConfig, install_sessions_source
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


def diagnostic_command() -> str:
    # Fixed metadata only, using the EXACT observer and normal connector. Child
    # stderr stays in memory and is classified; no argv/env/body is returned.
    diagnostic = """import json,sys
history=[]
class DiagnosticProbes(NativeProbes):
 def run(self,argv,**kwargs):
  labels={'/usr/bin/git':'git','/bin/launchctl':'launchctl','/usr/bin/pgrep':'pgrep',self.data['python']:'interpreter',self.data['uv_bin']:'uv-check',self.data['host_tmux']:'tmux'}
  probe=labels.get(argv[0],'other')
  try:result=super().run(argv,**kwargs)
  except Exception:
   history.append({'probe':probe,'returncode':None,'stderr_category':'probe-raised'})
   raise
  category='nonempty' if result.stderr else 'empty'
  for needle,label in [(b'getcwd','cwd'),(b'current working directory','cwd'),
                       (b'permission denied','permission'),(b'operation not permitted','permission'),
                       (b'dubious ownership','git-owner'),(b'no interpreter found','python-selection'),
                       (b'no such file','missing')]:
   if needle in result.stderr.lower():category=label;break
  entry={'probe':probe,'returncode':result.returncode,'stderr_category':category}
  if probe=='uv-check':
   signals=[(b'would install','would-install'),(b'would uninstall','would-uninstall'),
            (b'would update','would-update'),(b'would replace project environment at:','would-replace-env'),
            (b'would create project environment at:','would-create-env'),(b'would download','would-download'),
            (b'would make no changes','no-changes'),
            (b'error: the environment is outdated','env-outdated'),
            (b'error: failed to query python','python-query'),
            (b'error: failed to inspect','python-inspect'),
            (b'error: failed to build','build'),(b'error: failed to download','download'),
            (b'error: failed to create temporary directory','temp-create'),
            (b'error: failed to open file','file-open'),(b'error:','error'),(b'warning:','warning')]
   lines=[line.lstrip().lower() for line in result.stderr.splitlines()]
   entry['uv_signals']=[label for prefix,label in signals if any(line.startswith(prefix) for line in lines)]
  history.append(entry)
  return result
try:
 raw=sys.stdin.buffer.read(MAX_INPUT+1)
 if len(raw)>MAX_INPUT:raise ObservationError("runtime_observer_request_too_large")
 data=json.loads(raw)
 result={'state':observe(data,DiagnosticProbes(data))}
except Exception as error:
 result={'failure':str(error) if isinstance(error,ObservationError) else type(error).__name__}
result['probes']=history
print(json.dumps(result,sort_keys=True))
"""
    source = SCRIPT.decode()
    # Separate module name prevents the production script's main from running.
    launcher = (
        "import base64;ns={'__name__':'owned_diagnostic'};exec(compile(base64.b64decode('"
        + base64.b64encode(source.encode()).decode()
        + "'),'<owned-observer>','exec'),ns);exec(compile(base64.b64decode('"
        + base64.b64encode(diagnostic.encode()).decode()
        + "'),'<owned-diagnostic>','exec'),ns)"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", launcher])


def capture_observation(
    cfg: DaybookRuntimeConfig, token: dict[str, str], source: SourceTree, host_data: dict[str, Any]
) -> dict[str, Any]:
    from pyinfra import host
    from pyinfra.facts.server import Command

    captured: dict[str, Any] = {}

    def capture() -> None:
        try:
            payload = observation_payload(cfg, token, source)
            with io.StringIO(json.dumps(payload) + "\n") as stream:
                output = host.get_fact(Command, command=diagnostic_command(), _stdin=stream, _get_pty=False)
            captured.update(json.loads(output or "{}"))
        except Exception as error:
            captured.clear()
            captured["failure"] = type(error).__name__

    try:
        result = run_deploy_ssh(capture, host_name="owned-daybook", host_data=host_data)
    except Exception as error:
        return {"failure": type(error).__name__}
    if not result.succeeded:
        return {"failure": type(result.error).__name__ if result.error is not None else "OwnedFactFailed"}
    return captured


def source_run_with_upload_counter(*args: Any, **kwargs: Any) -> tuple[Any, dict[str, Any]]:
    from contextlib import ExitStack
    from unittest.mock import patch

    import paramiko
    from pyinfra.connectors.ssh import SSHConnector

    fail_upload = kwargs.pop("_owned_fail_upload", False)
    fail_setup = kwargs.pop("_owned_fail_sftp_setup", False)
    observe_reconcile = kwargs.pop("_owned_observe_reconcile_refusal", False)
    counts: dict[str, Any] = {"attempted": 0, "succeeded": 0, "failed": 0, "paths": []}
    original = paramiko.SFTPClient.putfo

    def observed(client: Any, file_obj: Any, remote_path: str, *upload_args: Any, **upload_kwargs: Any) -> Any:
        counts["attempted"] += 1
        remote = Path(remote_path)
        if remote.parent.parent != Path("/private/var/tmp") or not remote.parent.name.startswith(
            "ops-deploy-daybook-source-"
        ):
            raise AssertionError("owned source upload escaped its declared temporary scope")
        counts["paths"].append(remote_path)
        try:
            if fail_upload:
                raise OSError("owned injected SFTP transfer failure")
            result = original(client, file_obj, remote_path, *upload_args, **upload_kwargs)
        except Exception:
            counts["failed"] += 1
            raise
        counts["succeeded"] += 1
        return result

    original_shell = SSHConnector.run_shell_command

    def observed_shell(connector: Any, *shell_args: Any, **shell_kwargs: Any) -> Any:
        result = original_shell(connector, *shell_args, **shell_kwargs)
        if not result[0]:
            for line in result[1]:
                if line.buffer_name == "stderr" and line.line == "sessions_source_requires_reconcile_disabled_unloaded":
                    counts["reconcile_refusal_events"] += 1
        # No raw command, stdout/stderr body or other category is retained.
        return result

    # Count the actual SFTP transfer boundary, including individual attempts;
    # no file/body/argument is inspected or copied into the receipt.
    with ExitStack() as stack:
        stack.enter_context(patch.object(paramiko.SFTPClient, "putfo", observed))
        if observe_reconcile:
            counts["reconcile_refusal_events"] = 0
            stack.enter_context(patch.object(SSHConnector, "run_shell_command", observed_shell))
        if fail_setup:
            from pyinfra.api.exceptions import ConnectError

            with patch.object(
                SSHConnector,
                "get_file_transfer_connection",
                side_effect=ConnectError("owned injected SFTP setup failure"),
            ) as injected_setup:
                result = run_deploy_ssh(*args, **kwargs)
                assert injected_setup.call_count == 1
                counts["setup_attempted"] = injected_setup.call_count
        else:
            result = run_deploy_ssh(*args, **kwargs)
    return result, counts


def assert_source_setup_failure(run: Any, counts: dict[str, Any]) -> None:
    from pyinfra.api.exceptions import PyinfraError

    assert not run.succeeded
    # Single-host normal failed-op accounting raises this fixed base error
    # after callbacks. An escaped ConnectError is a different subclass/path.
    assert type(run.error) is PyinfraError
    assert str(run.error) == "No hosts remaining!"
    prefix = "Install exact Sessions source and locked managed environment | "
    prepared = run.op(prefix + "Prepare private temporary Daybook source upload directory")
    assert prepared.succeeded
    assert prepared.changed
    assert not run.op(prefix + "Stage exact Daybook Main source bundle").succeeded
    assert counts == {"attempted": 0, "succeeded": 0, "failed": 0, "paths": [], "setup_attempted": 1}


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
            "Workflow tools/controller/action caches and checkout are disposable-VM setup, outside fixture cleanup; "
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
        (controller / "src/daybook/operations_runtime.py").write_text(
            "import json,pathlib\nclass Config:\n @classmethod\n def load(cls,path,owner):\n"
            "  value=json.loads(pathlib.Path(path).read_text())\n"
            "  assert owner=='user' and value['schema']==5 and value['enabled'] is False\n"
            "  return value\n"
        )
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
                    "UV_PYTHON_PREFERENCE=only-managed",
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
        interpreter_metadata = json.loads(
            command(
                "/usr/bin/sudo",
                "-H",
                "-u",
                "runner",
                "--",
                str(checkout / ".venv/bin/python"),
                "-I",
                "-B",
                "-S",
                "-c",
                "import json,os,sys;print(json.dumps({'version':'%d.%d.%d'%sys.version_info[:3],"
                "'owned_managed':os.path.realpath(sys.base_prefix).startswith("
                "os.path.realpath(sys.argv[1])+'/cpython-3.14.7-')}))",
                str(root / "uv/python"),
            ).stdout
        )
        owned.report["fixture_interpreter"] = interpreter_metadata
        assert interpreter_metadata == {"version": "3.14.7", "owned_managed": True}
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
        # A recursive chown here would alter the synchronized editable source's
        # ctime and make uv correctly request a reinstall. Only these newly
        # created fixture resources need ownership; code/venv/cache stay intact.
        command(
            "/usr/sbin/chown",
            "runner:staff",
            *map(
                str,
                [
                    tmpdir,
                    journal,
                    journal / "deliveries",
                    journal / "halts",
                    root / "operations.json",
                    root / "credential.json",
                    root / "agent.plist",
                    root / "staged.plist",
                    root / "native-mode",
                    root / "native-status-count",
                ],
            ),
        )
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
            if not result.succeeded:
                # The normal verifier was first. Preserve its failure; diagnostic
                # can never turn it into a passing first/repeat or pre-warm it.
                owned.report["normal_verify_failed_before_diagnostic"] = True
                owned.report["normal_verify_failure"] = {
                    "error_type": type(result.error).__name__ if result.error is not None else "OperationFailed",
                    "failed_ops": [op.name for op in result.ops if not op.succeeded],
                }
                diagnostic_before = snapshot(protected)
                diagnostic_pid = job_pid(service)
                owned.report["failed_observation_diagnostic"] = capture_observation(cfg, token, source, host_data)
                owned.report["diagnostic_protected_metadata_equal"] = snapshot(protected) == diagnostic_before
                owned.report["diagnostic_keeper_pid_equal"] = job_pid(service) == diagnostic_pid
                owned.report["failed_verify_protected_metadata_equal"] = diagnostic_before == before
                assert owned.report["diagnostic_protected_metadata_equal"]
                assert owned.report["diagnostic_keeper_pid_equal"]
                # Always fail on ORIGINAL result even if diagnostic is healthy.
            assert result.succeeded, str(result.error)
            assert result.mutating_changed_ops == []
            assert job_pid(service) == pid
            assert snapshot(protected) == before
            assert capability_present()
            owned.report["repeats"]["pure-" + str(index)] = []
        # Independent Sessions code fixture: an existing old checkout plus
        # managed environment, and a newly resolved synthetic Main in a separate
        # controller tree. It cannot alter the runtime source binding above.
        session_controller = owned.root / "sessions-controller"
        command("/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(controller), str(session_controller))
        session_root = owned.root / "sessions"
        session_root.mkdir(mode=0o755)
        session_checkout = session_root / "daybook"
        command("/usr/bin/git", "clone", "--quiet", "--no-hardlinks", str(session_controller), str(session_checkout))
        command("/usr/sbin/chown", "-R", "runner:staff", str(session_root))  # before sync only
        command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            "runner",
            "--",
            str(uv_wrapper),
            "--directory",
            str(session_checkout),
            "sync",
            "--frozen",
            "--no-dev",
            "--python",
            "3.14.7",
        )
        (session_controller / "src/daybook/__init__.py").write_text("# owned new Sessions Main\n")
        command("/usr/bin/git", "-C", str(session_controller), "add", ".")
        command(
            "/usr/bin/git",
            "-C",
            str(session_controller),
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "--quiet",
            "-m",
            "owned Sessions Main",
        )
        session_revision = command("/usr/bin/git", "-C", str(session_controller), "rev-parse", "HEAD").stdout.strip()
        command("/usr/bin/git", "-C", str(session_controller), "update-ref", "refs/heads/main", session_revision)
        session_bundle = owned.root / "sessions-main.bundle"
        command(
            "/usr/bin/git", "-C", str(session_controller), "bundle", "create", str(session_bundle), "refs/heads/main"
        )
        session_source = SourceTree(session_controller, session_revision)
        session_cfg = DaybookSessionsConfig(
            daybook_sessions_launchd_scope="user",
            daybook_sessions_service_user="runner",
            daybook_sessions_service_group="staff",
            daybook_sessions_repo_ref=session_revision,
            daybook_sessions_repo_update=False,
            daybook_sessions_checkout_force=False,
            daybook_sessions_checkout_path=str(session_checkout),
            daybook_sessions_repo_bundle_path=str(session_root / "temporary-main.bundle"),
            daybook_sessions_uv_bin=str(uv_wrapper),
            daybook_sessions_launchd_path="/usr/bin:/bin:/usr/sbin:/sbin",
        )
        session_before = snapshot([session_checkout])
        system_label = "de.wersdoerfer.daybook.weeknotes-reconcile"
        # Only read the original fixed namespace. This fixture never creates,
        # disables/enables or bootstraps a real system reconcile label.
        disabled_system = command("/bin/launchctl", "print-disabled", "system").stdout
        assert system_label not in disabled_system
        temporary_before_guard = set(Path("/private/var/tmp").glob("ops-deploy-daybook-source-*"))
        system_guarded, system_uploads = source_run_with_upload_counter(
            install_sessions_source,
            DaybookSessionsConfig.model_validate(
                {
                    **session_cfg.model_dump(mode="json"),
                    "daybook_sessions_launchd_scope": "system",
                    "daybook_sessions_launchd_manage_state": True,
                }
            ),
            session_source,
            session_bundle,
            host_name="owned-daybook",
            host_data=host_data,
            _owned_observe_reconcile_refusal=True,
        )
        assert not system_guarded.succeeded
        guard_prefix = "Install exact Sessions source and locked managed environment | "
        assert not system_guarded.op(
            guard_prefix + "Prepare private temporary Daybook source upload directory"
        ).succeeded
        assert system_uploads == {
            "attempted": 0,
            "succeeded": 0,
            "failed": 0,
            "paths": [],
            "reconcile_refusal_events": 1,
        }
        assert set(Path("/private/var/tmp").glob("ops-deploy-daybook-source-*")) == temporary_before_guard
        assert snapshot([session_checkout]) == session_before
        assert snapshot(protected) == before
        assert job_pid(service) == pid
        owned.report["sessions_original_system_reconcile_guard_refuses_before_prep_upload"] = True
        owned.report["sessions_original_system_reconcile_fixed_refusal_observed"] = system_uploads[
            "reconcile_refusal_events"
        ]
        # Dedicated legacy source convergence must preserve an unrelated running
        # Inbox-backed keeper: its own interpreter/source/resources are distinct.
        source_first, source_uploads = source_run_with_upload_counter(
            install_sessions_source,
            session_cfg,
            session_source,
            session_bundle,
            host_name="owned-daybook",
            host_data=host_data,
        )
        assert source_first.succeeded, str(source_first.error)
        assert len(source_first.mutating_changed_ops) == 3
        assert {key: value for key, value in source_uploads.items() if key != "paths"} == {
            "attempted": 1,
            "succeeded": 1,
            "failed": 0,
        }
        assert len(source_uploads["paths"]) == 1
        assert not Path(source_uploads["paths"][0]).parent.exists()
        assert not Path(session_cfg.daybook_sessions_repo_bundle_path).exists()
        assert (
            command("/usr/bin/git", "-C", str(session_checkout), "rev-parse", "HEAD").stdout.strip() == session_revision
        )
        assert snapshot(protected) == before
        assert job_pid(service) == pid
        assert capability_present()
        session_current = snapshot([session_checkout])
        source_repeat, source_repeat_uploads = source_run_with_upload_counter(
            install_sessions_source,
            session_cfg,
            session_source,
            session_bundle,
            host_name="owned-daybook",
            host_data=host_data,
        )
        assert source_repeat.succeeded, str(source_repeat.error)
        assert source_repeat.mutating_changed_ops == []
        assert source_repeat_uploads == {"attempted": 0, "succeeded": 0, "failed": 0, "paths": []}
        assert snapshot([session_checkout]) == session_current
        assert snapshot(protected) == before
        assert job_pid(service) == pid
        assert capability_present()
        owned.report["sessions_source_first_managed_ops"] = 3
        owned.report["sessions_source_first_actual_sftp"] = source_uploads
        owned.report["sessions_source_repeat_managed_ops"] = 0
        owned.report["sessions_source_repeat_actual_sftp"] = source_repeat_uploads
        owned.report["sessions_source_bundle_removed_runtime_resources_preserved"] = True
        owned.report["sessions_legacy_first_repeat_unrelated_keeper_pid_resources_preserved"] = True
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
        # Fresh, separate source-run fault: a new synthetic Main requires a
        # transfer, whose actual SFTP method is forced to fail before bytes move.
        # The original failed upload stays failed; cleanup must still run.
        (session_controller / "src/daybook/__init__.py").write_text("# owned SFTP failure Main\n")
        command("/usr/bin/git", "-C", str(session_controller), "add", ".")
        command(
            "/usr/bin/git",
            "-C",
            str(session_controller),
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "--quiet",
            "-m",
            "owned transfer fault",
        )
        fault_revision = command("/usr/bin/git", "-C", str(session_controller), "rev-parse", "HEAD").stdout.strip()
        command("/usr/bin/git", "-C", str(session_controller), "update-ref", "refs/heads/main", fault_revision)
        fault_bundle = owned.root / "sessions-fault.bundle"
        command("/usr/bin/git", "-C", str(session_controller), "bundle", "create", str(fault_bundle), "refs/heads/main")
        fault_source_cfg = session_cfg.model_copy(update={"daybook_sessions_repo_ref": fault_revision})
        source_failure, failed_uploads = source_run_with_upload_counter(
            install_sessions_source,
            fault_source_cfg,
            SourceTree(session_controller, fault_revision),
            fault_bundle,
            host_name="owned-daybook",
            host_data=host_data,
            _owned_fail_upload=True,
        )
        assert not source_failure.succeeded
        assert failed_uploads["attempted"] == failed_uploads["failed"] == 3
        assert failed_uploads["succeeded"] == 0
        assert len(set(failed_uploads["paths"])) == 1
        assert not Path(failed_uploads["paths"][0]).parent.exists()
        assert snapshot([session_checkout]) == session_current
        assert snapshot(protected) == before
        assert job_pid(service) is None
        assert capability_present()
        owned.report["sessions_source_injected_sftp_failure_cleanup_and_old_source_exact"] = True
        owned.report["sessions_source_failed_actual_sftp_attempts"] = failed_uploads
        # SFTP negotiation can fail while the ordinary SSH connection remains
        # usable. It must remain a failed op and still remove its private prep.
        temporary_before = set(Path("/private/var/tmp").glob("ops-deploy-daybook-source-*"))
        setup_failure, setup_uploads = source_run_with_upload_counter(
            install_sessions_source,
            fault_source_cfg,
            SourceTree(session_controller, fault_revision),
            fault_bundle,
            host_name="owned-daybook",
            host_data=host_data,
            _owned_fail_sftp_setup=True,
        )
        owned.report["sessions_source_sftp_setup_error_type"] = type(setup_failure.error).__name__
        assert_source_setup_failure(setup_failure, setup_uploads)
        assert set(Path("/private/var/tmp").glob("ops-deploy-daybook-source-*")) == temporary_before
        assert snapshot([session_checkout]) == session_current
        assert snapshot(protected) == before
        assert job_pid(service) is None
        assert capability_present()
        owned.report["sessions_source_sftp_setup_failure_remains_failed_cleanup_and_source_exact"] = True
        # Disabled-first configuration staging is a separate managed stage.
        # It cannot activate/install the live label or update this exact code.
        stage_cfg = cfg.model_copy(update={"action": "replace", "confirmed": True})
        stage_protected = [path for path in protected if path != root / "operations.json"]
        stage_before = snapshot(stage_protected)
        staged = run_deploy_ssh(
            stage_daybook_runtime,
            stage_cfg,
            token,
            source,
            host_name="owned-daybook",
            host_data=host_data,
        )
        assert staged.succeeded, str(staged.error)
        assert len(staged.mutating_changed_ops) == 1
        assert json.loads((root / "operations.json").read_text())["enabled"] is False
        assert job_pid(service) is None
        assert capability_present()
        assert snapshot(stage_protected) == stage_before
        staged_before = snapshot(protected)
        staged_repeat = run_deploy_ssh(
            stage_daybook_runtime,
            stage_cfg,
            token,
            source,
            host_name="owned-daybook",
            host_data=host_data,
        )
        assert staged_repeat.succeeded, str(staged_repeat.error)
        assert staged_repeat.mutating_changed_ops == []
        assert snapshot(protected) == staged_before
        assert job_pid(service) is None
        assert capability_present()
        owned.report["disabled_replacement_first_managed_ops"] = 1
        owned.report["disabled_replacement_repeat_managed_ops"] = 0
        owned.report["disabled_replacement_no_activation_source_and_other_resources_equal"] = True
        # Deliberate fresh fault setup below restores only this synthetic profile
        # to enabled, exactly as initial fixture setup; not a production cutover.
        (root / "operations.json").write_text(
            render_resource(cfg.model_copy(update={"action": "cutover"}), "policy.json.j2")
        )
        before = snapshot(protected)
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
