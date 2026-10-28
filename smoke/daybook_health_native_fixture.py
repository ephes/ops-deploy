"""Owned root/GUI original health/preflight/closeout; synthetic records only."""

from __future__ import annotations

import json
import pwd
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import patch

import daybook_inbox_native_fixture as inbox
import daybook_transition_native_fixture as transition
from daybook_resources_native_fixture import provenance, wait
from daybook_runtime_native_fixture import snapshot
from mac_apps_owned import OwnedMac, command, job_pid
from pyinfra.connectors.ssh import SSHConnector

from ops_deploy.services.daybook_operations_runtime import (
    DaybookRuntimeConfig,
    RuntimeStopPolicy,
    RuntimeWorkers,
    check_daybook_runtime_update,
    closeout_daybook_runtime,
    stage_daybook_runtime,
    transition_daybook_runtime,
    verify_daybook_runtime_health,
)
from ops_deploy.services.daybook_operations_runtime.inspect import verify_daybook_runtime
from ops_deploy.services.daybook_operations_runtime.status import SourceStatus
from ops_deploy.services.daybook_voice_memo_inbox.render import SECRET_DEFAULTS
from ops_deploy.testing import run_deploy_ssh

APP = """import json,pathlib,shlex,subprocess,sys,time
def main():
    args=sys.argv[1:]
    if args[:2]==['voice-memos','--help']:return 0
    def option(name):return args[args.index(name)+1]
    root=pathlib.Path(option('--policy')).parent
    if args[:2]==['operations','host-keep']:
        tmux=option('--tmux');socket=option('--socket')
        while True:
            if subprocess.run([tmux,'-L',socket,'has-session','-t','=supervisor'],capture_output=True).returncode:
                child=shlex.join([sys.executable,'-I','-B','-c','import time;time.sleep(10000)','operations','serve'])
                subprocess.run([tmux,'-L',socket,'new-session','-d','-s','supervisor',child],capture_output=True,check=True)
            time.sleep(.1)
    with (root/'owned-managed-calls').open('a') as stream:stream.write(args[1]+'\\n')
    if args[:2]==['operations','idle']:return 0
    if args[:2]!=['operations','status']:return 7
    server=json.loads((root/'owned-server.json').read_text())
    if server.pop('cli_nonzero',False):return 17
    policy=json.loads(pathlib.Path(option('--policy')).read_text())
    rows=[];status='idle'
    for path in sorted((pathlib.Path(policy['journal'])/'deliveries').glob('*.json')):
        try:
            row=json.loads(path.read_text());status=row['phase']
        except (ValueError,KeyError):
            row={'private':'OWNED-SYNTHETIC-UNREADABLE'};status='unreadable'
        rows.append(row)
    print(json.dumps({'enabled':policy['enabled'],'status':status,'server':server,'deliveries':rows}))
    return 0
"""


def count(path: Path) -> int:
    return len(path.read_text().splitlines())


def protected(paths: list[Path], counter: Path) -> Any:
    return {key: value for key, value in snapshot(paths).items() if key != str(counter)}


def failure_run(call: Any, cfg: Any, token: Any, source: Any, transport: Any, category: str, **kwargs: Any) -> Any:
    reached = 0
    original = SSHConnector.run_shell_command

    def observe(connector: Any, *args: Any, **options: Any) -> Any:
        nonlocal reached
        succeeded, output = original(connector, *args, **options)
        if not succeeded:
            reached += sum(line.buffer_name == "stderr" and line.line == category for line in output)
        return succeeded, output

    with patch.object(SSHConnector, "run_shell_command", observe):
        result = run_deploy_ssh(
            call,
            cfg,
            *([token, source] if token is not None else []),
            host_name="owned-original-failure",
            host_data=transport,
            **kwargs,
        )
    assert not result.succeeded
    assert reached == 1
    return result


def main() -> None:
    owned = OwnedMac("daybook-health")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        uv = str(Path(sys.executable).parent / "uv")
        with patch.object(transition, "APP", APP):
            source, bundle = transition.synthetic_source(owned, uv)
        transport = owned.ssh_transport()
        cfg = inbox.configuration(owned, source, bundle, uv, actor, name="health")
        for label in (cfg.daybook_voice_memo_inbox_launchd_label, cfg.daybook_voice_memo_inbox_long_launchd_label):
            owned.adopt_gui_label(actor.pw_uid, label)
        installed, _ = inbox.run(
            owned, transport, cfg, dict.fromkeys(SECRET_DEFAULTS, "UNUSABLE-OWNED"), source, bundle
        )
        assert installed.succeeded
        transition.phase(owned, "owned-root-code-prerequisite", installed)
        root = Path(cfg.daybook_voice_memo_inbox_install_root)
        counter = root / "owned-managed-calls"
        counter.write_text("")
        counter.chmod(0o666)  # Explicit owned GUI-writable app-work counter, not code.
        server = root / "owned-server.json"
        remote = {"enabled": False, "active_state": None, "needs_operator": True, "expiry_pending": True}
        server.write_text(json.dumps({**remote, "enabled": True}))
        server.chmod(0o644)
        tmpdir = owned.root / "tmux"
        tmpdir.mkdir(mode=0o700)
        command("/usr/sbin/chown", "runner:staff", str(tmpdir))
        tmux = "/opt/homebrew/bin/tmux"
        assert Path(tmux).is_file(), "native workflow installs this owned fixture prerequisite"
        socket = "daybook-health-" + owned.suffix
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
                socket,
            ]
        )
        wait(lambda: (tmpdir / ("tmux-" + str(actor.pw_uid)) / socket).is_socket())
        tmux_prefix = [
            "/usr/bin/sudo",
            "-H",
            "-u",
            "runner",
            "--",
            "/usr/bin/env",
            "TMUX_TMPDIR=" + str(tmpdir),
            tmux,
            "-L",
            socket,
        ]
        command(*tmux_prefix, "new-session", "-d", "-s", "host", "/bin/sleep 10000")
        runtime = DaybookRuntimeConfig(user=actor.pw_name, revision=source.commit).model_copy(
            update={
                "mode": "host",
                "host_socket": socket,
                "host_tmux": PurePosixPath(tmux),
                "host_tmpdir": PurePosixPath(str(tmpdir)),
                "host_session": "host",
                "host_lock": PurePosixPath(str(owned.root / "owned-host.lock")),
                "home": PurePosixPath(cfg.daybook_voice_memo_inbox_service_home),
                "install_root": PurePosixPath(str(root)),
                "python": PurePosixPath(cfg.daybook_voice_memo_inbox_python),
                "uv_bin": PurePosixPath(uv),
                "importer_policy": PurePosixPath(cfg.daybook_voice_memo_inbox_policy_path),
                "label": cfg.daybook_voice_memo_inbox_launchd_label,
                "plist": PurePosixPath(cfg.daybook_voice_memo_inbox_plist_path),
                "staged_plist": PurePosixPath(str(root / "operations.launchd.plist")),
                "legacy_plist": PurePosixPath(str(root / "legacy.plist")),
                "closeout_marker": PurePosixPath(str(root / "closed-out")),
                "policy": PurePosixPath(str(root / "operations.json")),
                "journal": PurePosixPath(cfg.daybook_voice_memo_inbox_service_home + "/store"),
                "credential": PurePosixPath(cfg.daybook_voice_memo_inbox_service_home + "/operations-credential.json"),
                "workers": RuntimeWorkers(count=3, long=2),
                "status_sources": ("regular", "long"),
            }
        )
        token = {"executor_token": "UNUSABLE-OWNED-EXECUTOR-CREDENTIAL-ONLY"}
        staged = run_deploy_ssh(
            stage_daybook_runtime, runtime, token, source, host_name="owned-stage", host_data=transport
        )
        assert staged.succeeded
        cutover = runtime.model_copy(update={"action": "cutover", "confirmed": True, "start": True})
        started = run_deploy_ssh(
            transition_daybook_runtime, cutover, token, source, host_name="owned-start", host_data=transport
        )
        assert started.succeeded
        service = "gui/" + str(actor.pw_uid) + "/" + runtime.label
        pid = None  # First health itself must tolerate normal keeper startup.
        server.write_text(
            json.dumps(remote)
        )  # Owned setup: intentionally disabled remote sources after cutover prerequisite.
        paths = [root, Path(cfg.daybook_voice_memo_inbox_service_home)]
        before = protected(paths, counter)
        for name in ("empty-health-first", "empty-health-repeat"):
            previous = count(counter)
            result = run_deploy_ssh(
                verify_daybook_runtime_health, runtime, token, source, host_name="owned-health", host_data=transport
            )
            assert result.succeeded
            assert len(result.mutating_changed_ops) == 1
            assert count(counter) - previous == 2
            assert protected(paths, counter) == before
            if pid is None:
                pid = job_pid(service)
                assert pid is not None
            assert job_pid(service) == pid
            transition.phase(owned, name, result)
        # Existing pure resource API no longer invents remote-enabled/attention
        # refusals; it remains resource-only and cannot replace original CLIhealth.
        statuses = tuple(SourceStatus(key, False, None, True, 1, True) for key in runtime.status_sources)
        previous = count(counter)
        result = run_deploy_ssh(
            verify_daybook_runtime,
            runtime,
            token,
            source,
            statuses=statuses,
            host_name="owned-resource-only",
            host_data=transport,
        )
        assert result.succeeded
        assert not result.mutating_changed_ops
        assert count(counter) == previous
        assert protected(paths, counter) == before
        record = Path(str(runtime.journal)) / "deliveries/owned.json"
        record.write_text(json.dumps({"phase": "running", "private": "OWNED-RECORD-DISCARD"}))
        record.chmod(0o600)
        command("/usr/sbin/chown", "runner:staff", str(record))
        before = protected(paths, counter)
        previous = count(counter)
        result = run_deploy_ssh(
            verify_daybook_runtime_health, runtime, token, source, host_name="owned-nonempty", host_data=transport
        )
        assert result.succeeded
        assert count(counter) - previous == 2
        assert protected(paths, counter) == before
        assert job_pid(service) == pid
        transition.phase(owned, "nonempty-readable-health", result)
        record.write_text("OWNED-UNREADABLE-SYNTHETIC")
        before = protected(paths, counter)
        previous = count(counter)
        failed = failure_run(
            verify_daybook_runtime_health,
            runtime,
            token,
            source,
            transport,
            "runtime_health_local_unreadable_or_disabled",
        )
        assert count(counter) - previous == 1
        assert protected(paths, counter) == before
        assert job_pid(service) == pid
        transition.phase(owned, "unreadable-original-refusal", failed)
        owned.report["phases"]["unreadable-original-refusal"]["actual_managed_cli_calls"] = 1
        record.unlink()  # Explicit owned fault cleanup.
        server.write_text(json.dumps({**remote, "cli_nonzero": True}))
        before = protected(paths, counter)
        previous = count(counter)
        failed = failure_run(
            verify_daybook_runtime_health, runtime, token, source, transport, "runtime_health_cli_failed"
        )
        assert count(counter) - previous == 1
        assert protected(paths, counter) == before
        assert job_pid(service) == pid
        transition.phase(owned, "original-cli-nonzero-refusal", failed)
        owned.report["phases"]["original-cli-nonzero-refusal"]["actual_managed_cli_calls"] = 1
        server.write_text(json.dumps(remote))
        stop_cfg = runtime.model_copy(update={"action": "stop", "confirmed": True})
        before = protected(paths, counter)
        for name in ("managed-update-check", "managed-update-check-repeat"):
            previous = count(counter)
            result = run_deploy_ssh(
                check_daybook_runtime_update,
                stop_cfg,
                policy=RuntimeStopPolicy(),
                host_name="owned-preflight",
                host_data=transport,
            )
            assert result.succeeded
            assert len(result.mutating_changed_ops) == 1
            assert count(counter) - previous == 2
            assert protected(paths, counter) == before
            assert job_pid(service) == pid
            transition.phase(owned, name, result)
        server.write_text(json.dumps({**remote, "active_state": "assigned"}))
        before = protected(paths, counter)
        previous = count(counter)
        failed = failure_run(
            check_daybook_runtime_update,
            stop_cfg,
            None,
            None,
            transport,
            "runtime_machine_holds_work",
            policy=RuntimeStopPolicy(),
        )
        assert count(counter) - previous == 2
        assert protected(paths, counter) == before
        assert job_pid(service) == pid
        transition.phase(owned, "preflight-busy-original-refusal", failed)
        owned.report["phases"]["preflight-busy-original-refusal"]["actual_managed_cli_calls"] = 2
        close_cfg = runtime.model_copy(update={"action": "closeout", "confirmed": True})
        previous = count(counter)
        before = protected(paths, counter)
        closed = run_deploy_ssh(closeout_daybook_runtime, close_cfg, host_name="owned-closeout", host_data=transport)
        assert closed.succeeded
        assert len(closed.mutating_changed_ops) == 1
        assert not Path(str(runtime.legacy_plist)).exists()
        assert Path(str(runtime.closeout_marker)).is_file()
        assert job_pid(service) == pid
        assert count(counter) == previous
        after = protected(paths, counter)
        permitted = {str(runtime.legacy_plist), str(runtime.closeout_marker), str(root)}
        assert all(before.get(path) == after.get(path) for path in set(before) | set(after) if path not in permitted)
        assert before[str(root)][:5] == after[str(root)][:5]
        transition.phase(owned, "closeout-keeps-keeper", closed)
        before = protected(paths, counter)
        repeated = run_deploy_ssh(
            closeout_daybook_runtime, close_cfg, host_name="owned-closeout-repeat", host_data=transport
        )
        assert repeated.succeeded
        assert not repeated.mutating_changed_ops
        assert protected(paths, counter) == before
        assert job_pid(service) == pid
        assert count(counter) == previous
        transition.phase(owned, "closeout-repeat", repeated)
        owned.report.update(
            status="passed",
            synthetic_app_and_records_only=True,
            real_API_calls=0,
            inventory_record_body_reads=0,
            synthetic_record_reads_by_app=True,
            expected_faults=3,
            managed_health_cli_calls_per_full_success=2,
            managed_updatecheck_cli_calls_per_success=2,
            keeper_pid_preserved=pid,
            original_remote_flags_not_activation_requirements=True,
        )
    except BaseException as error:
        failure = error
    finally:
        for service in owned.labels:
            if service.startswith("gui/"):
                command("/bin/launchctl", "bootout", service, check=False)
                command("/bin/launchctl", "enable", service, check=False)
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
