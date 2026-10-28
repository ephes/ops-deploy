"""Owned root/GUI runtime transition with synthetic app/server/ledger only.

Reuses the qualified Inbox installation as an owned prerequisite, not a replay
of its entire proof matrix. No inventory, real app or remote API is reachable.
"""

from __future__ import annotations

import json
import os
import pwd
import sys
from pathlib import Path, PurePosixPath
from typing import Any
from unittest.mock import patch

import daybook_inbox_native_fixture as inbox
from daybook_resources_native_fixture import provenance, wait
from daybook_runtime_native_fixture import snapshot
from mac_apps_owned import OwnedMac, command, job_pid
from pyinfra.connectors.ssh import SSHConnector

from ops_deploy.core.git_source import SourceTree
from ops_deploy.services.daybook_operations_runtime import (
    DaybookRuntimeConfig,
    stage_daybook_runtime,
    transition_daybook_runtime,
)
from ops_deploy.services.daybook_operations_runtime.render import render_resource
from ops_deploy.services.daybook_voice_memo_inbox import report_daybook_inbox_interruption
from ops_deploy.services.daybook_voice_memo_inbox.render import SECRET_DEFAULTS
from ops_deploy.services.daybook_voice_memo_inbox.report import _ReportCommand
from ops_deploy.testing import run_deploy_ssh

APP = """import json,pathlib,sys,time
def main():
    args=sys.argv[1:]
    if args[:2]==['voice-memos','--help']:return 0
    if args[:3]==['voice-memos','status','--summary-only']:
        import os
        root=pathlib.Path(os.environ['DAYBOOK_VOICE_MEMOS_POLICY']).parent
        ledger=json.loads((root/'owned-synthetic-ledger.json').read_text())
        print(json.dumps({'long_in_flight_count':ledger['count'],'private':'OWNED-DISCARD-ONLY'}))
        return 0
    if args[:2]==['operations','serve'] or args[:2]==['voice-memos','ingest']:
        time.sleep(10000);return 0
    policy=pathlib.Path(args[args.index('--policy')+1])
    with (policy.parent/'owned-managed-calls').open('a') as stream:stream.write(args[1]+'\\n')
    if args[:2]==['operations','idle']:return 0
    if args[:2]==['operations','status']:
        enabled=json.loads(policy.read_text())['enabled']
        server=json.loads((policy.parent/'owned-server.json').read_text())
        print(json.dumps({'enabled':enabled,'status':'idle','server':server,'private':'OWNED-DISCARD-ONLY'}))
        return 0
    return 7
"""

CONFIG = """import json,pathlib
class Config:
    @classmethod
    def load(cls,path,owner):
        data=json.loads(pathlib.Path(path).read_text())
        assert data['schema']==5 and owner=='root'
        return data
"""


def synthetic_source(owned: OwnedMac, uv: str) -> tuple[SourceTree, Path]:
    with patch.object(inbox, "APP", APP):
        original, bundle = inbox.source_tree(owned, uv)
    (original.path / "src/daybook/operations_runtime.py").write_text(CONFIG)
    command("/usr/bin/git", "-C", str(original.path), "add", ".")
    command(
        "/usr/bin/git",
        "-C",
        str(original.path),
        "-c",
        "user.name=Owned",
        "-c",
        "user.email=owned@example.test",
        "commit",
        "-qm",
        "owned transition app",
    )
    revision = command("/usr/bin/git", "-C", str(original.path), "rev-parse", "HEAD").stdout.strip()
    command("/usr/bin/git", "-C", str(original.path), "update-ref", "refs/remotes/origin/main", revision)
    bundle.unlink()
    command("/usr/bin/git", "-C", str(original.path), "bundle", "create", str(bundle), "refs/remotes/origin/main")
    return SourceTree(original.path, revision), bundle


def gone(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def phase(owned: OwnedMac, name: str, result: Any) -> None:
    owned.report.setdefault("phases", {})[name] = {
        "succeeded": result.succeeded,
        "managed": len(result.mutating_changed_ops),
        "ops": [
            {"name": row.name, "succeeded": row.succeeded, "changed": row.changed, "read_only": row.read_only}
            for row in result.ops
        ],
    }


def refusal_run(cfg: Any, token: Any, source: SourceTree, transport: Any, category: str) -> Any:
    observed = 0
    original = SSHConnector.run_shell_command

    def observe(connector: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal observed
        success, output = original(connector, *args, **kwargs)
        if not success:
            observed += sum(line.buffer_name == "stderr" and line.line == category for line in output)
        return success, output

    with patch.object(SSHConnector, "run_shell_command", observe):
        result = run_deploy_ssh(
            transition_daybook_runtime, cfg, token, source, host_name="owned-exact-refusal", host_data=transport
        )
    assert not result.succeeded
    assert observed == 1, "exact genuine transition refusal must be reached once"
    return result


def main() -> None:
    owned = OwnedMac("daybook-transition")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        uv = str(Path(sys.executable).parent / "uv")
        assert command(uv, "--version").stdout.startswith("uv 0.13.5 ")
        source, bundle = synthetic_source(owned, uv)
        transport = owned.ssh_transport()
        cfg = inbox.configuration(owned, source, bundle, uv, actor, name="transition")
        for label in (cfg.daybook_voice_memo_inbox_launchd_label, cfg.daybook_voice_memo_inbox_long_launchd_label):
            owned.adopt_gui_label(actor.pw_uid, label)
        installed, _counts = inbox.run(
            owned, transport, cfg, dict.fromkeys(SECRET_DEFAULTS, "UNUSABLE-OWNED"), source, bundle
        )
        assert installed.succeeded
        phase(owned, "owned-inbox-prerequisite", installed)
        root = Path(cfg.daybook_voice_memo_inbox_install_root)
        calls = root / "owned-managed-calls"
        calls.write_text("")
        calls.chmod(0o666)  # Explicit disposable synthetic app log, GUI writable.
        server = root / "owned-server.json"
        server.write_text(json.dumps({"enabled": True, "active_state": None}))
        server.chmod(0o644)
        ledger = root / "owned-synthetic-ledger.json"
        ledger.write_text(json.dumps({"count": 3, "private": "UNUSABLE-OWNED-SYNTHETIC"}))
        ledger.chmod(0o644)
        ledger_before = snapshot([ledger])
        # Report deliberately retains the original real GUI account HOME;
        # source/policy/ledger remain wholly inside the disposable owned root.
        report_cfg = cfg.model_copy(update={"daybook_voice_memo_inbox_service_home": actor.pw_dir})
        seen_reports = []
        original_shell = SSHConnector.run_shell_command

        def observe_report(connector: Any, cmd: Any, *args: Any, **kwargs: Any) -> Any:
            success, output = original_shell(connector, cmd, *args, **kwargs)
            if isinstance(cmd, _ReportCommand):
                assert success
                result = json.loads(output.stdout)
                assert result == {"reported": True, "long_in_flight_count": 3}
                seen_reports.append(result)
            return success, output

        with patch.object(SSHConnector, "run_shell_command", observe_report):
            reported = run_deploy_ssh(
                report_daybook_inbox_interruption, report_cfg, host_name="owned-report", host_data=transport
            )
        assert seen_reports == [{"reported": True, "long_in_flight_count": 3}]
        assert reported.succeeded
        assert len(reported.mutating_changed_ops) == 1
        assert ledger_before == snapshot([ledger])
        assert calls.read_text() == ""
        owned.report["actual_synthetic_report_aggregate"] = seen_reports[0]
        phase(owned, "optional-managed-synthetic-ledger-report", reported)
        runtime = DaybookRuntimeConfig(user=actor.pw_name, revision=source.commit).model_copy(
            update={
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
                "credential": PurePosixPath(cfg.daybook_voice_memo_inbox_service_home + "/runtime-credentials.json"),
            }
        )
        token = {"executor_token": "UNUSABLE-OWNED-EXECUTOR-CREDENTIAL-ONLY"}
        staged = run_deploy_ssh(
            stage_daybook_runtime, runtime, token, source, host_name="owned-stage", host_data=transport
        )
        assert staged.succeeded
        phase(owned, "owned-disabled-stage-prerequisite", staged)
        assert json.loads(Path(str(runtime.policy)).read_text())["enabled"] is False
        original = Path(str(runtime.plist)).read_bytes()
        cutover = runtime.model_copy(update={"action": "cutover", "confirmed": True, "start": True})
        transitioned = run_deploy_ssh(
            transition_daybook_runtime, cutover, token, source, host_name="owned-cutover", host_data=transport
        )
        phase(owned, "cutover-start", transitioned)
        assert transitioned.succeeded
        assert len(transitioned.mutating_changed_ops) == 1
        service = "gui/" + str(actor.pw_uid) + "/" + runtime.label
        wait(lambda: job_pid(service) is not None)
        pid = job_pid(service)
        assert pid is not None
        assert Path(str(runtime.legacy_plist)).read_bytes() == original
        assert Path(str(runtime.plist)).read_text() == render_resource(cutover, "runtime.plist.j2")
        assert json.loads(Path(str(runtime.policy)).read_text())["enabled"] is True
        assert calls.read_text().splitlines() == ["status", "idle", "status"]
        protected = [root, Path(cfg.daybook_voice_memo_inbox_service_home)]
        before = snapshot(protected)
        refused = refusal_run(cutover, token, source, transport, "runtime_transition_requires_quiescence")
        phase(owned, "active-keeper-refusal", refused)
        assert not refused.succeeded
        assert snapshot(protected) == before
        assert job_pid(service) == pid
        # Fixture setup explicitly stops only its exact unique owned job.
        command("/bin/launchctl", "bootout", service)
        command("/bin/launchctl", "disable", service)
        wait(lambda: job_pid(service) is None)
        wait(lambda: gone(pid))
        server.write_text(json.dumps({"enabled": False, "active_state": None}))
        rollback = runtime.model_copy(update={"action": "rollback", "confirmed": True, "start": False})
        rolled = run_deploy_ssh(
            transition_daybook_runtime, rollback, token, source, host_name="owned-rollback", host_data=transport
        )
        phase(owned, "rollback-without-start", rolled)
        assert rolled.succeeded
        assert len(rolled.mutating_changed_ops) == 1
        assert Path(str(runtime.plist)).read_bytes() == original
        assert Path(str(runtime.legacy_plist)).read_bytes() == original
        assert json.loads(Path(str(runtime.policy)).read_text())["enabled"] is False
        assert job_pid(service) is None
        # Explicit rollback remains a managed workflow, not a no-op headline.
        command_before = snapshot([Path(str(runtime.plist)), Path(str(runtime.legacy_plist))])
        again = run_deploy_ssh(
            transition_daybook_runtime, rollback, token, source, host_name="owned-rollback-repeat", host_data=transport
        )
        phase(owned, "explicit-rollback-repeat", again)
        assert again.succeeded
        assert len(again.mutating_changed_ops) == 1
        assert command_before == snapshot([Path(str(runtime.plist)), Path(str(runtime.legacy_plist))])
        saved = Path(str(runtime.legacy_plist))
        saved.chmod(0o666)  # Explicit fixture fault, restored before next case.
        before = snapshot(protected)
        unsafe = refusal_run(rollback, token, source, transport, "runtime_transition_command_boundary_invalid")
        phase(owned, "unsafe-command-refuses-before-app-or-mutation", unsafe)
        assert not unsafe.succeeded
        assert snapshot(protected) == before
        saved.chmod(0o644)
        marker = Path(str(runtime.closeout_marker))
        marker.write_text("OWNED CLOSED OUT\n")
        marker.chmod(0o644)
        before = snapshot(protected)
        closed = refusal_run(rollback, token, source, transport, "runtime_closed_out_rollback_refused")
        phase(owned, "closed-out-rollback-refusal", closed)
        assert not closed.succeeded
        assert snapshot(protected) == before
        owned.report.update(
            synthetic_app_only=True,
            real_api_calls=0,
            real_ledger_reads=0,
            synthetic_ledger_metadata_exact=ledger_before == snapshot([ledger]),
            original_command_bytes_exact=True,
            expected_faults=3,
        )
    except BaseException as error:
        failure = error
        owned.report["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        reset = []
        for service in owned.labels:
            if service.startswith("gui/"):
                command("/bin/launchctl", "bootout", service, check=False)
                command("/bin/launchctl", "enable", service, check=False)
                reset.append(service)
        owned.report["owned_unique_disabled_entries_reset_enabled"] = reset
        owned.report["cleanup_limit"] = (
            "OS may retain unique enabled rows; native setup/cache I/O is counted separately."
        )
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
