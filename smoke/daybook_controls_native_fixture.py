"""Disposable exact-label operators; no inventory application or data actions."""

from __future__ import annotations

import os
import plistlib
import pwd
import re
from pathlib import Path
from typing import Any
from unittest.mock import patch

import paramiko
from daybook_archive_native_fixture import user_transport
from daybook_resources_native_fixture import provenance, wait
from daybook_runtime_native_fixture import snapshot
from mac_apps_owned import OwnedMac, command, job_pid
from pyinfra.connectors.ssh import SSHConnector

from ops_deploy.services.daybook_controls import DaybookControlConfig, run_daybook_control
from ops_deploy.services.daybook_weeknotes_controls import WeeknotesDisableConfig, disable_weeknotes_schedule
from ops_deploy.testing import run_deploy_ssh


def run(owned: OwnedMac, cfg: Any, transport: Any, phase: str, deploy_fn: Any = run_daybook_control) -> Any:
    uploads = 0
    original = paramiko.SFTPClient.putfo
    original_shell = SSHConnector.run_shell_command
    tokens = []

    def put(*args: Any, **kwargs: Any) -> Any:
        nonlocal uploads
        uploads += 1
        return original(*args, **kwargs)

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        result = original_shell(connector, *args, **kwargs)
        tokens.extend(
            line
            for line in result[1].stdout_lines
            if line in {"DAYBOOK_RECONCILE_DISABLED_CHANGED", "DAYBOOK_RECONCILE_ALREADY_DISABLED"}
        )
        return result

    with patch.object(paramiko.SFTPClient, "putfo", put), patch.object(SSHConnector, "run_shell_command", shell):
        result = run_deploy_ssh(
            deploy_fn,
            cfg,
            host_name="owned-control",
            host_data=transport,
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
        "actual_sftp": uploads,
        "error_type": type(result.error).__name__ if result.error else None,
        "weeknotes_result_tokens": tokens,
    }
    assert uploads == 0
    assert job_pid(owned.report["keeper_service"]) == owned.report["keeper_pid"]
    return result


def create_plist(path: Path, label: str, uid: int, gid: int) -> None:
    path.write_bytes(
        plistlib.dumps(
            {
                "Label": label,
                "ProgramArguments": ["/bin/sleep", "600"],
                "RunAtLoad": True,
            }
        )
    )
    os.chown(path, uid, gid)
    path.chmod(0o600)


def main() -> None:
    owned = OwnedMac("daybook-controls")
    failure: BaseException | None = None
    week_label: str | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        root_transport = owned.ssh_transport()
        root_report = dict(owned.report["transport"])
        direct_transport = user_transport(owned, actor)
        owned.report["transports"] = {"studio": root_report, "atlas": dict(owned.report["transport"])}
        keeper_label = "com.example.ops-mac-apps.controls-keeper." + owned.suffix
        owned.adopt_gui_label(actor.pw_uid, keeper_label)
        keeper = owned.root / "keeper.plist"
        create_plist(keeper, keeper_label, actor.pw_uid, actor.pw_gid)
        command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(keeper))
        keeper_service = "gui/" + str(actor.pw_uid) + "/" + keeper_label
        wait(lambda: job_pid(keeper_service) is not None)
        owned.report.update(keeper_service=keeper_service, keeper_pid=job_pid(keeper_service))
        owned.report["configuration_validation"] = {
            "original_declarations_validated": True,
            "owned_paths_and_labels_substituted_with_model_copy": True,
            "substituted_values_revalidated": False,
            "scope": "Mechanism proof; original home/label validation is covered separately by source tests.",
        }
        protected = []
        configurations = {}
        for service in ("photos", "archive", "attention", "inbox"):
            home = owned.root / ("home-" + service)
            agents = home / "Library/LaunchAgents"
            agents.mkdir(parents=True)
            for path in (home, home / "Library", agents):
                os.chown(path, actor.pw_uid, actor.pw_gid)
                path.chmod(0o700)
            for name in ("config.json", "state.sqlite3", "stdout.log", "credentials.json"):
                path = home / name
                path.write_bytes(b"OWNED retained synthetic private bytes")
                os.chown(path, actor.pw_uid, actor.pw_gid)
                path.chmod(0o600)
                protected.append(path)
            label = "com.example.ops-mac-apps.control-" + service + "." + owned.suffix
            owned.adopt_gui_label(actor.pw_uid, label)
            plist = agents / (label + ".plist")
            create_plist(plist, label, actor.pw_uid, actor.pw_gid)
            command("/bin/launchctl", "enable", "gui/" + str(actor.pw_uid) + "/" + label)
            command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(plist))
            wait(lambda selected=label: job_pid("gui/" + str(actor.pw_uid) + "/" + selected) is not None)
            cfg = DaybookControlConfig(
                service=service,
                action="remove" if service == "attention" else "disable",
                owner=actor.pw_name,
                confirmed=service == "attention",
            )
            cfg = cfg.model_copy(update={"home": str(home), "label": label})
            if service == "inbox":
                long_label = "com.example.ops-mac-apps.control-inbox-long." + owned.suffix
                owned.adopt_gui_label(actor.pw_uid, long_label)
                long_plist = agents / (long_label + ".plist")
                create_plist(long_plist, long_label, actor.pw_uid, actor.pw_gid)
                command("/bin/launchctl", "enable", "gui/" + str(actor.pw_uid) + "/" + long_label)
                command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(long_plist))
                wait(lambda selected=long_label: job_pid("gui/" + str(actor.pw_uid) + "/" + selected) is not None)
                cfg = cfg.model_copy(update={"long_label": long_label})
                protected.append(long_plist)
            configurations[service] = (cfg, plist)
        week_label = owned.label("weeknotes-disable")
        week_plist = owned.root / "weeknotes.plist"
        create_plist(week_plist, week_label, 0, 0)
        command("/bin/launchctl", "bootstrap", "system", str(week_plist))
        wait(lambda: job_pid("system/" + week_label) is not None)
        week_cfg = WeeknotesDisableConfig().model_copy(update={"label": week_label, "plist": str(week_plist)})
        protected.append(week_plist)
        before = snapshot(protected)
        for service, (cfg, plist) in configurations.items():
            transport = direct_transport if service == "archive" else root_transport
            first = run(owned, cfg, transport, service + "-first")
            assert first.succeeded
            assert len(first.mutating_changed_ops) == 1
            repeat = run(owned, cfg, transport, service + "-repeat")
            assert repeat.succeeded
            assert len(repeat.mutating_changed_ops) == 1
            assert plist.exists() is (service != "attention")
        cfg, plist = configurations["attention"]
        preserved = Path(cfg.home) / "state.sqlite3"
        plist.symlink_to(preserved)
        refused = run(owned, cfg, root_transport, "attention-genuine-linked-leaf-refusal")
        assert not refused.succeeded
        assert plist.is_symlink()
        assert snapshot(protected) == before
        plist.unlink()  # fixture-created link only, never a component data path
        create_plist(plist, cfg.label, actor.pw_uid, actor.pw_gid)
        command("/bin/launchctl", "enable", "gui/" + str(actor.pw_uid) + "/" + cfg.label)
        command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(plist))
        recovered = run(owned, cfg, root_transport, "attention-recovery")
        assert recovered.succeeded
        assert len(recovered.mutating_changed_ops) == 1
        assert not plist.exists()
        assert snapshot(protected) == before
        for phase in ("weeknotes-first", "weeknotes-repeat"):
            result = run(owned, week_cfg, root_transport, phase, disable_weeknotes_schedule)
            assert result.succeeded
            assert len(result.mutating_changed_ops) == 1
            assert job_pid("system/" + week_label) is None
            disabled = command("/bin/launchctl", "print-disabled", "system").stdout
            assert re.search(r'(?m)^\s*"' + re.escape(week_label) + r'"\s*=>\s*(?:true|disabled)\s*$', disabled)
            expected = (
                "DAYBOOK_RECONCILE_DISABLED_CHANGED"
                if phase.endswith("first")
                else "DAYBOOK_RECONCILE_ALREADY_DISABLED"
            )
            assert owned.report["phases"][phase]["weeknotes_result_tokens"] == [expected]
        refused = run(
            owned, week_cfg, direct_transport, "weeknotes-wrong-transport-refusal", disable_weeknotes_schedule
        )
        assert not refused.succeeded
        assert len(refused.mutating_changed_ops) == 0
        assert snapshot(protected) == before
        owned.report.update(
            status="passed",
            protected_synthetic_data_metadata_preserved=True,
            real_application_calls=0,
            successful_control_operations=11,
            actual_control_invocations=13,
            expected_failed_control_operations=2,
            removal_scope="Only fixture-created attention plist; no inventory restore/remove or data action.",
            repeat_scope="One original managed cleanup attempt sequence each repeat; no zero-op claim.",
        )
    except BaseException as error:
        failure = error
        owned.fail(error)
    finally:
        try:
            owned.cleanup()
        except BaseException as error:
            failure = failure or error
        try:
            if week_label is not None:
                command("/bin/launchctl", "enable", "system/" + week_label, check=False)
                disabled = command("/bin/launchctl", "print-disabled", "system").stdout
                assert not re.search(r'(?m)^\s*"' + re.escape(week_label) + r'"\s*=>\s*(?:true|disabled)\s*$', disabled)
                owned.report["weeknotes_system_disable_override_cleared"] = True
        except BaseException as error:
            failure = failure or error
            owned.fail(error)
        if failure is not None:
            owned.report["status"] = "failed"
        owned.receipt()
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
