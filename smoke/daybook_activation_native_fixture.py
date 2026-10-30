"""Owned fresh-apply activation; inert app, real launchctl and explicit fault proxy."""

from __future__ import annotations

import json
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

from ops_deploy.services.daybook_sessions.render import render_template
from ops_deploy.services.daybook_weeknotes_activation import WeeknotesActivationConfig, activate_weeknotes_schedule
from ops_deploy.services.daybook_weeknotes_activation.config import ENABLE_PHRASE
from ops_deploy.services.daybook_weeknotes_identity import WeeknotesIdentityConfig
from ops_deploy.services.daybook_weeknotes_identity.config import APPLY_PHRASE
from ops_deploy.services.daybook_weeknotes_identity.deploy import template_values
from ops_deploy.testing import run_deploy_ssh

FAKE_UV = r"""#!/usr/bin/python3
import json,os,pathlib,sys
runtime=pathlib.Path(__file__).parent/'runtime'
args=sys.argv[1:]
assert args[:4]==['run','--isolated','--frozen','--no-dev']
tail=args[4:]
if tail[0]=='python':
 action=tail[2]
else:
 assert tail[:2]==['daybook','weeknotes']
 action='status' if tail[2]=='reconcile-status' else 'apply' if '--apply' in tail else 'dry-run'
with (runtime/'calls.jsonl').open('a') as stream:
 stream.write(json.dumps({'action':action,'uid':os.geteuid(),'home':os.environ.get('HOME')})+'\n')
fault=runtime/'fault'
if fault.exists() and fault.read_text()==action:
 print('PRIVATE_SYNTHETIC_UNTRUSTED_BODY')
 print('PRIVATE_SYNTHETIC_DIAGNOSTIC',file=sys.stderr)
 raise SystemExit(1)
if action=='prepare':
 plan=pathlib.Path(tail[4])
 exists=plan.exists()
 if not exists:
  fd=os.open(str(plan),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'w') as stream:
   stream.write('OWNED inert preserved plan')
   stream.flush();os.fsync(stream.fileno())
 result={'schema_version':1,'status':'existing_plan_reused' if exists else 'plan_prepared','plan_hash':'c'*64}
elif action=='verify':
 result={'schema_version':1,'status':'attestation_verified','plan_hash':'c'*64}
elif action=='status':
 result={'schema_version':2,'weeks':{}}
else:
 apply=action=='apply'
 result={'schema_version':1,'identity_epoch':'monday-after-v1','plan_hash':'c'*64,
  'dry_run':not apply,'applied':apply,'status':'applied' if apply else 'dry_run_validated',
  'reason_code':None,'moves':[{'week':'2026-W01','audience':'public','blog_id':1,'post_id':2,
  'from_or_already_target':'from','result':'moved' if apply else 'would_move',
  'new_revision_id':4 if apply else None,'reason_code':None}]}
print(json.dumps(result,sort_keys=True))
"""


def write(path: Path, body: bytes, uid: int, gid: int, mode: int) -> None:
    path.write_bytes(body)
    os.chown(path, uid, gid)
    path.chmod(mode)


def content_free_reasons(output: Any) -> list[str]:
    reasons: list[str] = []
    allowed = {
        "weeknotes_activation_enabled_bootstrap_failed",
        "weeknotes_activation_loaded_verification_failed",
        "weeknotes_activation_before_enable_failed",
        "weeknotes_activation_state_unavailable",
    }
    combined = getattr(output, "combined_lines", output)
    if not isinstance(combined, list):
        return reasons
    for item in combined:
        line = getattr(item, "line", item[1] if isinstance(item, tuple) and len(item) == 2 else item)
        if not isinstance(line, str):
            continue
        assert "PRIVATE_SYNTHETIC_UNTRUSTED_BODY" not in line
        assert "PRIVATE_SYNTHETIC_DIAGNOSTIC" not in line
        try:
            value = json.loads(line)
        except (ValueError, TypeError):
            continue
        if (
            isinstance(value, dict)
            and set(value) == {"schema_version", "status", "reason_code"}
            and value["reason_code"] in allowed
        ):
            reasons.append(value["reason_code"])
    return reasons


def run(owned: OwnedMac, cfg: WeeknotesActivationConfig, transport: Any, phase: str) -> Any:
    uploads, calls = 0, 0
    reasons: list[str] = []
    original_put, original_shell = paramiko.SFTPClient.putfo, SSHConnector.run_shell_command

    def put(*args: Any, **kwargs: Any) -> Any:
        nonlocal uploads
        uploads += 1
        return original_put(*args, **kwargs)

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        outcome = original_shell(connector, *args, **kwargs)
        # Retain only fixed content-free diagnostics; raw output remains RAM.
        if isinstance(outcome, tuple):
            reasons.extend(content_free_reasons(outcome[1]))
        return outcome

    with patch.object(paramiko.SFTPClient, "putfo", put), patch.object(SSHConnector, "run_shell_command", shell):
        result = run_deploy_ssh(
            activate_weeknotes_schedule,
            cfg,
            host_name="owned-identity",
            host_data=transport,
            _sudo=True,
            _sudo_user="root",
            _su_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
        )
    owned.report.setdefault("phases", {})[phase] = {
        "succeeded": result.succeeded,
        "managed": len(result.mutating_changed_ops),
        "actual_sftp": uploads,
        "direct_shell_calls": calls,
        "error_type": type(result.error).__name__ if result.error else None,
        "emitted_reason_codes": reasons,
    }
    assert uploads == 0
    assert job_pid(owned.report["keeper_service"]) == owned.report["keeper_pid"]
    return result


def main() -> None:
    owned = OwnedMac("daybook-activation")
    failure: BaseException | None = None
    timer: str | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        transport = owned.ssh_transport()
        root_transport_report = dict(owned.report["transport"])
        direct_transport = user_transport(owned, actor)
        owned.report["transports"] = {"root": root_transport_report, "owner": dict(owned.report["transport"])}
        for name in ("home", "checkout", "runtime"):
            path = owned.root / name
            path.mkdir()
            os.chown(path, actor.pw_uid, actor.pw_gid)
            path.chmod(0o700)
        config = owned.root / "config"
        config.mkdir(mode=0o755)
        checkout = owned.root / "checkout"

        def git(*args: str) -> str:
            return command(
                "/usr/bin/sudo",
                "-H",
                "-S",
                "-n",
                "-i",
                "-u",
                actor.pw_name,
                "--",
                "/usr/bin/git",
                "-C",
                str(checkout),
                *args,
            ).stdout.strip()

        git("init", "--quiet", "--template=", "-b", "main")
        write(checkout / "README", b"OWNED inert source; no actual application", actor.pw_uid, actor.pw_gid, 0o600)
        git("add", ".")
        git(
            "-c",
            "user.name=Owned",
            "-c",
            "user.email=owned@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "owned inert source",
        )
        revision = git("rev-parse", "HEAD")
        uv = owned.root / "uv"
        write(uv, FAKE_UV.encode(), 0, 0, 0o755)
        timer = owned.label("identity-timer")
        timer_plist = owned.root / "timer.plist"
        keeper = owned.label("identity-keeper")
        keeper_plist = owned.root / "keeper.plist"
        for path, label in ((timer_plist, timer), (keeper_plist, keeper)):
            write(
                path,
                plistlib.dumps(
                    {"Label": label, "ProgramArguments": ["/bin/sleep", "600"], "RunAtLoad": label == keeper}
                ),
                0,
                0,
                0o644,
            )
            command("/bin/launchctl", "bootstrap", "system", str(path))
            if label == keeper:
                wait(lambda selected=label: job_pid("system/" + selected) is not None)
        owned.report.update(keeper_service="system/" + keeper, keeper_pid=job_pid("system/" + keeper))
        cfg = WeeknotesIdentityConfig(
            owner=actor.pw_name,
            action="apply",
            confirmation=APPLY_PHRASE,
            required_revision=revision,
            moves=[
                {
                    "week": "2026-W01",
                    "audience": "public",
                    "blog_id": 1,
                    "post_id": 2,
                    "expected_revision_id": 3,
                    "from_title": "Weeknotes 2025-12-29",
                    "from_slug": "weeknotes-2025-12-29",
                }
            ],
        )
        original_activation = WeeknotesActivationConfig(identity=cfg, confirmation=ENABLE_PHRASE)
        cfg = cfg.model_copy(
            update={
                "home": str(owned.root / "home"),
                "checkout": str(checkout),
                "runtime": str(owned.root / "runtime"),
                "config_dir": str(config),
                "helper": str(config / "helper.py"),
                "launcher": str(config / "launcher.sh"),
                "env_file": str(config / "operator.env"),
                "env_checksum": str(config / "operator.env.sha256"),
                "seed": str(owned.root / "runtime/seed.json"),
                "plan": str(owned.root / "runtime/plan.json"),
                "attestation": str(owned.root / "runtime/attestation.json"),
                "state": str(owned.root / "runtime/state.json"),
                "proof": str(config / "proof.json"),
                "uv_bin": str(uv),
                "scheduler_label": timer,
                "scheduler_plist": str(timer_plist),
            }
        )
        values = template_values(cfg)
        for resource_name, template in (
            (cfg.helper, "weeknotes-identity-ops.py.j2"),
            (cfg.launcher, "weeknotes-identity-ops.sh.j2"),
        ):
            write(Path(resource_name), render_template(template, values).encode(), 0, 0, 0o755)
        env = b"OWNED_AUTH=not-a-real-credential\nDAYBOOK_WEEKNOTES_POST_IDENTITY_EPOCH=monday-after-v1\n"
        write(Path(cfg.env_file), env, actor.pw_uid, actor.pw_gid, 0o600)
        import hashlib

        write(
            Path(cfg.env_checksum), (hashlib.sha256(env).hexdigest() + "  " + cfg.env_file + "\n").encode(), 0, 0, 0o644
        )
        protected = []
        for name in ("state.json", "attestation.json", "auth.json", ".state.lock", "stdout.log"):
            path = owned.root / "runtime" / name
            write(path, b"OWNED retained synthetic private bytes", actor.pw_uid, actor.pw_gid, 0o600)
            protected.append(path)
        before = snapshot(protected)
        owned.report["configuration_validation"] = {
            "original_models_validated": True,
            "owned_model_copy_values_revalidated": False,
            "scope": (
                "Mechanism only: exact real identity templates, inert UV and owned launchctl fault proxy. "
                "No actual application import, posts or content."
            ),
        }
        seed = Path(cfg.seed)
        write(
            seed,
            json.dumps(
                {
                    "schema_version": 1,
                    "identity_epoch": "monday-after-v1",
                    "moves": cfg.model_dump(mode="json")["moves"],
                }
            ).encode(),
            actor.pw_uid,
            actor.pw_gid,
            0o600,
        )
        write(Path(cfg.plan), b"OWNED inert preserved plan", actor.pw_uid, actor.pw_gid, 0o600)
        protected.extend([seed, Path(cfg.plan)])
        before = snapshot(protected)
        reconcile = config / "reconcile.sh"
        write(reconcile, b"#!/bin/bash\nexec /bin/sleep 600\n", 0, 0, 0o755)
        write(
            timer_plist,
            plistlib.dumps({"Label": timer, "ProgramArguments": [str(reconcile)], "RunAtLoad": False}),
            0,
            0,
            0o644,
        )
        proxy = owned.root / "launchctl-proxy"
        proxy_body = """#!/usr/bin/python3
import pathlib,subprocess,sys
root=pathlib.Path(__file__).parent
fault=(root/'control-fault').read_text() if (root/'control-fault').exists() else ''
marker=root/'after-bootstrap'
args=sys.argv[1:]
if args[0]=='bootstrap' and fault=='bootstrap': raise SystemExit(1)
if args[0]=='print' and fault=='postverify' and marker.exists(): raise SystemExit(1)
result=subprocess.run(['/bin/launchctl',*args],capture_output=True)
if args[0]=='bootstrap' and result.returncode==0:
 marker.write_text('OWNED successful bootstrap');marker.chmod(0o600)
sys.stdout.buffer.write(result.stdout);sys.stderr.buffer.write(result.stderr)
raise SystemExit(result.returncode)
"""
        write(proxy, proxy_body.encode(), 0, 0, 0o755)
        selected = original_activation.model_copy(
            update={"identity": cfg, "reconcile_launcher": str(reconcile), "launchctl_bin": str(proxy)}
        )
        marker, control_fault = owned.root / "after-bootstrap", owned.root / "control-fault"

        def phase(name: str) -> Any:
            marker.unlink(missing_ok=True)
            return run(owned, selected, transport, name)

        def state() -> dict[str, bool]:
            loaded = command("/bin/launchctl", "print", "system/" + timer, check=False).returncode == 0
            rows = command("/bin/launchctl", "print-disabled", "system").stdout
            disabled = re.search(r'(?m)^\s*"' + re.escape(timer) + r'"\s*=>\s*(?:true|disabled)\s*$', rows) is not None
            return {"loaded": loaded, "disabled": disabled}

        for name in ("activation-first", "activation-repeat"):
            result = phase(name)
            assert result.succeeded
            assert len(result.mutating_changed_ops) == 2
            assert state() == {"loaded": True, "disabled": False}
            assert job_pid("system/" + timer) is None
            assert snapshot(protected) == before
        for name, fault, expected in (
            ("enabled-bootstrap-genuine-failure", "bootstrap", {"loaded": False, "disabled": False}),
            ("loaded-postverify-genuine-failure", "postverify", {"loaded": True, "disabled": False}),
        ):
            write(control_fault, fault.encode(), 0, 0, 0o600)
            result = phase(name)
            assert not result.succeeded
            observed = state()
            assert observed == expected
            owned.report["phases"][name]["actual_post_failure_state"] = observed
            expected_reason = (
                "weeknotes_activation_enabled_bootstrap_failed"
                if fault == "bootstrap"
                else "weeknotes_activation_loaded_verification_failed"
            )
            assert owned.report["phases"][name]["emitted_reason_codes"] == [expected_reason]
            control_fault.unlink()
        bad_env = b"OWNED_AUTH=not-a-real-credential\n"
        write(Path(cfg.env_file), bad_env, actor.pw_uid, actor.pw_gid, 0o600)
        write(
            Path(cfg.env_checksum),
            (hashlib.sha256(bad_env).hexdigest() + "  " + cfg.env_file + "\n").encode(),
            0,
            0,
            0o644,
        )
        result = phase("missing-epoch-genuine-refusal")
        assert not result.succeeded
        assert state() == {"loaded": False, "disabled": True}
        write(Path(cfg.env_file), env, actor.pw_uid, actor.pw_gid, 0o600)
        write(
            Path(cfg.env_checksum), (hashlib.sha256(env).hexdigest() + "  " + cfg.env_file + "\n").encode(), 0, 0, 0o644
        )
        reconcile.chmod(0o644)
        result = phase("unsafe-reconcile-launcher-genuine-refusal")
        assert not result.succeeded
        assert state() == {"loaded": False, "disabled": True}
        reconcile.chmod(0o755)
        timer_plist.chmod(0o600)
        result = phase("unsafe-system-plist-genuine-refusal")
        assert not result.succeeded
        assert state() == {"loaded": False, "disabled": True}
        timer_plist.chmod(0o644)
        result = run(owned, selected, direct_transport, "wrong-connecting-uid-genuine-refusal")
        assert not result.succeeded
        assert len(result.mutating_changed_ops) == 0
        result = phase("recovery")
        assert result.succeeded
        assert len(result.mutating_changed_ops) == 2
        assert state() == {"loaded": True, "disabled": False}
        assert job_pid("system/" + timer) is None
        assert snapshot(protected) == before
        calls = [json.loads(line) for line in (owned.root / "runtime/calls.jsonl").read_text().splitlines()]
        assert calls
        assert all(call["uid"] == actor.pw_uid and call["home"] == actor.pw_dir for call in calls)
        owned.report.update(
            status="passed",
            real_application_calls=0,
            protected_synthetic_metadata_preserved=True,
            root_proof_written_only_after_successful_verify=True,
            real_launchctl_partial_failure_states_verified=True,
            schedule_never_kickstarted_or_run=True,
            actual_owner_login_context_verified=True,
            synthetic_app_calls=calls,
        )
    except BaseException as error:
        failure = error
        owned.fail(error)
    finally:
        try:
            if timer is not None:
                command("/bin/launchctl", "bootout", "system/" + timer, check=False)
                command("/bin/launchctl", "enable", "system/" + timer, check=False)
                rows = command("/bin/launchctl", "print-disabled", "system").stdout
                assert not re.search(r'(?m)^\s*"' + re.escape(timer) + r'"\s*=>\s*(?:true|disabled)\s*$', rows)
                owned.report["owned_system_disable_override_cleared"] = True
        except BaseException as error:
            failure = failure or error
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
