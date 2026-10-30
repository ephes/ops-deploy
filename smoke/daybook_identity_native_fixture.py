"""Owned identity mechanisms with inert UV/app code; never private post data."""

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
from ops_deploy.services.daybook_weeknotes_identity import WeeknotesIdentityConfig, run_weeknotes_identity
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


def run(owned: OwnedMac, cfg: WeeknotesIdentityConfig, transport: Any, phase: str) -> Any:
    uploads, calls = 0, 0
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
        return original_shell(connector, *args, **kwargs)

    with patch.object(paramiko.SFTPClient, "putfo", put), patch.object(SSHConnector, "run_shell_command", shell):
        result = run_deploy_ssh(
            run_weeknotes_identity,
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
    }
    assert uploads == 0
    assert job_pid(owned.report["keeper_service"]) == owned.report["keeper_pid"]
    return result


def main() -> None:
    owned = OwnedMac("daybook-identity")
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
                plistlib.dumps({"Label": label, "ProgramArguments": ["/bin/sleep", "600"], "RunAtLoad": True}),
                0,
                0,
                0o600,
            )
            command("/bin/launchctl", "bootstrap", "system", str(path))
            wait(lambda selected=label: job_pid("system/" + selected) is not None)
        owned.report.update(keeper_service="system/" + keeper, keeper_pid=job_pid("system/" + keeper))
        cfg = WeeknotesIdentityConfig(
            owner=actor.pw_name,
            action="prepare",
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
        env = b"OWNED_AUTH=not-a-real-credential\n"
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
                "Mechanism only: exact real helper/launcher templates, inert UV simulates app actions. "
                "No actual application import, posts or content."
            ),
        }
        for phase, action in (
            ("prepare-first", "prepare"),
            ("prepare-repeat", "prepare"),
            ("dry-run", "dry-run"),
            ("status", "status"),
            ("apply-first", "apply"),
            ("apply-repeat", "apply"),
            ("verify", "verify"),
        ):
            selected = cfg.model_copy(
                update={"action": action, "confirmation": APPLY_PHRASE if action == "apply" else ""}
            )
            result = run(owned, selected, transport, phase)
            assert result.succeeded
            assert len(result.mutating_changed_ops) == 2
            assert snapshot(protected) == before
        proof = Path(cfg.proof)
        proof_before = snapshot([proof])
        proof_body = proof.read_bytes()  # owned synthetic proof only
        proof.unlink()
        fault = owned.root / "runtime/fault"
        write(fault, b"verify", actor.pw_uid, actor.pw_gid, 0o600)
        result = run(
            owned,
            cfg.model_copy(update={"action": "apply", "confirmation": APPLY_PHRASE}),
            transport,
            "postverify-genuine-failure",
        )
        assert not result.succeeded
        assert not proof.exists()
        write(proof, proof_body, 0, 0, 0o600)
        proof_before = snapshot([proof])
        fault.unlink()
        seed = Path(cfg.seed)
        seed_body = seed.read_bytes()  # fixture-created synthetic intent only
        seed.unlink()
        seed.symlink_to(protected[0])
        result = run(owned, cfg, transport, "linked-seed-genuine-refusal")
        assert not result.succeeded
        assert seed.is_symlink()
        seed.unlink()
        write(seed, seed_body, actor.pw_uid, actor.pw_gid, 0o600)
        result = run(
            owned, cfg.model_copy(update={"required_revision": "0" * 40}), transport, "wrong-Main-genuine-refusal"
        )
        assert not result.succeeded
        for phase, fault_action in (("failed-apply", "apply"),):
            write(fault, fault_action.encode(), actor.pw_uid, actor.pw_gid, 0o600)
            result = run(
                owned, cfg.model_copy(update={"action": "apply", "confirmation": APPLY_PHRASE}), transport, phase
            )
            assert not result.succeeded
            assert snapshot([proof]) == proof_before
            fault.unlink()
        proof.unlink()
        write(fault, b"apply", actor.pw_uid, actor.pw_gid, 0o600)
        result = run(
            owned,
            cfg.model_copy(update={"action": "apply", "confirmation": APPLY_PHRASE}),
            transport,
            "failed-apply-absent-proof",
        )
        assert not result.succeeded
        assert not proof.exists()
        fault.unlink()
        write(proof, proof_body, 0, 0, 0o600)
        proof_before = snapshot([proof])
        seed_value = json.loads(seed_body)
        seed_value["moves"] = []
        write(seed, json.dumps(seed_value).encode(), actor.pw_uid, actor.pw_gid, 0o600)
        result = run(owned, cfg, transport, "wrong-intent-genuine-refusal")
        assert not result.succeeded
        write(seed, seed_body, actor.pw_uid, actor.pw_gid, 0o600)
        write(Path(cfg.env_file), b"OWNED changed fake auth", actor.pw_uid, actor.pw_gid, 0o600)
        result = run(owned, cfg, transport, "env-checksum-genuine-refusal")
        assert not result.succeeded
        write(Path(cfg.env_file), env, actor.pw_uid, actor.pw_gid, 0o600)
        Path(cfg.env_file).chmod(0o644)
        result = run(owned, cfg, transport, "env-mode-genuine-refusal")
        assert not result.succeeded
        Path(cfg.env_file).chmod(0o600)
        helper_body = Path(cfg.helper).read_bytes()  # owned rendered public code
        write(Path(cfg.helper), b"OWNED changed helper", 0, 0, 0o755)
        result = run(owned, cfg, transport, "helper-bytes-genuine-refusal")
        assert not result.succeeded
        write(Path(cfg.helper), helper_body, 0, 0, 0o755)
        untracked = checkout / "OWNED-untracked"
        write(untracked, b"OWNED dirty code", actor.pw_uid, actor.pw_gid, 0o600)
        result = run(owned, cfg, transport, "dirty-checkout-genuine-refusal")
        assert not result.succeeded
        untracked.unlink()
        result = run(owned, cfg, direct_transport, "wrong-connecting-uid-genuine-refusal")
        assert not result.succeeded
        assert len(result.mutating_changed_ops) == 0
        result = run(owned, cfg, transport, "recovery")
        assert result.succeeded
        assert len(result.mutating_changed_ops) == 2
        assert snapshot(protected) == before
        calls = [json.loads(line) for line in (owned.root / "runtime/calls.jsonl").read_text().splitlines()]
        assert calls
        assert all(call["uid"] == actor.pw_uid and call["home"] == actor.pw_dir for call in calls)
        owned.report.update(
            status="passed",
            real_application_calls=0,
            protected_synthetic_metadata_preserved=True,
            root_proof_written_only_after_successful_verify=True,
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
