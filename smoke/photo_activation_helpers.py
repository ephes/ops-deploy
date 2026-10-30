"""Installed unchanged launchd control DI cases; actual owned root/owner SSH.

These exercise the class's existing run injection, not a fabricated failure of
an unmodified whole installer. Only selected metadata leaves the target.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from importlib.resources import files
from typing import Any
from unittest.mock import patch

import paramiko
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.connectors.ssh import SSHConnector
from pyinfra.facts.server import Command, Os

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_stdin
from ops_deploy.services.daybook_controls.deploy import DIRECT
from ops_deploy.testing import run_deploy_ssh

EXPECTED_CONTROLS_SHA256 = "2a444aa29dcc301d3f5119c4ee39b3729a74bc82b7aae290d5643d5b98825460"

CASE_PROGRAM = r"""
import hashlib,json,os,pathlib,stat,subprocess,sys,types,base64
request=json.load(sys.stdin)
assert os.geteuid()==request['expected_uid']
assert request['module_alias'] in {'ops_photos_controls','ops_archive_controls'}
assert request['label'].startswith('com.example.ops-mac-apps.') and request['label'].endswith(request['owned_suffix'])
assert pathlib.Path(request['plist']).is_relative_to(pathlib.Path(request['owned_root']))
source=base64.b64decode(request['class_source'])
assert hashlib.sha256(source).hexdigest()==request['class_sha256']
module=types.ModuleType(request['module_alias']);sys.modules[module.__name__]=module
exec(compile(source,'<installed-original-photos-controls>','exec'),module.__dict__)
def public_code(path,uid,mode):
 path=pathlib.Path(path)
 assert path.is_relative_to(pathlib.Path(request['owned_root']))
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==uid and stat.S_IMODE(info.st_mode)==mode
  body=os.read(fd,1024*1024+1);assert len(body)<=1024*1024
  return body
 finally: os.close(fd)
def proxy_records():
 path=pathlib.Path(request['archive_proxy_events'])
 assert path.is_relative_to(pathlib.Path(request['owned_root']))
 if not path.exists(): return []
 body=public_code(path,request['uid'],0o600)
 rows=[json.loads(line) for line in body.splitlines()]
 for row in rows:
  assert set(row)=={'kind','uid','forwarded'}
  assert row['kind'] in {'photos-access-disarmed','archive-execute-disarmed'}
  assert row['uid']==request['uid'] and row['forwarded'] is False
 return rows
proxy_before=[]
if request['module_alias']=='ops_archive_controls':
 launcher=public_code(request['archive_launcher'],request['uid'],0o700)
 proxy=public_code(request['archive_proxy'],0,0o755)
 assert hashlib.sha256(launcher).hexdigest()==request['archive_launcher_sha256']
 assert hashlib.sha256(proxy).hexdigest()==request['archive_proxy_sha256'], 'owned_archive_proxy_hash_mismatch'
 assert launcher.count(request['archive_proxy'].encode())==2
 assert b'/opt/homebrew/bin/gtimeout' not in launcher
 proxy_before=proxy_records()
native=module.PhotosControls(request)
observed={'loaded_after_real_bootstrap':False,'mutations':[]}
def backend(argv):
 action=argv[1]
 if action in {'enable','bootstrap','disable','bootout'}: observed['mutations'].append(action)
 if action==request['cleanup_fault']:
  return subprocess.CompletedProcess(argv,1,b'',b'OWNED injected cleanup failure')
 result=native.native_run(argv)
 if action=='bootstrap' and result.returncode==0:
  assert native.snapshot(final=True)['loaded'] is True
  observed['loaded_after_real_bootstrap']=True
  return subprocess.CompletedProcess(argv,1,b'',b'OWNED injected failure AFTER actual loaded bootstrap')
 return result
controller=module.PhotosControls(request,run=backend)
try:
 controller.activate()
 raise AssertionError('expected installed control failure')
except module.PhotosControlError as error:
 category=str(error)
state=native.snapshot(final=True)
assert observed['loaded_after_real_bootstrap']
assert observed['mutations']==['enable','bootstrap','disable','bootout']
expected={
 'none':('photos_control_activation_failed_quiesced',True,False),
 'disable':('photos_control_activation_failed_NOT_quiesced',False,False),
 'bootout':('photos_control_activation_failed_NOT_quiesced',True,True),
}[request['cleanup_fault']]
assert (category,state['disabled'],state['loaded'])==expected
native.quiesce(force=True)
recovered=native.snapshot(final=True)
assert recovered['disabled'] is True and recovered['loaded'] is False and recovered['known_absent']
archive_report={}
if request['module_alias']=='ops_archive_controls':
 rows=proxy_records()
 assert rows[:len(proxy_before)]==proxy_before
 assert len(rows)>=len(proxy_before)
 archive_report={'archive_proxy_attested_before_bootstrap':True,'new_disarmed_proxy_calls':len(rows)-len(proxy_before),'all_recorded_proxy_calls_disarmed':True,'launcher_may_have_started':True}
print(json.dumps({'case':request['case'],'category':category,'disabled':state['disabled'],'loaded':state['loaded'],
 'bootstrap_was_really_loaded':True,'mutation_calls':observed['mutations'],'connecting_uid':os.geteuid(),
 'class_sha256':request['class_sha256'],'module_alias':module.__name__,'explicit_recovery_quiescent':True,**archive_report},sort_keys=True))
"""


def class_bytes() -> bytes:
    body = files("ops_deploy.services.daybook_photos_offload").joinpath("files/photos_controls.py").read_bytes()
    assert hashlib.sha256(body).hexdigest() == EXPECTED_CONTROLS_SHA256
    return body


@deploy("Owned installed-control dependency-injection mechanism")
def exercise(request: dict[str, Any]) -> None:
    if host.get_fact(Os, **DIRECT) != "Darwin":
        raise DeployError("Owned control case requires Darwin")
    if host.get_fact(Command, command="/usr/bin/id -u", **DIRECT) != str(request["expected_uid"]):
        raise DeployError("Owned control case connecting uid changed")
    secret_stdin(
        name="Exercise only owned installed-control rescue and explicit recovery",
        command=shlex.join(["/usr/bin/python3", "-I", "-B", "-c", CASE_PROGRAM]),
        content=SecretContent(json.dumps(request) + "\n"),
        **DIRECT,
    )


def rescue_case(
    owned: Any,
    actor: Any,
    transport: dict[str, Any],
    *,
    label: str,
    plist: str,
    kind: str,
    cleanup_fault: str,
    archive_launcher: str | None = None,
    archive_proxy: str | None = None,
    archive_launcher_sha256: str | None = None,
    archive_proxy_sha256: str | None = None,
    archive_proxy_events: str | None = None,
    expect_proxy_hash_refusal: bool = False,
) -> dict[str, Any]:
    assert kind in {"photos", "archive"}
    assert cleanup_fault in {"none", "disable", "bootout"}
    request = {
        "case": kind + "-" + cleanup_fault,
        "uid": actor.pw_uid,
        "label": label,
        "plist": plist,
        "owned_root": str(owned.root),
        "owned_suffix": owned.suffix,
        "expected_uid": 0 if kind == "photos" else actor.pw_uid,
        "module_alias": "ops_photos_controls" if kind == "photos" else "ops_archive_controls",
        "class_source": base64.b64encode(class_bytes()).decode(),
        "class_sha256": EXPECTED_CONTROLS_SHA256,
        "cleanup_fault": cleanup_fault,
    }
    if kind == "archive":
        assert all(
            isinstance(value, str) and value
            for value in (
                archive_launcher,
                archive_proxy,
                archive_launcher_sha256,
                archive_proxy_sha256,
                archive_proxy_events,
            )
        )
        request.update(
            archive_launcher=archive_launcher,
            archive_proxy=archive_proxy,
            archive_launcher_sha256=archive_launcher_sha256,
            archive_proxy_sha256=archive_proxy_sha256,
            archive_proxy_events=archive_proxy_events,
        )
    if expect_proxy_hash_refusal:
        assert kind == "archive"
        request["archive_proxy_sha256"] = "0" * 64
    reports = []
    guard_failure_seen = []
    original = SSHConnector.run_shell_command

    def shell(connector: Any, *args: Any, **kwargs: Any) -> Any:
        assert all(kwargs.get(key) in {False, None} for key in ("_sudo", "_doas", "_dzdo"))
        assert all(kwargs.get(key) in {"", None} for key in ("_sudo_user", "_su_user", "_doas_user", "_dzdo_user"))
        outcome = original(connector, *args, **kwargs)
        if isinstance(outcome, tuple):
            combined = getattr(outcome[1], "combined_lines", outcome[1])
            if isinstance(combined, list):
                for item in combined:
                    line = getattr(item, "line", item[1] if isinstance(item, tuple) and len(item) == 2 else item)
                    if not isinstance(line, str):
                        continue
                    if "AssertionError: owned_archive_proxy_hash_mismatch" in line:
                        guard_failure_seen.append(True)
                    try:
                        value = json.loads(line)
                    except (ValueError, TypeError):
                        continue
                    if (
                        isinstance(value, dict)
                        and value.get("case") == request["case"]
                        and value.get("class_sha256") == EXPECTED_CONTROLS_SHA256
                    ):
                        reports.append(value)
        return outcome

    def refuse_upload(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Owned control mechanism requires no SFTP upload")

    with (
        patch.object(SSHConnector, "run_shell_command", shell),
        patch.object(paramiko.SFTPClient, "putfo", refuse_upload),
    ):
        result = run_deploy_ssh(
            exercise,
            request,
            host_name="owned-control-rescue",
            host_data=transport,
            _sudo=True,
            _sudo_user="root",
            _su_user="root",
            _doas=True,
            _doas_user="root",
            _dzdo=True,
            _dzdo_user="root",
        )
    if expect_proxy_hash_refusal:
        assert not result.succeeded
        assert not result.mutating_changed_ops
        assert guard_failure_seen
        assert not reports
        report = {
            "case": "archive-proxy-hash-genuine-refusal",
            "before_any_mutation": True,
            "specific_proxy_hash_guard_reached": True,
            "actual_sftp": 0,
        }
        owned.report.setdefault("archive_proxy_guard_refusals", []).append(report)
        return report
    assert result.succeeded
    assert len(result.mutating_changed_ops) == 1
    assert len(reports) == 1
    report = reports[0]
    assert report["bootstrap_was_really_loaded"]
    assert report["explicit_recovery_quiescent"]
    assert report["connecting_uid"] == request["expected_uid"]
    assert report["mutation_calls"] == ["enable", "bootstrap", "disable", "bootout"]
    if kind == "archive":
        assert report["archive_proxy_attested_before_bootstrap"] is True
        assert report["all_recorded_proxy_calls_disarmed"] is True
        assert report["launcher_may_have_started"] is True
        assert type(report["new_disarmed_proxy_calls"]) is int
        assert report["new_disarmed_proxy_calls"] >= 0
    owned.report.setdefault("installed_control_DI_mechanisms", []).append(report)
    return report
