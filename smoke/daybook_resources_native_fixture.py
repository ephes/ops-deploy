"""Disposable Darwin resource mechanisms; never inventory or private app code.

The original private Weeknotes verifier has separate exact-code evidence. This
case proves shared FS/control/launchd mechanisms with real root/GUI ownership,
unusable fake auth, unique jobs and explicit fixture setup/cleanup accounting.
"""

from __future__ import annotations

import importlib.metadata
import importlib.resources
import json
import os
import plistlib
import pwd
import sys
import time
import types
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest.mock import patch

from mac_apps_owned import OwnedMac, command, file_state, job_pid, processes

from ops_deploy.services.daybook_sessions import DaybookSessionsConfig
from ops_deploy.services.daybook_sessions.render import _resource_texts


def wait(predicate: Any) -> None:
    for _ in range(100):
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("owned resource readiness did not converge")


@contextmanager
def installed_helpers() -> Any:
    names = {}
    try:
        for name, filename in (
            ("ops_sessions_resources", "resources_host.py"),
            ("ops_sessions_controls", "controls_host.py"),
            ("ops_sessions_launchd", "launchd_host.py"),
        ):
            names[name] = sys.modules.get(name)
            module = types.ModuleType(name)
            sys.modules[name] = module
            source = importlib.resources.files("ops_deploy.services.daybook_sessions").joinpath("files/" + filename)
            exec(compile(source.read_bytes(), "<owned-installed-" + filename + ">", "exec"), module.__dict__)
        yield tuple(sys.modules[name] for name in names)
    finally:
        for name, original in names.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


def provenance(owned: OwnedMac) -> None:
    owned.verify_implementation()
    package = Path(str(importlib.resources.files("ops_deploy")))
    actual = {
        str(path.relative_to(package))
        for path in package.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
    assert actual == set(owned.report["installed_resources"])
    distribution = importlib.metadata.distribution("ops-deploy")
    direct = json.loads(distribution.read_text("direct_url.json") or "{}")
    assert not direct.get("dir_info", {}).get("editable")
    assert direct.get("vcs_info", {}).get("commit_id") == os.environ["IMPLEMENTATION_SHA"]
    owned.report.update(
        installed_root=str(package),
        distribution_root=str(distribution.locate_file("")),
        actual_direct_url_commit=direct["vcs_info"]["commit_id"],
        actual_installed_resource_set_equal=True,
    )


def refuse(call: Any, error: str, resource_error: Any) -> None:
    observed = None
    try:
        call()
    except resource_error as failure:
        observed = str(failure)
    assert observed == error, "expected exact genuine owned resource refusal"


def configuration(owned: OwnedMac, actor: Any) -> DaybookSessionsConfig:
    root = owned.root
    return DaybookSessionsConfig(
        daybook_sessions_service_user=actor.pw_name,
        daybook_sessions_service_group="staff",
        daybook_sessions_service_home=str(root / "home"),
        daybook_sessions_repo_ref="a" * 40,
        daybook_sessions_config_dir=str(root / "etc"),
        daybook_sessions_log_dir=str(root / "logs"),
        daybook_sessions_launchd_enabled=False,
        daybook_sessions_brew_packages=[],
        daybook_sessions_aws_endpoint_url_s3="https://s3.example.test",
        daybook_archive_quote_classifier_enabled=True,
        daybook_archive_quote_classifier_launchd_enabled=False,
        daybook_archive_quote_classifier_cmd="/usr/bin/false",
        daybook_archive_url="https://archive.example.test",
        daybook_quotes_unused_path="s3://owned/unused.json",
        daybook_quotes_used_path="s3://owned/used.json",
        daybook_archive_browser_executable=str(root / "owned-browser"),
        daybook_weeknotes_reconcile_enabled=True,
        daybook_weeknotes_reconcile_launchd_retired=True,
        daybook_weeknotes_path="s3://owned/weeknotes",
        daybook_weeknotes_cast_base_url="https://cast.example.test",
        daybook_weeknotes_home_url="https://notes.example.test",
        daybook_weeknotes_public_blog_id="1",
        daybook_weeknotes_family_blog_id="2",
    )


def filesystem_case(owned: OwnedMac, resource: Any, controls: Any) -> None:
    actor = pwd.getpwnam("runner")
    cfg = configuration(owned, actor)
    values = cfg.model_dump(mode="json")
    data = {"config": values}
    root = owned.root

    def directory(path: Path, owner: str, mode: int) -> None:
        resource.ensure_directory({"path": str(path), "owner": owner, "group": "staff", "mode": mode})

    def user_file(path: Path, body: bytes) -> None:
        resource.put_bytes({"path": str(path), "owner": actor.pw_name, "group": "staff", "mode": 0o600}, body)

    home = Path(cfg.daybook_sessions_service_home)
    browser = Path(cfg.daybook_archive_browser_executable)
    profile = Path(cfg.daybook_archive_browser_user_data_dir)
    runtime = Path(cfg.daybook_weeknotes_reconcile_runtime_dir)
    agent = Path(cfg.daybook_weeknotes_reconcile_pi_agent_dir)
    authroot = Path(cfg.daybook_weeknotes_reconcile_pi_auth_source_root)
    for path in (home, home / ".daybook", profile, home / ".config", authroot, runtime, agent):
        directory(path, actor.pw_name, 0o700)
    directory(root / "etc", "root", 0o755)
    os.chown(root / "etc", 0, 0)
    directory(root / "logs", actor.pw_name, 0o755)
    resource.put_bytes(
        {"path": str(browser), "owner": "root", "group": "wheel", "mode": 0o755}, b"#!/bin/sh\nexit 99\n"
    )
    source, dest = authroot / "auth.json", agent / "auth.json"
    user_file(source, b"UNUSABLE-OWNED-AUTH-SEED")
    user_file(dest, b"UNUSABLE-OWNED-REFRESHED-AUTH")
    state, lock = runtime / "state.json", runtime / ".state.json.lock"
    user_file(state, b"UNUSABLE-SYNTHETIC-STATE")
    user_file(lock, b"UNUSABLE-SYNTHETIC-LOCK")
    marker = profile / ".daybook-archive-browser-profile"
    user_file(marker, b"OWNED-PROFILE-MARKER")
    log = root / "logs/protected.log"
    user_file(log, b"OWNED-LOG-BYTES")
    log.chmod(0o640)
    protected = [source, dest, state, lock, marker, log, browser]
    before = file_state(protected)
    assert controls.preflight(data) == actor.pw_uid
    controls.browser_access(values)  # actual sudo root -> runner /bin/test only
    with patch.object(controls.os, "read", side_effect=AssertionError("auth preservation must not read body")):
        controls.seed_auth(data, None)
    assert file_state(protected) == before

    # Unmarked, linked and wrong-owner profiles are refused before publication.
    payload = profile / "owned-profile-entry"
    user_file(payload, b"NO-BROWSER-DATA")
    marker.unlink()
    refuse(lambda: controls.preflight(data), "sessions_browser_profile_unmarked", resource.ResourceError)
    user_file(marker, b"OWNED-PROFILE-MARKER")
    os.chown(profile, 0, 0)
    refuse(lambda: controls.preflight(data), "sessions_browser_profile_unsafe", resource.ResourceError)
    os.chown(profile, actor.pw_uid, actor.pw_gid)
    profile.rename(profile.with_name("profile-saved"))
    profile.symlink_to(profile.with_name("profile-saved"), target_is_directory=True)
    refuse(lambda: controls.preflight(data), "sessions_browser_profile_unsafe", resource.ResourceError)
    profile.unlink()
    profile.with_name("profile-saved").rename(profile)
    controls.browser_access(values)

    # Current rotate:false: genuine seed once, metadata-only strict repeat.
    dest.unlink()
    controls.seed_auth(data, None)
    assert dest.read_bytes() == source.read_bytes()
    user_file(dest, b"UNUSABLE-OWNED-LATER-REFRESH")
    preserved = file_state([source, dest, state, lock])
    with patch.object(controls.os, "read", side_effect=AssertionError("repeat must not read auth body")):
        controls.seed_auth(data, None)
    assert file_state([source, dest, state, lock]) == preserved
    for mode in (0o644, 0o400):
        dest.chmod(mode)
        refuse(lambda: controls.seed_auth(data, None), "sessions_private_control_unsafe", resource.ResourceError)
    dest.chmod(0o600)
    extra = agent / "unexpected"
    user_file(extra, b"UNUSABLE-OWNED")
    refuse(lambda: controls.seed_auth(data, None), "sessions_auth_directory_not_isolated", resource.ResourceError)
    extra.unlink()
    hardlink = runtime / "owned-hardlink"
    os.link(dest, hardlink)
    refuse(lambda: controls.seed_auth(data, None), "sessions_private_control_unsafe", resource.ResourceError)
    hardlink.unlink()
    dest.rename(agent / "saved-auth")
    dest.symlink_to(source)
    refuse(lambda: controls.seed_auth(data, None), "sessions_private_control_unsafe", resource.ResourceError)
    dest.unlink()
    (agent / "saved-auth").rename(dest)
    controls.preflight(data)

    # Actual original templates and root/user modes; no helper execution,
    # checksum/credential output, real app checkout or global plist publication.
    fake = {
        "daybook_sessions_aws_access_key_id": "UNUSABLE-OWNED",
        "daybook_sessions_aws_secret_access_key": "UNUSABLE-OWNED",
        "daybook_archive_token": "UNUSABLE-OWNED",
        "daybook_weeknotes_cast_token": "UNUSABLE-OWNED",
        "daybook_weeknotes_home_token": "UNUSABLE-OWNED",
        "daybook_weeknotes_public_repositories_json": '{"owned":"https://example.test/owned.git"}',
        "daybook_weeknotes_confidential_names_json": '["UNUSABLE-OWNED"]',
    }
    rows = _resource_texts(cfg, fake)
    for row in rows:
        assert Path(row.path).is_relative_to(root)
        assert not row.path.endswith(".plist")
        resource.put_resource(vars(row))
    rails = [row for row in rows if row.owner == "root"]
    assert rails
    for row in rails:
        stat = Path(row.path).stat()
        assert (stat.st_uid, stat.st_gid, stat.st_mode & 0o777) == (0, 0, row.mode)
    rendered = file_state([Path(row.path) for row in rows])
    for row in rows:
        resource.put_resource(vars(row))
    resource.ensure_log({"path": str(log), "owner": actor.pw_name, "group": "staff", "mode": 0o640})
    assert file_state([Path(row.path) for row in rows]) == rendered
    assert file_state([source, state, lock, log, browser]) == {
        name: before[name] for name in map(str, [source, state, lock, log, browser])
    }
    # A synthetic operational root proof exercises root-only metadata/JSON read,
    # separately from the real private twelve-module semantics proof.
    proof = root / "etc/owned-proof.json"
    resource.put_bytes({"path": str(proof), "owner": "root", "group": "wheel", "mode": 0o600}, b'{"schema_version":1}')
    assert controls.read_private_json(str(proof), 0) == {"schema_version": 1}
    owned.report["filesystem"] = {
        "root_gui_browser_metadata_access": True,
        "unmarked_linked_wrong_owner_profile_refusals": True,
        "fake_auth_seed_publications": 1,
        "existing_and_repeat_auth_body_reads": 0,
        "auth_mode_link_hardlink_extra_name_refusals": True,
        "rendered_original_resource_publications": len(rows),
        "rendered_repeat_changed_files": 0,
        "root_wheel_rails_verified": len(rails),
        "protected_state_log_source_browser_exact": True,
        "root_operational_proof_metadata_mechanism": True,
        "private_identity_semantics": "separate exact-code proof; not executed by this public native case",
        "setup": (
            "Owned dirs, fake auth/state/log/browser/profile and root operational proof are explicit fixture writes; "
            "no read-only or whole-machine zero-IO claim."
        ),
    }


SYSTEM_PROBE = """import json,os,sys,types
request=json.load(sys.stdin)
for name,source in request['modules']:
 module=types.ModuleType(name);sys.modules[name]=module
 exec(compile(source,'<owned-installed-helper>','exec'),module.__dict__)
resources=sys.modules['ops_sessions_resources']
controls=sys.modules['ops_sessions_controls']
launchd=sys.modules['ops_sessions_launchd']
assert os.geteuid()==0
assert controls.preflight(request['data'])==request['uid']
controls.browser_access(request['data']['config'])
original_read=os.read
def refuse_read(*args):raise AssertionError('existing auth body read forbidden')
try:
 os.read=refuse_read
 controls.seed_auth(request['data'],None)
finally:os.read=original_read
mutations=[]
class ObservedLaunchd(launchd.Launchd):
 def mutate(self,*args):
  super().mutate(*args);mutations.append(list(args))
controller=ObservedLaunchd('system')
controller.retire(request['label'],request['plist'])
first=len(mutations)
controller.retire(request['label'],request['plist'])
assert first==2 and len(mutations)==first
assert controller.state(request['label'])=={'loaded':False,'disabled':True,'running':False}
print(json.dumps({'python':sys.version.split()[0],'uid':os.geteuid(),
 'root_gui_browser_and_auth_metadata':True,'existing_auth_body_reads':0,
 'retirement_mutations':mutations,'retirement_repeat_mutations':0}))
"""


def system_helper_probe(owned: OwnedMac, label: str, plist: Path) -> dict[str, Any]:
    actor = pwd.getpwnam("runner")
    modules = []
    for name, filename in (
        ("ops_sessions_resources", "resources_host.py"),
        ("ops_sessions_controls", "controls_host.py"),
        ("ops_sessions_launchd", "launchd_host.py"),
    ):
        source = importlib.resources.files("ops_deploy.services.daybook_sessions").joinpath("files/" + filename)
        modules.append([name, source.read_text()])
    data = {
        "modules": modules,
        "data": {"config": configuration(owned, actor).model_dump(mode="json")},
        "uid": actor.pw_uid,
        "label": label,
        "plist": str(plist),
    }
    # Same /usr/bin/python3 -I -B interpreter as resource_command. All input is
    # known public code or owned fake declarations; no real credential/app data.
    checked = command("/usr/bin/python3", "-I", "-B", "-c", SYSTEM_PROBE, input=json.dumps(data))
    result: dict[str, Any] = json.loads(checked.stdout)
    assert result["uid"] == 0
    assert result["root_gui_browser_and_auth_metadata"] is True
    assert result["existing_auth_body_reads"] == 0
    return result


def timer_case(owned: OwnedMac, resource: Any, launchd: Any) -> None:
    mutations = []

    class ObservedLaunchd(launchd.Launchd):
        def mutate(self, *args: str) -> None:
            super().mutate(*args)
            mutations.append(list(args))

    actor = pwd.getpwnam("runner")
    domains = ["system", "gui/" + str(actor.pw_uid)]
    records = []
    for domain in domains:
        assert command("/bin/launchctl", "print", domain, check=False).returncode == 0
        controller = ObservedLaunchd(domain)
        for kind in ("idle", "missing-plist", "running"):
            label = owned.label("sessions-resource-" + domain.split("/")[0] + "-" + kind)
            if domain != "system":
                owned.labels.remove("system/" + label)
                owned.adopt_gui_label(actor.pw_uid, label)
            plist = owned.root / (label + ".plist")
            plist.write_bytes(
                plistlib.dumps(
                    {
                        "Label": label,
                        "ProgramArguments": ["/bin/sleep", "300"] if kind == "running" else ["/usr/bin/true"],
                        "RunAtLoad": kind == "running",
                        "StartInterval": 3600,
                    }
                )
            )
            plist.chmod(0o644)
            command("/bin/launchctl", "bootstrap", domain, str(plist))
            wait(lambda controller=controller, label=label: controller.state(label)["loaded"])
            count = len(mutations)
            if kind == "running":
                wait(
                    lambda controller=controller, label=label, domain=domain: (
                        controller.state(label)["running"] and job_pid(domain + "/" + label) is not None
                    )
                )
                pid = job_pid(domain + "/" + label)
                identity = processes()[pid]
                before = file_state([plist])
                refuse(
                    lambda controller=controller, label=label, plist=plist: controller.retire(label, str(plist)),
                    "sessions_timer_in_flight",
                    resource.ResourceError,
                )
                assert len(mutations) == count
                assert job_pid(domain + "/" + label) == pid
                assert processes()[pid] == identity
                assert file_state([plist]) == before
                records.append(
                    {"domain": domain, "case": kind, "genuine_refusal": True, "pid_and_resource_exact": True}
                )
                continue
            if kind == "missing-plist":
                plist.unlink()  # explicit fixture setup, not hidden fact mutation
            if domain == "system" and kind == "idle":
                protected_auth = (
                    Path(configuration(owned, actor).daybook_weeknotes_reconcile_pi_agent_dir) / "auth.json"
                )
                auth_before = file_state([protected_auth])
                probe = system_helper_probe(owned, label, plist)
                assert file_state([protected_auth]) == auth_before
                mutations.extend(probe["retirement_mutations"])
                owned.report["production_system_interpreter_probe"] = probe
            else:
                controller.retire(label, str(plist))
            assert mutations[count:] == [["bootout", domain + "/" + label], ["disable", domain + "/" + label]]
            assert not plist.exists()
            assert controller.state(label) == {"loaded": False, "disabled": True, "running": False}
            count = len(mutations)
            controller.retire(label, str(plist))
            assert len(mutations) == count
            records.append({"domain": domain, "case": kind, "actual_bootout_disable": 2, "repeat_mutations": 0})
    owned.report["timers"] = records
    owned.report["timer_mutations"] = mutations
    owned.report["timer_scope"] = (
        "Shared Launchd mechanisms on unique owned labels only; "
        "original exact global reconcile identity validation remains separate source/tests."
    )


def main() -> None:
    owned = OwnedMac("daybook-resources")
    failure: BaseException | None = None
    try:
        provenance(owned)
        with installed_helpers() as (resource, controls, launchd):
            filesystem_case(owned, resource, controls)
            timer_case(owned, resource, launchd)
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
    finally:
        # Restore only our owned disabled entries. macOS may retain explicit
        # false/enabled rows; that is not claimed to be absent/global zero I/O.
        restored = []
        enabled = []
        for service in owned.labels:
            try:
                pid = job_pid(service)
                identity = processes().get(pid) if pid is not None else None
                command("/bin/launchctl", "bootout", service, check=False)
                if pid is not None and identity is not None:
                    wait(lambda pid=pid, identity=identity: processes().get(pid) != identity)
                domain, label = service.rsplit("/", 1)
                with installed_helpers() as (_resource, _controls, launchd):
                    controller = launchd.Launchd(domain)
                    if controller.state(label)["disabled"]:
                        command("/bin/launchctl", "enable", service)
                        enabled.append(service)
                    state = controller.state(label)
                assert not state["loaded"]
                assert not state["disabled"]
                restored.append(service)
            except BaseException as error:
                failure = failure or error
        owned.report["owned_labels_enabled_unloaded_before_final_cleanup"] = restored
        owned.report["owned_disabled_entries_reset_enabled"] = enabled
        owned.report["interpreter_scope"] = (
            "Production /usr/bin/python3 -I -B runs browser/auth guards and system retirement/repeat. "
            "Other mechanism assertions execute identical installed helper bytes in controller Python3.13."
        )
        owned.report["cleanup_limit"] = (
            "Only actually disabled owned entries reset to enabled; see owned_disabled_entries_reset_enabled. "
            "OS may retain enabled rows. "
            "Workflow/controller/cache setup is outside fixture root cleanup."
        )
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
