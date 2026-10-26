"""Real old→selected UniFi deployment on an owned disposable systemd VM."""

from __future__ import annotations

import hashlib
import http.cookiejar
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import time
import urllib.request
from dataclasses import asdict
from importlib import import_module
from pathlib import Path
from typing import Any

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.unifi import deploy_unifi

PASSWORD = "fixture-unifi-mongo-20261026"
HA_PASSWORD = "fixture-homeassistant-20261026"
BOOTSTRAP_PASSWORD = "fixture-bootstrap-admin-20261026"
CONTROLLER_ADMIN_PASSWORD = "fixture-controller-admin-20261026"


def run(*args: str, stdin: str | None = None) -> str:
    result = subprocess.run(args, input=stdin, text=True, capture_output=True)
    if result.returncode:
        # Dummy fixture only, but never publish even its database URI/password.
        raise RuntimeError(f"{args[0]} failed: {result.returncode}")
    return result.stdout.strip()


def write(path: str, text: str, mode: int = 0o644) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    target.chmod(mode)


def mongo(script: str, *, authenticate: bool = True) -> str:
    auth = f'if (!db.getSiblingDB("admin").auth("unifi",{json.dumps(PASSWORD)})) quit(20);' if authenticate else ""
    return run("mongosh", "--quiet", "--norc", "--host", "127.0.0.1", "--file", "/dev/stdin", stdin=auth + script)


def cfg() -> Any:
    api = import_module("ops_deploy.services.unifi")
    address = re.search(r"\bsrc ([0-9.]+)", run("ip", "-4", "route", "get", "8.8.8.8"))
    assert address
    return api.UnifiConfig(
        installed_package_version="9.5.21-31260-1",
        controller_bind_address=address[1],
        external_hostname="unifi.example.com",
        traefik_enabled=False,
        manage_firewall=False,
        create_homeassistant_user=True,
        jvm_min_heap_mb=256,
        jvm_max_heap_mb=768,
        healthcheck_timeout=300,
        routine=api.UnifiRoutine(
            package_version="9.5.21-31260-1",
            package_url="https://dl.ui.com/unifi/9.5.21/unifi_sysvinit_all.deb",
            package_sha256="7da1cc9ab1ae0c8f302c242d622ee52f867457a69116b2aa4c13812e756986af",
        ),
    )


def setup(config: Any) -> None:
    write(
        "/etc/mongod.conf",
        """storage:
  dbPath: /var/lib/mongodb
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  quiet: true
  verbosity: 0
net:
  port: 27017
  bindIp: 127.0.0.1
security:
  authorization: enabled
setParameter:
  suppressNoTLSPeerCertificateWarning: true
  diagnosticDataCollectionEnabled: false
""",
    )
    run("systemctl", "enable", "--now", "mongod")
    for _ in range(30):
        try:
            mongo('db.getSiblingDB("admin").runCommand({ping:1})', authenticate=False)
            break
        except RuntimeError:
            time.sleep(1)
    # Bootstrap belongs to the owned fixture, not the deployment's supported
    # existing-install contract. MongoDB authorization remains enabled throughout.
    mongo(
        'db.getSiblingDB("admin").createUser({user:"fixture-bootstrap",pwd:'
        + json.dumps(BOOTSTRAP_PASSWORD)
        + ',roles:[{role:"userAdminAnyDatabase",db:"admin"}]});',
        authenticate=False,
    )
    mongo(
        'const a=db.getSiblingDB("admin");if(!a.auth("fixture-bootstrap",'
        + json.dumps(BOOTSTRAP_PASSWORD)
        + '))quit(20);a.createUser({user:"unifi",pwd:'
        + json.dumps(PASSWORD)
        + ",roles:["
        '{role:"readWrite",db:"unifi"},{role:"dbOwner",db:"unifi"},'
        '{role:"readWrite",db:"unifi_stat"},{role:"dbOwner",db:"unifi_stat"},'
        '{role:"readWrite",db:"unifi_audit"},'
        '{role:"clusterMonitor",db:"admin"}]});',
        authenticate=False,
    )


def deploy(
    config: Any, evidence: Path, label: str, *, wrong_password: bool = False, expect_refusal: str | None = None
) -> list[Any]:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    from ops_deploy.testing.harness import collect_ops

    state = State(Inventory(([("@local", {})], {})), Config())
    error = None
    try:
        connect_all(state)
        add_deploy(
            state,
            deploy_unifi,
            cfg=config,
            secrets=SecretValues(
                SecretRef("fixture.yml"),
                {
                    "mongodb_password": "wrong-fixture-password" if wrong_password else PASSWORD,
                    "homeassistant_password": HA_PASSWORD,
                },
            ),
        )
        run_ops(state)
    except Exception as exc:
        error = type(exc).__name__
    finally:
        ops = collect_ops(state, "@local")
        disconnect_all(state)
    admission = None
    if error:
        # Persist only the production probe's fixed status label, never its
        # payload or subprocess diagnostics (even with dummy fixture secrets).
        api = import_module("ops_deploy.services.unifi.deploy")
        probe_result = subprocess.run(
            shlex.split(api.PREFLIGHT_COMMAND),
            input=api.payload(
                config,
                SecretValues(
                    SecretRef("fixture.yml"),
                    {
                        "mongodb_password": "wrong-fixture-password" if wrong_password else PASSWORD,
                        "homeassistant_password": HA_PASSWORD,
                    },
                ),
            ),
            text=True,
            capture_output=True,
        )
        status_label = probe_result.stdout.strip()
        admission = status_label if re.fullmatch(r"ready|refused:[a-z0-9_]+", status_label) else "unavailable"
    result = {
        "admission": admission,
        "operations": [{k: v for k, v in asdict(op).items() if k != "args"} for op in ops],
        "error": error,
    }
    (evidence / (label + ".json")).write_text(json.dumps(result, indent=2))
    mutations = [op for op in ops if op.changed and not op.read_only]
    if wrong_password or expect_refusal:
        assert error
        assert not mutations
        if expect_refusal is not None:
            assert admission == expect_refusal, result
    else:
        assert error is None, result
        assert ops, result
        assert all(op.succeeded for op in ops), result
        if label.endswith("repeat"):
            assert not mutations, result
    return mutations


def protection() -> str:
    return mongo(
        'const u=db.getSiblingDB("unifi");print(JSON.stringify({site:u.site.find({},{_id:1,name:1}).toArray(),'
        'sentinel:u.ops_fixture.findOne({_id:"protected"}),audit_sentinel:db.getSiblingDB("unifi_audit").ops_fixture.findOne({_id:"protected"}),auth:db.getSiblingDB("admin").runCommand({getCmdLineOpts:1}).parsed.security}));'
    )


def complete_controller_setup(evidence: Path) -> dict[str, Any]:
    """Use the vendor setup API before protecting data or testing an update."""
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
        urllib.request.HTTPCookieProcessor(cookies),
    )
    # Load the frontend session, then mirror its csrf_token -> X-Csrf-Token
    # cookie/header binding on each state-changing request.
    opener.open("https://127.0.0.1:8443/", timeout=30).close()
    steps: list[dict[str, Any]] = []
    # Exact commands/fields from 9.4.19's bundled setup frontend. This is
    # fixture-only wizard completion, never a deployment operation.
    for endpoint, body in (
        (
            "/api/cmd/sitemgr",
            {
                "cmd": "add-default-admin",
                "name": "fixtureadmin",
                "email": "fixture@example.com",
                "x_password": CONTROLLER_ADMIN_PASSWORD,
            },
        ),
        ("/api/login", {"username": "fixtureadmin", "password": CONTROLLER_ADMIN_PASSWORD}),
        ("/api/cmd/system", {"cmd": "set-installed"}),
    ):
        headers = {"Content-Type": "application/json"}
        for cookie in cookies:
            if cookie.name == "csrf_token" and cookie.value is not None:
                headers["X-Csrf-Token"] = cookie.value
        request = urllib.request.Request(
            "https://127.0.0.1:8443" + endpoint,
            data=json.dumps(body).encode(),
            headers=headers,
        )
        with opener.open(request, timeout=30) as response:
            phase = str(body.get("cmd", "login"))
            steps.append(
                {
                    "phase": phase,
                    "status": response.status,
                    "content_type": response.headers.get_content_type(),
                    "redirected": response.url != request.full_url,
                }
            )
            (evidence / "wizard-http.json").write_text(json.dumps(steps, indent=2))
            try:
                result = json.load(response)
            except json.JSONDecodeError:
                raise RuntimeError(f"wizard {phase} returned non-JSON; see wizard-http.json") from None
            assert result["meta"]["rc"] == "ok", f"wizard {phase} rejected"
    assert_controller_initialized()
    sites = json.load(opener.open("https://127.0.0.1:8443/api/self/sites", timeout=20))
    assert sites["meta"]["rc"] == "ok"
    expected = mongo('print(db.getSiblingDB("unifi").site.findOne({name:"default"})._id.toString());')
    assert any(site["_id"] == expected and site["name"] == "default" for site in sites["data"])
    return {"wizard_api_completed": True, "site_id": expected}


def assert_controller_initialized() -> None:
    assert re.search(r"(?m)^is_default\s*=\s*false\s*$", Path("/var/lib/unifi/system.properties").read_text())


def application_database_proof(evidence: Path, phase: str) -> dict[str, Any]:
    """Prove the running application reads the same authenticated database."""
    assert_controller_initialized()
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
        urllib.request.HTTPCookieProcessor(cookies),
    )
    request = urllib.request.Request(
        "https://127.0.0.1:8443/api/login",
        data=json.dumps({"username": "homeassistant", "password": HA_PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
    )
    assert json.load(opener.open(request, timeout=20))["meta"]["rc"] == "ok"
    sites = json.load(opener.open("https://127.0.0.1:8443/api/self/sites", timeout=20))
    assert sites["meta"]["rc"] == "ok"
    expected = mongo('print(db.getSiblingDB("unifi").site.findOne({name:"default"})._id.toString());')
    assert any(site["_id"] == expected and site["name"] == "default" for site in sites["data"])
    # The sole Mongo process must be the authenticated system service. An
    # application-owned embedded database would invalidate this proof.
    mongo_pid = run("systemctl", "show", "-p", "MainPID", "--value", "mongod")
    assert run("pgrep", "-x", "mongod").splitlines() == [mongo_pid]
    assert_no_embedded_database(evidence, phase)
    return {"authenticated": True, "site_id": expected, "only_system_mongo": True, "no_embedded_database_files": True}


def assert_no_embedded_database(evidence: Path, phase: str, embedded: Path = Path("/var/lib/unifi/db")) -> None:
    # An empty vendor-created directory is not an embedded database. Preserve
    # bounded entry-name evidence before refusing any actual database files.
    entries = sorted(path.name for path in embedded.iterdir()) if embedded.is_dir() else []
    directory_proof = {
        "exists": embedded.exists(),
        "is_directory": embedded.is_dir(),
        "is_symlink": embedded.is_symlink(),
        "entries": entries[:100],
    }
    (evidence / f"embedded-directory-{phase}.json").write_text(json.dumps(directory_proof, indent=2))
    assert not embedded.is_symlink()
    assert not embedded.exists() or (embedded.is_dir() and not entries)


def runtime() -> dict[str, str]:
    """Record the executable of the actual controller process, not JAVA_HOME."""
    pid = run("systemctl", "show", "-p", "MainPID", "--value", "unifi")
    assert pid.isdigit()
    assert pid != "0"
    executable = str(Path("/proc", pid, "exe").resolve(strict=True))
    return {"pid": pid, "executable": executable, "version": run(executable, "--version")}


def main(evidence: Path) -> None:
    marker = json.loads(Path("/var/tmp/unifi-routine-owned-vm.json").read_text())
    assert marker == {"run": os.environ["GITHUB_RUN_ID"], "machine": Path("/etc/machine-id").read_text().strip()}
    config = cfg()
    setup(config)
    previous = config.model_copy(
        update={
            "routine": import_module("ops_deploy.services.unifi").UnifiRoutine(
                package_version="9.4.19-31042-1",
                package_url="https://dl.ui.com/unifi/9.4.19/unifi_sysvinit_all.deb",
                package_sha256="95bbde1c98ce4690116be114e783adbc893bc7558518aaf01562f76fe037e570",
            )
        }
    )
    # Exercise actual production admission before any controller/account/data
    # mutation, retaining each deliberately protected fixture record.
    for database in ("unifi", "unifi_stat", "unifi_audit"):
        mongo(f'db.getSiblingDB({json.dumps(database)}).ops_guard.insertOne({{_id:"protected",value:1}});')
        deploy(previous, evidence, "nonempty-" + database, expect_refusal="refused:fresh_controller_database_not_empty")
        assert (
            mongo(f'print(db.getSiblingDB({json.dumps(database)}).ops_guard.findOne({{_id:"protected"}}).value);')
            == "1"
        )
        assert not Path("/var/lib/unifi").exists()
        mongo(f"db.getSiblingDB({json.dumps(database)}).ops_guard.drop();")
    administrator = (
        'const a=db.getSiblingDB("admin");if(!a.auth("fixture-bootstrap",'
        + json.dumps(BOOTSTRAP_PASSWORD)
        + "))quit(20);"
    )
    mongo(administrator + 'a.revokeRolesFromUser("unifi",[{role:"readWrite",db:"unifi_audit"}]);', authenticate=False)
    deploy(
        previous,
        evidence,
        "insufficient-audit-access",
        expect_refusal="refused:fresh_database_permissions_insufficient",
    )
    assert not Path("/var/lib/unifi").exists()
    mongo(administrator + 'a.grantRolesToUser("unifi",[{role:"readWrite",db:"unifi_audit"}]);', authenticate=False)
    # This is explicit fixture CRUD under the application identity, not a claim
    # that controller-generated audit events were observed.
    mongo(
        'const c=db.getSiblingDB("unifi_audit").ops_permission_probe;'
        'c.createIndex({value:1});c.insertOne({_id:"owned",value:1});'
        'c.updateOne({_id:"owned"},{$set:{value:2}});'
        'if(c.findOne({_id:"owned"}).value!==2)quit(30);'
        'c.deleteOne({_id:"owned"});c.dropIndex("value_1");c.drop();'
    )
    audit_permission_proof = {"direct_authenticated_crud": True, "controller_generated_events": "not asserted"}
    (evidence / "audit-permissions.json").write_text(json.dumps(audit_permission_proof, indent=2))
    deploy(previous, evidence, "install-first")
    assert json.loads(run("curl", "-kfsS", "https://127.0.0.1:8443/status"))["meta"]["server_version"] == "9.4.19"
    deploy(previous, evidence, "install-repeat")
    (evidence / "runtime-before-wizard.json").write_text(json.dumps(runtime(), indent=2))
    wizard = complete_controller_setup(evidence)
    (evidence / "wizard-completion.json").write_text(json.dumps(wizard, indent=2))
    mongo(
        'const u=db.getSiblingDB("unifi");'
        'u.ops_fixture.insertOne({_id:"protected",value:"preserve"});'
        'db.getSiblingDB("unifi_audit").ops_fixture.insertOne({_id:"protected",value:"preserve-audit"});'
    )
    before = protection()
    runtime_before = runtime()
    (evidence / "runtime-before-update.json").write_text(json.dumps(runtime_before, indent=2))
    deploy(config, evidence, "update-first")
    assert run("dpkg-query", "-W", "-f=${Version}", "unifi") == "9.5.21-31260-1"
    assert json.loads(run("curl", "-kfsS", "https://127.0.0.1:8443/status"))["meta"]["server_version"] == "9.5.21"
    runtime_after = runtime()
    (evidence / "runtime-after-update.json").write_text(json.dumps(runtime_after, indent=2))
    assert runtime_before["executable"] == runtime_after["executable"]
    assert runtime_before["version"] == runtime_after["version"]
    deploy(config, evidence, "update-repeat")
    database_proof = application_database_proof(evidence, "after-update")
    (evidence / "application-database.json").write_text(json.dumps(database_proof, indent=2))
    assert protection() == before
    identity = mongo('print(db.getSiblingDB("unifi").admin.findOne({name:"homeassistant"})._id.toString());')
    mongo(
        'const u=db.getSiblingDB("unifi");'
        'u.admin.updateOne({name:"homeassistant"},{$set:{x_shadow:"invalid-fixture-hash"}});'
        'const id=u.admin.findOne({name:"homeassistant"})._id;'
        'u.privilege.updateMany({admin_id:{$in:[id,id.toString()]}},{$set:{role:"admin",permissions:["fixture"]}});'
    )
    path = Path("/etc/mongod.conf")
    path.write_text(path.read_text().replace("quiet: true", "quiet: false"))
    run("systemctl", "restart", "mongod")
    # Requires=mongod restarts the controller too. Complete the deliberate
    # fixture mutation before asking deployment admission to inspect it.
    for attempt in range(60):
        try:
            mongo('if(db.getSiblingDB("admin").runCommand({ping:1}).ok!==1)quit(22);')
            status = json.loads(run("curl", "-kfsS", "https://127.0.0.1:8443/status"))
            assert status["meta"]["server_version"] == "9.5.21"
            assert status["meta"]["up"] is True
            assert Path("/usr/lib/unifi/run").is_dir()
            break
        except (RuntimeError, AssertionError):
            if attempt == 59:
                raise
            time.sleep(2)
    deploy(config, evidence, "repair-first")
    deploy(config, evidence, "repair-repeat")
    assert application_database_proof(evidence, "after-repair") == database_proof
    assert mongo('print(db.getSiblingDB("unifi").admin.findOne({name:"homeassistant"})._id.toString());') == identity
    assert protection() == before
    deploy(config, evidence, "bad-auth", wrong_password=True)
    assert protection() == before
    routine_api = import_module("ops_deploy.services.unifi.routine")

    source = routine_api.PACKAGE.joinpath("files/install_package.py").read_text()
    pid = run("systemctl", "show", "-p", "MainPID", "--value", "unifi")
    invalid = subprocess.run(
        shlex.split(
            routine_api.command(
                source, "/var/cache/ops-deploy-unifi/unifi_9.4.19-31042-1_all.deb", "9.4.19-31042-1", "0" * 64
            )
        ),
        input=json.dumps({"initialize": False}).encode(),
        capture_output=True,
    )
    assert invalid.returncode != 0
    assert run("systemctl", "show", "-p", "MainPID", "--value", "unifi") == pid
    assert not Path("/usr/sbin/policy-rc.d").exists()
    deploy(config, evidence, "final-repeat")
    (evidence / "receipt.json").write_text(
        json.dumps(
            {
                "implementation_sha": os.environ["IMPLEMENTATION_SHA"],
                "harness_sha": os.environ["HARNESS_SHA"],
                "old_version": "9.4.19-31042-1",
                "selected_version": "9.5.21-31260-1",
                "audit_permission_proof": audit_permission_proof,
                "application_database": database_proof,
                "runtime_before_update": runtime_before,
                "runtime_after_update": runtime_after,
                "protection_sha256": hashlib.sha256(before.encode()).hexdigest(),
                "passed": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
