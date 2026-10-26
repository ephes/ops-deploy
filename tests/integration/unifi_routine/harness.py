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
        '{role:"clusterMonitor",db:"admin"}]});',
        authenticate=False,
    )


def deploy(config: Any, evidence: Path, label: str, *, wrong_password: bool = False) -> list[Any]:
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
    if wrong_password:
        assert error
        assert not mutations
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
        'sentinel:u.ops_fixture.findOne({_id:"protected"}),auth:db.getSiblingDB("admin").runCommand({getCmdLineOpts:1}).parsed.security}));'
    )


def application_database_proof() -> dict[str, Any]:
    """Prove the running application reads the same authenticated database."""
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
    assert not Path("/var/lib/unifi/db").exists()
    return {"authenticated": True, "site_id": expected, "only_system_mongo": True}


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
    deploy(previous, evidence, "install-first")
    assert json.loads(run("curl", "-kfsS", "https://127.0.0.1:8443/status"))["meta"]["server_version"] == "9.4.19"
    deploy(previous, evidence, "install-repeat")
    # Model completing the controller's setup wizard, which creates a site.
    mongo(
        'const u=db.getSiblingDB("unifi");'
        'if(!u.site.findOne({name:"default"})) u.site.insertOne({name:"default",desc:"Fixture"});'
        'u.ops_fixture.insertOne({_id:"protected",value:"preserve"});'
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
    database_proof = application_database_proof()
    (evidence / "application-database.json").write_text(json.dumps(database_proof, indent=2))
    assert protection() == before
    identity = mongo('print(db.getSiblingDB("unifi").admin.findOne({name:"homeassistant"})._id.toString());')
    mongo(
        'const u=db.getSiblingDB("unifi");'
        'u.admin.updateOne({name:"homeassistant"},{$set:{x_shadow:"invalid-fixture-hash"}});'
        'u.privilege.updateMany({},{$set:{role:"admin",permissions:["fixture"]}});'
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
            assert Path("/usr/lib/unifi/run").is_dir()
            break
        except (RuntimeError, AssertionError):
            if attempt == 59:
                raise
            time.sleep(2)
    deploy(config, evidence, "repair-first")
    deploy(config, evidence, "repair-repeat")
    assert application_database_proof() == database_proof
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
