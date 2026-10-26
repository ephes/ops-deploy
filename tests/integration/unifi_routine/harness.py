"""Real old→selected UniFi deployment on an owned disposable systemd VM."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import asdict
from importlib import import_module
from pathlib import Path
from typing import Any

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.unifi import deploy_unifi

PASSWORD = "fixture-unifi-mongo-20261026"
HA_PASSWORD = "fixture-homeassistant-20261026"


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
        'db.getSiblingDB("admin").createUser({user:"unifi",pwd:' + json.dumps(PASSWORD) + ",roles:["
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
    result = {"operations": [{k: v for k, v in asdict(op).items() if k != "args"} for op in ops], "error": error}
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
    deploy(config, evidence, "update-first")
    assert run("dpkg-query", "-W", "-f=${Version}", "unifi") == "9.5.21-31260-1"
    assert json.loads(run("curl", "-kfsS", "https://127.0.0.1:8443/status"))["meta"]["server_version"] == "9.5.21"
    deploy(config, evidence, "update-repeat")
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
    deploy(config, evidence, "repair-first")
    deploy(config, evidence, "repair-repeat")
    assert mongo('print(db.getSiblingDB("unifi").admin.findOne({name:"homeassistant"})._id.toString());') == identity
    assert protection() == before
    deploy(config, evidence, "bad-auth", wrong_password=True)
    assert protection() == before
    from ops_deploy.services.unifi.routine import PACKAGE, command

    source = PACKAGE.joinpath("files/install_package.py").read_text()
    pid = run("systemctl", "show", "-p", "MainPID", "--value", "unifi")
    invalid = subprocess.run(
        shlex.split(
            command(source, "/var/cache/ops-deploy-unifi/unifi_9.4.19-31042-1_all.deb", "9.4.19-31042-1", "0" * 64)
        ),
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
                "protection_sha256": hashlib.sha256(before.encode()).hexdigest(),
                "passed": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
