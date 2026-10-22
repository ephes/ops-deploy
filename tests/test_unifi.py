"""Existing-install admission, config parity, no-op and secret regression tests."""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import jinja2
import pytest
import yaml
from pydantic import ValidationError
from pyinfra.api import Config

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.unifi import UnifiConfig, deploy_unifi
from ops_deploy.services.unifi.deploy import FIREWALL_RULES, PREFLIGHT_COMMAND, payload
from ops_deploy.services.unifi.render import render_template, role_vars
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

ROOT = Path(__file__).parents[1]
PACKAGE = ROOT / "src/ops_deploy/services/unifi"
CFG = UnifiConfig(controller_bind_address="10.2.3.4", external_hostname="unifi.example.com")
SENTINEL = "unifi-probe-sentinel-4XvkZ"
SECRETS = SecretValues(SecretRef("secrets/test.yml"), {"mongodb_password": SENTINEL})
ARGS = "/etc/unifi-secrets/mongodb.jvmargs"
UNIT = "/etc/systemd/system/unifi.service"
ROUTE = "/etc/traefik/dynamic/unifi.yml"


def host_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("unifi_preflight", PACKAGE / "files/preflight.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def converged(**overrides: Any) -> dict[str, Any]:
    content = render_template(CFG, "mongodb.jvmargs.j2", mongodb_password=SENTINEL)
    facts = {
        **fakehost.LINUX,
        "existing-install": ["ready"],
        # Fact matching uses substrings of the script's source, not operation names.
        "Only a private temporary mongosh HOME": ["ready"],
        "Is a UniFi restart owed?": ["current"],
        "show -p NeedDaemonReload --value unifi.service": ["no"],
        "ufw show added": [
            f"ufw allow {port}/{proto} comment {shlex.quote(comment)}" for port, proto, comment in FIREWALL_RULES
        ],
        **fakehost.directory("/etc/unifi-secrets", mode="drwxr-x---"),
        **fakehost.file(ARGS, content, mode="-rw-r-----"),
        **fakehost.stat(ARGS, group="unifi", mode="-rw-r-----"),
        **fakehost.file(UNIT, render_template(CFG, "unifi.service.j2")),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory("/etc/logrotate.d"),
        **fakehost.directory("/etc/cron.daily"),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.file(ROUTE, render_template(CFG, "unifi.traefik.yml.j2")),
        **fakehost.file("/etc/logrotate.d/mongodb", render_template(CFG, "mongodb-logrotate.j2")),
        **fakehost.file(
            "/etc/cron.daily/mongodb-log-check", render_template(CFG, "mongodb-log-check.sh.j2"), mode="-rwxr-xr-x"
        ),
        **fakehost.service("unifi.service"),
    }
    facts.update(fakehost.stat("/etc/unifi-secrets", group="unifi", mode="drwxr-x---"))
    return {**overrides, **{key: value for key, value in facts.items() if key not in overrides}}


def test_converged_controller_has_zero_mutating_operations() -> None:
    run = run_deploy_fake(deploy_unifi, CFG, SECRETS, responses=converged())
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.uploads == []
    assert not any(command.startswith("systemctl") and "mongod" in command for command in run.executed_commands)


def test_route_drift_only_writes_route_and_does_not_restart() -> None:
    run = run_deploy_fake(deploy_unifi, CFG, SECRETS, responses=converged(**fakehost.file(ROUTE, "drift\n")))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == ["Converge existing UniFi | Configure /etc/traefik/dynamic/unifi.yml"]
    assert not any(command.startswith("systemctl restart") for command in run.executed_commands)


@pytest.mark.parametrize("answer", [[], ["refused:mongodb_auth_config_drift"], ["ops-deploy-probe-failed"]])
def test_admission_refuses_before_any_mutation(answer: list[str]) -> None:
    run = run_deploy_fake(
        deploy_unifi, CFG, SECRETS, responses=converged(**{"Only a private temporary mongosh HOME": answer})
    )
    assert not run.succeeded
    assert run.executed_commands == []
    assert run.uploads == []


def test_argfile_drift_restarts_controller_without_leaking_secret(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    run = run_deploy_fake(
        deploy_unifi,
        CFG,
        SECRETS,
        responses=converged(**fakehost.file(ARGS, "drift", mode="-rw-r-----")),
        pyinfra_config=Config(DIFF=True),
    )
    assert run.succeeded, run.error
    assert "systemctl restart unifi.service" in run.executed_commands
    assert SENTINEL not in caplog.text
    assert not any(SENTINEL in command for command in run.executed_commands + run.fact_commands)


def test_lost_restart_is_recovered() -> None:
    run = run_deploy_fake(deploy_unifi, CFG, SECRETS, responses=converged(**{"Is a UniFi restart owed?": ["owed"]}))
    assert run.succeeded, run.error
    assert "systemctl restart unifi.service" in run.executed_commands


@pytest.mark.parametrize("password", ["", "CHANGEME", "with@delimiter", "with\nnewline", "with%20escape"])
def test_ambiguous_uri_credentials_refused_without_host_access(password: str) -> None:
    values = SecretValues(SecretRef("secrets/test.yml"), {"mongodb_password": password})
    with pytest.raises((ValueError, KeyError)):
        payload(CFG, values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"mongodb_enable_auth": False},
        {"version": "shell;code"},
        {"controller_bind_address": "host"},
        {"traefik_ip_allowlist": ['bad"yaml']},
        {"traefik_ip_allowlist": ['fe80::1%bad"yaml']},
        {"jvm_min_heap_mb": 4096, "jvm_max_heap_mb": 1024},
    ],
)
def test_unsupported_or_unsafe_config_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UnifiConfig(**{**CFG.model_dump(), **overrides})


def test_javascript_uses_json_encoding_and_never_writes_database() -> None:
    module = host_module()
    script = module.javascript(json.loads(payload(CFG, SECRETS)))
    assert json.dumps(SENTINEL) in script
    assert "getCmdLineOpts" in script
    assert 'config.get("disableLogging")' in script
    for write in ("createUser", "updateOne", "insertOne", "drop", "config.set"):
        assert write not in script
    assert SENTINEL not in PREFLIGHT_COMMAND


def test_host_failure_never_prints_child_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = host_module()
    monkeypatch.setattr(module.json, "load", lambda stream: {})

    def fail(payload: Any) -> None:
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(module, "check", fail)
    assert module.main() == 1
    output = capsys.readouterr()
    assert SENTINEL not in output.out + output.err
    assert output.out == "refused:preflight_failed_use_ansible\n"


@pytest.mark.skipif(not os.environ.get("OPS_LIBRARY_PATH"), reason="OPS_LIBRARY_PATH not set")
def test_templates_and_supported_defaults_match_current_role() -> None:
    source = Path(os.environ["OPS_LIBRARY_PATH"]) / "roles/unifi_deploy"
    defaults = yaml.safe_load((source / "defaults/main.yml").read_text())
    cfg = CFG
    for field in (
        "version",
        "jvm_min_heap_mb",
        "jvm_max_heap_mb",
        "traefik_entrypoints",
        "mongodb_log_max_size_mb",
        "mongodb_logrotate_enabled",
        "mongodb_monitor_script_enabled",
        "manage_firewall",
        "create_homeassistant_user",
    ):
        found = getattr(cfg, field)
        assert (list(found) if isinstance(found, tuple) else found) == defaults[f"unifi_{field}"]
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(source / "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    for template in (PACKAGE / "templates").iterdir():
        assert template.read_bytes() == (source / "templates" / template.name).read_bytes()
        expected = env.get_template(template.name).render(**role_vars(cfg), unifi_mongodb_password=SENTINEL)
        assert render_template(cfg, template.name, mongodb_password=SENTINEL) == expected


def mongodb_state() -> dict[str, Any]:
    return {
        "opts": {
            "security": {"authorization": "enabled"},
            "net": {"bindIp": "127.0.0.1", "port": 27017},
            "systemLog": {"quiet": True, "verbosity": 0},
            "setParameter": {"suppressNoTLSPeerCertificateWarning": True, "diagnosticDataCollectionEnabled": False},
        },
        "parameters": {"suppressNoTLSPeerCertificateWarning": True, "diagnosticDataCollectionEnabled": False},
        "site": True,
        "ha": None,
        "privileges": [],
    }


@pytest.mark.parametrize(
    ("section", "key", "value", "reason"),
    [
        ("security", "authorization", "disabled", "mongodb_auth_config_drift"),
        ("net", "bindIp", "0.0.0.0", "mongodb_bind_config_drift"),
        ("net", "port", 12345, "mongodb_bind_config_drift"),
        ("systemLog", "quiet", False, "mongodb_logging_config_drift"),
        ("parameters", "diagnosticDataCollectionEnabled", True, "mongodb_parameter_drift"),
    ],
)
def test_mongodb_drift_is_refused(section: str, key: str, value: Any, reason: str) -> None:
    module = host_module()
    state = mongodb_state()
    module.check_mongodb_state(state, json.loads(payload(CFG, SECRETS)))
    if section == "parameters":
        state[section][key] = value
    else:
        state["opts"][section][key] = value
    with pytest.raises(ValueError, match=reason):
        module.check_mongodb_state(state, json.loads(payload(CFG, SECRETS)))


@pytest.mark.parametrize("fail", [False, True])
def test_mongosh_client_state_is_private_and_cleaned(monkeypatch: pytest.MonkeyPatch, fail: bool) -> None:
    module = host_module()
    homes: list[Path] = []

    def child(args: list[str], *, stdin: str, env: dict[str, str]) -> str:
        home = Path(env["HOME"])
        homes.append(home)
        assert home.stat().st_mode & 0o777 == 0o700
        settings = home / ".mongodb/mongosh/config"
        assert settings.stat().st_mode & 0o777 == 0o600
        assert json.loads(settings.read_text()) == {"disableLogging": True, "enableTelemetry": False, "updateURL": ""}
        assert SENTINEL not in " ".join(args)
        assert SENTINEL in stdin
        if fail:
            raise RuntimeError(SENTINEL)
        return "OPS_UNIFI=" + json.dumps(mongodb_state())

    monkeypatch.setattr(module, "run", child)
    if fail:
        with pytest.raises(RuntimeError):
            module.mongodb_state(json.loads(payload(CFG, SECRETS)))
    else:
        assert module.mongodb_state(json.loads(payload(CFG, SECRETS))) == mongodb_state()
    assert len(homes) == 1
    assert not homes[0].exists()


def test_missing_ha_site_or_user_refuses_instead_of_creating() -> None:
    module = host_module()
    data = json.loads(payload(CFG, SECRETS))
    data.update(create_homeassistant_user=True, homeassistant_password="fixture")
    state = mongodb_state()
    state["site"] = False
    with pytest.raises(ValueError, match="ha_default_site_missing"):
        module.check_mongodb_state(state, data)
    state["site"] = True
    with pytest.raises(ValueError, match="ha_user_missing"):
        module.check_mongodb_state(state, data)


@pytest.mark.parametrize("active", [True, False])
def test_pending_unit_reload_is_recovered_before_restart_or_start(active: bool) -> None:
    run = run_deploy_fake(
        deploy_unifi,
        CFG,
        SECRETS,
        responses=converged(
            **{
                "Is a UniFi restart owed?": ["owed" if active else "inactive"],
                "show -p NeedDaemonReload --value unifi.service": ["yes"],
                **fakehost.service("unifi.service", running=active),
            }
        ),
    )
    assert run.succeeded, run.error
    commands = run.executed_commands
    action = f"systemctl {'restart' if active else 'start'} unifi.service"
    assert "systemctl daemon-reload" in commands
    assert commands.index("systemctl daemon-reload") < commands.index(action)


def test_runtime_parameters_do_not_assume_getcmdlineopts_boolean_types() -> None:
    module = host_module()
    state = mongodb_state()
    state["opts"]["setParameter"] = {
        "suppressNoTLSPeerCertificateWarning": "true",
        "diagnosticDataCollectionEnabled": "false",
    }
    state["parameters"] = {
        "suppressNoTLSPeerCertificateWarning": True,
        "diagnosticDataCollectionEnabled": False,
    }
    module.check_mongodb_state(state, json.loads(payload(CFG, SECRETS)))
    assert "getParameter:1" in module.javascript(json.loads(payload(CFG, SECRETS)))


@pytest.mark.skipif(not shutil.which("node"), reason="node unavailable for generated Mongo JavaScript fixture")
@pytest.mark.parametrize("representation", ["object", "string"])
def test_generated_mongo_probe_reads_both_privilege_id_representations(representation: str) -> None:
    module = host_module()
    setup = r"""
class Id { constructor(hex) { this.hex=hex; } toString() { return this.hex; } }
const fixtureHa={_id:new Id("012345678901234567890123"),x_shadow:"fixture"};
const fixtureSite={_id:new Id("abcdefabcdefabcdefabcdef")};
const kind=REPRESENTATION;
const docs=[{admin_id:kind==="string"?fixtureHa._id.toString():fixtureHa._id,
             site_id:kind==="string"?fixtureSite._id.toString():fixtureSite._id,role:"readonly",permissions:[]}];
function equal(a,b) { return typeof a===typeof b && (a instanceof Id ? b instanceof Id && a.hex===b.hex : a===b); }
function field(q,v) { return q && q.$in ? q.$in.some(x=>equal(x,v)) : equal(q,v); }
function match(q,d) { return field(q.admin_id,d.admin_id) && field(q.site_id,d.site_id); }
const collection={findOne:q=>docs.find(d=>match(q,d))||null,
                  find:q=>({toArray:()=>docs.filter(d=>match(q,d))})};
const admin={auth:()=>true,runCommand:()=>({ok:1,parsed:{},
  suppressNoTLSPeerCertificateWarning:true,diagnosticDataCollectionEnabled:false})};
const unifi={admin:{findOne:()=>fixtureHa},site:{findOne:()=>fixtureSite},privilege:collection};
const db={getSiblingDB:name=>name==="admin"?admin:unifi};
const config={get:key=>({disableLogging:true,enableTelemetry:false,updateURL:""})[key]};
function quit(code) { process.exit(code); }
function print(value) { console.log(value); }
""".replace("REPRESENTATION", json.dumps(representation))
    script = module.javascript(json.loads(payload(CFG, SECRETS)))
    result = subprocess.run(["node"], input=setup + script, text=True, capture_output=True, check=True, timeout=10)
    state = json.loads(result.stdout.removeprefix("OPS_UNIFI="))
    privileges = state.get("privileges", [state.get("privilege")])
    assert len(privileges) == 1
    assert privileges[0] is not None
    assert privileges[0]["role"] == "readonly"


def test_conflicting_or_missing_ha_privileges_refuse_before_store_access(monkeypatch: pytest.MonkeyPatch) -> None:
    module = host_module()
    monkeypatch.setattr(module, "matches_password", lambda password, hashed: True)
    state = mongodb_state()
    state["ha"] = {"x_shadow": "fixture"}
    data = json.loads(payload(CFG, SECRETS))
    data.update(create_homeassistant_user=True, homeassistant_password="fixture")
    for privileges in ([], [{"role": "readonly", "permissions": []}, {"role": "admin", "permissions": []}]):
        state["privileges"] = privileges
        with pytest.raises(ValueError, match="ha_privilege_drift"):
            module.check_mongodb_state(state, data)


def test_unknown_pending_reload_state_refuses_before_mutation() -> None:
    run = run_deploy_fake(
        deploy_unifi,
        CFG,
        SECRETS,
        responses=converged(**{"show -p NeedDaemonReload --value unifi.service": ["unexpected"]}),
    )
    assert not run.succeeded
    assert run.executed_commands == []
