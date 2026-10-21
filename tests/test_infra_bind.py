"""``deploy_bind`` against the fake connector, plus its config.

The host probe's answers are scripted; ``tests/test_infra_bind_host.py`` runs
the host script for real and ``tests/test_infra_bind_docker.py`` runs the
deploy against a real named.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.infra.bind import BindConfig, BindZone, TsigKey, deploy_bind
from ops_deploy.infra.bind.deploy import HOST_SCRIPT, candidates, check_secrets
from ops_deploy.infra.bind.render import render_keys
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import UBUNTU

P = "BIND authoritative | "
PROBE = "' probe )"
APPLY = "' apply"
SECRETS = {
    "xfer": SecretStr("Zml4dHVyZS14ZmVyLWtleS0wMQ=="),
    "acme": SecretStr("Zml4dHVyZS1hY21lLWtleS0wMg=="),
}
INSTALL = P + "Install the BIND configuration (validated, restored on failure)"
RELOAD = P + "Reload named"
DISTRIBUTION = 'printf "%s %s" "$ID"'


@pytest.fixture
def zones_dir(tmp_path: Path) -> Path:
    (tmp_path / "db.example.org").write_text("$TTL 300\n@ IN SOA ns1 h 2026102101 1 1 1 1\n@ IN NS ns1\n")
    (tmp_path / "db.home.example.org").write_text("$TTL 60\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\n")
    return tmp_path


def config(zones_dir: Path, **changes: Any) -> BindConfig:
    base: dict[str, Any] = {
        "zone_files_dir": str(zones_dir),
        "zones": [
            {"name": "example.org", "file": "db.example.org", "type": "master", "allow_transfer": ('key "xfer"',)},
            {
                "name": "home.example.org",
                "file": "db.home.example.org",
                "type": "master",
                "dynamic": True,
                "update_policy": ('grant "acme" name _acme-challenge.home.example.org. TXT',),
            },
        ],
        "tsig_keys": [{"name": "xfer"}, {"name": "acme"}],
    }
    return BindConfig.model_validate({**base, **changes})


def files_state(cfg: BindConfig, overrides: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Probe output for a converged host (every file the same), with per-path overrides."""

    states: dict[str, Any] = {}
    for item in candidates(
        cfg,
        "/etc/bind/named.conf.default-zones",
        SECRETS if cfg.tsig_keys else {},
        {zone.name: b"" for zone in cfg.zones},
    ):
        base = (
            {"state": "present", "attrs": True, "journal": False}
            if item.kind == "seed"
            else {"state": "same", "attrs": True, "journal": False}
        )
        states[item.path] = {**base, **(overrides or {}).get(item.path, {})}
    return states


def probe_output(
    cfg: BindConfig,
    overrides: dict[str, dict[str, Any]] | None = None,
    remove: dict[str, str] | None = None,
    ufw: str = "absent",
    leftovers: list[str] | None = None,
) -> str:
    return json.dumps(
        {
            "files": files_state(cfg, overrides),
            "remove": remove if remove is not None else ({} if cfg.tsig_keys else {cfg.keys_file: "missing"}),
            "leftovers": leftovers or [],
            "ufw": ufw,
        }
    )


def host(cfg: BindConfig, probe: str | None = None, installed: bool = True, **extra: Any) -> dict[str, Any]:
    packages = "\n".join(f"ii |{name}|" for name in cfg.packages) if installed else ""
    return {
        DISTRIBUTION: ["ubuntu 24.04"],
        PROBE: [probe if probe is not None else probe_output(cfg)],
        **extra,
        **UBUNTU,
        "dpkg-query -W": packages.splitlines(),
        f"stat -c %a {cfg.config_dir}": ["755"],
        f"stat -c %a {cfg.dynamic_zone_dir}": ["775"],
        f"stat -c %a {cfg.working_dir}": ["775"],
        **fakehost.stat(cfg.config_dir, group="bind", mode="drwxr-xr-x"),
        **fakehost.stat(cfg.dynamic_zone_dir, user="bind", group="bind", mode="drwxrwxr-x"),
        **fakehost.stat(cfg.working_dir, user="bind", group="bind", mode="drwxrwxr-x"),
        **fakehost.service("named.service"),
    }


def run(cfg: BindConfig, responses: dict[str, Any], secrets: dict[str, SecretStr] | None = None) -> FakeRun:
    result = run_deploy_fake(deploy_bind, cfg, SECRETS if secrets is None else secrets, responses=responses)
    assert result.succeeded, result.error
    return result


def failed(cfg: BindConfig, responses: dict[str, Any], secrets: dict[str, SecretStr] | None = None) -> FakeRun:
    result = run_deploy_fake(deploy_bind, cfg, SECRETS if secrets is None else secrets, responses=responses)
    assert not result.succeeded
    return result


def secret_values() -> list[str]:
    return [secret.get_secret_value() for secret in SECRETS.values()]


def request_of(result: FakeRun, marker: str) -> dict[str, Any]:
    [(_, stdin)] = [entry for entry in result.stdin if marker in entry[0]]
    request: dict[str, Any] = json.loads(stdin)
    return request


# -- converged, fresh and changed hosts ---------------------------------------------------


def test_converged_host_plans_only_read_only_checks(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg))

    assert result.mutating_changed_ops == []
    assert result.changed_ops == [
        P + "Verify authoritative answers for example.org",
        P + "Verify authoritative answers for home.example.org",
    ]
    assert not any(APPLY in command for command in result.executed_commands)
    assert not any("systemctl reload" in command for command in result.executed_commands)
    # The probe got the key file on stdin; nothing else carries a secret.
    assert len(result.stdin) == 1
    for value in secret_values():
        assert value not in result.all_text()


def test_fresh_host_installs_packages_then_the_validated_configuration(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    missing = {path: {"state": "missing", "attrs": False} for path in files_state(cfg)}

    responses = host(cfg, probe_output(cfg, missing), installed=False)
    responses.update(fakehost.service("named.service", running=False, enabled=False))

    result = run(cfg, responses)

    assert result.mutating_changed_ops == [
        P + "Install BIND packages",
        INSTALL,
        P + "Ensure named is enabled and running",
        RELOAD,
    ]
    commands = result.executed_commands
    assert any("bind9 bind9-utils dnsutils" in command for command in commands)
    assert commands.index(next(c for c in commands if APPLY in c)) < commands.index("systemctl reload named")
    request = request_of(result, APPLY)
    assert [(item["path"], item["kind"]) for item in request["files"]] == [
        ("/etc/bind/named.conf.keys", "keys"),
        ("/etc/bind/named.conf.options", "config"),
        ("/etc/bind/named.conf.local", "config"),
        ("/etc/bind/db.example.org", "zone"),
        ("/var/lib/bind/db.home.example.org", "seed"),
        ("/etc/bind/named.conf", "config"),
    ]
    keys = base64.b64decode(request["files"][0]["data"])
    assert keys == render_keys(cfg, SECRETS).reveal()
    assert (request["files"][0]["user"], request["files"][0]["group"], request["files"][0]["mode"]) == (
        "root",
        "bind",
        "0640",
    )
    assert (request["files"][4]["user"], request["files"][4]["mode"]) == ("bind", "0644")
    assert request["remove"] == []
    assert request["named_conf"] == "/etc/bind/named.conf"
    # Key material only ever on stdin (probe and apply).
    assert len(result.stdin) == 2
    for value in secret_values():
        assert value not in result.all_text()


def test_a_rotated_key_reinstalls_and_reloads(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg, probe_output(cfg, {"/etc/bind/named.conf.keys": {"state": "differs"}})))

    assert result.mutating_changed_ops == [INSTALL, RELOAD]


def test_wrong_owner_or_mode_alone_reinstalls(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg, probe_output(cfg, {"/etc/bind/named.conf.options": {"attrs": False}})))

    assert result.mutating_changed_ops == [INSTALL, RELOAD]


def test_an_existing_dynamic_zone_is_never_planned(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    # Whatever named made of the file and its journal, the seed is not compared or written.
    (zones_dir / "db.home.example.org").write_text("changed seed\n")
    state = {"/var/lib/bind/db.home.example.org": {"state": "present", "journal": True}}

    result = run(cfg, host(cfg, probe_output(cfg, state)))

    assert result.mutating_changed_ops == []


def test_a_missing_dynamic_zone_with_a_journal_is_refused_before_any_change(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    state = {"/var/lib/bind/db.home.example.org": {"state": "missing", "journal": True}}

    result = failed(cfg, host(cfg, probe_output(cfg, state), installed=False))

    assert "refusing to seed the dynamic zone" in str(result.error)
    assert result.executed_commands == []


def test_a_changed_static_zone_with_a_journal_is_refused(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    state = {"/etc/bind/db.example.org": {"state": "differs", "journal": True}}

    result = failed(cfg, host(cfg, probe_output(cfg, state)))

    assert "refusing to replace a zone file that has a journal" in str(result.error)
    assert result.executed_commands == []


def test_an_unchanged_static_zone_may_have_a_journal(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    state = {"/etc/bind/db.example.org": {"journal": True}}

    assert run(cfg, host(cfg, probe_output(cfg, state))).mutating_changed_ops == []


@pytest.mark.parametrize("path", ["/etc/bind/named.conf", "/etc/bind/db.example.org", "/etc/bind/named.conf.keys"])
def test_a_managed_path_that_is_not_a_regular_file_is_refused(zones_dir: Path, path: str) -> None:
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg, probe_output(cfg, {path: {"state": "other", "attrs": False}})))

    assert f"{path} is not a regular file" in str(result.error)
    assert result.executed_commands == []


def test_without_keys_the_keys_file_is_removed_and_not_included(zones_dir: Path) -> None:
    cfg = config(zones_dir, tsig_keys=[], zones=[{"name": "example.org", "file": "db.example.org"}])

    converged = run(cfg, host(cfg), secrets={})
    assert converged.mutating_changed_ops == []

    result = run(cfg, host(cfg, probe_output(cfg, remove={cfg.keys_file: "file"})), secrets={})

    assert result.mutating_changed_ops == [INSTALL, RELOAD]
    request = request_of(result, APPLY)
    assert request["remove"] == ["/etc/bind/named.conf.keys"]
    assert "named.conf.keys" not in "".join(base64.b64decode(item["data"]).decode() for item in request["files"])


def test_a_secondary_ensures_its_working_dir_and_installs_no_zone_file(zones_dir: Path) -> None:
    cfg = config(
        zones_dir,
        recursion=False,
        tsig_keys=[{"name": "xfer"}],
        zones=[{"name": "example.org", "file": "db.example.org", "type": "secondary", "primaries": ("192.0.2.1",)}],
    )
    responses = host(cfg)
    responses[f"stat -c %a {cfg.working_dir}"] = ["2775"]

    result = run(cfg, responses, secrets={"xfer": SECRETS["xfer"]})

    assert result.mutating_changed_ops == [
        P + "Clear special mode bits on /var/cache/bind",
    ]
    files = candidates(cfg, "/etc/bind/named.conf.default-zones", {"xfer": SECRETS["xfer"]}, {})
    assert [item.kind for item in files] == ["keys", "config", "config", "config"]


def test_the_disabled_role_is_a_no_op(zones_dir: Path) -> None:
    cfg = config(zones_dir, enabled=False)

    result = run(cfg, {})

    assert result.ops == []
    assert result.events == []


def test_a_failed_probe_stops_the_deploy(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg, probe="partial\n\nops-deploy-probe-failed"))

    assert "probe failed; nothing was changed" in str(result.error)
    assert result.executed_commands == []


def test_verify_asks_for_an_authoritative_answer_per_zone(zones_dir: Path) -> None:
    cfg = config(
        zones_dir,
        verify_retries=3,
        verify_delay=2,
        zones=[
            {"name": "example.org", "file": "db.example.org"},
            {"name": ".", "file": "db.root", "type": "hint"},
            {"name": "sec.example.org", "file": "db.sec", "type": "slave", "primaries": "192.0.2.1"},
        ],
        tsig_keys=[],
    )
    (zones_dir / "db.root").write_text(". 1 IN NS a.\n")

    result = run(cfg, host(cfg), secrets={})

    verify = [c for c in result.executed_commands if "dig " in c]
    assert len(verify) == 2
    assert "dig @127.0.0.1 example.org SOA +comments +norecurse" in verify[0]
    assert "dig @127.0.0.1 sec.example.org SOA +comments +norecurse" in verify[1]
    assert "grep -q 'status: NOERROR'" in verify[0]
    assert "grep -Eq 'flags:[^;]* aa[ ;]'" in verify[0]
    assert "-lt 3" in verify[0]
    assert "sleep 2" in verify[0]


def test_verify_can_be_turned_off(zones_dir: Path) -> None:
    cfg = config(zones_dir, verify_enabled=False)

    assert run(cfg, host(cfg)).changed_ops == []


def test_ufw_warnings(zones_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    cfg = config(zones_dir)
    run(cfg, host(cfg, probe_output(cfg, ufw="active-no-53")))
    assert "UFW is active but no explicit TCP/UDP 53 rule was found" in caplog.text
    caplog.clear()
    run(cfg, host(cfg, probe_output(cfg, ufw="inactive")))
    assert "UFW is inactive" in caplog.text
    caplog.clear()
    run(cfg, host(cfg, probe_output(cfg, ufw="active")))
    assert "UFW" not in caplog.text


def test_debian_13_includes_the_root_hints(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    named_conf = {"/etc/bind/named.conf": {"state": "differs"}}
    responses = host(cfg, probe_output(cfg, named_conf))
    responses[DISTRIBUTION] = ["debian 13"]

    result = run(cfg, responses)

    request = request_of(result, APPLY)
    text = base64.b64decode(request["files"][-1]["data"]).decode()
    assert text.endswith('include "/etc/bind/named.conf.root-hints";\n')


def test_the_script_is_fish_safe() -> None:
    assert "\\\\" not in HOST_SCRIPT
    assert "\\'" not in HOST_SCRIPT


# -- secrets and controller files ---------------------------------------------------------


@pytest.mark.parametrize(
    ("secrets", "message"),
    [
        ({"xfer": SECRETS["xfer"]}, "missing: ['acme']"),
        ({**SECRETS, "other": SecretStr("b3RoZXI=")}, "unexpected: ['other']"),
        ({**SECRETS, "acme": SecretStr("CHANGEME")}, "TSIG key acme"),
        ({**SECRETS, "acme": SecretStr("")}, "TSIG key acme"),
        ({**SECRETS, "acme": SecretStr('abc"; } ; key "x')}, "TSIG key acme"),
        ({**SECRETS, "acme": SecretStr("abc")}, "TSIG key acme"),
    ],
    ids=["missing", "extra", "placeholder", "empty", "injection", "padding"],
)
def test_secrets_are_checked_without_printing_them(
    zones_dir: Path, secrets: dict[str, SecretStr], message: str
) -> None:
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg), secrets=secrets)

    assert message in str(result.error)
    for secret in secrets.values():
        if secret.get_secret_value():
            assert secret.get_secret_value() not in str(result.error)
    assert result.executed_commands == []


def test_check_secrets_accepts_exactly_the_keys(zones_dir: Path) -> None:
    assert check_secrets(config(zones_dir), SECRETS) == SECRETS
    assert check_secrets(config(zones_dir, tsig_keys=[]), None) == {}


def test_missing_zone_files_are_named(zones_dir: Path) -> None:
    (zones_dir / "db.example.org").unlink()
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg))

    assert "Missing zone files: db.example.org" in str(result.error)


def test_a_missing_zone_directory_is_refused(tmp_path: Path) -> None:
    cfg = config(tmp_path / "nowhere")

    result = failed(cfg, host(cfg))

    assert "bind_zone_files_dir not found" in str(result.error)


# -- config validation (the role's validate.yml, and what is stricter) ----------------------


def test_defaults_are_the_roles(zones_dir: Path) -> None:
    cfg = BindConfig(zone_files_dir=str(zones_dir), zones=[BindZone(name="example.org", file="db.example.org")])

    assert cfg.packages == ("bind9", "bind9-utils", "dnsutils")
    assert cfg.keys_file == "/etc/bind/named.conf.keys"
    assert cfg.query_cache_acl == ("localhost", "localnets")
    assert cfg.zone_path(cfg.zones[0]) == "/etc/bind/db.example.org"
    assert TsigKey(name="k").algorithm == "hmac-sha256"


@pytest.mark.parametrize(
    ("zones", "message"),
    [
        ([], "at least 1"),
        ([{"name": "a.org", "file": "db.a", "type": "secondary"}], "non-empty primaries"),
        ([{"name": "a.org", "file": "db.a", "type": "slave", "primaries": ()}], "non-empty primaries"),
        ([{"name": "a.org", "file": "db.a", "dynamic": True}], "non-empty update_policy"),
        (
            [
                {
                    "name": "a.org",
                    "file": "db.a",
                    "dynamic": True,
                    "type": "hint",
                    "update_policy": "grant x zonesub ANY",
                }
            ],
            "must be type master/primary",
        ),
        ([{"name": "a.org", "file": "../db.a"}], "one file name"),
        ([{"name": "a.org", "file": "/etc/bind/db.a"}], "only supported for transfer-backed"),
        ([{"name": "a.org", "file": "db.a"}, {"name": "a.org", "file": "db.b"}], "each zone name may appear once"),
        ([{"name": 'a"org', "file": "db.a"}], "not a zone name"),
        ([{"name": "a.org", "file": "db.a", "extra_config": ("x;\ny;",)}], "control characters"),
        ([{"name": "a.org", "file": "db.a", "type": "bogus"}], "Input should be"),
        (
            [
                {"name": "a.org", "file": "db.a", "dynamic": True, "update_policy": "grant k zonesub ANY"},
                {"name": "b.org", "file": "db.a", "dynamic": True, "update_policy": "grant k zonesub ANY"},
            ],
            "shares its file",
        ),
    ],
)
def test_invalid_zones_are_refused(zones_dir: Path, zones: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        config(zones_dir, zones=zones)


def test_static_zones_may_share_a_file(zones_dir: Path) -> None:
    cfg = config(
        zones_dir,
        tsig_keys=[],
        zones=[{"name": "a.org", "file": "db.example.org"}, {"name": "b.org", "file": "db.example.org"}],
    )

    files = candidates(cfg, "/x", {}, {"a.org": b"a", "b.org": b"a"})
    assert [item.path for item in files if item.kind == "zone"] == ["/etc/bind/db.example.org"]


def test_other_settings_are_validated(zones_dir: Path) -> None:
    with pytest.raises(ValidationError, match="at least one ACL entry"):
        config(zones_dir, allow_transfer=())
    with pytest.raises(ValidationError, match="each key name may appear once"):
        config(zones_dir, tsig_keys=[{"name": "k"}, {"name": "k"}])
    with pytest.raises(ValidationError, match="not a TSIG key name"):
        config(zones_dir, tsig_keys=[{"name": 'k" ; x'}])
    with pytest.raises(ValidationError, match="Input should be"):
        config(zones_dir, tsig_keys=[{"name": "k", "algorithm": "sha1"}])
    with pytest.raises(ValidationError, match="control characters"):
        config(zones_dir, extra_options=("a;\nb;",))
    with pytest.raises(ValidationError):
        config(zones_dir, secret="x")


def test_leftover_backups_refuse_before_any_change(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg, probe_output(cfg, leftovers=["/etc/bind/.ops-deploy-bind.0123"])))

    assert "/etc/bind/.ops-deploy-bind.0123 holds backups of an interrupted or unrestored run" in str(result.error)
    assert result.executed_commands == []
