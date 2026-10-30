"""os_lifecycle: config validation, the Nyxmon rules, and the deploys' plans on the fake connector."""

from __future__ import annotations

import base64
import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED, probe_command, probe_output
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services import _metrics_httpd as metrics_httpd
from ops_deploy.services.os_lifecycle import (
    PASSWORD_KEY,
    PRIVATE_KEY_KEY,
    OsLifecycleChecksConfig,
    OsLifecycleConfig,
    Thresholds,
    deploy_os_lifecycle,
    deploy_os_lifecycle_checks,
    endpoint_rules,
    lifecycle_check,
    remote_rules,
    report_rules,
)
from ops_deploy.services.os_lifecycle import deploy as oslc
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.metrics_httpd_fixtures import verify_op, without_switch

PASSWORD = "fixture-endpoint-password"
PRIVATE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
)
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: PASSWORD, PRIVATE_KEY_KEY: PRIVATE_KEY})
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureFixtureFixtureFixtureFixtureFixture0"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostHostHostHostHostHostHostHostHostHostHost0"
TAILSCALE_IP = "100.64.0.7"
SNAPSHOT: dict[str, Any] = {
    "fetched_at": "2026-10-22",
    "debian": [
        {"cycle": "13", "codename": "Trixie", "releaseDate": "2025-08-09", "support": "2028-08-09", "eol": "2030-06-30"}
    ],
    "ubuntu": [
        {"cycle": "24.04", "releaseDate": "2024-04-25", "support": "2029-05-31", "eol": "2029-05-31", "lts": True}
    ],
}
REMOTE: dict[str, Any] = {
    "hosts": [{"name": "marina", "address": "host.example.invalid", "host_keys": [HOST_KEY]}],
}


def endpoint_cfg(**changes: Any) -> OsLifecycleConfig:
    fields: dict[str, Any] = {
        "secrets": "secrets/fixture.yml",
        "host_label": "example",
        "exposure": "endpoint",
        "reboot_class": "B",
        "auth_user": "nyxmon",
        "endoflife": SNAPSHOT,
    }
    return OsLifecycleConfig.model_validate({**fields, **changes})


def ssh_cfg(**changes: Any) -> OsLifecycleConfig:
    fields: dict[str, Any] = {
        "host_label": "marina",
        "exposure": "ssh",
        "reboot_class": "C",
        "user": "os-lifecycle",
        "endoflife": SNAPSHOT,
        "ssh": {"public_key": PUBLIC_KEY},
    }
    return OsLifecycleConfig.model_validate({**fields, **changes})


# -- config ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("build", "changes", "message"),
    [
        (endpoint_cfg, {"auth_user": None}, "auth_user"),
        (endpoint_cfg, {"secrets": None}, "secrets"),
        (endpoint_cfg, {"ssh": {"public_key": PUBLIC_KEY}}, "only for exposure ssh"),
        (endpoint_cfg, {"remote": {**REMOTE, "port": 9113}}, "remote.port"),
        (endpoint_cfg, {"host_label": "Bad-Name"}, "host_label"),
        (endpoint_cfg, {"reboot_class": "D"}, "reboot_class"),
        (endpoint_cfg, {"port": 0}, "port"),
        (endpoint_cfg, {"path": "x"}, "path"),
        (endpoint_cfg, {"endoflife": {**SNAPSHOT, "fetched_at": "22.10.2026"}}, "fetched_at"),
        (endpoint_cfg, {"endoflife": {**SNAPSHOT, "debian": [{"cycle": "13", "releaseDate": "x"}]}}, "releaseDate"),
        (endpoint_cfg, {"endoflife": {**SNAPSHOT, "debian": [{**SNAPSHOT["debian"][0], "link": "x"}]}}, "link"),
        (endpoint_cfg, {"remote": {"hosts": []}}, "hosts"),
        (endpoint_cfg, {"remote": {"hosts": [{**REMOTE["hosts"][0], "host_keys": []}]}}, "host_keys"),
        (endpoint_cfg, {"remote": {"hosts": [{**REMOTE["hosts"][0], "host_keys": ["ssh-ed25519 a b"]}]}}, "SSH public"),
        (endpoint_cfg, {"remote": {"hosts": [{**REMOTE["hosts"][0], "address": "-oProxyCommand=x"}]}}, "address"),
        (endpoint_cfg, {"remote": {"hosts": [REMOTE["hosts"][0], REMOTE["hosts"][0]]}}, "unique"),
        # Unit names and the configuration directory are fixed (a later deploy must find them).
        (endpoint_cfg, {"service_name": "custom-endpoint"}, "service_name"),
        (endpoint_cfg, {"timer_name": "custom-collector"}, "timer_name"),
        (endpoint_cfg, {"config_dir": "/etc/other"}, "config_dir"),
        (endpoint_cfg, {"remote": {**REMOTE, "service_name": "custom-os-remote"}}, "service_name"),
        (endpoint_cfg, {"remote": {**REMOTE, "timer_name": "custom-pull"}}, "timer_name"),
        (ssh_cfg, {"ssh": None}, "needs ssh"),
        (ssh_cfg, {"remote": REMOTE}, "drop remote"),
        (ssh_cfg, {"auth_user": "nyxmon"}, "drop remote and auth_user"),
        (ssh_cfg, {"user": "root"}, "root"),
        (ssh_cfg, {"ssh": {"public_key": f'command="x" {PUBLIC_KEY}'}}, "SSH public"),
        (ssh_cfg, {"ssh": {"public_key": f"{PUBLIC_KEY} comment"}}, "SSH public"),
        (ssh_cfg, {"ssh": {"public_key": PUBLIC_KEY, "from_sources": ['1.2.3.4",command="x']}}, "from_sources"),
        (ssh_cfg, {"ssh": {"public_key": PUBLIC_KEY, "key_comment": "a b"}}, "key_comment"),
    ],
)
def test_bad_configs_are_refused(build: Any, changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        build(**changes)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"uptime_warning_days": 300}, "uptime"),
        ({"reboot_warning_hours": 504}, "reboot"),
        ({"eol_critical_days": 200}, "eol"),
        ({"report_max_age_seconds": 0}, "report_max_age_seconds"),
    ],
)
def test_bad_thresholds_are_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Thresholds.model_validate(changes)


# -- rules -----------------------------------------------------------------------------------------


def paths(rules: list[dict[str, Any]]) -> list[tuple[str, str, Any, str]]:
    return [(r["path"], r["op"], r["value"], r["severity"]) for r in rules]


def test_endpoint_rules_have_the_design_defaults() -> None:
    assert paths(endpoint_rules(Thresholds())) == [
        ("$.meta.age_seconds", "<", 7200, "critical"),
        ("$.uu.enabled", "==", True, "critical"),
        ("$.uu.last_success_age_hours", "<=", 48, "warning"),
        ("$.uu.last_success_age_hours", "<=", 168, "critical"),
        ("$.apt.security_index_age_hours", "<=", 48, "warning"),
        ("$.apt.security_index_age_hours", "<=", 168, "critical"),
        ("$.apt.pending_security_max_age_hours", "<=", 72, "warning"),
        ("$.apt.pending_security_max_age_hours", "<=", 168, "critical"),
        ("$.reboot.required_age_hours", "<=", 168, "warning"),
        ("$.reboot.required_age_hours", "<=", 504, "critical"),
        ("$.reboot.uptime_days", "<=", 120, "warning"),
        ("$.reboot.uptime_days", "<=", 240, "critical"),
        ("$.os.upgrade_due", "==", False, "warning"),
        ("$.os.support_days_remaining", ">=", 365, "warning"),
        ("$.os.eol_days_remaining", ">=", 180, "warning"),
        ("$.os.eol_days_remaining", ">=", 60, "critical"),
        ("$.os.lifecycle_sources_agree", "==", True, "warning"),
        ("$.os.lifecycle_data_age_days", "<=", 120, "warning"),
    ]


def test_partial_rules_leave_out_uu_and_the_index_age() -> None:
    rules = paths(endpoint_rules(Thresholds(), unattended_upgrades=False, security_index=False))

    assert not [r for r in rules if r[0].startswith(("$.uu.", "$.apt.security_index"))]
    assert ("$.apt.pending_security_max_age_hours", "<=", 72, "warning") in rules


def test_remote_rules_watch_the_pull_and_the_window_thresholds() -> None:
    rules = paths(remote_rules(Thresholds(), "marina", reboot_window=True))

    assert rules[:4] == [
        ("$.meta.age_seconds", "<", 7200, "critical"),
        ("$.hosts.marina.pull_ok", "==", True, "warning"),
        ("$.hosts.marina.last_pull_success_age_hours", "<=", 3, "critical"),
        ("$.hosts.marina.report_age_hours", "<=", 3, "critical"),
    ]
    assert ("$.hosts.marina.report.reboot.required_age_hours", "<=", 192, "warning") in rules
    assert ("$.hosts.marina.report.reboot.required_age_hours", "<=", 360, "critical") in rules
    assert all(r[0].startswith(("$.meta.", "$.hosts.marina.")) for r in rules)


def failing(rules: list[dict[str, Any]], report: dict[str, Any]) -> list[tuple[str, str]]:
    """The rules a report fails, as Nyxmon's json-metrics evaluates them (a missing or null value fails)."""

    compare = {
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }
    failed = []
    for rule in rules:
        value: Any = report
        for part in rule["path"].removeprefix("$.").split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value is None or not compare[rule["op"]](value, rule["value"]):
            failed.append((rule["path"], rule["severity"]))
    return failed


def test_track_latest_stable_replaces_the_support_rules() -> None:
    default = paths(report_rules(Thresholds()))
    tracked = paths(report_rules(Thresholds(), track_latest_stable=True))

    assert ("$.os.releases_behind", "<=", 0, "warning") in tracked
    assert ("$.os.releases_behind", "<=", 0, "warning") not in default
    for rule in [("$.os.upgrade_due", "==", False, "warning"), ("$.os.support_days_remaining", ">=", 365, "warning")]:
        assert rule in default
        assert rule not in tracked
    # The hard EOL deadlines stay for both.
    for rule in [("$.os.eol_days_remaining", ">=", 180, "warning"), ("$.os.eol_days_remaining", ">=", 60, "critical")]:
        assert rule in default
        assert rule in tracked
    remote = paths(remote_rules(Thresholds(), "heis", track_latest_stable=True))
    assert ("$.hosts.heis.report.os.releases_behind", "<=", 0, "warning") in remote


def os_section(**values: Any) -> dict[str, Any]:
    return {
        "os": {
            "releases_behind": 0,
            "upgrade_due": False,
            "support_days_remaining": 640,
            "eol_days_remaining": 1340,
            "lifecycle_sources_agree": True,
            "lifecycle_data_age_days": 10,
            **values,
        }
    }


@pytest.mark.parametrize(
    ("values", "tracked", "default"),
    [
        # The day before Debian 14: current stable, nothing fails.
        ({}, [], []),
        # Its release day: Debian 13 still has 423 days of regular support.
        ({"releases_behind": 1, "support_days_remaining": 423}, [("$.os.releases_behind", "warning")], []),
        # A year later the EOL view warns too; the tracked host warned since the release day.
        (
            {"releases_behind": 1, "support_days_remaining": 58},
            [("$.os.releases_behind", "warning")],
            [("$.os.support_days_remaining", "warning")],
        ),
        # Unknown is not green.
        ({"releases_behind": None}, [("$.os.releases_behind", "warning")], []),
    ],
)
def test_the_latest_stable_rule_on_reports(
    values: dict[str, Any], tracked: list[tuple[str, str]], default: list[tuple[str, str]]
) -> None:
    report = os_section(**values)
    os_rules = [r for r in report_rules(Thresholds()) if r["path"].startswith("$.os.")]
    tracked_rules = [r for r in report_rules(Thresholds(), track_latest_stable=True) if r["path"].startswith("$.os.")]

    assert failing(tracked_rules, report) == tracked
    assert failing(os_rules, report) == default


def test_third_party_updates_warn_after_30_days_only_when_watched() -> None:
    rule = ("$.apt.pending_third_party_max_age_hours", "<=", 720, "warning")

    assert rule not in paths(report_rules(Thresholds()))
    rules = report_rules(Thresholds(), third_party_updates=True)
    assert rule in paths(rules)
    third = [r for r in rules if "third_party" in r["path"]]
    assert failing(third, {"apt": {"pending_third_party_max_age_hours": 0}}) == []
    assert failing(third, {"apt": {"pending_third_party_max_age_hours": 720.0}}) == []
    assert failing(third, {"apt": {"pending_third_party_max_age_hours": 720.5}}) == [
        ("$.apt.pending_third_party_max_age_hours", "warning")
    ]
    assert failing(third, {"apt": None}) == [("$.apt.pending_third_party_max_age_hours", "warning")]
    remote = paths(remote_rules(Thresholds(), "marina", third_party_updates=True))
    assert ("$.hosts.marina.report.apt.pending_third_party_max_age_hours", "<=", 720, "warning") in remote


def test_a_check_keeps_its_json_types() -> None:
    check = lifecycle_check(
        service_name="OS lifecycle",
        name="OS Lifecycle (example)",
        url="http://host.example.invalid:9113/.well-known/os-lifecycle",
        rules=endpoint_rules(Thresholds()),
        auth_username="nyxmon",
    )

    stored = json.dumps(check.desired_data(PASSWORD), sort_keys=True)
    assert '"timeout": 15.0' in stored
    assert '"value": true' in stored
    assert check.check_interval == 1800


# -- rendered files -----------------------------------------------------------------------------


def test_the_policy_carries_the_snapshot_and_the_group() -> None:
    policy = json.loads(oslc.render_policy(ssh_cfg()))

    assert policy["host"] == "marina"
    assert policy["state_group"] == "os-lifecycle"
    assert policy["reboot_class"] == "C"
    assert policy["endoflife"]["debian"][0]["support"] == "2028-08-09"


def test_the_collector_key_can_only_show_the_report() -> None:
    lines = oslc.render_authorized_keys(ssh_cfg()).splitlines()

    assert lines[0].startswith("#")
    assert lines[1] == (
        'restrict,command="/usr/bin/python3 -I /usr/local/lib/os-lifecycle/os_lifecycle_status.py show '
        f'--state-dir /var/lib/os-lifecycle" {PUBLIC_KEY} os-lifecycle-collector'
    )
    sourced = oslc.render_authorized_keys(ssh_cfg(ssh={"public_key": PUBLIC_KEY, "from_sources": ["192.0.2.0/24"]}))
    assert sourced.splitlines()[1].startswith('from="192.0.2.0/24",restrict,command="')


def test_the_pull_trusts_only_the_pinned_host_keys() -> None:
    cfg = endpoint_cfg(remote=REMOTE)

    assert oslc.render_known_hosts(cfg) == f"os-lifecycle-marina {HOST_KEY}\n"
    config = json.loads(oslc.render_pull_config(cfg))
    host = {"name": "marina", "address": "host.example.invalid", "port": 22, "user": "os-lifecycle"}
    assert config["hosts"] == [host]
    assert config["identity_file"] == "/etc/os-lifecycle/collector_ed25519"


def test_the_endpoint_argv_is_a_valid_metrics_httpd_command_line() -> None:
    cfg = endpoint_cfg(remote=REMOTE)

    for remote in (False, True):
        assert metrics_httpd.problems(oslc.httpd_endpoint(cfg, TAILSCALE_IP, remote=remote)) == []
    unit = oslc.render_endpoint_unit(cfg, TAILSCALE_IP, remote=True)
    assert "--port 9114 --path /.well-known/os-lifecycle-remote --json-path /var/lib/os-lifecycle/remote.json" in unit
    assert "IPAddressDeny=any\nIPAddressAllow=localhost\nIPAddressAllow=100.64.0.0/10\n" in unit


def test_the_collector_runs_sandboxed_and_writes_only_its_state() -> None:
    unit = oslc.render_collector_service(endpoint_cfg())

    assert "ProtectSystem=strict\nReadWritePaths=/var/lib/os-lifecycle\n" in unit
    assert "ExecStart=/usr/bin/python3 -I /usr/local/lib/os-lifecycle/os_lifecycle_status.py collect " in unit


# -- plans ----------------------------------------------------------------------------------------

P = "OS lifecycle | "
UNITS = "/etc/systemd/system"
SCRIPTS = "/usr/local/lib/os-lifecycle"
HTPASSWD = "/etc/os-lifecycle/htpasswd"
STATE_PROBE = "if test -e /var/lib/os-lifecycle/state.json"
REMOTE_PROBE = "if test -e /var/lib/os-lifecycle/remote.json"
HASH = hash_password(PASSWORD)
COLLECTOR_TIMER = "Write the OS lifecycle report hourly"
PULL_TIMER = "Pull the OS lifecycle reports of remote hosts"
REMOTE_UNIT = "os-lifecycle-remote-endpoint.service"
TRACES = "systemctl show --property=LoadState --value"
SSH_TRACES = (oslc.ENDPOINT_UNITS, (oslc.HTPASSWD_PATH, oslc.IDENTITY_PATH))
REMOTE_TRACES = (oslc.REMOTE_UNITS, (oslc.IDENTITY_PATH,))


def traces(units: Sequence[str], paths: Sequence[PurePosixPath], found: dict[str, str] | None = None) -> dict[str, Any]:
    """The leftover probe's answer: nothing left (not-found, inactive, no file) except ``found``."""

    states = found or {}
    lines = [f"unit {unit} {states.get(unit, 'not-found inactive absent')}" for unit in units]
    lines += [f"file {path} {states.get(str(path), 'absent')}" for path in paths]
    return {TRACES: lines}


def converged_endpoint(cfg: OsLifecycleConfig) -> dict[str, Any]:
    scripts = {
        "os_lifecycle_status.py": oslc.STATUS_SCRIPT,
        "os_lifecycle_httpd.py": oslc.HTTPD_SCRIPT,
        "os_lifecycle_pull.py": oslc.PULL_SCRIPT,
    }
    responses: dict[str, Any] = {
        **traces(*REMOTE_TRACES),
        **fakehost.UBUNTU,
        "tailscale ip --4": [TAILSCALE_IP],
        STATE_PROBE: ["present"],
        REMOTE_PROBE: ["present"],
        **fakehost.deb_installed("python3", "distro-info-data", "apache2-utils"),
        **fakehost.accounts({"metrics": "/home/metrics"}),
        **fakehost.stat("/etc/os-lifecycle", group="metrics", mode="drwxr-x---"),
        **fakehost.stat("/var/lib/os-lifecycle", group="metrics", mode="drwxr-x---"),
        **fakehost.directory(SCRIPTS),
        **fakehost.directory(UNITS),
        **{k: v for name, text in scripts.items() for k, v in fakehost.file(f"{SCRIPTS}/{name}", text).items()},
        **fakehost.file("/etc/os-lifecycle/policy.json", oslc.render_policy(cfg)),
        **fakehost.file(HTPASSWD, f"nyxmon:{HASH}\n"),
        **fakehost.stat(HTPASSWD, group="metrics", mode="-rw-r-----"),
        **fakehost.file(f"{UNITS}/os-lifecycle-collector.service", oslc.render_collector_service(cfg)),
        **fakehost.file(f"{UNITS}/os-lifecycle-collector.timer", oslc.render_timer(COLLECTOR_TIMER)),
        **fakehost.file(f"{UNITS}/os-lifecycle-endpoint.service", oslc.render_endpoint_unit(cfg, TAILSCALE_IP)),
        **fakehost.service("os-lifecycle-collector.timer"),
        **fakehost.service("os-lifecycle-endpoint.service"),
    }
    if cfg.remote is not None:
        responses.update(
            {
                **fakehost.file("/etc/os-lifecycle/remote-hosts.json", oslc.render_pull_config(cfg)),
                **fakehost.file("/etc/os-lifecycle/known_hosts", oslc.render_known_hosts(cfg)),
                **fakehost.file("/etc/os-lifecycle/collector_ed25519", PRIVATE_KEY, mode="-rw-------"),
                **fakehost.file(f"{UNITS}/os-lifecycle-pull.service", oslc.render_pull_service(cfg)),
                **fakehost.file(f"{UNITS}/os-lifecycle-pull.timer", oslc.render_timer(PULL_TIMER)),
                **fakehost.file(f"{UNITS}/{REMOTE_UNIT}", oslc.render_endpoint_unit(cfg, TAILSCALE_IP, remote=True)),
                **fakehost.service("os-lifecycle-pull.timer"),
                **fakehost.service(REMOTE_UNIT),
            }
        )
    return responses


def run(responses: dict[str, Any], cfg: OsLifecycleConfig, secrets: SecretValues | None = SECRETS) -> FakeRun:
    result = run_deploy_fake(deploy_os_lifecycle, cfg, secrets, responses=responses)
    assert result.succeeded, result.error
    return result


def test_a_converged_endpoint_host_plans_only_read_only_checks() -> None:
    cfg = endpoint_cfg(remote=REMOTE)

    result = run(converged_endpoint(cfg), cfg)

    assert result.mutating_changed_ops == []
    assert [op.name for op in result.ops if op.changed] == [
        verify_op(P, "os-lifecycle-endpoint"),
        verify_op(P, "os-lifecycle-remote-endpoint"),
    ]
    assert without_switch(result.stdin) == []
    assert not any("systemctl start" in c or "restart" in c for c in result.executed_commands)


def test_a_fresh_endpoint_host_installs_everything_once() -> None:
    cfg = endpoint_cfg()

    result = run({**traces(*REMOTE_TRACES), **fakehost.UBUNTU, "tailscale ip --4": [TAILSCALE_IP]}, cfg)

    assert result.mutating_changed_ops == [
        f"{P}Install the OS lifecycle packages",
        f"{P}Ensure group metrics",
        f"{P}Ensure user metrics",
        f"{P}Ensure /etc/os-lifecycle",
        f"{P}Ensure /var/lib/os-lifecycle",
        f"{P}Ensure {SCRIPTS}",
        f"{P}Install {SCRIPTS}/os_lifecycle_status.py",
        f"{P}Write /etc/os-lifecycle/policy.json",
        f"{P}Install systemd unit os-lifecycle-collector.service",
        f"{P}Install systemd unit os-lifecycle-collector.timer",
        f"{P}Reload systemd for the OS lifecycle collector",
        f"{P}Run os-lifecycle-collector.service once",
        f"{P}Enable os-lifecycle-collector.timer",
        f"{P}Start os-lifecycle-collector.timer",
        f"{P}Install {SCRIPTS}/os_lifecycle_httpd.py",
        f"{P}Write {HTPASSWD}",
        f"{P}Install systemd unit os-lifecycle-endpoint.service",
        f"{P}Reload systemd for os-lifecycle-endpoint",
        f"{P}Enable os-lifecycle-endpoint.service",
        f"{P}Start os-lifecycle-endpoint.service",
    ]
    commands = result.executed_commands
    assert any("apt-get" in c and "apache2-utils" in c and "distro-info-data" in c for c in commands)
    assert any("useradd" in c and "-s /usr/sbin/nologin" in c for c in commands)
    assert PASSWORD not in result.all_text()


def test_python_never_stages_the_rust_release() -> None:
    cfg = endpoint_cfg(httpd_rust_version="0.1.0", httpd_rust_sha256="7" * 64)

    result = run(converged_endpoint(cfg), cfg)

    assert not any("/opt/metrics-httpd/0.1.0" in c and "install" in c.lower() for c in result.executed_commands)
    assert not any(op.name.startswith(f"{P}Check the metrics-httpd") for op in result.ops)


def test_the_remote_pull_writes_the_key_privately() -> None:
    cfg = endpoint_cfg(remote=REMOTE)
    responses = converged_endpoint(cfg)
    for path in ("/etc/os-lifecycle/collector_ed25519", "/etc/os-lifecycle/known_hosts"):
        responses = {k: v for k, v in responses.items() if path not in k}

    result = run(responses, cfg)

    assert result.mutating_changed_ops == [
        f"{P}Write /etc/os-lifecycle/collector_ed25519",
        f"{P}Write /etc/os-lifecycle/known_hosts",
        f"{P}Run os-lifecycle-pull.service once",
    ]
    (install,) = [(c, s) for c, s in result.stdin if "collector_ed25519" in c]
    assert " 0600 root root" in install[0]
    assert base64.b64decode(install[1]).decode() == PRIVATE_KEY
    assert PRIVATE_KEY.splitlines()[1] not in result.all_text()
    assert result.upload("/etc/os-lifecycle/known_hosts").decode() == f"os-lifecycle-marina {HOST_KEY}\n"


def test_the_remote_pull_refuses_a_missing_key() -> None:
    cfg = endpoint_cfg(remote=REMOTE)
    secrets = SecretValues(SecretRef("secrets/fixture.yml"), {PASSWORD_KEY: PASSWORD})

    result = run_deploy_fake(deploy_os_lifecycle, cfg, secrets, responses=converged_endpoint(cfg))

    assert not result.succeeded
    assert PRIVATE_KEY_KEY in str(result.error)


def test_an_ssh_host_gets_no_listener_and_a_restricted_key() -> None:
    cfg = ssh_cfg()

    result = run({**traces(*SSH_TRACES), **fakehost.UBUNTU}, cfg, None)

    names = result.mutating_changed_ops
    assert f"{P}Write /var/lib/os-lifecycle-ssh/.ssh/authorized_keys" in names
    assert not any("endpoint" in name or "htpasswd" in name for name in names)
    assert any("useradd" in c and "-s /bin/sh" in c and "os-lifecycle" in c for c in result.executed_commands)
    assert not any("apache2-utils" in c for c in result.executed_commands)
    keys = result.upload("/var/lib/os-lifecycle-ssh/.ssh/authorized_keys").decode()
    assert keys == oslc.render_authorized_keys(cfg)
    assert not any("tailscale" in c for c in result.fact_commands)


@pytest.mark.parametrize(
    ("found", "named"),
    [
        (
            {"os-lifecycle-endpoint.service": "loaded active present"},
            "os-lifecycle-endpoint.service (loaded, active, unit file present)",
        ),
        # Running with its unit file gone, failed, masked, or a file systemd has not loaded.
        (
            {"os-lifecycle-remote-endpoint.service": "not-found active absent"},
            "os-lifecycle-remote-endpoint.service (not-found, active, unit file absent)",
        ),
        ({"os-lifecycle-endpoint.service": "not-found failed absent"}, "(not-found, failed, unit file absent)"),
        ({"os-lifecycle-pull.timer": "masked inactive present"}, "os-lifecycle-pull.timer (masked, inactive"),
        ({"os-lifecycle-pull.service": "not-found inactive present"}, "os-lifecycle-pull.service (not-found"),
        ({"/etc/os-lifecycle/htpasswd": "present"}, "/etc/os-lifecycle/htpasswd"),
        ({"/etc/os-lifecycle/collector_ed25519": "present"}, "/etc/os-lifecycle/collector_ed25519"),
    ],
)
def test_ssh_refuses_a_host_that_keeps_the_endpoint_exposure(found: dict[str, str], named: str) -> None:
    responses = {**traces(*SSH_TRACES, found), **fakehost.UBUNTU}

    result = run_deploy_fake(deploy_os_lifecycle, ssh_cfg(), None, responses=responses)

    assert not result.succeeded
    assert "nothing of it may stay behind" in str(result.error)
    assert named in str(result.error)
    assert result.mutating_changed_ops == []


@pytest.mark.parametrize(
    "answer",
    [
        [FAILED],
        [],
        # One line short, a line for another unit, a word missing (systemctl printed nothing).
        traces(*SSH_TRACES)[TRACES][:-1],
        ["unit other.service not-found inactive absent", *traces(*SSH_TRACES)[TRACES][1:]],
        ["unit os-lifecycle-endpoint.service inactive absent", *traces(*SSH_TRACES)[TRACES][1:]],
    ],
)
def test_ssh_refuses_without_a_complete_answer(answer: list[str]) -> None:
    responses = {TRACES: answer, **fakehost.UBUNTU}

    result = run_deploy_fake(deploy_os_lifecycle, ssh_cfg(), None, responses=responses)

    assert not result.succeeded
    assert "unknown (no complete answer)" in str(result.error)
    assert result.mutating_changed_ops == []


@pytest.mark.parametrize(
    ("found", "named"),
    [
        ({"os-lifecycle-pull.timer": "loaded active present"}, "os-lifecycle-pull.timer (loaded, active"),
        ({"os-lifecycle-remote-endpoint.service": "loaded active present"}, "os-lifecycle-remote-endpoint.service"),
        ({"/etc/os-lifecycle/collector_ed25519": "present"}, "/etc/os-lifecycle/collector_ed25519"),
    ],
)
def test_an_endpoint_without_remote_refuses_a_host_that_keeps_the_pull(found: dict[str, str], named: str) -> None:
    cfg = endpoint_cfg()
    responses = {**converged_endpoint(cfg), **traces(*REMOTE_TRACES, found)}

    result = run_deploy_fake(deploy_os_lifecycle, cfg, SECRETS, responses=responses)

    assert not result.succeeded
    assert "an endpoint without remote" in str(result.error)
    assert named in str(result.error)
    assert result.mutating_changed_ops == []


def test_an_endpoint_with_remote_keeps_its_pull_without_asking() -> None:
    cfg = endpoint_cfg(remote=REMOTE)

    result = run(converged_endpoint(cfg), cfg)

    assert not any(TRACES in command for command in result.fact_commands)


# -- the leftover probe on a real shell, with a stand-in systemctl ----------------------------------------

SYSTEMCTL = """#!/bin/sh
[ "$1" = show ] && [ "$3" = --value ] || exit 2
{fail}case "${{2#--property=}} $4" in
{cases}  "LoadState "*) echo not-found ;;
  "ActiveState "*) echo inactive ;;
  *) exit 2 ;;
esac
"""


def probe_on_shell(
    tmp_path: Path,
    units: Sequence[str],
    paths: Sequence[PurePosixPath],
    states: dict[str, tuple[str, str]],
    *,
    fail: bool = False,
) -> list[str] | None:
    """Run the leftover probe (wrapped as :func:`probe` wraps it) with ``systemctl`` answering ``states``."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    cases = "".join(
        f"  'LoadState {unit}') echo {load} ;;\n  'ActiveState {unit}') echo {active} ;;\n"
        for unit, (load, active) in states.items()
    )
    stub = bin_dir / "systemctl"
    stub.write_text(SYSTEMCTL.format(fail="exit 1\n" if fail else "", cases=cases))
    stub.chmod(0o755)
    command = oslc.leftover_command(units, paths, unit_dir=PurePosixPath(tmp_path / "units"))
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    out = subprocess.run(["sh", "-c", probe_command(command)], env=env, capture_output=True, text=True, check=False)
    return oslc.leftovers(probe_output(out.stdout), units, paths)


def test_an_endpoint_unit_of_a_deploy_with_another_script_dir_is_found(tmp_path: Path) -> None:
    # An endpoint deploy with script_dir /opt/old-os-lifecycle; the ssh config has the default script_dir.
    (tmp_path / "units").mkdir()
    old = endpoint_cfg(script_dir="/opt/old-os-lifecycle")
    unit = tmp_path / "units" / "os-lifecycle-endpoint.service"
    unit.write_text(oslc.render_endpoint_unit(old, TAILSCALE_IP))
    secrets = (PurePosixPath(tmp_path / "htpasswd"), PurePosixPath(tmp_path / "collector_ed25519"))
    running = {"os-lifecycle-endpoint.service": ("loaded", "active")}

    assert probe_on_shell(tmp_path, oslc.ENDPOINT_UNITS, secrets, running) == [
        "os-lifecycle-endpoint.service (loaded, active, unit file present)"
    ]
    # Found by name, also before systemd loaded the file; nothing in the probe depends on a path of the config.
    assert probe_on_shell(tmp_path, oslc.ENDPOINT_UNITS, secrets, {}) == [
        "os-lifecycle-endpoint.service (not-found, inactive, unit file present)"
    ]


def test_the_leftover_probe_is_the_same_for_every_configuration() -> None:
    probes = []
    for cfg in (ssh_cfg(), ssh_cfg(script_dir="/opt/old-os-lifecycle", site_path="/srv/os-lifecycle")):
        result = run({**traces(*SSH_TRACES), **fakehost.UBUNTU}, cfg, None)
        probes += [command for command in result.fact_commands if TRACES in command]

    assert len(probes) == 2
    assert probes[0] == probes[1]
    assert "/usr/local/lib" not in probes[0]


def test_the_leftover_probe_on_a_shell(tmp_path: Path) -> None:
    (tmp_path / "units").mkdir()
    key = tmp_path / "collector_ed25519"
    secrets = (PurePosixPath(tmp_path / "htpasswd"), PurePosixPath(key))

    assert probe_on_shell(tmp_path, oslc.ENDPOINT_UNITS, secrets, {}) == []
    gone = {"os-lifecycle-remote-endpoint.service": ("not-found", "active")}
    assert probe_on_shell(tmp_path, oslc.ENDPOINT_UNITS, secrets, gone) == [
        "os-lifecycle-remote-endpoint.service (not-found, active, unit file absent)"
    ]
    key.symlink_to(tmp_path / "missing")
    assert probe_on_shell(tmp_path, oslc.ENDPOINT_UNITS, secrets, {}) == [str(key)]
    assert probe_on_shell(tmp_path, oslc.ENDPOINT_UNITS, secrets, {}, fail=True) is None


def test_the_leftover_probe_refuses_whitespace() -> None:
    with pytest.raises(ValueError, match="whitespace"):
        oslc.leftover_command(("a b.service",), ())


def test_an_existing_ssh_account_with_a_nologin_shell_is_refused() -> None:
    responses = {
        **traces(*SSH_TRACES),
        **fakehost.UBUNTU,
        **fakehost.accounts({"os-lifecycle": "/var/lib/os-lifecycle-ssh"}),
    }

    result = run_deploy_fake(deploy_os_lifecycle, ssh_cfg(), None, responses=responses)

    assert not result.succeeded
    assert "shell /bin/sh" in str(result.error)


# -- the checks deploy -------------------------------------------------------------------------------

CHECK = lifecycle_check(
    service_name="OS lifecycle",
    name="OS Lifecycle (example)",
    url="http://host.example.invalid:9113/.well-known/os-lifecycle",
    rules=endpoint_rules(Thresholds()),
    auth_username="nyxmon",
)
PROBE = " probe /home/nyxmon/site/db.sqlite3 'OS lifecycle' "


def checks_cfg() -> OsLifecycleChecksConfig:
    return OsLifecycleChecksConfig(secrets="secrets/fixture.yml", checks=(CHECK,))


def test_the_checks_are_upserted_with_the_login_on_stdin_only() -> None:
    result = run_deploy_fake(deploy_os_lifecycle_checks, checks_cfg(), SECRETS, responses={PROBE: ["check absent"]})

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == ["OS lifecycle Nyxmon checks | Upsert Nyxmon check OS Lifecycle (example)"]
    (upsert,) = [(c, s) for c, s in result.stdin if " apply " in c]
    assert json.loads(upsert[1])["data"]["auth"] == {"username": "nyxmon", "password": PASSWORD}
    assert PASSWORD not in result.all_text()


def test_current_checks_are_left_alone() -> None:
    responses = {PROBE: [f"check {CHECK.digest(PASSWORD)}"]}

    result = run_deploy_fake(deploy_os_lifecycle_checks, checks_cfg(), SECRETS, responses=responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []


def test_checks_need_unique_names() -> None:
    with pytest.raises(ConfigValidationError, match="unique"):
        OsLifecycleChecksConfig(secrets="secrets/fixture.yml", checks=(CHECK, CHECK))
