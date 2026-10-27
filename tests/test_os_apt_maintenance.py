"""os_apt_maintenance: the endpoint host deploy and the Nyxmon upsert (plans and the upsert script)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.os_apt_maintenance import (
    OsAptMaintenanceConfig,
    OsAptNyxmonConfig,
    deploy_os_apt_maintenance,
    deploy_os_apt_maintenance_nyxmon,
)
from ops_deploy.services.os_apt_maintenance import deploy as module
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

VALUE = "fixture-endpoint-password"
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {"endpoint_password": VALUE})
BIND = "100.64.0.7"
PREFIX = "Deploy os apt maintenance | "
NYX = "Upsert Nyxmon OS apt maintenance checks | "
TEMPLATES = Path(module.__file__).parent / "templates"
SCRIPT = Path(module.__file__).parent / "files" / "nyxmon_checks.py"


def config(**changes: Any) -> OsAptMaintenanceConfig:
    return OsAptMaintenanceConfig.model_validate(
        {"auth_user": "nyxmon", "host_id": "fractal", "secrets": "secrets/fixture.yml", **changes}
    )


PATHS = {
    "os_apt_maintenance.py.j2": "/usr/local/sbin/os-apt-maintenance",
    "os_apt_maintenance_httpd.py.j2": "/usr/local/bin/os_apt_maintenance_httpd.py",
    "os-apt-maintenance.service.j2": "/etc/systemd/system/os-apt-maintenance.service",
    "os-apt-maintenance.timer.j2": "/etc/systemd/system/os-apt-maintenance.timer",
    "os-apt-maintenance-refresh.service.j2": "/etc/systemd/system/os-apt-maintenance-refresh.service",
    "os-apt-maintenance-refresh.timer.j2": "/etc/systemd/system/os-apt-maintenance-refresh.timer",
    "os-apt-maintenance-endpoint.service.j2": "/etc/systemd/system/os-apt-maintenance-endpoint.service",
}


def converged(cfg: OsAptMaintenanceConfig) -> dict[Any, Any]:
    responses: dict[Any, Any] = {
        **fakehost.UBUNTU,
        "tailscale ip --4": [BIND],
        **fakehost.accounts({"metrics": "/home/metrics"}),
        **fakehost.deb_installed("python3", "apache2-utils"),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/usr/local/sbin"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.stat("/var/lib/os-apt-maintenance", group="metrics", mode="drwxr-x---"),
        **fakehost.stat("/etc/os-apt-maintenance-endpoint", group="metrics", mode="drwxr-x---"),
        **fakehost.file("/etc/os-apt-maintenance-endpoint/htpasswd", f"nyxmon:{hash_password(VALUE)}\n"),
        **fakehost.stat("/etc/os-apt-maintenance-endpoint/htpasswd", group="metrics", mode="-rw-r-----"),
        **fakehost.stat("/var/lib/os-apt-maintenance/state.json", group="metrics", mode="-rw-r-----"),
        "if test -e /var/lib/os-apt-maintenance/state.json": ["present"],
        **fakehost.service("os-apt-maintenance-endpoint.service"),
        **fakehost.service("os-apt-maintenance.timer"),
        **fakehost.service("os-apt-maintenance-refresh.timer"),
    }
    for template, path in PATHS.items():
        mode = "-rw-r--r--" if path.startswith("/etc/systemd/") else "-rwxr-xr-x"
        responses.update(fakehost.file(path, module.render_role(template, cfg, BIND), mode=mode))
    return responses


def run(cfg: OsAptMaintenanceConfig, responses: dict[Any, Any], urls: list[str] | None = None) -> FakeRun:
    return run_deploy_fake(
        deploy_os_apt_maintenance, cfg, SECRETS, None if urls is None else urls.append, responses=responses
    )


def changed(result: FakeRun) -> list[str]:
    return [name.removeprefix(PREFIX) for name in result.mutating_changed_ops]


def test_converged_host_changes_nothing_reloads_nothing_and_runs_no_apt() -> None:
    cfg = config()
    urls: list[str] = []
    result = run(cfg, converged(cfg), urls)

    assert result.succeeded, result.error
    assert changed(result) == []
    commands = " ".join(result.executed_commands)
    assert "daemon-reload" not in commands
    assert "--init-state" not in commands
    assert "systemctl start os-apt-maintenance.service" not in commands
    assert urls == [f"http://{BIND}:9106/.well-known/os-apt-maintenance"]


def test_disabled_role_retains_pretask_url_without_managing_host_resources() -> None:
    urls: list[str] = []
    result = run(config(enabled=False), {**fakehost.UBUNTU, "tailscale ip --4": [BIND]}, urls)

    assert result.succeeded, result.error
    assert result.ops == []
    assert urls == [f"http://{BIND}:9106/.well-known/os-apt-maintenance"]


def test_first_deploy_initializes_state_then_runs_maintenance_once() -> None:
    cfg = config()
    responses = converged(cfg)
    responses["if test -e /var/lib/os-apt-maintenance/state.json"] = ["absent"]

    names = changed(run(cfg, responses))

    init = names.index("Initialize apt maintenance state file without running apt")
    assert names[init + 1] == "Run apt maintenance once on deploy"
    assert names[init + 2] == "Ensure apt maintenance state permissions for endpoint"


def test_first_deploy_without_run_on_first_deploy_only_initializes() -> None:
    cfg = config(run_on_first_deploy=False)
    responses = converged(cfg)
    responses["if test -e /var/lib/os-apt-maintenance/state.json"] = ["absent"]

    assert "Run apt maintenance once on deploy" not in changed(run(cfg, responses))


def test_an_unknown_state_fails_instead_of_running_apt() -> None:
    cfg = config()
    responses = converged(cfg)
    responses["if test -e /var/lib/os-apt-maintenance/state.json"] = ["ops-deploy-probe-failed"]

    result = run(cfg, responses)

    assert not result.succeeded
    assert "systemctl start os-apt-maintenance.service" not in " ".join(result.executed_commands)


def test_a_changed_timer_reloads_and_restarts_only_the_timer() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.update(fakehost.file(PATHS["os-apt-maintenance.timer.j2"], "old", mode="-rw-r--r--"))

    names = changed(run(cfg, responses))

    assert "Install systemd unit os-apt-maintenance.timer" in names
    assert "Reload systemd for the apt maintenance units" in names
    assert "Restart os-apt-maintenance.timer" in names
    assert "Restart os-apt-maintenance-endpoint.service" not in names


def test_a_rotated_password_rewrites_htpasswd_and_restarts_the_endpoint() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.update(fakehost.file("/etc/os-apt-maintenance-endpoint/htpasswd", "nyxmon:$2y$05$wrong\n"))

    names = changed(run(cfg, responses))

    assert "Write /etc/os-apt-maintenance-endpoint/htpasswd" in names
    assert "Restart os-apt-maintenance-endpoint.service" in names
    assert "Reload systemd for the apt maintenance units" not in names


def test_refresh_off_stops_and_removes_the_refresh_units() -> None:
    cfg = config(refresh_enabled=False)
    responses = converged(cfg)
    responses["test -e /etc/systemd/system/os-apt-maintenance-refresh.timer && echo present"] = ["present"]

    names = changed(run(cfg, responses))

    assert "Stop apt index refresh timer os-apt-maintenance-refresh.timer" in names
    assert "Remove /etc/systemd/system/os-apt-maintenance-refresh.timer" in names
    assert "Reload systemd for the endpoint implementation" in names


@pytest.mark.parametrize("active", [True, False])
def test_refresh_off_checks_loaded_timer_even_when_unit_files_are_absent(active: bool) -> None:
    cfg = config(refresh_enabled=False)
    responses = converged(cfg)
    for kind in ("service", "timer"):
        responses[f"test -e /etc/systemd/system/os-apt-maintenance-refresh.{kind} ||"] = []
    responses.update(fakehost.service("os-apt-maintenance-refresh.timer", running=active, enabled=active))

    result = run(cfg, responses)

    assert result.succeeded, result.error
    commands = " ".join(result.executed_commands)
    assert ("systemctl stop os-apt-maintenance-refresh.timer" in commands) == active
    assert ("systemctl disable os-apt-maintenance-refresh.timer" in commands) == active
    assert "apt-get" not in commands
    if not active:
        assert changed(result) == []


def test_rust_endpoint_argv_and_sandbox_fit_the_switch() -> None:
    from ops_deploy.services._metrics_httpd import problems

    endpoint = module.httpd_endpoint(config(), BIND)

    assert problems(endpoint) == []
    assert endpoint.argv[:3] == ("apt-state", "--bind", BIND)
    assert "ReadOnlyPaths=/var/lib/os-apt-maintenance/state.json" in endpoint.sandbox
    assert endpoint.ip_address_allow == ("localhost", "100.64.0.0/10")


@pytest.mark.parametrize(
    "change",
    [
        {"host_id": ""},
        {"timer_on_calendar": "Sun\nExecStart=/bin/sh"},
        {"timer_state": "restarted"},
        {"refresh_service_name": "os-apt-maintenance"},
        {"auth_user": "CHANGE_ME"},
        {"unknown": True},
    ],
)
def test_invalid_config_never_reaches_the_host(change: dict[str, Any]) -> None:
    with pytest.raises(ConfigValidationError):
        config(**change)


# -- Nyxmon --------------------------------------------------------------------------

TARGETS = [
    {"display_name": "fractal", "url": "http://100.64.0.1:9106/.well-known/os-apt-maintenance"},
    {"display_name": "staging.wersdoerfer.de", "url": "http://100.64.0.3:9106/.well-known/os-apt-maintenance"},
]


def nyxmon_config(**changes: Any) -> OsAptNyxmonConfig:
    return OsAptNyxmonConfig.model_validate({"targets": TARGETS, "secrets": "secrets/fixture.yml", **changes})


def make_db(path: Path) -> None:
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE service (id INTEGER PRIMARY KEY, name TEXT);"
        "CREATE TABLE health_check (id INTEGER PRIMARY KEY, name TEXT, service_id INT, check_type TEXT, url TEXT,"
        " check_interval INT, status TEXT, next_check_time INT, processing_started_at INT, disabled INT, data TEXT);"
    )
    db.commit()
    db.close()


def apply(path: Path, cfg: OsAptNyxmonConfig) -> str:
    payload = {"db": str(path), "service": cfg.nyxmon_service, "checks": module.nyxmon_checks(cfg, VALUE)}
    out = subprocess.run(
        [sys.executable, "-I", str(SCRIPT), "apply"], input=json.dumps(payload), capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def probe(path: Path, cfg: OsAptNyxmonConfig) -> str:
    names = [check["name"] for check in module.nyxmon_checks(cfg, VALUE)]
    args = [sys.executable, "-I", str(SCRIPT), "probe", str(path), cfg.nyxmon_service, *names]
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def test_upsert_then_probe_is_current_and_a_repeat_writes_nothing(tmp_path: Path) -> None:
    db = tmp_path / "db.sqlite3"
    make_db(db)
    cfg = nyxmon_config()

    assert not module.nyxmon_current(probe(db, cfg), module.nyxmon_checks(cfg, VALUE))
    assert apply(db, cfg) == "changed=true"
    assert module.nyxmon_current(probe(db, cfg), module.nyxmon_checks(cfg, VALUE))
    assert apply(db, cfg) == "changed=false"
    rows = sqlite3.connect(db).execute("select name, status, disabled, next_check_time from health_check").fetchall()
    assert rows == [
        ("OS apt maintenance (fractal)", "idle", 0, 0),
        ("OS apt maintenance (staging.wersdoerfer.de)", "idle", 0, 0),
    ]


def test_disabled_is_not_compared_and_an_update_keeps_the_status(tmp_path: Path) -> None:
    """The playbook's semantics (D7): a manually disabled, current check stays disabled."""

    db = tmp_path / "db.sqlite3"
    make_db(db)
    cfg = nyxmon_config()
    apply(db, cfg)
    conn = sqlite3.connect(db)
    conn.execute("update health_check set disabled = 1, status = 'warning', next_check_time = 99")
    conn.commit()

    assert module.nyxmon_current(probe(db, cfg), module.nyxmon_checks(cfg, VALUE))
    assert apply(db, cfg) == "changed=false"
    # A real change re-enables it, but keeps status and schedule.
    moved = nyxmon_config(targets=[{**TARGETS[0], "url": "http://100.64.0.9:9106/x"}, TARGETS[1]])
    assert not module.nyxmon_current(probe(db, moved), module.nyxmon_checks(moved, VALUE))
    assert apply(db, moved) == "changed=true"
    row = conn.execute("select disabled, status, next_check_time from health_check where name like '%fractal%'")
    assert row.fetchone() == (0, "warning", 99)


def test_the_payload_is_the_playbooks() -> None:
    check = module.nyxmon_checks(nyxmon_config(), VALUE)[0]

    assert check["name"] == "OS apt maintenance (fractal)"
    assert check["data"]["timeout"] == 10.0
    assert check["data"]["retry_delay"] == 2.0
    assert check["data"]["auth"] == {"username": "nyxmon", "password": VALUE}
    assert [c["path"] for c in check["data"]["checks"]] == [
        "$.summary.last_run_ok",
        "$.summary.last_success_fresh",
        "$.meta.state_file_fresh",
        "$.reboot_required",
    ]


def nyxmon_run(found: list[str] | None, exists: str = "present") -> FakeRun:
    responses: dict[Any, Any] = {
        **fakehost.LINUX,
        "if test -e /home/nyxmon/site/db.sqlite3": [exists],
    }
    if found is not None:
        responses[" probe /home/nyxmon/site/db.sqlite3"] = found
    return run_deploy_fake(deploy_os_apt_maintenance_nyxmon, nyxmon_config(), SECRETS, responses=responses)


def current_lines() -> list[str]:
    cfg = nyxmon_config()
    lines = ["service present"]
    for check in module.nyxmon_checks(cfg, VALUE):
        state = json.dumps(
            [check["check_type"], check["url"], check["check_interval"], json.dumps(check["data"], sort_keys=True)]
        )
        lines.append(
            f"check {hashlib.sha256(check['name'].encode()).hexdigest()} {hashlib.sha256(state.encode()).hexdigest()}"
        )
    return lines


def test_a_current_database_is_not_written_and_the_password_stays_off_the_probe() -> None:
    result = nyxmon_run(current_lines())

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert not any(VALUE in command for command in result.executed_commands)


def test_a_stale_database_is_upserted_with_the_payload_on_stdin_only() -> None:
    lines = current_lines()
    lines[1] = lines[1].rsplit(" ", 1)[0] + " absent"

    result = nyxmon_run(lines)

    assert [n.removeprefix(NYX) for n in result.mutating_changed_ops] == [
        "Upsert Nyxmon OS apt maintenance json-metrics checks"
    ]
    assert not any(VALUE in command for command in result.executed_commands)
    assert any(VALUE in stdin for _, stdin in result.stdin)


def test_no_database_skips_the_upsert() -> None:
    result = nyxmon_run(None, exists="absent")

    assert result.succeeded
    assert result.mutating_changed_ops == []
