"""nyxmon backup, restore and removal against the fake connector."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import yaml

from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.nyxmon import (
    NyxmonBackupConfig,
    NyxmonRemoveConfig,
    NyxmonRestoreConfig,
    deploy_nyxmon_backup,
    deploy_nyxmon_remove,
    deploy_nyxmon_restore,
)
from ops_deploy.testing import FakeRun, run_deploy_fake

STAMP = "20261014T120000"
SITE = "/home/nyxmon/site"
DIR = f"/opt/backups/nyxmon/manual-{STAMP}"
PRESENT = (SITE, f"{SITE}/.env", f"{SITE}/db.sqlite3", f"{SITE}/staticfiles", "/home/nyxmon/logs")


def deployed(*missing: str, **extra: Any) -> dict[str, Any]:
    return {
        "date +%Y%m%dT%H%M%S": [STAMP],
        **{f"test -e {path} &&": ["yes"] for path in PRESENT if path not in missing},
        **extra,
    }


def backup(cfg: NyxmonBackupConfig, responses: dict[str, Any]) -> FakeRun:
    return run_deploy_fake(deploy_nyxmon_backup, cfg, responses=responses)


def assignments(command: str) -> dict[str, str]:
    """The ``NAME=value`` lines in front of a script body (arrays as their raw text)."""

    values = {}
    for line in command.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.isidentifier() and name.isupper():
            values[name] = value if value.startswith("(") else shlex.split(value)[0] if value else ""
    return values


def test_backup_copies_state_writes_metadata_and_fetches(tmp_path: Path) -> None:
    local = tmp_path / "backups"
    cfg = NyxmonBackupConfig(host_name="macmini", local_dir=local)

    result = backup(cfg, deployed())

    assert result.succeeded, result.error
    script = next(c for c in result.executed_commands if "backup.sh" in c or "STOP_ORDER=" in c)
    values = assignments(script)
    assert values["DIR"] == DIR
    assert values["STOP_ORDER"] == "(nyxmon-monitor.service nyxmon.service)"
    assert values["START_ORDER"] == "(nyxmon.service nyxmon-monitor.service)"
    assert values["DIRS"] == (
        f"(1:{SITE}/media:media 1:{SITE}/staticfiles:static 0:{SITE}/cache:cache 1:/home/nyxmon/logs:logs)"
    )
    assert "trap start_services EXIT" in script
    metadata = yaml.safe_load(result.upload(f"{DIR}/metadata.yml"))
    assert metadata == {
        "timestamp": STAMP,
        "host": "macmini",
        "site_path": SITE,
        "database": f"{SITE}/db.sqlite3",
        "version": "unknown",
        "stop_services": True,
        "include_logs": True,
        "include_cache": False,
        "include_static": True,
        "services": ["nyxmon-monitor.service", "nyxmon.service"],
    }
    assert (
        f"(umask 077; cd /opt/backups/nyxmon && tar -C /opt/backups/nyxmon -czf manual-{STAMP}.tar.gz manual-{STAMP})"
        f" && chmod 0600 {DIR}.tar.gz" in result.executed_commands
    )
    assert "nyxmon backup | Fetch the backup archive" in result.changed_ops
    assert local.stat().st_mode & 0o777 == 0o700


def test_backup_metadata_is_the_role_yaml() -> None:
    result = backup(NyxmonBackupConfig(host_name="macmini", fetch_local=False), deployed())

    # to_nice_yaml: sorted keys, block style.
    assert result.upload(f"{DIR}/metadata.yml").decode().splitlines()[:3] == [
        f"database: {SITE}/db.sqlite3",
        "host: macmini",
        "include_cache: false",
    ]


def test_backup_reports_the_installed_version() -> None:
    version = {
        f"test -e {SITE}/.venv/bin/python &&": ["yes"],
        f"{SITE}/.venv/bin/python -c": ["0.4.2"],
    }

    result = backup(NyxmonBackupConfig(host_name="macmini", fetch_local=False), deployed(**version))

    assert yaml.safe_load(result.upload(f"{DIR}/metadata.yml"))["version"] == "0.4.2"


def test_backup_without_archive_stops_after_the_manifest() -> None:
    cfg = NyxmonBackupConfig(host_name="macmini", create_archive=False, generate_checksums=False)

    result = backup(cfg, deployed())

    assert result.succeeded, result.error
    assert not any("tar -C" in c for c in result.executed_commands)
    assert not any("sha256sum" in c for c in result.executed_commands)
    assert "nyxmon backup | Fetch the backup archive" not in result.changed_ops


def test_backup_refuses_a_host_without_the_database() -> None:
    result = backup(NyxmonBackupConfig(host_name="macmini"), deployed(f"{SITE}/db.sqlite3"))

    assert "Nyxmon SQLite database not found" in str(result.error)
    assert result.executed_commands == []


def test_backup_needs_logs_only_when_included() -> None:
    missing_logs = deployed("/home/nyxmon/logs")

    assert "Nyxmon logs not found" in str(backup(NyxmonBackupConfig(host_name="m"), missing_logs).error)
    assert backup(NyxmonBackupConfig(host_name="m", include_logs=False, fetch_local=False), missing_logs).succeeded


def restore(cfg: NyxmonRestoreConfig) -> FakeRun:
    return run_deploy_fake(deploy_nyxmon_restore, cfg, responses={"date +%Y%m%dT%H%M%S": [STAMP]})


def test_restore_runs_the_role_phases_in_one_script() -> None:
    result = restore(NyxmonRestoreConfig(host_name="macmini", archive="manual-1.tar.gz"))

    assert result.succeeded, result.error
    (script,) = result.executed_commands
    values = assignments(script)
    assert values["ARCHIVE"] == "manual-1.tar.gz"
    assert values["STAMP"] == STAMP
    assert values["SAFETY"] == "1"
    assert values["REQUIRED_FIELDS"] == "(timestamp host site_path)"
    assert values["HEALTH_URL"] == "http://127.0.0.1:10017/admin/login/"
    assert values["HEALTH_HEADERS"] == "(-H 'X-Forwarded-Proto: https')"
    for phase in ("# -- validate", "# -- prepare", "# -- restore", "# -- verify", "trap cleanup EXIT"):
        assert phase in script
    assert result.changed_ops == ["nyxmon restore | Restore nyxmon"]


def test_restore_dry_run_is_labelled() -> None:
    result = restore(NyxmonRestoreConfig(host_name="macmini", dry_run=True))

    assert result.changed_ops == ["nyxmon restore | Restore nyxmon (dry run)"]
    assert assignments(result.executed_commands[0])["DRY_RUN"] == "1"


def test_restore_archive_must_be_a_name_below_the_root() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        NyxmonRestoreConfig(host_name="m", archive="/etc/shadow.tar.gz")


def installed() -> dict[str, Any]:
    return {
        "for unit in nyxmon.service": [
            *("Id=nyxmon.service", "LoadState=loaded", "ActiveState=active", "UnitFileState=enabled", "---"),
            *("Id=nyxmon-monitor.service", "LoadState=loaded", "ActiveState=failed", "UnitFileState=enabled", "---"),
        ],
        **{
            f"test -e {path} &&": ["yes"]
            for path in (
                "/etc/systemd/system/nyxmon.service",
                "/etc/systemd/system/nyxmon-monitor.service",
                "/etc/traefik/dynamic/nyxmon.yml",
                "/home/nyxmon",
            )
        },
        "find /home/nyxmon": [f"{SITE}/db.sqlite3"],
        "ps -u nyxmon": ["  1234"],
        "getent passwd nyxmon": ["nyxmon:x:999:999::/home/nyxmon:/bin/bash"],
        "getent group nyxmon": ["nyxmon:x:999:"],
        "find /tmp -mindepth 1": ["/tmp/nyxmon-restore"],
    }


def test_remove_takes_units_route_data_user_and_temp_files() -> None:
    result = run_deploy_fake(deploy_nyxmon_remove, NyxmonRemoveConfig(confirm=True), responses=installed())

    assert result.succeeded, result.error
    commands = result.executed_commands
    assert commands[:5] == [
        "systemctl stop nyxmon.service || true",
        "systemctl disable nyxmon.service || true",
        "systemctl disable nyxmon-monitor.service || true",
        "rm -rf /etc/systemd/system/nyxmon.service",
        "rm -rf /etc/systemd/system/nyxmon-monitor.service",
    ]
    # The route goes only while no Traefik transaction holds its host lock.
    assert commands[5:7] == [route_guard_command(), "rm -rf /etc/traefik/dynamic/nyxmon.yml"]
    assert commands[7].startswith("for pid in $(ps -u nyxmon")
    assert commands[8:] == [
        "rm -rf /home/nyxmon",
        "userdel -r nyxmon || true",
        "groupdel nyxmon || true",
        "rm -rf /tmp/nyxmon-restore",
        "systemctl daemon-reload",
    ]


def test_second_removal_changes_nothing() -> None:
    gone = {
        "for unit in nyxmon.service": [
            *("Id=nyxmon.service", "LoadState=not-found", "ActiveState=inactive", "---"),
            *("Id=nyxmon-monitor.service", "LoadState=not-found", "ActiveState=inactive", "---"),
        ]
    }

    result = run_deploy_fake(deploy_nyxmon_remove, NyxmonRemoveConfig(confirm=True), responses=gone)

    assert result.succeeded, result.error
    assert result.changed_ops == []


def test_removal_needs_confirmation() -> None:
    result = run_deploy_fake(deploy_nyxmon_remove, NyxmonRemoveConfig(), responses=installed())

    assert "removal not confirmed" in str(result.error)
    assert result.executed_commands == []


def test_remove_only_owned_privacy_dropin_and_keep_operator_directory() -> None:
    directory = "/etc/systemd/system/nyxmon.service.d"
    responses = {
        **installed(),
        f"test -e {directory}/sqlite-privacy.conf &&": ["yes"],
        f"test -e {directory} &&": ["yes"],
        f"find {directory} -mindepth 1": [f"{directory}/operator.conf"],
    }
    run = run_deploy_fake(deploy_nyxmon_remove, NyxmonRemoveConfig(confirm=True), responses=responses)
    assert run.succeeded, run.error
    assert f"rm -rf {directory}/sqlite-privacy.conf" in run.executed_commands
    assert not any(f"rmdir -- {directory}" in command for command in run.executed_commands)
    assert not any(command == f"rm -rf {directory}" for command in run.executed_commands)


def test_remove_empty_privacy_directory_uses_nonrecursive_rmdir() -> None:
    directory = "/etc/systemd/system/nyxmon.service.d"
    run = run_deploy_fake(
        deploy_nyxmon_remove,
        NyxmonRemoveConfig(confirm=True),
        responses={**installed(), f"test -e {directory} &&": ["yes"]},
    )
    assert run.succeeded, run.error
    assert f"rmdir -- {directory}" in run.executed_commands
    assert f"rm -rf {directory}" not in run.executed_commands


def test_remove_directory_after_its_only_owned_dropin() -> None:
    directory = "/etc/systemd/system/nyxmon.service.d"
    run = run_deploy_fake(
        deploy_nyxmon_remove,
        NyxmonRemoveConfig(confirm=True),
        responses={
            **installed(),
            f"test -e {directory}/sqlite-privacy.conf &&": ["yes"],
            f"test -e {directory} &&": ["yes"],
        },
    )
    assert run.succeeded, run.error
    commands = run.executed_commands
    assert commands.index(f"rm -rf {directory}/sqlite-privacy.conf") < commands.index(f"rmdir -- {directory}")
