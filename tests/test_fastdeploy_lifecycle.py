"""FastDeploy backup, restore and removal against the fake connector."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.fastdeploy import (
    FastdeployBackupConfig,
    FastdeployRemoveConfig,
    FastdeployRestoreConfig,
    deploy_fastdeploy_backup,
    deploy_fastdeploy_remove,
    deploy_fastdeploy_restore,
)
from ops_deploy.testing import FakeRun, run_deploy_fake

STAMP = "20261014T120000"
PASSWORD = "pg:secret\\value"
SECRETS = SecretValues(SecretRef("secrets/prod/fastdeploy.yml"), {"postgres_password": PASSWORD})
TIME = {"date +%Y%m%dT%H%M%S": [STAMP]}


def body(result: FakeRun) -> tuple[str, str]:
    """The bash script of the one ``secret_stdin`` operation and the stdin it got."""

    ((command, stdin),) = result.stdin
    assert result.executed_commands == [command]
    assert command.startswith("bash -c ")
    return shlex.split(command)[2], stdin


def settings(script: str) -> dict[str, str]:
    values = {}
    for line in script.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.isidentifier() and name.isupper():
            values[name] = value if value.startswith("(") else (shlex.split(value) or [""])[0]
    return values


def test_backup_passes_the_password_on_stdin_only(tmp_path: Path) -> None:
    cfg = FastdeployBackupConfig(host_name="macmini", local_dir=tmp_path / "b")

    result = run_deploy_fake(deploy_fastdeploy_backup, cfg, SECRETS, responses=TIME)

    assert result.succeeded, result.error
    script, stdin = body(result)
    assert stdin == f"{PASSWORD}\n"
    assert PASSWORD not in result.all_text()
    assert script.rstrip().endswith("IFS= read -r PGPW || true\nfd_backup")
    values = settings(script)
    assert values["B_DIR"] == f"/opt/backups/fastdeploy/manual-{STAMP}"
    assert values["B_PG_USER"] == "postgres"
    assert values["B_DUMP_OPTIONS"] == "(--clean --if-exists --no-owner)"
    assert values["B_DUMP_OPTIONS_JSON"] == '"--clean --if-exists --no-owner"'
    assert values["B_EXTRA"] == "{}"
    assert values["B_RUNNER_EXCLUDES"] == "(.config/sops/age/keys.txt)"
    assert "FastDeploy backup | Fetch the backup archive" in result.changed_ops
    assert (tmp_path / "b").stat().st_mode & 0o777 == 0o700


def test_backup_without_secrets_sends_an_empty_line() -> None:
    cfg = FastdeployBackupConfig(host_name="macmini", fetch_local=False, archive_format="tar.zst")

    result = run_deploy_fake(deploy_fastdeploy_backup, cfg, responses=TIME)

    assert result.succeeded, result.error
    assert body(result)[1] == "\n"
    assert "FastDeploy backup | Fetch the backup archive" not in result.changed_ops


def test_password_with_a_line_break_is_refused() -> None:
    broken = SecretValues(SecretRef("secrets/prod/fastdeploy.yml"), {"postgres_password": "a\nb"})

    result = run_deploy_fake(deploy_fastdeploy_restore, FastdeployRestoreConfig(host_name="m"), broken, responses=TIME)

    assert "cannot contain line breaks" in str(result.error)
    assert result.executed_commands == []


def test_restore_runs_with_a_safety_backup_and_rollback() -> None:
    result = run_deploy_fake(
        deploy_fastdeploy_restore, FastdeployRestoreConfig(host_name="macmini"), SECRETS, responses=TIME
    )

    assert result.succeeded, result.error
    script, stdin = body(result)
    assert stdin == f"{PASSWORD}\n"
    values = settings(script)
    assert values["STAMP"] == STAMP
    assert values["R_ARCHIVE"] == "latest"
    assert values["R_SAFETY"] == "1"
    assert values["R_SAFETY_PREFIX"] == "pre-restore"
    # The safety backup is the backup role with the restore's overrides.
    assert values["B_EXTRA"] == '{"safety_backup": true}'
    assert values["B_FETCH"] == "0"
    assert values["B_PG_USER"] == "postgres"
    for function in ("validate_phase", "safety_phase", "restore_phase", "verify_phase", "restore_finish"):
        assert f"{function}()" in script
    assert script.rstrip().endswith("fd_restore")
    assert result.changed_ops == ["FastDeploy restore | Restore FastDeploy"]


@pytest.mark.parametrize("archive", ["../x.tar.gz", "/opt/../etc", "a b"])
def test_restore_archive_names_are_checked(archive: str) -> None:
    with pytest.raises(ValidationError):
        FastdeployRestoreConfig(host_name="m", archive=archive)


def test_restore_accepts_names_paths_and_snapshot_directories() -> None:
    for archive in ("manual-1", "manual-1.tar.zst", "/opt/backups/fastdeploy/pre-restore-1"):
        assert FastdeployRestoreConfig(host_name="m", archive=archive).archive == archive


def installed() -> dict[str, Any]:
    return {
        "for unit in fastdeploy.service": [
            "Id=fastdeploy.service",
            "LoadState=loaded",
            "ActiveState=active",
            "UnitFileState=enabled",
            "---",
        ],
        **{
            f"test -e {path} &&": ["yes"]
            for path in (
                "/etc/systemd/system/fastdeploy.service",
                "/etc/traefik/dynamic/fastdeploy.yml",
                "/home/fastdeploy",
                "/home/deploy",
            )
        },
        "find /etc/sudoers.d": ["/etc/sudoers.d/fastdeploy_nyxmon", "/etc/sudoers.d/fastdeploy_work"],
        "cd / && runuser -u postgres -- psql -tAc 'SELECT 1 FROM pg_database": ["1"],
        "cd / && runuser -u postgres -- psql -tAc 'SELECT 1 FROM pg_roles": ["1"],
        "ps -u fastdeploy": ["  4321"],
        "getent passwd fastdeploy": ["fastdeploy:x:998:998::/home/fastdeploy:/bin/bash"],
        "getent group fastdeploy": ["fastdeploy:x:998:"],
        "getent passwd deploy": ["deploy:x:997:997::/home/deploy:/bin/bash"],
        "getent group deploy": ["deploy:x:997:"],
    }


def test_remove_takes_everything_in_the_role_order() -> None:
    result = run_deploy_fake(deploy_fastdeploy_remove, FastdeployRemoveConfig(confirm=True), responses=installed())

    assert result.succeeded, result.error
    assert result.executed_commands == [
        "systemctl stop fastdeploy.service || true",
        "systemctl disable fastdeploy.service || true",
        "rm -rf /etc/systemd/system/fastdeploy.service",
        "rm -rf /etc/traefik/dynamic/fastdeploy.yml",
        "rm -f /etc/sudoers.d/fastdeploy_nyxmon",
        "rm -f /etc/sudoers.d/fastdeploy_work",
        "cd / && runuser -u postgres -- dropdb fastdeploy || true",
        "cd / && runuser -u postgres -- dropuser fastdeploy || true",
        "pkill -u fastdeploy || true",
        "rm -rf /home/fastdeploy",
        "rm -rf /home/deploy",
        "userdel -r fastdeploy || true",
        "groupdel fastdeploy || true",
        "userdel -r deploy || true",
        "groupdel deploy || true",
        "systemctl daemon-reload",
    ]


def test_second_removal_changes_nothing() -> None:
    gone = {
        "for unit in fastdeploy.service": [
            "Id=fastdeploy.service",
            "LoadState=not-found",
            "ActiveState=inactive",
            "---",
        ]
    }

    result = run_deploy_fake(deploy_fastdeploy_remove, FastdeployRemoveConfig(confirm=True), responses=gone)

    assert result.succeeded, result.error
    assert result.changed_ops == []


def test_removal_needs_confirmation() -> None:
    result = run_deploy_fake(deploy_fastdeploy_remove, FastdeployRemoveConfig(), responses=installed())

    assert "removal not confirmed" in str(result.error)
    assert result.executed_commands == []
