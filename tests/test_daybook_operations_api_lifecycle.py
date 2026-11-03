"""Operations API backup, restore and remove against the fake connector."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ops_deploy.services.daybook_operations_api import (
    OperationsApiBackupConfig,
    OperationsApiRemoveConfig,
    OperationsApiRestoreConfig,
    deploy_daybook_operations_api_backup,
    deploy_daybook_operations_api_remove,
    deploy_daybook_operations_api_restore,
)
from ops_deploy.testing import run_deploy_fake

TOOL = (
    "runuser -u daybook-operations -- /home/daybook-operations/venv/bin/python "
    "/home/daybook-operations/site/services/operations_api/lifecycle.py"
)
CONFIG = "--config /etc/daybook-operations/lifecycle.json"
ARCHIVE = "/opt/backups/daybook_operations/20261103T101500123456Z.tar"
UNITS = ("daybook-operations", "daybook-operations-reconcile")


def unit_states(active: str = "active", enabled: str = "enabled", load: str = "loaded") -> dict[str, list[str]]:
    """The ``systemctl show`` blocks ``base._units.unit_states`` reads, for both units."""

    lines: list[str] = []
    for unit in UNITS:
        lines += [f"Id={unit}.service", f"LoadState={load}", f"ActiveState={active}", f"UnitFileState={enabled}", "---"]
    return {"systemctl show --property Id": lines}


ACTIVE = unit_states()


def test_backup_runs_the_tool_as_the_service_account_into_a_new_archive() -> None:
    cfg = OperationsApiBackupConfig()
    assert cfg.destination(datetime(2026, 11, 3, 10, 15, 0, 123456, tzinfo=UTC)) == ARCHIVE
    run = run_deploy_fake(deploy_daybook_operations_api_backup, OperationsApiBackupConfig(archive=ARCHIVE))
    assert run.succeeded, run.error
    assert f"{TOOL} backup {CONFIG} --archive {ARCHIVE}" in run.executed_commands
    assert any("mkdir -p /opt/backups/daybook_operations" in c for c in run.executed_commands)
    assert any("chmod 700 /opt/backups/daybook_operations" in c for c in run.executed_commands)
    assert any(
        "chown daybook-operations:daybook-operations /opt/backups/daybook_operations" in c
        for c in run.executed_commands
    )
    assert not any("require_mount" in c for c in run.executed_commands)


def test_backup_names_are_unique_per_run() -> None:
    first, second = OperationsApiBackupConfig().destination(), OperationsApiBackupConfig().destination()
    assert first != second
    assert first.startswith("/opt/backups/daybook_operations/")
    assert first.endswith("Z.tar")


def test_backup_mount_guard_runs_first_and_rejects_paths_off_the_mount() -> None:
    run = run_deploy_fake(
        deploy_daybook_operations_api_backup, OperationsApiBackupConfig(required_mount="/opt/backups", archive=ARCHIVE)
    )
    assert run.succeeded, run.error
    guard = next(i for i, c in enumerate(run.executed_commands) if "require_mount /opt/backups" in c)
    tool = next(i for i, c in enumerate(run.executed_commands) if " backup " in c and TOOL in c)
    assert guard < tool
    with pytest.raises(ValidationError):
        OperationsApiBackupConfig(required_mount="/opt/backups", root="/var/backups/daybook")
    with pytest.raises(ValidationError):
        OperationsApiBackupConfig(required_mount="/opt/backups", archive="/tmp/x.tar")
    # The host resolves the archive too, so a symlinked parent cannot leave the mount.
    archive = "/opt/backups/redirect/a.tar"
    run = run_deploy_fake(
        deploy_daybook_operations_api_backup, OperationsApiBackupConfig(required_mount="/opt/backups", archive=archive)
    )
    command = next(c for c in run.executed_commands if "require_mount /opt/backups" in c)
    assert f"require_mount /opt/backups /opt/backups/daybook_operations {archive}" in command


@pytest.mark.parametrize(
    "values",
    [
        {"archive": ARCHIVE, "clients_quiesced": True},
        {"archive": ARCHIVE, "confirmed": True},
        {"archive": "latest", "confirmed": True, "clients_quiesced": True},
        {"archive": "", "confirmed": True, "clients_quiesced": True},
    ],
)
def test_restore_refuses_before_any_command(values: dict[str, object]) -> None:
    run = run_deploy_fake(deploy_daybook_operations_api_restore, OperationsApiRestoreConfig.model_validate(values))
    assert not run.succeeded
    assert "Quiesce every client" in str(run.error)
    assert run.executed_commands == []


def test_restore_flags_are_strict_booleans() -> None:
    with pytest.raises(ValidationError):
        OperationsApiRestoreConfig(archive=ARCHIVE, confirmed="yes")


def test_restore_validates_then_stops_and_disables_then_restores() -> None:
    cfg = OperationsApiRestoreConfig(archive=ARCHIVE, confirmed=True, clients_quiesced=True)
    run = run_deploy_fake(deploy_daybook_operations_api_restore, cfg, responses=ACTIVE)
    assert run.succeeded, run.error
    commands = run.executed_commands
    validate = commands.index(f"{TOOL} validate {CONFIG} --archive {ARCHIVE}")
    restore = commands.index(f"{TOOL} restore --clients-quiesced {CONFIG} --archive {ARCHIVE}")
    stops = [i for i, c in enumerate(commands) if c.startswith("systemctl stop daybook-operations")]
    disables = [i for i, c in enumerate(commands) if c.startswith("systemctl disable daybook-operations")]
    assert len(stops) == 2
    assert len(disables) == 2
    assert validate < min(stops + disables)
    assert max(stops + disables) < restore
    assert not any("systemctl start" in c or "systemctl enable" in c for c in commands)


@pytest.mark.parametrize("active", ["activating", "deactivating"])
def test_restore_stops_a_unit_restarting_or_shutting_down(active: str) -> None:
    cfg = OperationsApiRestoreConfig(archive=ARCHIVE, confirmed=True, clients_quiesced=True)
    run = run_deploy_fake(deploy_daybook_operations_api_restore, cfg, responses=unit_states(active=active))
    assert run.succeeded, run.error
    for unit in UNITS:
        assert f"systemctl stop {unit}.service" in run.executed_commands
        assert f"systemctl disable {unit}.service" in run.executed_commands


def test_restore_leaves_stopped_disabled_units_alone() -> None:
    cfg = OperationsApiRestoreConfig(archive=ARCHIVE, confirmed=True, clients_quiesced=True)
    run = run_deploy_fake(
        deploy_daybook_operations_api_restore, cfg, responses=unit_states(active="inactive", enabled="disabled")
    )
    assert run.succeeded, run.error
    assert not any(c.startswith(("systemctl stop", "systemctl disable")) for c in run.executed_commands)


def test_restore_validate_only_touches_no_unit() -> None:
    cfg = OperationsApiRestoreConfig(archive=ARCHIVE, confirmed=True, clients_quiesced=True, validate_only=True)
    run = run_deploy_fake(deploy_daybook_operations_api_restore, cfg, responses=ACTIVE)
    assert run.succeeded, run.error
    assert run.executed_commands == [f"{TOOL} validate {CONFIG} --archive {ARCHIVE}"]


def test_remove_refuses_without_both_confirmations() -> None:
    for values in ({"confirmed": True}, {"clients_quiesced": True}, {}):
        run = run_deploy_fake(deploy_daybook_operations_api_remove, OperationsApiRemoveConfig.model_validate(values))
        assert not run.succeeded
        assert "Quiesce clients and confirm removal" in str(run.error)
        assert run.executed_commands == []


def test_remove_drops_entry_points_and_keeps_data() -> None:
    responses = {
        "test -e /etc/systemd/system/daybook-operations.service &&": ["yes"],
        "test -e /etc/systemd/system/daybook-operations-reconcile.service &&": ["yes"],
        "test -e /etc/traefik/dynamic/daybook-operations.yml &&": ["yes"],
        **ACTIVE,
        # files.file reads the File fact through stat.
        "stat ": ["user=root group=root mode=-rw-r--r-- atime=0 mtime=0 ctime=0 size=10 '/x'"],
    }
    run = run_deploy_fake(
        deploy_daybook_operations_api_remove,
        OperationsApiRemoveConfig(confirmed=True, clients_quiesced=True),
        responses=responses,
    )
    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    for unit in ("daybook-operations", "daybook-operations-reconcile"):
        assert commands.index(f"systemctl disable {unit}.service") < commands.index(f"systemctl stop {unit}.service")
        assert f"rm -f /etc/systemd/system/{unit}.service" in commands
    assert "rm -f /etc/traefik/dynamic/daybook-operations.yml" in commands
    assert "systemctl daemon-reload" in commands
    for kept in ("/home/daybook-operations", "/etc/daybook-operations", "/opt/backups", "dropdb", "userdel"):
        assert f"rm -rf {kept}" not in commands
        assert kept not in commands.replace("/etc/daybook-operations.", "")


def test_second_remove_changes_nothing() -> None:
    run = run_deploy_fake(
        deploy_daybook_operations_api_remove,
        OperationsApiRemoveConfig(confirmed=True, clients_quiesced=True),
        responses=unit_states(active="inactive", enabled="", load="not-found"),
    )
    assert run.succeeded, run.error
    assert run.changed_ops == []
    assert not any("daemon-reload" in c for c in run.executed_commands)
