"""work_app backup, restore and remove against the fake connector."""

import shlex
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.services.work_app import (
    WorkAppBackupConfig,
    WorkAppRemoveConfig,
    WorkAppRestoreConfig,
    deploy_work_app_backup,
    deploy_work_app_remove,
    deploy_work_app_restore,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

STAMP = "20261015T101500"
BACKUP = f"/opt/backups/work_app/manual-{STAMP}"
SITE = "/home/work/site"
EXISTS = {
    "test -e /home/work/site &&": ["yes"],
    "test -e /home/work/site/db.sqlite3 &&": ["yes"],
    "test -e /home/work/site/staticfiles &&": ["yes"],
    "test -e /home/work/site/.env &&": ["yes"],
    "test -e /etc/systemd/system/work-app.service &&": ["yes"],
    "test -e /etc/traefik/dynamic/work-app.yml &&": ["yes"],
}


def backup(cfg: WorkAppBackupConfig, extra: dict[str, Any] | None = None, *, exists: bool = True) -> FakeRun:
    responses = {"date +%Y%m%dT%H%M%S": [STAMP], **(EXISTS if exists else {}), **(extra or {})}
    return run_deploy_fake(deploy_work_app_backup, cfg, responses=responses)


def test_backup_writes_the_roles_layout(tmp_path: Path) -> None:
    run = backup(WorkAppBackupConfig(local_dir=tmp_path / "local", ops_library_version="2.31.40"))

    assert run.succeeded, run.error
    commands = run.executed_commands
    for path in (BACKUP, *(f"{BACKUP}/{sub}" for sub in ("database", "static", "configs", "env"))):
        assert f"work_app backup | Ensure {path}" in run.changed_ops or any(path in c for c in commands)
    hot = next(c for c in commands if ".backup '$tgt'" in c)
    assert f"db=/home/work/site/db.sqlite3 tgt={BACKUP}/database/db.sqlite3 mode={BACKUP}/database/.mode" in hot
    assert 'sqlite3 "$db" ".timeout 30000" ".backup \'$tgt\'"' in hot
    assert '[ "$out" = ok ]' in hot  # the copy's integrity check, exactly ``ok``
    assert "seq 1 3" in hot
    assert 'systemctl stop "$unit"' in hot  # the offline fallback
    assert f"rsync -a --delete /home/work/site/staticfiles/ {BACKUP}/static/" in commands
    assert f"install -o root -g root -m 0600 /home/work/site/.env {BACKUP}/env/.env" in commands
    assert (
        f"install -o root -g root -m 0600 /etc/systemd/system/work-app.service {BACKUP}/configs/work-app.service"
        in commands
    )
    assert f"install -o root -g root -m 0600 /etc/traefik/dynamic/work-app.yml {BACKUP}/configs/traefik.yml" in commands
    metadata = next(c for c in commands if "metadata.yml" in c and "cat >" in c)
    for line in (
        'slug: "work_app"',
        f'timestamp: "{STAMP}"',
        'host: "macmini"',
        'ops_library_version: "2.31.40"',
        'sqlite_mode: "$MODE"',
        "include_static: True",
        'database_path: "/home/work/site/db.sqlite3"',
    ):
        assert line in metadata
    manifest = next(c for c in commands if "manifest.sha256" in c)
    assert "find . -type f ! -name manifest.sha256 -print0 | sort -z | xargs -0 sha256sum" in manifest
    assert (
        f"(umask 077 && tar -C /opt/backups/work_app -czf {BACKUP}.tar.gz manual-{STAMP}) && chmod 0600 {BACKUP}.tar.gz"
    ) in commands
    assert "work_app backup | Fetch the backup archive" in run.changed_ops
    assert (tmp_path / "local").stat().st_mode & 0o777 == 0o700


def test_backup_requires_the_site() -> None:
    run = backup(WorkAppBackupConfig(), exists=False)

    assert "must exist on the target host" in str(run.error)
    assert run.executed_commands == []


def test_backup_without_a_database_records_it_as_missing() -> None:
    present = {k: v for k, v in EXISTS.items() if "db.sqlite3" not in k}
    run = run_deploy_fake(
        deploy_work_app_backup,
        WorkAppBackupConfig(fetch_local=False),
        responses={"date +%Y%m%dT%H%M%S": [STAMP], **present},
    )

    assert run.succeeded, run.error
    assert not any("sqlite3" in c and ".backup" in c for c in run.executed_commands)
    metadata = next(c for c in run.executed_commands if "cat >" in c)
    assert 'MODE="missing"' in metadata


def test_force_stop_goes_straight_to_the_offline_copy() -> None:
    run = backup(WorkAppBackupConfig(force_stop=True, fetch_local=False))

    copy = next(c for c in run.executed_commands if "systemctl stop" in c)
    assert ".backup" not in copy
    assert """trap 'rc=$?; systemctl start "$unit" || rc=1; """ in copy
    assert "unit=work-app.service;" in copy


def test_backup_options_leave_parts_out() -> None:
    cfg = WorkAppBackupConfig(
        include_static=False,
        include_env=False,
        include_systemd=False,
        include_traefik=False,
        manifest=False,
        create_archive=False,
    )

    run = backup(cfg)

    commands = " ".join(run.executed_commands)
    assert "rsync" not in commands
    assert "install -o root" not in commands
    assert "manifest.sha256" not in commands
    assert "tar -C" not in commands
    assert "include_env: False" in commands


def test_backup_validation() -> None:
    with pytest.raises(ValidationError):
        WorkAppBackupConfig(prefix="a b")
    with pytest.raises(ValidationError):
        WorkAppBackupConfig(root="/opt/x;rm")


# -- restore ------------------------------------------------------------

ARCHIVE = f"/opt/backups/work_app/manual-{STAMP}.tar.gz"
PAYLOAD = f"manual-{STAMP}"
LISTING = [
    f"{PAYLOAD}/",
    f"{PAYLOAD}/database/",
    f"{PAYLOAD}/database/db.sqlite3",
    f"{PAYLOAD}/static/",
    f"{PAYLOAD}/static/a.css",
    f"{PAYLOAD}/configs/",
    f"{PAYLOAD}/configs/work-app.service",
    f"{PAYLOAD}/configs/traefik.yml",
    f"{PAYLOAD}/env/",
    f"{PAYLOAD}/env/.env",
    f"{PAYLOAD}/metadata.yml",
    f"{PAYLOAD}/manifest.sha256",
]
METADATA = [
    'slug: "work_app"',
    f'timestamp: "{STAMP}"',
    'host: "macmini"',
    'ops_library_version: "2.31.40"',
    'sqlite_mode: "hot"',
]


def restore_responses(**changes: Any) -> dict[str, Any]:
    responses: dict[str, Any] = {
        "find /opt/backups/work_app -maxdepth 1": [f"1760000000.5 {ARCHIVE}"],
        f"test -f {ARCHIVE}": ["yes"],
        f"tar -tzf {ARCHIVE}": LISTING,
        f"tar -xzOf {ARCHIVE} {PAYLOAD}/metadata.yml": METADATA,
        "date +%Y%m%dT%H%M%S": ["20261015T120000"],
    }
    responses.update(changes)
    return responses


def restore(cfg: WorkAppRestoreConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    return run_deploy_fake(deploy_work_app_restore, cfg, responses=responses or restore_responses())


def cfg_restore(**changes: Any) -> WorkAppRestoreConfig:
    return WorkAppRestoreConfig(ops_library_version="2.31.40", **changes)


def staged(command: str, staging: str = "/tmp/work-app-restore") -> str:
    """A step while the staging directory exists: a failure removes it (``cleanup``)."""

    return f"( {command} ) || {{ rc=$?; rm -rf {staging}; exit $rc; }}"


def test_restore_of_the_latest_archive_runs_the_roles_sequence() -> None:
    run = restore(cfg_restore())

    assert run.succeeded, run.error
    commands = run.executed_commands
    staging = "/tmp/work-app-restore"
    payload = f"{staging}/{PAYLOAD}"
    expected = [
        f"rm -rf {staging} && mkdir -m 0700 {staging}",
        staged(f"tar -xzf {ARCHIVE} -C {staging}"),
        staged(f"cd {payload} && sha256sum -c manifest.sha256"),
        staged("systemctl stop work-app.service"),
        staged(
            "install -d -o work -g work -m 0750 /home/work/site.pre-restore-20261015T120000 && "
            "rsync -a /home/work/site/ /home/work/site.pre-restore-20261015T120000/"
        ),
        staged("install -d -o work -g work -m 0750 /home/work/site/staticfiles"),
        staged(f"rsync -a --delete {payload}/static/ /home/work/site/staticfiles/"),
        staged(
            "rm -f /home/work/site/db.sqlite3-wal /home/work/site/db.sqlite3-shm /home/work/site/db.sqlite3-journal"
        ),
        staged(f"install -o work -g work -m 0600 {payload}/database/db.sqlite3 /home/work/site/db.sqlite3"),
        staged(f"install -o work -g work -m 0600 {payload}/env/.env /home/work/site/.env"),
    ]
    positions = [commands.index(c) for c in expected]
    assert positions == sorted(positions)
    assert any("manage.py check --deploy" in c for c in commands)
    assert any("manage.py showmigrations" in c for c in commands)
    assert any("PRAGMA integrity_check" in c for c in commands)
    restart = commands.index("systemctl restart work-app.service")
    assert commands.index(expected[-1]) < restart
    # The staging directory goes right after the last step that reads it (the Traefik config).
    removal = commands.index(f"rm -rf {staging}")
    route = next(i for i, c in enumerate(commands) if "traefik.yml" in c and "cmp -s" in c)
    assert removal == route + 1
    assert removal < commands.index("systemctl restart work-app.service")
    assert commands[-1] == (
        "if [ -d /home/work/site.pre-restore-20261015T120000 ]; then echo 'Pre-restore copy of /home/work/site "
        "(database and .env included) kept at /home/work/site.pre-restore-20261015T120000. Nothing removes it; "
        "prune it by hand once the restored Work app is confirmed.'; fi"
    )
    assert "chown -R work:work /home/work/site/staticfiles" in commands


def test_restore_applies_unit_and_route_only_when_they_differ() -> None:
    run = restore(cfg_restore())

    unit = next(c for c in run.executed_commands if "work-app.service" in c and "cmp -s" in c)
    assert "systemctl daemon-reload" in unit
    route = next(c for c in run.executed_commands if "traefik.yml" in c and "cmp -s" in c)
    assert "systemctl reload traefik || true" in route
    assert "644 root root" in route


def test_dry_run_unpacks_and_checks_but_changes_nothing_else() -> None:
    run = restore(cfg_restore(dry_run=True))

    commands = run.executed_commands
    assert any("sha256sum -c" in c for c in commands)
    assert not any("systemctl" in c or "install" in c for c in commands)
    assert commands[-1] == "rm -rf /tmp/work-app-restore"


def test_the_pre_restore_copy_is_kept_unless_deletion_is_asked_for() -> None:
    snapshot = "/home/work/site.pre-restore-20261015T120000"

    # work_app_restore_safe_snapshot_delete defaults to false (ops-library a811bc16).
    assert WorkAppRestoreConfig().safe_snapshot_delete is False
    kept = restore(cfg_restore())
    assert f"rm -rf {snapshot}" not in kept.executed_commands
    assert "work_app restore | Report the kept pre-restore copy " + snapshot in kept.changed_ops
    assert "work_app restore | Report the kept pre-restore copy " + snapshot not in kept.mutating_changed_ops
    deleted = restore(cfg_restore(safe_snapshot_delete=True))
    assert f"rm -rf {snapshot}" in deleted.executed_commands


def test_cleanup_and_snapshot_flags() -> None:
    run = restore(cfg_restore(cleanup=False, safe_snapshot_delete=False))

    assert not any(c.startswith("rm -rf") and "pre-restore" in c for c in run.executed_commands)
    assert not any("rm -rf /tmp/work-app-restore" in c for c in run.executed_commands[1:])
    none = restore(cfg_restore(create_safe_snapshot=False))
    assert not any("pre-restore" in c for c in none.executed_commands)


def test_explicit_archive_name_is_taken_below_the_root() -> None:
    responses = restore_responses()
    run = restore(cfg_restore(archive=f"manual-{STAMP}.tar.gz"), responses)

    assert run.succeeded, run.error
    assert any(f"tar -xzf {ARCHIVE}" in c for c in run.executed_commands)


def test_missing_archive_is_refused() -> None:
    run = restore(
        cfg_restore(archive="gone.tar.gz"), restore_responses(**{"test -f /opt/backups/work_app/gone.tar.gz": []})
    )

    assert "does not exist" in str(run.error)
    assert run.executed_commands == []


def test_no_archives_is_refused() -> None:
    run = restore(cfg_restore(), restore_responses(**{"find /opt/backups/work_app -maxdepth 1": []}))

    assert "no work app backup archives" in str(run.error)


def test_wrong_slug_is_refused_before_any_change() -> None:
    meta = [line.replace("work_app", "homelab") if "slug" in line else line for line in METADATA]
    run = restore(cfg_restore(), restore_responses(**{f"tar -xzOf {ARCHIVE} {PAYLOAD}/metadata.yml": meta}))

    assert "does not match expected slug" in str(run.error)
    assert run.executed_commands == []


def test_missing_metadata_field_is_refused() -> None:
    meta = [line for line in METADATA if not line.startswith("host")]
    run = restore(cfg_restore(), restore_responses(**{f"tar -xzOf {ARCHIVE} {PAYLOAD}/metadata.yml": meta}))

    assert "missing required field 'host'" in str(run.error)
    assert run.executed_commands == []


def test_version_mismatch_is_refused_unless_allowed() -> None:
    run = restore(WorkAppRestoreConfig(ops_library_version="2.99.0"))
    assert "ops-library 2.31.40" in str(run.error)
    assert run.executed_commands == []

    allowed = restore(WorkAppRestoreConfig(ops_library_version="2.99.0", allow_version_mismatch=True))
    assert allowed.succeeded, allowed.error


def test_unreadable_metadata_is_refused() -> None:
    run = restore(cfg_restore(), restore_responses(**{f"tar -xzOf {ARCHIVE} {PAYLOAD}/metadata.yml": []}))

    assert "no readable metadata.yml" in str(run.error)


def test_archive_without_payload_directory_is_refused() -> None:
    run = restore(cfg_restore(), restore_responses(**{f"tar -tzf {ARCHIVE}": ["loose-file"]}))

    assert "expected payload directory" in str(run.error)


def test_payload_falls_back_to_the_first_directory() -> None:
    renamed = [line.replace(PAYLOAD, "other-name") for line in LISTING]
    responses = restore_responses(
        **{
            f"tar -tzf {ARCHIVE}": renamed,
            f"tar -xzOf {ARCHIVE} other-name/metadata.yml": METADATA,
        }
    )

    run = restore(cfg_restore(), responses)

    assert run.succeeded, run.error
    assert any("cd /tmp/work-app-restore/other-name && sha256sum -c" in c for c in run.executed_commands)


def test_archive_without_a_database_leaves_it_alone() -> None:
    listing = [line for line in LISTING if "database" not in line]
    run = restore(cfg_restore(), restore_responses(**{f"tar -tzf {ARCHIVE}": listing}))

    assert run.succeeded, run.error
    commands = " ".join(run.executed_commands)
    assert "db.sqlite3" not in commands
    assert "PRAGMA" not in commands


def test_env_and_static_options() -> None:
    run = restore(cfg_restore(restore_env=False, rebuild_static=True, fix_permissions=False, verify_http=False))

    commands = run.executed_commands
    assert not any("env/.env" in c for c in commands)
    assert not any("/static/" in c for c in commands)
    assert any("manage.py collectstatic --noinput" in c for c in commands)
    assert not any(c.startswith("chown -R") for c in commands)
    assert not any("curl" in c for c in commands)


def test_failing_step_stops_the_restore_after_the_stop() -> None:
    responses = restore_responses(**{"systemctl restart work-app.service": {"success": False}})
    run = restore(cfg_restore(), responses)

    assert not run.succeeded
    assert run.executed_commands[-1] == "systemctl restart work-app.service"
    # The staging directory was already gone: nothing after the Traefik config reads it.
    assert "rm -rf /tmp/work-app-restore" in run.executed_commands


@pytest.mark.parametrize("cleanup", [True, False])
def test_a_failing_step_removes_the_staging_directory_with_cleanup(cleanup: bool) -> None:
    stop = staged("systemctl stop work-app.service") if cleanup else "systemctl stop work-app.service"
    run = restore(cfg_restore(cleanup=cleanup), restore_responses(**{stop: {"success": False}}))

    assert not run.succeeded
    assert run.executed_commands[-1] == stop
    assert ("rm -rf /tmp/work-app-restore; exit $rc" in stop) is cleanup


def test_expected_content_is_checked() -> None:
    run = restore(cfg_restore(expected_content="Sign in"))

    check = next(c for c in run.executed_commands if "did not answer as expected" in c)
    assert "grep -qF 'Sign in'" in shlex.split(check)[-1]


# -- remove -------------------------------------------------------------


def remove(cfg: WorkAppRemoveConfig, extra: dict[str, Any] | None = None) -> FakeRun:
    responses: dict[str, Any] = {
        "test -e /etc/systemd/system/work-app.service &&": ["yes"],
        "test -e /home/work/site/db.sqlite3 &&": ["yes"],
        "test -e /home/work/site/db.sqlite3-wal &&": ["yes"],
        "test -e /home/work &&": ["yes"],
        "getent group work": ["work:x:999:"],
        **fakehost.LINUX,
        **fakehost.system_account("work", "/home/work"),
        **fakehost.directory("/home/work", user="work"),
        **fakehost.file("/etc/systemd/system/work-app.service", "unit"),
        **fakehost.file("/etc/traefik/dynamic/work-app.yml", "route"),
        **fakehost.file("/home/work/site/db.sqlite3", "db", user="work"),
        **fakehost.file("/home/work/site/db.sqlite3-wal", "wal", user="work"),
        **(extra or {}),
    }
    return run_deploy_fake(deploy_work_app_remove, cfg, responses=responses)


def test_remove_requires_confirmation() -> None:
    run = remove(WorkAppRemoveConfig())

    assert "removal blocked" in str(run.error)
    assert run.executed_commands == []


def test_remove_everything() -> None:
    run = remove(WorkAppRemoveConfig(confirm=True, auto_confirm=True))

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "systemctl stop work-app.service || true" in commands
    assert "systemctl disable work-app.service || true" in commands
    assert "rm -f /etc/systemd/system/work-app.service" in commands
    assert "systemctl daemon-reload" in commands
    assert "rm -f /etc/traefik/dynamic/work-app.yml" in commands
    assert "rm -f /home/work/site/db.sqlite3" in commands
    assert "rm -f /home/work/site/db.sqlite3-wal" in commands
    assert not any("db.sqlite3-shm" in c for c in commands)
    assert "userdel -r work && [ ! -e /home/work ]" in commands
    assert "if getent group work >/dev/null; then groupdel work; fi" in commands
    # The user module removes the home directory, so no separate removal.
    assert not any(c == "rm -rf /home/work" for c in commands)


def test_remove_database_asks_without_auto_confirm() -> None:
    run = remove(WorkAppRemoveConfig(confirm=True))

    # Under pytest there is no terminal to ask on.
    assert not run.succeeded
    assert not any("userdel" in c for c in run.executed_commands)


def test_keeping_the_database_keeps_home_and_user() -> None:
    run = remove(WorkAppRemoveConfig(confirm=True, remove_database=False, remove_home=False, remove_user=False))

    assert run.succeeded, run.error
    commands = run.executed_commands
    assert "rm -f /etc/systemd/system/work-app.service" in commands
    assert not any("db.sqlite3" in c or "userdel" in c or "groupdel" in c for c in commands)


@pytest.mark.parametrize(
    "flags",
    [
        {"remove_database": False},
        {"remove_database": False, "remove_user": False},
        {"remove_database": False, "remove_home": False},
    ],
)
def test_keeping_the_database_while_removing_its_home_is_refused(flags: dict[str, bool]) -> None:
    run = remove(WorkAppRemoveConfig(confirm=True, **flags))

    assert "lives inside" in str(run.error)
    assert run.executed_commands == []


def test_home_is_removed_when_the_user_stays() -> None:
    run = remove(WorkAppRemoveConfig(confirm=True, auto_confirm=True, remove_user=False))

    assert "rm -rf /home/work" in run.executed_commands
    assert not any("userdel" in c for c in run.executed_commands)


def test_traefik_config_can_stay() -> None:
    run = remove(WorkAppRemoveConfig(confirm=True, auto_confirm=True, remove_traefik_config=False))

    assert "rm -f /etc/traefik/dynamic/work-app.yml" not in run.executed_commands


def test_removing_an_already_removed_app_changes_nothing() -> None:
    responses = {
        **fakehost.LINUX,
        "cat /etc/passwd | cut": ["root:x:0:0:root:/root:/bin/bash|root|root||!"],
    }
    run = run_deploy_fake(
        deploy_work_app_remove, WorkAppRemoveConfig(confirm=True, auto_confirm=True), responses=responses
    )

    assert run.succeeded, run.error
    assert run.executed_commands == []


def test_home_is_removed_even_when_the_user_is_already_gone() -> None:
    responses = {
        **fakehost.LINUX,
        "test -e /home/work &&": ["yes"],
        **fakehost.directory("/home/work", user="work"),
        "cat /etc/passwd | cut": ["root:x:0:0:root:/root:/bin/bash|root|root||!"],
    }
    run = run_deploy_fake(
        deploy_work_app_remove, WorkAppRemoveConfig(confirm=True, auto_confirm=True), responses=responses
    )

    assert run.succeeded, run.error
    assert run.executed_commands == ["rm -rf /home/work"]


def test_a_failed_config_install_is_not_masked_by_the_follow_up() -> None:
    run = restore(cfg_restore())

    unit = next(c for c in run.executed_commands if "cmp -s" in c and "work-app.service" in c)
    assert "&& { systemctl daemon-reload; }" in unit
