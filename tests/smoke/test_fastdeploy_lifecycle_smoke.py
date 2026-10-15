"""FastDeploy backup, restore and removal on the smoke target.

Deploys FastDeploy (``test_fastdeploy_smoke``'s fixture, with a registered
service and a runner), backs it up with a marker table, loses the marker and
the registered service, and restores the archive. A broken archive (no env
file) then fails the restore, which rolls back to its safety backup. Finally
FastDeploy is removed twice (the second run changes nothing) and deployed again.
"""

from __future__ import annotations

import shlex
import tarfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.services.fastdeploy import (
    FastdeployBackupConfig,
    FastdeployRemoveConfig,
    FastdeployRestoreConfig,
    deploy_fastdeploy,
    deploy_fastdeploy_backup,
    deploy_fastdeploy_remove,
    deploy_fastdeploy_restore,
)
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost
from tests.smoke.test_fastdeploy_smoke import REGISTERED, RUNNER, SITE, Deployed, deployed

__all__ = ["deployed"]  # the module fixture, deployed once more here

ROOT = "/opt/backups/fastdeploy"
PSQL = "cd / && runuser -u postgres -- psql -XAtq -d fastdeploy"


def marker(smoke_host: SmokeHost) -> str:
    return smoke_host.out(f"{PSQL} -c \"SELECT to_regclass('public.smoke_marker') IS NOT NULL\"")


@dataclass(frozen=True)
class Cycle:
    archive: Path
    backup: SshRun
    restore: SshRun
    restored_marker: str
    restored_registration: bool
    stage_left: str
    runner_marker: str
    restored_services: str
    failed_restore: SshRun
    marker_after_rollback: str
    remove: SshRun
    remove_again: SshRun


def run(smoke_host: SmokeHost, label: str, fn: object, *args: object, ok: bool = True) -> SshRun:
    result = run_deploy_ssh(fn, *args, host_name=smoke_host.name, host_data=smoke_host.host_data)  # type: ignore[arg-type]
    TIMINGS[f"fastdeploy {label}"] = result.seconds
    if ok:
        assert result.succeeded, (label, result.error, [op.name for op in result.ops if not op.succeeded])
    return result


@pytest.fixture(scope="module")
def cycle(smoke_host: SmokeHost, deployed: Deployed, tmp_path_factory: pytest.TempPathFactory) -> Cycle:
    local = tmp_path_factory.mktemp("fastdeploy-backups")
    secrets = deployed.secrets
    # pg_dump runs as postgres and writes below /opt/backups, which is 0755 on
    # macmini; a nyxmon backup that created it first leaves it 0700, as the role does.
    smoke_host.run("install -d -m 0755 /opt/backups && chmod 0755 /opt/backups")
    # The registered service goes into the database too, as a real registration
    # does, so the restore's service count check has something to compare.
    sync = "set -a; . ./.env.shell; set +a; exec .venv/bin/python commands.py syncservices"
    smoke_host.run(f"cd {SITE} && runuser -u fastdeploy -- sh -c {shlex.quote(sync)}")
    smoke_host.run(f"{PSQL} -c 'DROP TABLE IF EXISTS smoke_marker' -c 'CREATE TABLE smoke_marker AS SELECT 1 AS x'")
    backup_cfg = FastdeployBackupConfig(host_name="smoke", prefix="smoke", local_dir=local)
    backup = run(smoke_host, "backup", deploy_fastdeploy_backup, backup_cfg, secrets)
    (archive,) = local.glob("smoke-*.tar.gz")

    smoke_host.run(f"{PSQL} -c 'DROP TABLE smoke_marker' && rm -rf {REGISTERED}")
    restore_cfg = FastdeployRestoreConfig(host_name="smoke", archive=archive.name)
    restore = run(smoke_host, "restore", deploy_fastdeploy_restore, restore_cfg, secrets)
    restored_marker = marker(smoke_host)
    restored_registration = smoke_host.run(f"test -x {REGISTERED}/deploy.sh", check=False).returncode == 0
    stage_left = smoke_host.out("ls -A /tmp/fastdeploy-restore")
    runner_marker = smoke_host.out(f"cat {RUNNER}/marker")
    restored_services = smoke_host.out(f"{PSQL} -c 'SELECT COUNT(*) FROM service'")

    # An archive without the env file: the restore fails after dropping the
    # database and rolls back to the safety backup it took first.
    name = archive.name.removesuffix(".tar.gz")
    smoke_host.run(
        f"set -e; tmp=$(mktemp -d); tar -C $tmp -xzf {ROOT}/{name}.tar.gz; "
        f"mv $tmp/{name} $tmp/broken-{name}; rm $tmp/broken-{name}/config/fastdeploy.env; "
        f"cd $tmp/broken-{name} && find . -type f ! -name manifest.sha256 -print0 | sort -z "
        "| xargs -0 sha256sum > manifest.sha256; "
        f"tar -C $tmp -czf {ROOT}/broken-{name}.tar.gz broken-{name}; rm -rf $tmp"
    )
    broken = restore_cfg.model_copy(update={"archive": f"broken-{name}.tar.gz"})
    failed_restore = run(smoke_host, "failed restore", deploy_fastdeploy_restore, broken, secrets, ok=False)
    marker_after_rollback = marker(smoke_host)
    smoke_host.run(f"rm -f {ROOT}/broken-{name}.tar.gz")

    remove_cfg = FastdeployRemoveConfig(confirm=True)
    remove = run(smoke_host, "remove", deploy_fastdeploy_remove, remove_cfg)
    remove_again = run(smoke_host, "remove again", deploy_fastdeploy_remove, remove_cfg)
    run(smoke_host, "deploy after remove", deploy_fastdeploy, deployed.cfg, secrets)
    return Cycle(
        archive,
        backup,
        restore,
        restored_marker,
        restored_registration,
        stage_left,
        runner_marker,
        restored_services,
        failed_restore,
        marker_after_rollback,
        remove,
        remove_again,
    )


def test_backup_archive_has_the_role_layout(cycle: Cycle) -> None:
    name = cycle.archive.name.removesuffix(".tar.gz")
    with tarfile.open(cycle.archive) as archive:
        names = set(archive.getnames())
    for entry in (
        "metadata.yml",
        "manifest.sha256",
        "database/fastdeploy.sql",
        "config/fastdeploy.env",
        "systemd/fastdeploy.service",
        "services/smoke-registered/deploy.sh",
        "deploy_runners/smoke-registered/marker",
    ):
        assert f"{name}/{entry}" in names, entry


def test_backup_directories_are_shared_with_postgres_only(smoke_host: SmokeHost, cycle: Cycle) -> None:
    name = cycle.archive.name.removesuffix(".tar.gz")
    listing = smoke_host.out(f"stat -c '%a %U %G' {ROOT} {ROOT}/{name} {ROOT}/{name}/database")
    assert listing.splitlines() == ["750 root postgres", "750 root postgres", "750 postgres postgres"]


def test_restore_brings_database_and_registrations_back(smoke_host: SmokeHost, cycle: Cycle) -> None:
    assert cycle.restored_marker == "t"
    assert cycle.restored_registration
    assert cycle.runner_marker == "runner"
    assert cycle.stage_left == ""
    assert smoke_host.out(f"ls -d {ROOT}/pre-restore-*.tar.gz | wc -l") != "0"


def test_restore_passed_the_service_count_check(cycle: Cycle) -> None:
    # The metadata counts one registered service; the restore checks the table against it.
    assert cycle.restored_services == "1"


def test_failed_restore_rolls_back_to_the_safety_backup(smoke_host: SmokeHost, cycle: Cycle) -> None:
    assert not cycle.failed_restore.succeeded
    assert cycle.marker_after_rollback == "t"


def test_remove_removes_everything_and_converges(smoke_host: SmokeHost, cycle: Cycle) -> None:
    assert "Remove FastDeploy | Drop database fastdeploy" in cycle.remove.changed_ops
    assert cycle.remove_again.changed_ops == []


def test_deploy_after_remove_runs(smoke_host: SmokeHost, cycle: Cycle) -> None:
    assert smoke_host.out("systemctl is-active fastdeploy") == "active"
