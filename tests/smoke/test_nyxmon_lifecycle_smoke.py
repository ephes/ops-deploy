"""nyxmon backup, restore and removal on the smoke target.

Deploys nyxmon (``test_nyxmon_smoke``'s fixture), backs it up with a marker
account and media file, loses both, restores the archive, then removes nyxmon
twice (the second run changes nothing) and deploys it again.
"""

from __future__ import annotations

import shlex
import tarfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from ops_deploy.services.nyxmon import (
    NyxmonBackupConfig,
    NyxmonRemoveConfig,
    NyxmonRestoreConfig,
    deploy_nyxmon,
    deploy_nyxmon_backup,
    deploy_nyxmon_remove,
    deploy_nyxmon_restore,
)
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost
from tests.smoke.test_nyxmon_smoke import Deployed, deployed

__all__ = ["deployed"]  # the module fixture, deployed once more here

SITE = "/home/nyxmon/site"
MARKER = "smoke-lifecycle-marker"
MEDIA = f"{SITE}/media/smoke-lifecycle.txt"


def manage(smoke_host: SmokeHost, code: str) -> str:
    shell = f"set -a; . ./.env.shell; set +a; exec .venv/bin/python manage.py shell -c {shlex.quote(code)}"
    out = smoke_host.out(f"cd {SITE} && runuser -u nyxmon -- sh -c {shlex.quote(shell)}")
    return out.splitlines()[-1] if out else ""


def marker_exists(smoke_host: SmokeHost) -> bool:
    code = f"from django.contrib.auth.models import User; print(User.objects.filter(username={MARKER!r}).exists())"
    return manage(smoke_host, code) == "True"


@dataclass(frozen=True)
class Cycle:
    archive: Path
    backup: SshRun
    dry_run: SshRun
    restore: SshRun
    restored_marker: bool
    restored_media: str
    leftovers: str
    remove: SshRun
    remove_again: SshRun
    redeploy: SshRun


def run(smoke_host: SmokeHost, label: str, fn: object, *args: object) -> SshRun:
    result = run_deploy_ssh(fn, *args, host_name=smoke_host.name, host_data=smoke_host.host_data)  # type: ignore[arg-type]
    TIMINGS[f"nyxmon {label}"] = result.seconds
    assert result.succeeded, (label, result.error, [op.name for op in result.ops if not op.succeeded])
    return result


@pytest.fixture(scope="module")
def cycle(smoke_host: SmokeHost, deployed: Deployed, tmp_path_factory: pytest.TempPathFactory) -> Cycle:
    local = tmp_path_factory.mktemp("nyxmon-backups")
    manage(smoke_host, f"from django.contrib.auth.models import User; User.objects.get_or_create(username={MARKER!r})")
    smoke_host.run(
        f"install -d -o nyxmon -g nyxmon {SITE}/media && echo lifecycle > {MEDIA} && chown nyxmon:nyxmon {MEDIA}"
    )
    backup = run(
        smoke_host,
        "backup",
        deploy_nyxmon_backup,
        NyxmonBackupConfig(host_name="smoke", prefix="smoke", local_dir=local),
    )
    (archive,) = local.glob("smoke-*.tar.gz")

    manage(
        smoke_host, f"from django.contrib.auth.models import User; User.objects.filter(username={MARKER!r}).delete()"
    )
    smoke_host.run(f"rm -f {MEDIA}")
    dry_run = run(
        smoke_host, "restore dry run", deploy_nyxmon_restore, NyxmonRestoreConfig(host_name="smoke", dry_run=True)
    )
    assert not marker_exists(smoke_host), "a dry run restored data"
    restore = run(smoke_host, "restore", deploy_nyxmon_restore, NyxmonRestoreConfig(host_name="smoke"))
    restored_marker = marker_exists(smoke_host)
    restored_media = smoke_host.out(f"cat {MEDIA}")
    leftovers = smoke_host.out(f"ls -A /tmp/nyxmon-restore; ls -d {SITE}.pre-restore-* 2>/dev/null || true")

    remove_cfg = NyxmonRemoveConfig(confirm=True)
    remove = run(smoke_host, "remove", deploy_nyxmon_remove, remove_cfg)
    remove_again = run(smoke_host, "remove again", deploy_nyxmon_remove, remove_cfg)
    redeploy = run(smoke_host, "deploy after remove", deploy_nyxmon, deployed.cfg, deployed.secrets)
    return Cycle(
        archive, backup, dry_run, restore, restored_marker, restored_media, leftovers, remove, remove_again, redeploy
    )


def test_backup_archive_has_the_role_layout(cycle: Cycle) -> None:
    name = cycle.archive.name.removesuffix(".tar.gz")
    with tarfile.open(cycle.archive) as archive:
        names = set(archive.getnames())
    for entry in ("metadata.yml", "manifest.sha256", "database/db.sqlite3", "config/.env", "media/smoke-lifecycle.txt"):
        assert f"{name}/{entry}" in names, entry
    assert cycle.archive.parent.stat().st_mode & 0o777 == 0o700


def test_backup_leaves_private_root_owned_copies(smoke_host: SmokeHost, cycle: Cycle) -> None:
    name = cycle.archive.name.removesuffix(".tar.gz")
    listing = smoke_host.out(f"stat -c '%a %U' /opt/backups/nyxmon /opt/backups/nyxmon/{name}/database/db.sqlite3")
    assert listing.splitlines() == ["700 root", "600 root"]


def test_restore_brings_data_back_and_cleans_up(smoke_host: SmokeHost, cycle: Cycle) -> None:
    assert cycle.restored_marker
    assert cycle.restored_media == "lifecycle"
    # Neither the staging directory nor the safety snapshot is left.
    assert cycle.leftovers == ""
    assert cycle.dry_run.changed_ops == ["nyxmon restore | Restore nyxmon (dry run)"]


def test_remove_removes_everything_and_converges(smoke_host: SmokeHost, cycle: Cycle) -> None:
    assert "Remove nyxmon | Remove /home/nyxmon" in cycle.remove.changed_ops
    assert cycle.remove_again.changed_ops == []


def test_deploy_after_remove_runs(smoke_host: SmokeHost, cycle: Cycle) -> None:
    for unit in ("nyxmon", "nyxmon-monitor"):
        assert smoke_host.out(f"systemctl is-active {unit}") == "active"
