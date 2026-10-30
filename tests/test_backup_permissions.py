"""Backup permissions and restored directory modes against real local files."""

from __future__ import annotations

import os
import shlex
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from ops_deploy.services._lifecycle import COMMON, archive_permissions, script
from ops_deploy.services.fastdeploy import FastdeployBackupConfig
from ops_deploy.services.fastdeploy.lifecycle import LIFECYCLE, backup_values
from ops_deploy.services.nyxmon.lifecycle import FILES


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.parametrize("wanted", ["0600", "0640"])
def test_archive_restriction_is_bounded_and_repeat_preserves_ctime(tmp_path: Path, wanted: str) -> None:
    root = tmp_path / "backups with spaces"
    root.mkdir()
    archives = [root / name for name in ("old.tar", "old.tar.gz", "old.tar.zst", "old.tgz", "line\nbreak.tar.gz")]
    untouched = [root / "notes.txt", root / ".hidden.tar.gz", tmp_path / "outside.tar.gz"]
    (root / "snapshot").mkdir()
    untouched.append(root / "snapshot" / "nested.tar.gz")
    for path in [*archives, *untouched]:
        path.write_bytes(b"fixture archive contents\n")
        path.chmod(0o644)
    (root / "linked.tar.gz").symlink_to(untouched[2])
    command = archive_permissions(str(root), wanted)
    subprocess.run(["sh", "-ec", command], check=True, capture_output=True)
    assert all(mode(path) == int(wanted, 8) for path in archives)
    assert all(mode(path) == 0o644 for path in untouched)
    before = {path: path.stat().st_ctime_ns for path in archives}
    subprocess.run(["sh", "-ec", command], check=True, capture_output=True)
    assert {path: path.stat().st_ctime_ns for path in archives} == before
    assert all(path.read_bytes() == b"fixture archive contents\n" for path in [*archives, *untouched])


@pytest.mark.skipif(shutil.which("rsync") is None, reason="needs rsync, as on the target")
@pytest.mark.parametrize(
    ("fetch", "create", "wanted"), [(True, True, "0600"), (False, True, "0640"), (False, False, "0600")]
)
def test_fastdeploy_backup_restricts_old_and_new_archives(
    tmp_path: Path, fetch: bool, create: bool, wanted: str
) -> None:
    site = tmp_path / "site"
    (site / "services").mkdir(parents=True)
    (site / ".env").write_text("FIXTURE=not-a-real-secret\n")
    sudoers = tmp_path / "sudoers"
    sudoers.mkdir()
    root = tmp_path / "backups"
    root.mkdir()
    old = root / "legacy.tar.gz"
    old.write_bytes(b"old archive\n")
    old.chmod(0o644)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    umask_log = tmp_path / "tar-umask"
    wrappers = {
        "chown": "exit 0",
        "stat": "echo stub",
        "runuser": 'shift 3; exec "$@"',
        "pg_dump": "echo fixture-database-dump",
        "install": '''mode=644
while [ "$#" -gt 2 ]; do
    case "$1" in -o|-g) shift 2;; -m) mode=$2; shift 2;; *) exit 2;; esac
done
exec /usr/bin/install -m "$mode" "$@"''',
        "tar": f'umask > {shlex.quote(str(umask_log))}; exec {shlex.quote(shutil.which("tar") or "tar")} "$@"',
    }
    for name, body in wrappers.items():
        path = bindir / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)
    cfg = FastdeployBackupConfig(
        host_name="fixture",
        site_path=str(site),
        root=str(root),
        sudoers_dir=str(sudoers),
        deploy_home=str(tmp_path / "deploy"),
        disk_check=False,
        generate_checksums=False,
        report_size=False,
        units=(),
        traefik_config_path="",
        fetch_local=fetch,
        create_archive=create,
        archive_mode=wanted,
    )
    directory = root / "manual-20261029T120000"
    command = script(LIFECYCLE, backup_values(cfg, str(directory)), call="PGPW=\nfd_backup")
    result = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert mode(old) == int(wanted, 8)
    assert old.read_bytes() == b"old archive\n"
    artifact = Path(f"{directory}.tar.gz")
    if create:
        assert mode(artifact) == int(wanted, 8)
        assert int(umask_log.read_text().strip(), 8) == 0o077
    else:
        assert not artifact.exists()
        assert not umask_log.exists()


@pytest.mark.skipif(shutil.which("rsync") is None, reason="needs rsync, as on the target")
def test_nyxmon_restore_resets_rsync_destination_modes(tmp_path: Path) -> None:
    content = tmp_path / "snapshot"
    (content / "database").mkdir(parents=True)
    (content / "database" / "db.sqlite3").write_text("fixture database\n")
    site = tmp_path / "site"
    site.mkdir()
    directories = []
    for name in ("media", "static", "cache", "logs"):
        (content / name).mkdir(mode=0o700)
        (content / name / "payload").write_text(name)
        target = site / name
        directories.append(f"{name}:{target}")
    # Execute the production restore function with service/ownership boundaries stubbed.
    body = "restore() {" + (FILES / "restore.sh").read_text().split("\nrestore() {", 1)[1].split("\nset +e", 1)[0]
    command = "\n".join(
        [
            "set -euo pipefail",
            COMMON.read_text(),
            'set_attrs() { chmod "$3" "$4"; }',
            'copy_file() { cp "$4" "$5"; }',
            "start_services() { :; }",
            "STOP_ORDER=() CONFIGS=()",
            "OWNER=fixture GROUP=fixture VERIFY_SQLITE=0 SYSTEM_FILES=0 FIX_OWNERSHIP=0",
            f"content={shlex.quote(str(content))} DB={shlex.quote(str(site / 'db.sqlite3'))}",
            f"DIRS=({' '.join(shlex.quote(value) for value in directories)})",
            body,
            "restore",
        ]
    )
    result = subprocess.run(["bash", "-c", command], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    assert all(mode(site / name) == 0o755 for name in ("media", "static", "cache", "logs"))
    assert all((site / name / "payload").read_text() == name for name in ("media", "static", "cache", "logs"))
