"""Retired USB targets: replicas whose source is gone, destroyed on each drive before the sync."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.infra.backup import SnapshotRetention, SyncoidJob, UsbReplicationConfig
from ops_deploy.infra.backup.render import render
from tests import stubs

JOBS = (
    SyncoidJob(source="tank/photos", target="vault/photos", readonly=True),
    SyncoidJob(source="tank/replica/fast", target="vault/replica/fast", recursive=True, readonly=True),
)
RETENTION = (
    SnapshotRetention(
        source="tank/replica/fast/general", target="vault/replica/fast/general", keep_days=1, prefixes=("autosnap_",)
    ),
)
RETIRED = "vault/replica/fast/minio"


def config(**changes: Any) -> UsbReplicationConfig:
    values: dict[str, Any] = {
        "pool": "vault",
        "device": "/dev/disk/by-id/usb-owned",
        "jobs": JOBS,
        "snapshot_retention": RETENTION,
        "retired_targets": (RETIRED,),
        **changes,
    }
    return UsbReplicationConfig.model_validate(values)


def test_the_source_of_a_retired_target_is_its_place_below_the_recursive_job() -> None:
    assert config().retired_source(RETIRED) == "tank/replica/fast/minio"
    assert config(retired_targets=("vault/replica/fast/a/b",)).retired_source("vault/replica/fast/a/b") == (
        "tank/replica/fast/a/b"
    )


@pytest.mark.parametrize(
    ("retired", "message"),
    [
        (("other/replica/fast/minio",), "not a dataset of the pool"),
        (("vaultx/replica/fast/minio",), "not a dataset of the pool"),
        (("vault/minio",), "not below a recursive job's target"),
        # A non-recursive job's target or anything inside it.
        (("vault/photos/old",), "not below a recursive job's target"),
        # The recursive job's target itself, or one of its ancestors.
        (("vault/replica/fast",), "not below a recursive job's target"),
        (("vault/replica",), "not below a recursive job's target"),
        # A retention target, inside one, or containing one.
        (("vault/replica/fast/general",), "overlaps"),
        (("vault/replica/fast/general/child",), "overlaps"),
        ((RETIRED, RETIRED + "/child"), "overlaps"),
        ((RETIRED, RETIRED), "unique"),
        (("vault/replica/fast/*",), "validation error"),
        (("vault/replica/fast/a b",), "validation error"),
        (("vault/replica/fast/",), "validation error"),
        (("vault/replica/fast/../x",), "validation error"),
    ],
)
def test_a_retired_target_that_could_hit_live_data_is_refused(retired: tuple[str, ...], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        config(retired_targets=retired)


def test_a_retired_target_containing_another_job_target_is_refused() -> None:
    nested = (*JOBS, SyncoidJob(source="tank/other", target="vault/replica/fast/minio/keep"))
    with pytest.raises(ValidationError, match="overlaps"):
        config(jobs=nested)


def test_retired_targets_need_the_pool() -> None:
    with pytest.raises(ValidationError, match="require the pool"):
        UsbReplicationConfig(enabled=False, retired_targets=(RETIRED,))


def test_without_retired_targets_the_script_is_unchanged() -> None:
    script = render(config(retired_targets=()), "zfs-usb-replication.sh")

    assert "destroy" not in script
    assert "dataset_exists" not in script


def test_retired_targets_are_destroyed_after_the_import_and_before_any_sync() -> None:
    script = render(config(), "zfs-usb-replication.sh")

    body = script[script.index("replicate_device() {") :]
    order = [
        body.index('zfs load-key -L "file://${key_path}" "${pool}"'),
        body.index("  destroy_retired_targets\n"),
        body.index("zfs mount -a"),
        body.index('"${retention_script}"'),
        body.index('"${syncoid_bin}"'),
    ]
    assert order == sorted(order)
    assert f'zfs destroy -r "{RETIRED}"' in script
    assert 'if dataset_exists "tank/replica/fast/minio"; then' in script


# -- the rendered script, run with stand-ins for zpool, zfs and syncoid ----------------------

BASH = shutil.which("bash")

ZPOOL = """#!/bin/sh
# The pool is already imported from the drive under test.
case "$*" in
  "list -H -o name") echo vault ;;
  "list -v -H -P vault") printf 'vault\\t%s\\n' "$FAKE_DEVICE" ;;
  "get -H -o value guid vault") echo 42 ;;
  "list -Hp -o size,alloc,free vault") printf '100\\t10\\t90\\n' ;;
  *) ;;
esac
"""
ZFS = """#!/bin/sh
echo "zfs $*" >> "$FAKE_LOG"
case "$1 $2 $3 $4 $5" in
  "list -H -o name "*)
    for name in $FAKE_EXISTING; do
      [ "$name" = "$5" ] && { echo "$5"; exit 0; }
    done
    if [ -n "$FAKE_LIST_ERROR" ]; then echo "$FAKE_LIST_ERROR" >&2; exit 1; fi
    echo "cannot open '$5': dataset does not exist" >&2
    exit 1 ;;
esac
case "$1 $2 $3 $4" in
  "get -H -o value keystatus") echo available ;;
  "destroy -r "*) [ -z "$FAKE_DESTROY_FAILS" ] || exit 1 ;;
esac
exit 0
"""
SYNCOID = """#!/bin/sh
echo "syncoid $*" >> "$FAKE_LOG"
"""
LOGGER = """#!/bin/sh
shift 2
echo "logger $*" >> "$FAKE_LOG"
"""
WRITER = """#!/bin/sh
echo "state $*" >> "$FAKE_LOG"
"""


def run_script(tmp_path: Path, existing: str, **env: str) -> tuple[int, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, content in (("zpool", ZPOOL), ("zfs", ZFS), ("syncoid", SYNCOID), ("logger", LOGGER)):
        stubs.install(bin_dir / name, content)
    writer = tmp_path / "writer"
    stubs.install(writer, WRITER)
    device = tmp_path / "usb-owned"
    device.write_text("")
    cfg = config(
        device=str(device),
        syncoid_path=str(bin_dir / "syncoid"),
        state_writer_path=str(writer),
        exportfs_lock_dir=str(tmp_path / "exports.d"),
        retention_script_path=str(bin_dir / "zfs"),
        wait_for_async_destroy=False,
    )
    script = tmp_path / "zfs-usb-replication.sh"
    script.write_text(render(cfg, "zfs-usb-replication.sh"))
    log = tmp_path / "log"
    log.write_text("")
    result = subprocess.run(
        [str(BASH), str(script)],
        env={
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "FAKE_LOG": str(log),
            "FAKE_DEVICE": str(device),
            "FAKE_EXISTING": existing,
            **env,
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result.returncode, log.read_text().splitlines()


needs_bash4 = pytest.mark.skipif(
    BASH is None or subprocess.run([BASH, "-c", "((BASH_VERSINFO[0] >= 4))"], check=False).returncode != 0,
    reason="the USB script needs bash 4 (mapfile)",
)


@needs_bash4
def test_an_existing_retired_target_without_source_is_destroyed_and_logged(tmp_path: Path) -> None:
    rc, log = run_script(tmp_path, RETIRED)

    assert rc == 0, log
    destroy = log.index(f"zfs destroy -r {RETIRED}")
    assert f"logger Destroying retired target {RETIRED} on {tmp_path}/usb-owned" in log
    assert f"logger Destroyed retired target {RETIRED} on {tmp_path}/usb-owned" in log
    assert destroy < log.index("zfs mount -a")
    assert destroy < min(i for i, line in enumerate(log) if line.startswith("syncoid "))
    assert any(line.startswith("state ") and "--result success" in line for line in log)


@needs_bash4
def test_an_absent_retired_target_is_no_error(tmp_path: Path) -> None:
    rc, log = run_script(tmp_path, "")

    assert rc == 0, log
    assert not any("destroy" in line for line in log)
    assert any(line.startswith("syncoid ") for line in log)


@needs_bash4
def test_a_failed_destroy_fails_the_run_before_any_sync(tmp_path: Path) -> None:
    rc, log = run_script(tmp_path, RETIRED, FAKE_DESTROY_FAILS="1")

    assert rc != 0
    assert not any(line.startswith("syncoid ") for line in log)
    assert any(line.startswith("state ") and "--result failed" in line for line in log)


@needs_bash4
def test_a_retired_target_whose_source_still_exists_is_kept(tmp_path: Path) -> None:
    rc, log = run_script(tmp_path, f"{RETIRED} tank/replica/fast/minio")

    assert rc != 0
    assert not any(line.startswith("zfs destroy") for line in log)
    assert any("still has its source tank/replica/fast/minio; refusing" in line for line in log)


@needs_bash4
def test_an_unreadable_dataset_state_fails_without_destroying(tmp_path: Path) -> None:
    rc, log = run_script(tmp_path, "", FAKE_LIST_ERROR="cannot open: I/O error")

    assert rc != 0
    assert not any(line.startswith("zfs destroy") for line in log)
    assert any("Cannot check dataset" in line for line in log)
