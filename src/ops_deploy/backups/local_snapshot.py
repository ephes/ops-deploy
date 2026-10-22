"""Local rollback snapshots, only on a mounted external disk, with retention.

For the rare case where a deploy needs a fast local rollback copy (a runtime
or binary tree, not service data: data backups go through Echoport, see
:mod:`ops_deploy.backups.echoport_sync`). :func:`local_snapshot` writes one
``tar.gz`` of the given paths to ``<base_dir>/<name>/<prefix>-<UTC stamp>.tar.gz``
and then prunes:

- ``base_dir`` must be the policy's mount point or lie below it, and the mount
  point must be mounted read-write (the :mod:`~ops_deploy.backups.mounts`
  guard). The script then walks from the mount point down to
  ``<base_dir>/<name>`` one level at a time: no component may be a symlink,
  and a missing one is created on its own (mode 0700), so nothing is created
  anywhere else. The directory must resolve to itself (``pwd -P``) and
  ``findmnt --target`` must place it on the mount point;
- the archive is written to ``<final>.partial.XXXXXX`` (``mktemp``: created
  exclusively, never through a symlink) next to its final name, with no
  temporary files anywhere else, and renamed when complete; a failed or
  interrupted run (``HUP``/``INT``/``TERM``) removes its partial file;
- retention: of the archives named exactly ``<prefix>-YYYYMMDDTHHMMSSZ.tar.gz``
  in that directory, only the ``keep`` newest are kept, and none older than
  ``max_age_days``; partial files older than an hour (from killed runs) are
  removed too. The archive just written is never pruned, and nothing else in
  the directory is touched. A failing listing fails the run (the new archive
  stays).

Every snapshot run prunes, so retention holds as long as snapshots are taken.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field

from ops_deploy.backups.mounts import MOUNT_GUARD_SCRIPT, MountMissingError, canonical_path, mount_guard_args
from ops_deploy.backups.remote import RemoteCommandError, Runner

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

SNAPSHOT_SCRIPT = (
    "guard_mount() {\n"
    + MOUNT_GUARD_SCRIPT
    + """}
set -euo pipefail
umask 077
mountpoint=$1
fstype=$2
source=$3
base=$4
name=$5
prefix=$6
keep=$7
max_age=$8
shift 8
guard_mount "$mountpoint" "$fstype" "$source" rw
case "$base" in
    "$mountpoint" | "$mountpoint"/*) ;;
    *) echo "snapshot: $base is not on $mountpoint" >&2; exit 2 ;;
esac
dir=$base/$name
# Walk down from the mount point, one level at a time: no component may be a
# symlink, and each missing one is created on its own (mode 0700), so nothing
# is ever created anywhere but below the verified mount point.
if [ -L "$mountpoint" ]; then
    echo "snapshot: $mountpoint is a symlink" >&2
    exit 1
fi
current=$mountpoint
IFS=/ read -r -a parts <<<"${dir#"$mountpoint"/}"
for part in "${parts[@]}"; do
    current=$current/$part
    if [ -L "$current" ]; then
        echo "snapshot: $current is a symlink" >&2
        exit 1
    fi
    if [ ! -e "$current" ]; then
        mkdir -m 0700 -- "$current"
    fi
    if [ ! -d "$current" ]; then
        echo "snapshot: $current is not a directory" >&2
        exit 1
    fi
done
if [ "$(cd -- "$dir" && pwd -P)" != "$dir" ]; then
    echo "snapshot: $dir does not resolve to itself" >&2
    exit 1
fi
on=$(findmnt --noheadings --first-only --output TARGET --target "$dir")
if [ "$on" != "$mountpoint" ]; then
    echo "snapshot: $dir is on $on, not on $mountpoint" >&2
    exit 1
fi
relative=()
for src in "$@"; do
    if [ ! -e "$src" ]; then
        echo "snapshot: $src does not exist" >&2
        exit 1
    fi
    relative+=("${src#/}")
done
stamp=$(date -u +%Y%m%dT%H%M%SZ)
final=$dir/$prefix-$stamp.tar.gz
if [ -e "$final" ] || [ -L "$final" ]; then
    echo "snapshot: $final already exists" >&2
    exit 1
fi
partial=
cleanup() {
    if [ -n "$partial" ]; then
        rm -f -- "$partial"
    fi
}
on_signal() {
    cleanup
    exit 1
}
trap cleanup EXIT
trap on_signal HUP INT TERM
# mktemp creates the file exclusively and never follows a symlink.
partial=$(mktemp "$final.partial.XXXXXX")
tar -czf - -C / "${relative[@]}" >"$partial"
if [ -e "$final" ] || [ -L "$final" ]; then
    echo "snapshot: $final already exists" >&2
    exit 1
fi
mv -- "$partial" "$final"
partial=
trap - EXIT HUP INT TERM
size=$(wc -c <"$final" | tr -d " ")
echo "SNAPSHOT $final $size"
retention_failed() {
    echo "snapshot: retention failed in $dir ($final was kept)" >&2
    exit 1
}
pattern="$prefix-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z.tar.gz"
# Listings go through command substitution, not process substitution, so a
# failing find or sort fails the run (set -e, pipefail) instead of pruning less.
# Every pattern matches only [A-Za-z0-9._-] after the directory (whose path is
# checked on the controller), so a listed name never holds a newline.
listing=$(find "$dir" -maxdepth 1 -type f -name "$pattern" | sort -r) || retention_failed
count=0
while IFS= read -r file; do
    if [ -z "$file" ]; then
        continue
    fi
    count=$((count + 1))
    if [ "$file" != "$final" ] && [ "$count" -gt "$keep" ]; then
        rm -f -- "$file"
        echo "PRUNED $file"
    fi
done <<<"$listing"
listing=$(find "$dir" -maxdepth 1 -type f -name "$pattern" -mmin "+$max_age") || retention_failed
while IFS= read -r file; do
    if [ -n "$file" ] && [ "$file" != "$final" ]; then
        rm -f -- "$file"
        echo "PRUNED $file"
    fi
done <<<"$listing"
alnum="[A-Za-z0-9]"
suffix="$alnum$alnum$alnum$alnum$alnum$alnum"
listing=$(find "$dir" -maxdepth 1 -type f -name "$pattern.partial.$suffix" -mmin +60) || retention_failed
while IFS= read -r file; do
    if [ -n "$file" ]; then
        rm -f -- "$file"
        echo "PRUNED $file"
    fi
done <<<"$listing"
"""
)


class SnapshotError(RuntimeError):
    """The snapshot could not be written."""


@dataclass(frozen=True)
class SnapshotPolicy:
    """Where snapshots may go and how many stay.

    ``base_dir`` is the explicitly configured directory on the external disk;
    ``mountpoint`` the disk's mount point (``base_dir`` itself or a parent).
    ``fstype``/``source`` optionally pin what must be mounted there.
    """

    mountpoint: str
    base_dir: str
    keep: int = 3
    max_age_days: int = 14
    fstype: str | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        mount_guard_args(self.mountpoint, fstype=self.fstype, source=self.source)
        if not canonical_path(self.base_dir):
            raise ValueError(f"base_dir must be an absolute path in plain form (got {self.base_dir!r})")
        if self.base_dir != self.mountpoint and not self.base_dir.startswith(f"{self.mountpoint}/"):
            raise ValueError(f"base_dir {self.base_dir} is not on the mount point {self.mountpoint}")
        if self.keep < 1 or self.max_age_days < 1:
            raise ValueError("keep and max_age_days must be at least 1")


@dataclass(frozen=True)
class SnapshotResult:
    """The archive written and the archives the retention removed."""

    path: str
    size_bytes: int
    pruned: tuple[str, ...] = field(default=())


def snapshot_args(policy: SnapshotPolicy, name: str, prefix: str, sources: Sequence[str]) -> list[str]:
    """Arguments of :data:`SNAPSHOT_SCRIPT`, validated."""

    for what, value in (("name", name), ("prefix", prefix)):
        if not _NAME.fullmatch(value):
            raise ValueError(f"invalid snapshot {what}: {value!r}")
    if not sources:
        raise ValueError("a snapshot needs at least one source path")
    for src in sources:
        if not canonical_path(src):
            raise ValueError(f"snapshot source must be an absolute path other than / (got {src!r})")
    guard = mount_guard_args(policy.mountpoint, fstype=policy.fstype, source=policy.source)
    return [
        *guard[:3],
        policy.base_dir,
        name,
        prefix,
        str(policy.keep),
        str(policy.max_age_days * 24 * 60),
        *sources,
    ]


def local_snapshot(
    runner: Runner,
    policy: SnapshotPolicy,
    name: str,
    prefix: str,
    sources: Sequence[str],
    *,
    timeout: float = 3600,
) -> SnapshotResult:
    """Write one snapshot of ``sources`` and apply the retention.

    Raises :class:`MountMissingError` when the disk is not mounted (nothing is
    written) and :class:`SnapshotError` for any other failure.
    """

    args = snapshot_args(policy, name, prefix, sources)
    try:
        result = runner(SNAPSHOT_SCRIPT, args, timeout)
    except RemoteCommandError as exc:
        raise SnapshotError(f"{name}: snapshot failed: {exc}") from exc
    lines = result.stdout.splitlines()
    errors = result.stderr.strip().splitlines()
    if not result.ok:
        message = errors[-1] if errors else f"{name}: snapshot failed (exit {result.returncode})"
        if message.startswith("mount guard:") or (message.startswith("snapshot:") and " is on " in message):
            raise MountMissingError(message)
        raise SnapshotError(message)
    written = [line.split() for line in lines if line.startswith("SNAPSHOT ")]
    if len(written) != 1 or len(written[0]) != 3 or not written[0][2].isdigit():
        raise SnapshotError(f"{name}: the snapshot script reported no archive")
    pruned = tuple(line.removeprefix("PRUNED ") for line in lines if line.startswith("PRUNED "))
    return SnapshotResult(written[0][1], int(written[0][2]), pruned)


def local_snapshot_command(policy: SnapshotPolicy, name: str, prefix: str, sources: Sequence[str]) -> str:
    """The snapshot as one shell command for a pyinfra operation (``server.shell``)."""

    return shlex.join(["bash", "-c", SNAPSHOT_SCRIPT, "local-snapshot", *snapshot_args(policy, name, prefix, sources)])
