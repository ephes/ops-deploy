"""Refuse to write below a mount point that is not mounted.

A directory meant to live on an external disk (``/mnt/<disk>/...``) silently
lands on the root filesystem when the disk is not mounted and something runs
``mkdir -p``. :func:`require_mount` checks with ``findmnt`` that ``path`` itself
is a mount point (optionally of the expected filesystem type and source, and
mounted read-write) and raises :class:`MountMissingError` otherwise. There is no
fallback: no directory is created and nothing is written anywhere else.

The check is one bash script (:data:`MOUNT_GUARD_SCRIPT`), used two ways:

- from the controller before a step, through a
  :data:`~ops_deploy.backups.remote.Runner` (:func:`require_mount`);
- inside a deploy as a pyinfra command (:func:`require_mount_command`), whose
  non-zero exit fails the operation and stops the host's run.
"""

from __future__ import annotations

import re
import shlex

from ops_deploy.backups.remote import RemoteCommandError, Runner

_PATH = re.compile(r"/[A-Za-z0-9._/+@-]*")
_WORD = re.compile(r"[A-Za-z0-9._/:+@=-]*")

# $1 mount point, $2 expected fstype ("" = any), $3 expected source ("" = any),
# $4 "rw" to require a read-write mount ("" = any). Exit 0 only when mounted
# exactly there; never creates anything. findmnt prints nothing and exits 1
# for a path that is not a mount point.
MOUNT_GUARD_SCRIPT = """set -euo pipefail
mountpoint=$1
fstype=$2
source=$3
mode=$4
case "$mountpoint" in
    /?*) ;;
    *) echo "mount guard: refusing mount point $mountpoint (absolute path other than / required)" >&2; exit 2 ;;
esac
if ! command -v findmnt >/dev/null 2>&1; then
    echo "mount guard: findmnt not found" >&2
    exit 3
fi
if ! line=$(findmnt --mountpoint "$mountpoint" --noheadings --first-only --output TARGET,FSTYPE,SOURCE,OPTIONS); then
    echo "mount guard: $mountpoint is not mounted" >&2
    exit 1
fi
read -r got_target got_fstype got_source got_options <<<"$line"
if [ "$got_target" != "$mountpoint" ]; then
    echo "mount guard: $mountpoint is not mounted (findmnt: $got_target)" >&2
    exit 1
fi
if [ -n "$fstype" ] && [ "$got_fstype" != "$fstype" ]; then
    echo "mount guard: $mountpoint is $got_fstype, expected $fstype" >&2
    exit 1
fi
if [ -n "$source" ] && [ "$got_source" != "$source" ]; then
    echo "mount guard: $mountpoint is mounted from $got_source, expected $source" >&2
    exit 1
fi
if [ "$mode" = rw ]; then
    case ",$got_options," in
        *,rw,*) ;;
        *) echo "mount guard: $mountpoint is not mounted read-write ($got_options)" >&2; exit 1 ;;
    esac
fi
"""


def canonical_path(value: str) -> bool:
    """Whether ``value`` is an absolute path other than ``/`` in plain form.

    No empty, ``.`` or ``..`` components and no trailing slash, so the text is
    the path the kernel resolves (apart from symlinks, which the scripts check).
    """

    parts = value.split("/")[1:]
    return bool(_PATH.fullmatch(value)) and value != "/" and not ({"", ".", ".."} & set(parts))


class MountMissingError(RuntimeError):
    """The mount point is missing, of another kind, or could not be checked."""


def mount_guard_args(
    mountpoint: str, *, fstype: str | None = None, source: str | None = None, writable: bool = True
) -> list[str]:
    """Arguments of :data:`MOUNT_GUARD_SCRIPT`; refuses ``/`` and relative paths."""

    if not canonical_path(mountpoint):
        raise ValueError(f"mount point must be an absolute path other than / (got {mountpoint!r})")
    for what, value in (("fstype", fstype), ("source", source)):
        if value is not None and (not value or not _WORD.fullmatch(value)):
            raise ValueError(f"invalid {what}: {value!r}")
    return [mountpoint, fstype or "", source or "", "rw" if writable else ""]


def require_mount(
    runner: Runner,
    mountpoint: str,
    *,
    fstype: str | None = None,
    source: str | None = None,
    writable: bool = True,
    timeout: float = 30,
) -> None:
    """Raise :class:`MountMissingError` unless ``mountpoint`` is mounted as expected."""

    args = mount_guard_args(mountpoint, fstype=fstype, source=source, writable=writable)
    try:
        result = runner(MOUNT_GUARD_SCRIPT, args, timeout)
    except RemoteCommandError as exc:
        raise MountMissingError(f"{mountpoint}: mount check failed: {exc}") from exc
    if not result.ok:
        message = result.stderr.strip().splitlines()
        raise MountMissingError(message[-1] if message else f"{mountpoint}: mount check failed")


def require_mount_command(
    mountpoint: str, *, fstype: str | None = None, source: str | None = None, writable: bool = True
) -> str:
    """The guard as one shell command for a pyinfra operation (``server.shell``).

    The script has no backslashes or single quotes, so it survives pyinfra's
    ``sh -c '...'`` wrapping and a fish login shell unchanged.
    """

    args = mount_guard_args(mountpoint, fstype=fstype, source=source, writable=writable)
    return shlex.join(["bash", "-c", MOUNT_GUARD_SCRIPT, "mount-guard", *args])
