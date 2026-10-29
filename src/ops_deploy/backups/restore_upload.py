"""The ordinary restore wrapper's optional local-archive upload prelude.

This is controller-side managed work, before the restore operation. It does not
read archive contents or select the requested restore archive. The original
wrapper's first-remote-name classifier and all-local-archive transfer are kept.
Both upload and later restore must use the same inventory-resolved SSH target.
"""

from __future__ import annotations

import math
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ops_deploy.backups.remote import (
    RemoteCommandError,
    Runner,
    SshTarget,
    SubprocessRunner,
    check_arg,
    ssh_command,
    ssh_runner,
)

# Deliberately keep ls/head and the non-anchored gz/zst classifier: the original
# wrapper uploads if the first *.tar.* name is another format, even if a later
# entry is usable. Only the fixed category crosses the SSH boundary here.
REMOTE_PRESENT = r"""set -e
first=$(ls "$1"/*.tar.* 2>/dev/null | head -1)
if [ -n "$first" ] && ! printf '%s\n' "$first" | grep -q '__NO_BACKUPS__' &&
   printf '%s\n' "$first" | grep -qE '\.tar\.(gz|zst)'; then
    printf 'present\n'
else
    printf 'upload\n'
fi
"""

PREPARE = """set -e
[ -d "$1" ] || install -d -m 0700 -o root -g root "$1"
mktemp -d /tmp/_backup_upload.XXXXXXXXXX
"""

FINISH = """set -e
mv "$1"/*.tar.* "$2/"
rmdir "$1"
chown --reference="$2" "$2"/*.tar.*
chmod 600 "$2"/*.tar.*
"""


class RestoreUploadError(RuntimeError):
    """The prelude failed; earlier managed stages may already have changed data.

    ``stage`` and ``temporary_directory`` contain operational metadata only.
    A failure retains the unique staging directory if it still exists. In
    particular, a lost SSH/rsync result is not proof the remote writer stopped;
    the caller must not remove staging or proceed with restore on that basis.
    """

    def __init__(self, stage: str, temporary_directory: str | None = None) -> None:
        super().__init__(f"restore upload failed at {stage}; restore was not started")
        self.stage = stage
        self.temporary_directory = temporary_directory


@dataclass(frozen=True)
class RestoreUploadResult:
    outcome: Literal["no-local-archives", "remote-present", "uploaded"]
    transferred_entries: int = 0


def upload_restore_archives(
    target: SshTarget,
    local_directory: Path,
    remote_root: str,
    *,
    timeout: float = 900,
    remote: Runner | None = None,
    transfer: Runner | None = None,
) -> RestoreUploadResult:
    """Upload all local ``*.tar.*`` entries only when the original rule asks.

    A local immediate gz/zst entry triggers the remote check, just as ``find``
    did (including directories and dotfiles). Transfer follows Bash's ordinary
    non-dot glob, and includes other ``tar.*`` formats. Existing backup-root
    ownership/mode survive; all resulting root archives receive mode 0600 and
    that root's owner. There is no archive-content inspection or new checksum
    barrier. Errors stop before restore and never claim a zero-mutation refusal.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("restore upload timeout must be finite and positive")
    local_directory = local_directory.absolute()
    if not local_directory.is_dir() or not any(
        path.name.endswith((".tar.gz", ".tar.zst")) for path in local_directory.iterdir()
    ):
        return RestoreUploadResult("no-local-archives")
    check_arg(remote_root)
    run_remote = remote if remote is not None else ssh_runner(target)
    run_transfer = transfer if transfer is not None else SubprocessRunner()
    temporary: str | None = None
    stage = "remote-check"
    try:
        present = run_remote(REMOTE_PRESENT, (remote_root,), timeout)
        if not present.ok or present.stdout.strip() not in {"present", "upload"}:
            raise RestoreUploadError(stage)
        if present.stdout.strip() == "present":
            return RestoreUploadResult("remote-present")
        stage = "prepare"
        prepared = run_remote(PREPARE, (remote_root,), timeout)
        if not prepared.ok or re.fullmatch(r"/tmp/_backup_upload\.[A-Za-z0-9]{10}", prepared.stdout.strip()) is None:
            raise RestoreUploadError(stage)
        temporary = prepared.stdout.strip()
        stage = "transfer"
        sources = sorted(path for path in local_directory.glob("*.tar.*") if not path.name.startswith("."))
        # No match expands to the literal glob in the original shell, which
        # makes rsync fail rather than treating a dotfile-only source as empty.
        source_args = [str(path) for path in sources] or [str(local_directory / "*.tar.*")]
        hostname = target.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        argv = (
            "rsync",
            "-avz",
            "--progress",
            "--chmod=F600",
            "-e",
            shlex.join(ssh_command(target)[:-1]),
            # Bound the remote rsync server too; killing local SSH alone does
            # not establish that its remote child has quiesced.
            f"--rsync-path=timeout -k 30 {math.ceil(timeout)} rsync",
            "--",
            *source_args,
            f"{hostname}:{temporary}/",
        )
        copied = run_transfer('exec "$@"\n', argv, timeout)
        if not copied.ok:
            raise RestoreUploadError(stage, temporary)
        stage = "finish"
        finished = run_remote(FINISH, (temporary, remote_root), timeout)
        if not finished.ok:
            raise RestoreUploadError(stage, temporary)
    except RemoteCommandError:
        # Do not propagate arbitrary remote stdout/stderr or archive names.
        raise RestoreUploadError(stage, temporary) from None
    return RestoreUploadResult("uploaded", len(sources))
