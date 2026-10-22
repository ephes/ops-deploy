"""Backup steps a deploy runs before it changes anything.

- :func:`run_echoport_backup`: trigger a registered Echoport target, wait,
  check the run and its MinIO object, return the run ID (the default way to
  take a pre-deploy or manual backup);
- :func:`require_mount`: refuse to go on unless a path is a mounted
  filesystem (never falls back to ``/``);
- :func:`local_snapshot`: a local rollback archive under an explicitly
  configured directory on a mounted external disk, with retention.

These run from the controller through a :data:`Runner` (``ssh`` to the host,
script on stdin), not as pyinfra operations, so a failure stops the caller
before pyinfra plans anything. This package is not part of the size-capped
shared layer. See the "Backups" documentation page.
"""

from ops_deploy.backups.echoport_sync import (
    EchoportBackupError,
    EchoportBackupResult,
    EchoportSite,
    run_echoport_backup,
)
from ops_deploy.backups.local_snapshot import (
    SnapshotError,
    SnapshotPolicy,
    SnapshotResult,
    local_snapshot,
    local_snapshot_command,
)
from ops_deploy.backups.mounts import MountMissingError, require_mount, require_mount_command
from ops_deploy.backups.remote import (
    CommandResult,
    RemoteCommandError,
    Runner,
    SshTarget,
    SubprocessRunner,
    ssh_runner,
)

__all__ = [
    "CommandResult",
    "EchoportBackupError",
    "EchoportBackupResult",
    "EchoportSite",
    "MountMissingError",
    "RemoteCommandError",
    "Runner",
    "SnapshotError",
    "SnapshotPolicy",
    "SnapshotResult",
    "SshTarget",
    "SubprocessRunner",
    "local_snapshot",
    "local_snapshot_command",
    "require_mount",
    "require_mount_command",
    "run_echoport_backup",
    "ssh_runner",
]
