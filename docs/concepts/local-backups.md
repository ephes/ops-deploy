# Local backups and restore work directories

The backup ports (`nyxmon`, `fastdeploy`, `work_app`, `traefik`) write a
directory and an archive on the host, and their restores unpack an archive
into a work directory. Where an off-host backup (Echoport) already holds the
same data, those local archives are only rollback snapshots. Two settings,
shared by all four ports (`ops_deploy.services._lifecycle.local_backup`),
keep them off the root filesystem and bound how many stay.

## `required_mount`

The mount point that the backup `root` (and, for a restore, its work
directory, for FastDeploy also the safety backup's root) must lie below:

| Config | Guarded fields |
|---|---|
| `NyxmonBackupConfig`, `WorkAppBackupConfig`, `TraefikBackupConfig`, `FastdeployBackupConfig` | `root` |
| `NyxmonRestoreConfig`, `WorkAppRestoreConfig`, `TraefikRestoreConfig` | `staging_dir` |
| `FastdeployRestoreConfig` | `temp_dir`, `safety_backup_root` |

The config refuses a guarded path that is not strictly below the mount
point (or that contains `..`), and a mount point that is `/` or not
canonical. On the host, before the first write, the run lists the mount point
(which triggers an automount), requires `findmnt --mountpoint <mount> --types
noautofs` to find a real filesystem there (an automount alone does not
count) and requires every guarded path to resolve (`realpath -m`) below it.
Otherwise the run stops with "is not mounted; refusing to write below it"
before it creates a directory. It never creates the mount point. `None` (the
default) checks nothing.

## `retain_count` and `retain_days`

Backup configs only. With either above `0`, every snapshot the backup writes
is recorded as an empty file `<root>/.ops-deploy-snapshots/<prefix>-<timestamp>`.
Before its first write such a backup refuses a name that is already taken (the
directory, either archive or the record), so it never enrolls something
another run or tool wrote under the same name.
After the archive is packed (before it is fetched), the recorded snapshots
are pruned: a snapshot goes, directory and `.tar.gz`/`.tar.zst` archive, when
it is beyond the newest `retain_count` of its prefix or its timestamp is more
than `retain_days` days before the backup's (the host's local time). The
snapshot just written always stays. Snapshots without a record (written by
Ansible, by hand, or before retention was set) are never removed, nor is
anything else in the root. `0` turns a limit off; both `0` (the default)
records and prunes nothing.

A restore never prunes. `FastdeployRestoreConfig.safety_backup_retention`
records its safety backup, so the next backup into the same root prunes it
by that backup's limits.

## Restore work directories

With `required_mount`, the FastDeploy restore also puts its database
passfile directory below `temp_dir` instead of `/tmp`.

Each restore removes its work directory whether it succeeds or fails:
nyxmon and FastDeploy run as one bash script with an `EXIT` trap (nyxmon
checks the mount before it sets the trap, so a rejected path is never
removed), the
Traefik restore's shell command traps `EXIT`, and the work_app restore
removes the staging directory as soon as the last file has been taken from
it, and on a failure of any step before that (with `cleanup`, the default).
An interrupted connection can still leave one behind; the next restore
resets it.

## Example

On a host whose `/opt/backups` is a mount of an external disk:

```python
NyxmonBackupConfig(host_name="host", required_mount="/opt/backups", retain_count=3, retain_days=14)
NyxmonRestoreConfig(host_name="host", required_mount="/opt/backups", staging_dir="/opt/backups/nyxmon/.restore-work")
```

A staging directory inside the backup root is not picked up as a backup:
`latest` only considers archive files directly below the root.

## Tests

`tests/test_local_backup.py`: config refusals, the mount check (mounted,
not mounted, missing mount point, a link out of the mount) and retention
(per prefix, by age, a dot prefix, unrecorded snapshots and other entries
kept, a record name with a newline ignored, the current snapshot kept, a
taken name refused) run in bash with a `findmnt` stub; nyxmon's and
FastDeploy's backups write nothing without the mount; the Traefik restore
and the work_app restore steps remove the staging directory on success and
on failure; and what each deploy runs, in order, with and without the
settings.
