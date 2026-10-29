# Backups before a deploy

`ops_deploy.backups` holds the steps a deploy, or an explicit backup command,
runs **before** it changes anything:

| Step | What it does | Fails when |
|---|---|---|
| `run_echoport_backup` | runs a registered Echoport target now, waits, checks the run and its MinIO object, returns the run ID | Echoport exits non-zero (unknown or inactive target, a run of it already active, timeout, failed run), the output lacks run ID, object or size, the object is missing or has another size, the checksum differs |
| `require_mount` | checks with `findmnt` that a path is a mounted filesystem (optionally of a given type and source, read-write) | not mounted, other filesystem, read-only, no `findmnt` |
| `local_snapshot` | writes one rollback archive under an explicitly configured directory on a mounted disk, then applies the retention | the disk is not mounted, the directory leaves the disk, a source is missing, `tar` fails |

Every failure raises (`EchoportBackupError`, `MountMissingError`,
`SnapshotError`); the caller stops there. Nothing falls back to another
location, and nothing is written on `/` when a disk is missing.

The default for a manual or pre-deploy backup is the Echoport step: the
backup lands in Echoport's object store with Echoport's own retention and
restore path. Local snapshots are for the rare fast rollback copy of a runtime
or binary tree, not for service data.

## How the steps run

The steps run on the controller, outside pyinfra: each sends a fixed bash
script on stdin (`ssh ... bash -s -- ARGS`) through a `Runner`, reads the
result and decides. A pyinfra operation could not do this, since pyinfra plans
every operation before it executes any. The caller (the private repository's
deploy command) runs them before it starts pyinfra, so a failed backup means
no deploy at all.

```python
from ops_deploy.backups import EchoportSite, SshTarget, run_echoport_backup, ssh_runner

runner = ssh_runner(SshTarget("echoport-host.example", user="root"))
site = EchoportSite(site_path="/srv/echoport/site", user="echoport", minio_alias="minio")
result = run_echoport_backup(runner, site, "nyxmon", triggered_by="ops:predeploy:nyxmon")
print(result.run_id, result.object, result.restore_hint)
```

- `ssh_runner` uses `BatchMode=yes` (it never prompts) and the connection
  settings of pyinfra's ssh connector (`SshTarget`: hostname, user, port, key,
  known-hosts file, host key checking, extra `-o` options).
- Only the arguments pass through the remote login shell, quoted. An argument
  with a backslash, newline or NUL is refused before anything runs (a fish
  login shell reads backslashes inside single quotes differently from `sh`).
- Timeouts stop the work, not just the wait: on the controller the runner's
  whole process group gets `SIGTERM` (the scripts trap it and remove partial
  files), and whatever is left of the group `SIGKILL` after `stop_grace`
  (30 s), even when the group's leader has already exited. Since killing a
  local `ssh` leaves the remote side running, `ssh_runner` also runs the
  remote command under coreutils `timeout -k 30 <seconds>` and waits a minute
  longer than that itself; a stop on the host raises `RemoteCommandError`.
- `SubprocessRunner()` with no prefix runs the scripts on the local machine;
  tests use it with stub executables on `PATH`.

## Echoport: `run_echoport_backup`

1. Runs `manage.py backup <target> --triggered-by <label>` from the site
   directory as the Echoport user (`EchoportSite.become`: `runuser` when the
   SSH user is root, `sudo -n -H` for a user with passwordless sudo, `none`
   when the SSH user is the Echoport user). Echoport's command is synchronous.
   `timeout` (default 3 h) bounds it on the controller; Echoport's per-target
   timeout lies below that.
2. Parses the output: `Run ID`, `Storage: <bucket>/<key>` and
   `Size: <n> bytes` must be present, the key must lie under `<target>/` and
   the size must be positive. A `Checksum:` line (64 hex digits) is read when
   present; Echoport stores a SHA-256 per run but its command does not print it
   today, so the checksum is usually `None`.
3. Checks the object independently of Echoport's result: `mc stat --json
   <alias>/<bucket>/<key>` as the Echoport user must report exactly one file
   of exactly the reported size. With a checksum and `verify_checksum=True`
   (default) the object is also streamed through `sha256sum` (`mc cat`), which
   reads the whole archive; `checksum_timeout` bounds it.
4. Returns `EchoportBackupResult`: run ID, object, size, checksum (and whether
   it was verified), the object's size and last-modified time, start and end
   times, and `restore_hint` (`manage.py restore <target> <run_id>`).
   `as_record()` gives a JSON-ready dict for the caller's evidence log.

The `target` must match `[A-Za-z0-9][A-Za-z0-9._-]*` and the `triggered_by`
label `[A-Za-z0-9][A-Za-z0-9._:@/+=-]*` (at most 100 characters, Echoport's
column size); anything else raises `ValueError` before the host is contacted.

## Mount guard: `require_mount`

```python
from ops_deploy.backups import require_mount, require_mount_command

require_mount(runner, "/mnt/data", fstype="ext4")  # from the controller
server.shell(name="Require /mnt/data", commands=[require_mount_command("/mnt/data")])  # inside a deploy
```

The path must be absolute, without `..` or a trailing slash, and not `/`.
`findmnt --mountpoint` must report exactly that path; `fstype` and `source`
pin what is mounted there, and `writable=True` (default) requires `rw` in the
mount options. The guard never creates a directory. `require_mount_command`
is the same script as one `bash -c` command, safe for pyinfra's `sh -c`
wrapping and a fish login shell; its non-zero exit fails the operation.

## Local rollback snapshots: `local_snapshot`

```python
from ops_deploy.backups import SnapshotPolicy, local_snapshot

policy = SnapshotPolicy(mountpoint="/mnt/data", base_dir="/mnt/data/rollback", keep=3, max_age_days=14)
result = local_snapshot(runner, policy, "myservice", "runtime", ["/srv/myservice/runtime"])
```

- `base_dir` is configured explicitly and must be the mount point or below
  it, in plain form (absolute, no `.`, `..` or empty components). The mount
  guard runs first (read-write required). The script then walks from the
  mount point down to `<base_dir>/<name>` one level at a time: no component
  may be a symlink (not even one to a sibling directory on the same disk),
  and each missing one is created on its own with mode 0700, so nothing is
  ever created elsewhere. The directory must resolve to itself (`pwd -P`)
  and `findmnt --target` must place it on the mount point.
- The archive is `<base_dir>/<name>/<prefix>-YYYYMMDDTHHMMSSZ.tar.gz`
  (mode 0600, paths stored relative to `/`). It is written to
  `<archive>.partial.XXXXXX`, created exclusively by `mktemp` (never through
  a symlink) in the same directory, and renamed when complete; an existing
  file or symlink at the archive name is refused. A failed or interrupted run
  (`HUP`, `INT`, `TERM`) removes its partial file. No temporary files are
  written anywhere else.
- Retention, after every snapshot: of the archives named exactly
  `<prefix>-<stamp>.tar.gz` in that directory, the `keep` newest stay and
  none older than `max_age_days`; partial files older than an hour are
  removed (`.partial.` plus six letters or digits, as `mktemp` names them).
  The new archive is never removed, and no other file is touched.
  `SnapshotResult.pruned` lists what was removed. A failing listing fails
  the run with `SnapshotError` (the new archive stays).
- `local_snapshot_command` is the same as one shell command for a pyinfra
  operation.

## Local archives before an ordinary restore

`ops_deploy.backups.restore_upload.upload_restore_archives` supplies the existing
ordinary restore wrapper's upload prelude. This is managed controller work before
restore, not a pyinfra dry operation. The private wrapper supplies a single
inventory-resolved `SshTarget` for both upload and the subsequent restore.

An immediate local `.tar.gz` or `.tar.zst` entry triggers a remote check. The
original first-name rule is preserved: inspect the first `*.tar.*` entry, and
upload if its name does not contain `.tar.gz` or `.tar.zst`. An unexpected first
suffix therefore still requests upload even if another remote archive exists.
The transfer includes **all** non-hidden local `*.tar.*` entries, not only the
requested archive or latest backup. Archive bodies are never interpreted.

A missing remote root is created root-owned with mode 0700; an existing root
retains its owner and mode. A unique private `/tmp/_backup_upload.XXXXXXXXXX`
directory receives the real rsync transfer. Files are then moved into the root,
all root archive matches receive its owner/group and mode 0600, and the empty
staging directory is removed. The requested archive is selected by the existing
restore implementation afterwards. No checksum or acknowledgement gate is added.

The helper uses the existing bounded process-group runner and a bounded remote
rsync server. Check, prepare, transfer and finish failures stop before restore.
An error can follow real root creation, transfer or a partial move; it never
means zero mutation. Failure retains the unique staging identity when known.
An uncertain remote result must be investigated before any cleanup or retry;
killing the controller's SSH process is not evidence of remote quiescence.

The [owned primitive fixture](https://github.com/ephes/ops-deploy/tree/main/tests/integration/restore_upload)
uses synthetic archives in a networkless, unprivileged Linux container, with
real rsync and Linux ownership/mode operations. It replaces only SSH with a local
owned destination; separate tests check the exact inventory SSH argv. It does not
qualify a production restore or any service's archive/content recovery behavior.
Private normal-wrapper adoption is a separate follow-up.
