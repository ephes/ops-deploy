# .DS_Store cleanup

`infra.dsstore_cleanup` removes macOS `.DS_Store` files below a few
directories once a night, for example on a Samba share that holds a media
library.

## Why not a Samba veto

Finder writes a `.DS_Store` into every folder it opens or copies onto a
share. `veto files = /.DS_Store/` keeps them out, but Finder then aborts
copying any folder that contains one (error -8062, nothing is copied). So the
share accepts them and this job removes them later. AppleDouble `._*` files
are a different case: a share with `vfs objects = fruit streams_xattr` keeps
that metadata in extended attributes, and `veto files = /._*/` does not
disturb Finder.

## What it installs

- `/usr/local/sbin/dsstore-cleanup` (bash, `root:root 0755`): for each
  directory argument it runs
  `find <dir> -xdev -type f -name .DS_Store -delete` and logs one line to the
  journal, `dsstore-cleanup: removed <n> .DS_Store file(s) below <dir>`. Only
  regular files named exactly `.DS_Store` go: directories and symlinks with
  that name, and other file systems mounted below the directory, are left
  alone, and a symlinked or missing directory is skipped. A skipped directory
  or a `find` error fails the run (the other directories still run).
- `dsstore-cleanup.service`: oneshot, `RequiresMountsFor=` the directories,
  `Nice=10`, idle I/O class, `ProtectSystem=strict` with only the directories
  writable, no network, capabilities limited to `CAP_DAC_OVERRIDE`,
  `CAP_DAC_READ_SEARCH` and `CAP_FOWNER`.
- `dsstore-cleanup.timer`: `OnCalendar=` (default `*-*-* 22:30:00`),
  `Persistent=true`, enabled and started.

The deploy never starts the service. A changed unit reloads systemd and
restarts the timer (new schedule); a changed script changes nothing else. A
converged host runs nothing.

## Usage

```python
from ops_deploy.infra import DsStoreCleanupConfig, deploy_dsstore_cleanup

deploy_dsstore_cleanup(cfg=DsStoreCleanupConfig(paths=("/fast/media",)))
# remove again:
deploy_dsstore_cleanup(cfg=DsStoreCleanupConfig(state="absent"))
```

| Field         | Default            | Meaning                                                                       |
|---------------|--------------------|-------------------------------------------------------------------------------|
| `state`       | `"present"`        | `"absent"` stops and disables the timer and removes the units and the script. |
| `paths`       | `()`               | Absolute directories, required when present; no `.`/`..`, spaces, `%`, `$`.  |
| `on_calendar` | `"*-*-* 22:30:00"` | systemd calendar expression of the timer (host time zone).                    |

## Verifying

```bash
systemctl list-timers dsstore-cleanup.timer
systemctl start dsstore-cleanup.service   # one run now
journalctl -u dsstore-cleanup.service
```
