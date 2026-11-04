# Media backup and restore

`ops_deploy.services.metube`, `ops_deploy.services.jellyfin` and
`ops_deploy.services.navidrome` port the `metube_backup`, `metube_restore`,
`jellyfin_backup`, `jellyfin_restore`, `navidrome_backup` and
`navidrome_restore` roles (ops-library `44a532ba`, recorded in the drift
manifest together with `metube_shared`, `navidrome_shared` and
`restore_preserve_internal`). None of them needs secrets. Backups written by
either tool restore with the other.

```python
from ops_deploy.services.metube import MetubeBackupConfig, deploy_metube_backup

deploy_metube_backup(MetubeBackupConfig(prefix="manual", required_mount="/opt/backups"))
```

| API | Role |
| --- | --- |
| `MetubeBackupConfig`, `deploy_metube_backup` | `metube_backup` |
| `MetubeRestoreConfig`, `deploy_metube_restore` | `metube_restore` |
| `JellyfinBackupConfig`, `deploy_jellyfin_backup` | `jellyfin_backup` |
| `JellyfinRestoreConfig`, `deploy_jellyfin_restore` | `jellyfin_restore` |
| `NavidromeBackupConfig`, `deploy_navidrome_backup` | `navidrome_backup` |
| `NavidromeRestoreConfig`, `deploy_navidrome_restore` | `navidrome_restore` behind ops-control's Native recovery quarantine |

The fields are the roles' variables without the `<service>_backup_` /
`<service>_restore_` / `<service>_` prefix, with the `*_shared` defaults:
roots `/opt/backups/<service>`, staging `/tmp/<service>-restore`, MeTube state
`/var/lib/metube`, env file `/etc/metube/metube.env`, unit
`/etc/systemd/system/metube.service`; Jellyfin data, config and log
`/var/lib/jellyfin`, `/etc/jellyfin`, `/var/log/jellyfin`, unit
`/lib/systemd/system/jellyfin.service`; Navidrome data `/var/lib/navidrome`,
config `/etc/navidrome.toml`, log `/var/log/navidrome`; routes
`/etc/traefik/dynamic/<service>.yml`. Roots, staging and live directories that
are a shared system directory (`/`, `/etc`, `/var/lib`, `/tmp`, `/opt/backups`
and the like) or contain `..` are refused, as are archives with `..`.

Each backup and restore runs on the host as one Python program
(`_lifecycle/files/media_lifecycle_host.py`) with its settings on stdin.

## Backup

In the roles' order: the version (MeTube `yt_dlp.__version__` from the venv,
Jellyfin `dpkg-query -W -f=${Version} jellyfin`, Navidrome `navidrome
--version`; empty when it cannot run), the timestamp (the host's local
`%Y%m%dT%H%M%S`), the root, backup directory and its subdirectories
(`owner`/`group`/`dir_mode`, default `root:root 0700`), every archive directly
in the root restricted to `0600`, the existence checks (MeTube: state
directory and env file; Jellyfin: data and config directories; Navidrome: data
directory and config file are mandatory; the run stops before stopping the
service otherwise), then with `stop_service` the service stopped (as the
systemd module does: only when running or deactivating; an unknown unit, or
one `systemctl show` cannot read, fails the run), the included
pieces copied (`rsync -a`, with `--delete` from `use_delete` except for logs;
single files `file_mode` `0600`) and the service started again (after
`daemon-reload`) only when the backup stopped it or failed to stop it. Then
`manifest.yml` (Jellyfin only with `generate_manifest`) and the archive
`<root>/<prefix>-<timestamp>.tar.gz` (`0600`, written under a hidden name and
renamed). The directory stays next to it, as the roles leave it. With
`fetch_local` the archive is fetched to `local_dir` (default
`~/backups/<service>`, `dir_mode`) as a `0600` file. Then the roles' pruning:
archives `<prefix>-*.tar.gz` beyond the newest `retain` (default `7`) by mtime,
or, without `create_archive`, the backup directories (MeTube and Jellyfin
only; Navidrome's role prunes nothing then).

`required_mount` (default `None`) stops the run before its first write unless
the root lies on that mounted filesystem
([Local backups](../concepts/local-backups.md)). These configs have no
`retain_count`/`retain_days` (snapshot records): they keep the roles' own
retention.

## Restore

The archive is `latest` (the newest `*.tar.gz` file in the root by mtime), an
absolute path or a name below the root. Before anything changes: the archive
must exist, ops-library's preserver (`preserve.py`, the role file
unchanged) refuses overlapping live, staging and source paths, the archive is
unpacked into the staging directory (Jellyfin and Navidrome reset it first;
MeTube keeps it, `0755`) and its single payload directory must hold the data
(`state/` or `data/`). A staging directory with more than one payload directory
is refused; the roles would pick one at random.

Then, as in the roles: the service is stopped (MeTube and Jellyfin with
`stop_service`), the data directory (Jellyfin also the config directory, when
the archive has one) is kept as a pre-restore copy
(`<dir>.pre-restore-<timestamp>-*`, reported, never pruned), the live
directories are ensured, the data, config, unit, route and logs present in the
archive are restored (files `root:root 0644`), systemd reloads when the unit
changed, Traefik reloads when the route changed (MeTube and Jellyfin; started
instead when it is not running, as the `service` module does; a failure is
tolerated and Traefik is never restarted: the role's restart task cannot fire,
because a failed `service` task registers no `rc`), Jellyfin and Navidrome directories
are chowned recursively to the service account (`chown -R`, which changes
links themselves and never follows them out of the directory), the service is enabled and
restarted (`restart`, default true) and the staging directory removed
(`cleanup`). A failed step ends the run there, as in the roles: the service
stays stopped and the staging directory stays for inspection. MeTube does not
reset its staging directory (as its role), so after a failed MeTube restore
the next one is refused (two payload directories) until
`/tmp/metube-restore` is cleared by hand. A route in
Traefik's dynamic directory is restored only while no Traefik transaction
holds its lock: the route guard runs before the program starts and again
right before the route is written.

The roles have no dry run; neither do these restores.

### Navidrome recovery

`deploy_navidrome_restore` is the port of ops-control's
`playbooks/navidrome/restore.yml` on a Native (pyinfra) Navidrome: the role
behind `navidrome_restore_quarantine.yml`.

- `confirm=True` is required before any host query (the playbook's
  `navidrome_ansible_rollback=true`): this is destructive live data recovery.
- The paths are the canonical ones; any other value is refused, and there is
  no full rescan.
- Before the role steps the program refuses, without writing anything:
  - unsafe ancestors of `/var/lib/ops-deploy/navidrome`: missing, linked, not
    root-owned or group/other-writable;
  - the Native `pending` or `restart` marker;
  - an existing `/tmp/navidrome-restore`;
  - a `restored/` parent that is not a root-owned `0700` directory;
  - current `/etc/navidrome.toml`, unit or route that is not a safe root-owned
    regular file.
- It then copies those three files into
  `/var/lib/ops-deploy/navidrome/restored/restore-<uuid>/current/` (`0600`) and
  reports the attempt path.
- The archived config, unit and route go to `archived/` there, never to their
  live locations. The data is restored with the role's pre-restore copy, and
  the canonical unit starts.
- Nothing is pruned. Afterwards: verify health and library state, then
  `just deploy-one navidrome macmini`.

## Tests

`tests/test_media_lifecycle.py`: plans against the fake connector (payloads,
mount check, fetch before pruning, the route guard, confirmation before any
probe, canonical-path and path refusals) and the host program against tmp
directories with `systemctl`, `rsync` and `findmnt` stubs: archive layout and
privacy, the stop/start rule, mandatory paths, pruning, MeTube, Jellyfin and
Navidrome restores with their pre-restore copies and service calls, the
quarantine and each of its refusals, and the encoded program through bash.
The real GNU `rsync`/`tar`/`findmnt` behaviour on a Debian host is not
exercised here.
