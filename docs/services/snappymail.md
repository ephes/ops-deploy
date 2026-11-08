# SnappyMail ordinary deployment

`deploy_snappymail(config, secrets)` manages selected SnappyMail 3.0.0 code,
PHP-FPM pool, nginx loopback site, Traefik route and explicitly owned persistent
configuration. Supply `admin_password` through `SecretValues`. Matching passwords
retain the existing hash; a genuine credential change generates a new hash.
Credentials use stdin and are not embedded in process arguments.

The release and persistent-data roots must be disjoint. The application `data`
link points to the configured external data root. The role template defines only owned INI section/key values. SnappyMail may
normalize a fresh INI to its own defaults/version entries and mode0600 on first
HTTP access; that is application initialization, not a second deployment write.
The API uses PHP INI semantics and Snappy's configured value types to compare
owned values, retaining exact existing bytes when they match. Changed owned keys
retain unowned settings (including admin TOTP), sections and unrelated lines;
safe existing0600/0640 modes are retained with the required owner/group. Duplicate
or ambiguous configuration is diagnosed before replacement. This preserves the
role's declared intent without its historical whole-file overwrite.

Existing sessions, contacts,
mailbox settings, logs, caches, data marker metadata and unrelated domains are
preserved. Only named `remove_domains` are removed; an entry cannot appear in both
managed and removed domain lists. There is no recursive ownership normalization
or cleanup. An empty data root is initialized from the pinned archive; unknown
nonempty data without its marker is refused before seeding.

Full archive-owned code bytes and internal link identity are checked against
verified manifests. A matching version marker alone does not authorize replacing
local vendor/trust repairs. Current 3.0.0 is the only selected release; the
previous 2.38.2 and 2.38.0 manifests admit an explicitly qualified update path.
Unrelated old code files remain untouched, including older
`snappymail/v/<version>/` trees; the nginx site serves below `/snappymail/`
only the selected release's `static/` and `themes/` and refuses everything
else there (`403`), so an old release's `include.php` cannot run its code.

Release manifests (`_mail_web/releases/snappymail-<version>.json.gz`) record
the upstream archive URL and SHA-256 and every regular file (mode, SHA-256)
and link of the archive except `data/`, which only seeds an empty data root.
The 3.0.0 manifest was built from `snappymail-3.0.0.tar.gz` (SHA-256
`ac495fb8eb95a27c3f2bfab74db0d15b12079c35ef1c533dc70504865f21d000`) after its
detached signature verified against the SnappyMail release key
`1016 E470 7914 5542 F8BA  1335 4820 8BA1 3290 F3EB` (the same key in
`build/SnappyMail.asc` at tag `v3.0.0` and on keys.openpgp.org); the same
builder reproduces the 2.38.2 manifest byte for byte (only `previous_only`
changed). The JSON is `json.dumps(record, sort_keys=True)`, gzip with mtime 0.

SnappyMail 3.0.0 needs PHP 8.2 or newer and the same PHP extensions. Its
owned `application.ini` keys, domain JSON format, admin bcrypt hash and
`setup.php` (which writes the `INSTALLED` marker on the first request after
the version change) are unchanged from 2.38.2. The data root's `VERSION`
file is the seeding marker and keeps the version it was seeded with.

The Traefik router carries an `ipAllowList` (`snappymail-ipwhitelist`) while
`traefik_ip_whitelist_enabled` (default on, as for PostfixAdmin), so only
`traefik_ip_whitelist` sources (default: the tailnet's two ranges) reach the
login page and the admin panel; everyone else gets `403`. An enabled empty
list is refused. TLS verification and the system CA store remain enabled;
this API introduces no certificate bypass or private CA replacement.

The shared mail-web helper validates the complete nginx/FPM candidate dependency
closure and PHP syntax before committing owned files. Runtime activation checks
the local page and the other configured mail web app. Exceptions restore owned
bytes, mode, ownership and links, then recover the previous runtime state. This
is bounded exception recovery, not recovery from power loss or a killed helper.
A no-op does not stage files, upload helpers, rotate hashes or restart services.

`traefik_sts_preload` defaults to false and can preserve an explicitly selected
existing route policy. Backup/restore remain separate workflows; the removal is
below ([Removal](#removal)).

Existing admin hashes must have the canonical bcrypt encoding used by the selected
release and PHP. Malformed, unsupported or unavailable verification refuses
without replacing the stored credential. All checks use the selected versioned
PHP CLI; system alternatives are preserved. Shared-runtime changes also probe
the configured peer's actual loopback listener with an independent bounded
preservation check (10 seconds, three attempts).

Owned x86 Linux qualification passed in GitHub run `40557194107`, using immutable
implementation `f5c66d70bf03985a3ebbf18ba34d07d6dd3f347f` and separate harness
`ce824efcceab4289b2115534c3c3354ba78d3eed`. The combined two-app fixture exercised
fresh setup, partial-schema retry, configuration/credential changes, authenticated
previous-release updates, invalid candidate refusal, real systemd restart failure
and recovery, and nine zero-change repeats. Actual PHP CLI/FPM 8.3.6, PostgreSQL
16.15 and nginx 1.24.0 were recorded. Synthetic mail stayed local with verified
TLS. Inventory deployment qualification is separate. The original failed run
`40553538688` is retained; its failure was a fixture TOTP-seeding assumption.

## Backup and restore

`ops_deploy.services.snappymail` also ports `snappymail_backup` and
`snappymail_restore`. Neither needs secrets; archives written by either tool
restore with the other.

| Function | Config | Role |
|---|---|---|
| `deploy_snappymail_backup` | `SnappyMailBackupConfig(host_name=...)` | `snappymail_backup` |
| `deploy_snappymail_restore` | `SnappyMailRestoreConfig(host_name=...)` | `snappymail_restore` |

The fields are the roles' variables without the `snappymail_backup_` or
`snappymail_restore_` prefix (`root`, `prefix`, `archive_format`,
`stop_services`, `retain`, `fetch_local`, `fetch_dir`; `archive` for the
restore source, `clean`, `owner`, `group`, `mode`, `restart_services`; the
backup's `owner`, `group`, `mode`, `dir_mode`, `manifest`), plus `host_name`
(the manifest's `host`), `data_dir`, `dry_run` and `required_mount`. The
backup's `prefix` and `fetch_local` default to the playbook's `manual` and
`true`; its root must lie outside the data directory.

**Backup.** One host script: optionally stop nginx and the SnappyMail PHP-FPM
service (from `/etc/php/<version>/fpm/.../snappymail.conf`), fail without the
data directory, ensure the backup root (`root:root 0700`), restrict older
archives to `0600`, pack `<root>/<prefix>-<timestamp>.tar.gz` (or `.tar.zst`)
with the data directory as its only top-level entry (`0600`), start the units
it stopped again whatever happened, write `<archive>.yml`, and with `retain`
keep only the newest N archives (with their manifests). The archive is fetched
into `~/backups/snappymail` (`0700`, the copy `0600`).

**Restore.** One host script:

1. Pick `latest` (the newest `*.tar.gz`/`*.tar.zst` by mtime directly in the
   root) or a name below the root; run `preserve.py --validate-layout`.
2. Unpack into `<data parent>/.snappymail-restore-XXXXXXXXXX`, require the
   data directory's name at the top, find the PHP-FPM pool (required when
   `restart_services`, so nginx is never stopped without it), run the
   preservation preflight (mounts, free space).
3. With `dry_run`, stop here (the staging directory goes; without the data
   parent the dry run stops before unpacking).
4. Stop nginx and PHP-FPM (`rsync` is installed with apt before the
   script runs, for a real restore only), keep the live data as
   `<data>.pre-restore-<utc>-<random>` (`preserve.py`; with `clean`, the
   default, the live directory is left empty), copy the payload in
   (`rsync -a`), set `snappymail:snappymail 0750` on every entry, then enable
   and restart both units.

The staging directory always goes; no path removes a pre-restore copy. A
failure before the live data was touched starts the units the restore stopped
again; after that they stay stopped and the message points to the copy, as in
the role. A failed stop ends the restore at once (units it stopped start again;
the one whose stop failed is left alone). `archive` is never an absolute path, an extracted directory or a
symlink; an existing data parent keeps its mode.
`required_mount` (ops-control: `/mnt/cryptdata`) guards the backup root and
the data directory, next to which the restore stages.

Tests: `tests/test_snappymail_backup_restore.py` (planned settings, and both
scripts end to end with stubbed `systemctl` and the real `preserve.py`).


## Removal

`remove_snappymail(SnappyMailRemoveConfig(confirm=True))` ports the
`snappymail_remove` role at ops-library `44a532b` (role and
`snappymail_shared` files under `tests/parity/snappymail/remove`). Without
`confirm` it fails before any host probe. In the role's order it removes the
nginx site files, the Traefik route (behind the transaction guard), every
regular file named `snappymail.conf` below `/etc/php` (the role's `find`), the
`*snappymail*.sock` entries below `/run/php`, `/opt/snappymail`,
`/mnt/cryptdata/snappymail`, the `snappymail` user (`userdel -r`) and group;
failures from the socket step on are ignored, as in the role.

Unlike the role, nginx, Traefik and PHP-FPM are never stopped. The role stops
all three and relies on its `reloaded` handlers to start them again, which run
only when their files were removed; on a host without the SnappyMail route
Traefik (and every route on the host) stays down. Here nginx and the PHP-FPM
services of the removed pools (`php<version>-fpm` for pools under
`/etc/php/<version>/fpm/`) are reloaded, or started when down, right after
their files went (before the sockets, directories and account), failures
ignored; then whatever still runs as `snappymail` is ended (SIGTERM, SIGKILL
after 5 s), as the role's PHP-FPM stop did, so `userdel` does not fail on a
worker still finishing a request. Traefik is not reloaded; its file provider
drops the route.
