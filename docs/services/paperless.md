# Paperless deployment and recovery

The `PaperlessConfig`, `PaperlessCredentials` and `deploy_paperless`
API composes the checksum-bound 3.2.1 release and current `paperless_deploy`
role behavior. Owned current-release and 3.0.4-to-3.2.1 upgrade application
matrices passed. Private inventory adoption remains a separate pending step.

The initial typed configuration renders all eight original role templates byte
for byte in three synthetic Ansible oracle cases: defaults, authenticated Redis,
and a custom service account/storage root. Bash parsing of the resulting
environment is also tested. These local checks do not qualify systemd, database,
scanner or application behavior on Linux. The runtime remains pinned to the
declared 3.2.1 release and Python 3.14.

Paperless's uv dependency uses the original role's 0.13.5 checksums and defaults
through `PaperlessUvConfig`; the independent shared `UvInstallConfig` default
now also selects 0.13.5. Callers may supply that dependency's original version,
checksum, owner/group, update/force and deprecated compatibility-link settings.
Its install directory must match `PaperlessConfig.uv_install_dir`; the original
`uv_binary` setting selects every Paperless environment/package command. The
private adapter retains generic `uv_*` inventory names and the role-level
`paperless_uv_install_dir` precedence. This avoids the demonstrated 0.13.5 to
0.13.4 downgrade in the first owned typed attempt.

Prerequisite package admission reuses the existing installed-package/`Provides`
lookup, matching Ansible's treatment of virtual packages. An installed provider
avoids a redundant install; a genuinely missing package still queues installation.

Readiness retains the original final HTTP200 requirement. The release redirects
`/api/` to its schema UI; the Paperless-specific check admits only that one
same-origin `/api/schema/view/` destination and requires its actual final200.
Unexpected redirects, loops and failed final responses refuse. Each of ten
attempts has a ten-second deadline, with six seconds between attempts. It reads
no response body, supplies no credentials, and leaves the shared no-redirect
HTTP helper unchanged. The owned actual response was302 with `Location:
schema/view/`, resolving to `/api/schema/view/` and final200; inventory adoption
remains separate.

The approved search-index change replaces unconditional Ansible reindexing with
explicit release/package/migration/force triggers and bounded checks of index
metadata, schema/language sentinels and the live-document SQL count. The source
manager in the release's locked `django-soft-delete` 1.0.23 filters
`deleted_at IS NULL`; the owned application/schema and soft-delete cases passed. The schema fingerprint
now matches the exact release field descriptors using its locked whoosh-compat
0.3.0 types in an isolated local source oracle. That oracle loads only the two
schema modules without the application/backend package initializer; it is not
full application or Linux native qualification. The initial metadata helper reads only `meta.json` and
`.index_settings.json`, each capped at 1 MiB, without opening the search backend
or reading document names, IDs or content. Invalid metadata requests repair;
unsafe/unreadable paths refuse rather than starting it.

Tantivy's segment counts subtract `deletes.num_deleted_docs` from `max_doc`.
Equal counts do not prove content freshness or segment-body integrity. The
integration also triggers on schema/language changes and retains the explicit
`force_reindex` option. Concurrent ingestion may produce a
count mismatch and additional reindexing. The prepared managed helper stops all
configured Paperless units and attempts to resume every previously running unit
after success or an ordinary failure. A stop, reindex or resume failure remains
nonzero. Local simulated command tests cover these failures and ordinary retry;
actual owned systemd/application failure, prior-state resumption and ordinary
retry also passed. Abrupt
process or host loss cannot guarantee resumption. Application command output is
discarded to avoid logging document metadata. The helper retains the original
role's lack of a separate reindex timeout.

If the entire configured `data/index` directory is missing, the managed reindex
child creates only that leaf as the Paperless service user after stopping the
units. It pins existing ancestors with directory descriptors and refuses symbolic
links, non-directories or missing parents. Existing directories receive no
ownership, mode or timestamp write. It then executes the unchanged upstream
management command. This repairs a demonstrated upstream/original-role gap:
`wipe_index()` iterates a missing directory and fails before rebuilding. The
original role remains unchanged. The new owned case removes the entire index,
checks the exact old helper's failure, then requires normal typed recovery and a
strict healthy repeat. Both current and upgrade matrices passed that recovery;
the old helper's retained failure changes only its expected system-check root
timestamps and is never called a zero-mutation phase.

The prepared count command uses one fixed `COUNT(*)` with the release's
soft-delete predicate, a read-only PostgreSQL transaction and a 30-second
statement timeout. It returns only the aggregate and refuses query errors or
unexpected output. Actual owned application schema/manager parity and soft-delete
convergence passed in both matrices.

This preparation does not change the original Ansible role, which still rebuilds
on every deployment. Owned application, OCR/SFTP and recovery qualification
passed; inventory adoption remains pending. No production document or index
contents were inspected.

## Deployment and recovery

Existing Python trust floors are checked before dependencies change. The
deployment reuses the uv, Redis and PostgreSQL17 implementations, then installs
the role's prerequisite packages without upgrading installed versions. Callers
using shared Redis supply its independently declared password through
`shared_redis_password`; inequality refuses before any operation. Dependency
ports and authentication must match the application configuration.
If the declared database role needs its login/password repaired, Django probes
wait for that managed prerequisite instead of attempting authentication with
the old role state during planning.

The archive checksum, versioned release and editable distribution source are
checked independently of the historical install marker. Missing or broken
Python3.14 environments and missing application/supporting distributions request
repair. `uv pip check` inspects dependency metadata without importing the app:
exit1 requests repair, while inspection errors refuse. The explicit PostgreSQL
extra distributions are checked separately. The original editable installation,
supporting packages and final fido2 pin remain in order. Healthy environments
are neither recreated nor recursively chowned; only ownership mismatches in
the installed venv are changed. Ownership traversal pins ancestor and directory
descriptors so a renamed service-owned directory cannot redirect a root write.
Every ancestor of `site_root/.venv` must be a real directory, not a symlink;
for example, `/home -> /var/home` refuses ownership inspection rather than
being treated as a broken environment and recreated. This stricter path
admission differs from the original recursive ownership operation.
The OCR patch runs as the service user. No Python patch-version upgrade is requested.

A present interpreter, including uv's normal symlink, still passes the original
trust preflight before any dependency write. An existing unexecutable interpreter
therefore fails that preflight; it is not silently cleared to bypass the check.
Missing interpreters can enter the explicit environment recovery path.

Release extraction validates the exact archive in a private staging directory
before replacing a broken versioned release or legacy current directory. A
healthy current symlink remains untouched. The original OCR compatibility
replacement changes only its exact old program fragment; an upstream file
without that fragment is left unchanged. NLTK datasets retain their original
creates-only gates. Static assets inspect public installed program files,
preserve the original compiled-frontend precedence, and run collectstatic only
when those assets or their declared dependencies change. The frontend overlay
uses the original recursive remote-copy semantics: only its root has a fixed0755
mode; identical children retain their metadata, while changed/missing files use
source modes and missing subtrees preserve source metadata. Inspection does not
invent a recursive executable-bit requirement. These checks may update
access metadata and do not claim global zero I/O.

Migrations check actual pending schema work with `migrate --check --plan
--skip-checks`. Only that status command skips Django system checks: Paperless
system checks create and delete write-test files in data/media/consume roots.
Actual managed migrations retain every original system check. Administrator checks select only
the declared identities and flags. Existing password/email values are left
alone; strict missing-user failure can follow prior creation/promotions, as in
the original role. Management programs travel via protected stdin and application
output is suppressed. An explicit blocking stdin bootstrap avoids Django's
interactive-console race, and apply steps must emit their completion marker.
Owned old-command controls changed four roots' mtime/ctime; the corrected status
command kept all captured metadata exact. Healthy ordinary/fish/recovery repeats
also preserved entire captured state. This does not claim global zero I/O or
exclude natural effects outside the declared projection.

Scanner passwords use libcrypt comparison and protected chpasswd stdin only
when different; empty passwords remain unmanaged. A mounted SFTP inbox is not
chowned to scanner before restoring consume ownership. Bind identity and the
owned fstab entry are checked independently, with no healthy remount. A failed
mount after updating fstab is a real partial change. The recursive default ACL
check follows the original setfacl test/mask semantics and reads filesystem
metadata, not document bodies; it retains the original traversal latency limit.
SSH candidate syntax is validated before publication, then the combined global
configuration before a changed-file restart. Combined-validation failure may
therefore leave a published drop-in but never restarts SSH. The optional
Ghostscript AppArmor reload retains the original ignored-failure behavior; such
a failure is not evidence of a successful reload.

The four exact original units are loaded before a managed reindex. Normal
rollout starts/enables them and restarts only for declared relevant changes.
Migrations and static-file repair do not independently request a restart, matching
the original role; a reindex still performs its explicitly managed stop/resume.
The Traefik route retains the original template and watcher behavior. Final
health checks require all four units active and the loopback `/api/` response
to follow only the validated same-origin schema-UI redirect and terminate at
HTTP200.

## Owned qualification and inventory adoption

Current run40777068134 at9ac completed50 typed phases (47 healthy and3 expected
faults); upgrade-only run40788020395 at02d completed50 (48 healthy and2 expected
faults), including the actual3.0.4-to-3.2.1 upgrade with12 managed operations and
zero uploads. Each leg has26 healthy zero-managed/zero-upload repeats with102
successful operations and entire captured public/private state equality. The two
declared synthetic scanner-password rotation/restoration phases intentionally
change private state. Original Ansible and the failing old index helper are
separate observations, never no-op claims.

Real PostgreSQL17, Redis, four systemd units, expected schema redirect/final200,
synthetic SFTP/OCR/authenticated search, SQL/soft-delete/schema/language/count,
index failure/resume/retry, Python/release/package/static recovery, yescrypt,
recursive ACL and bind recovery passed. Current covers missing/unexecutable
Python; upgrade covers wrong Python and missing supporting distributions. Both
runs collected complete evidence and cleaned their owned resources with exits0.
Their825/849 installed noneditable resource maps matched their immutable sources.
The final905-resource composition preserves all873 separately qualified peer
resources and all32 Paperless resources from these runs; no peer-only native
replay is claimed.

The [concrete native fixture](https://github.com/ephes/ops-deploy/tree/main/tests/integration/paperless)
uses disposable public GitHub Ubuntu24 x86 VMs with systemd Docker userspaces
sharing each VM's kernel. It is not KVM, a physical scanner/encrypted-device proof,
or production qualification. Original bootstrap needed explicitly recorded
package-cache/index-directory and lost-SSH-handler fixture recovery; there is no
pristine original-bootstrap success claim. Every earlier failure is retained,
including the first upgrade deadline124 with unknown interrupted effects.
The separate macmini inventory adoption completed on2026-10-29 using the exact
905-resource artifact: normal EV-first default deployment111 successful
operations,4 managed changes/2 uploads, then explicit repeat110 successful
operations with0 managed changes/0 uploads. Only the original UV manager0.13.4→
0.13.5, Redis cache, missing constraints file and exact route preload-line removal
changed; package versions, application/index state and service PIDs stayed strict.
The original runner expected5 managed changes and stopped after successful first
because PostgreSQL's later cache operation reported no change. That failed
assertion is retained; the first was never replayed. The separately adjudicated
repeat passed strict whole protected-state checks and released the owned mutex.

Only named operational paths, two index metadata files and read-only aggregate
SQL count were observed; no document bodies/names or application index opener.
Raw private bodies remained remote; ephemeral comparison keys/values stayed in
process RAM. Separate first/repeat keys do not prove cross-process private-body
equality, though all persisted operational fields matched and the desired route/
constraints were rebound. Loopback HTTPS status is certificate-unverified and
there is no global zero-I/O claim. Direct legacy entrypoint retirement
remains tracked separately; deployment does not qualify backup, restore or
removal, which are ported below ([Backup and restore](#backup-and-restore),
[Removal](#removal)).

## Backup and restore

`ops_deploy.services.paperless` also ports `paperless_backup` and
`paperless_restore`. Archives written by either tool restore with the other.

| Function | Config | Role |
|---|---|---|
| `deploy_paperless_backup` | `PaperlessBackupConfig(host_name=...)` | `paperless_backup` |
| `deploy_paperless_restore` | `PaperlessRestoreConfig(host_name=...)` | `paperless_restore` |

The fields are the roles' variables without the `paperless_backup_` or
`paperless_restore_` prefix (the restore's shared paths without `paperless_`:
`site_root`, `site_owner`, `media_path`, ...). The exporter/importer
passphrase and the PostgreSQL passwords are `SecretStr` fields; they reach the
host on the script's stdin only and the database tools as a passfile the
PostgreSQL account writes itself, below one private directory per run that
is always removed. `PaperlessRestoreConfig.safety_backup`
holds the backup settings the role's safety snapshot starts from (the
inventory's `paperless_backup_*` values); `safety_config` applies the role's
overrides.

**Backup.** One host script: required paths (manage.py directory,
virtualenv, `.env`, media, data, and logs/consume/export when included), the
backup root (parent `0755`, root `root_mode`), older archives restricted,
`<root>/<prefix>-<timestamp>/` with its subdirectories (`database/` owned by
the dump account; the snapshot stays root's while root writes into it and
gets the role's owners and modes at the end), the disk check (15 % headroom), `manage.py --version`,
`document_exporter` into `exporter/` (passphrase on its stdin), `pg_dump` as
the PostgreSQL account, the directories (`rsync -a`), config, unit, Traefik
and SSH files, `metadata.yml`, `manifest.sha256` and the archive, written to a
private temp file and renamed into place. The archive is fetched into
`~/backups/paperless` (`0700`, the copy `0600`).

**Restore.** One host script in the role's phases:

1. Validate: pick `latest` (the newest `*.tar.*` in the search root) or a
   name below it, unpack it under a fresh `<staging>/<archive>-<timestamp>`
   (a staging root that is not root's directory is refused), require
   exactly one directory, `metadata.yml` with the required fields, the host
   match, `manifest.sha256`, the storage plan (media and data always,
   consume/export/logs by their metadata flags), the external root, the
   database dump and, with `use_importer`, the exporter artefact; warn when
   the backup's Paperless version differs from the installed one.
2. Prepare: the disk check (snapshot size × 1.5 on the site root); with
   `dry_run`, stop here. Then the safety snapshot
   `<backup root>/pre-restore-<timestamp>` (`files/backup.sh` with the role's
   overrides: no exporter, no archive, checksums, peer authentication; it
   stays root's, since a rollback installs its unit files).
3. Restore: stop the services, drop and create the database, then
   `document_importer` (a failure falls back to the raw snapshot) or the SQL
   dump with the role's ownership and privilege reconciliation plus the
   directories (`rsync -a --delete`); config files, units, the Traefik route
   and the SSH snippet; `daemon-reload`. A route that differs is written only
   while no Traefik transaction holds its lock: a lock held before the
   services stop refuses the restore, one taken later leaves the route and
   fails the restore after it finished.
4. Verify: start the services, wait until each is active, the PostgreSQL
   connection test and the HTTP health check. A failure restores the safety
   snapshot raw (no importer, no checks) and fails.

The staging directory goes after a success, a dry run or a completed
rollback; the safety snapshot goes after a success (`safety_backup_cleanup`)
and stays after a rollback unless `cleanup_after_rollback`. A failure before
verification leaves the services stopped and the safety snapshot in place, as
with the role. Deliberate differences are listed in the module docstring:
archive names only (no absolute paths, directories or controller upload),
`metadata.yml` read line by line, the Traefik lock check, `files.get` for the
fetch.

Tests: `tests/test_paperless_backup_restore.py` (planned settings, and both
scripts end to end with a fake `manage.py`, `pg_dump`/`psql` and stubbed
`systemctl`).

## Removal

`remove_paperless(PaperlessRemoveConfig(confirm=True, ...))` ports the
`paperless_remove` role at ops-library `44a532b` (role files under
`tests/parity/paperless/remove`, digest in the drift manifest). Without
`confirm` it fails before any host probe. Every field has the role's default
(`paperless_` dropped); destructive flags are opt-in as in the role, and
`home_path`, `site_root`, `remove_virtualenv` and `remove_current_symlink`
derive from `username` and `remove_site_root` as the role's templated defaults
do. System roots, traversals and a root account are refused.

The role's order:

1. stop and disable each of the four units (`systemd` semantics, failures
   ignored), remove their unit files and reload systemd (`remove_service_units`);
2. the Traefik route (behind the transaction guard) and the scanner's sshd
   drop-in;
3. `site_root`, its `.venv`, `paperless-ngx` link and `.env`, the temp
   directory, then the selected storage subdirectories (`media`, `data`,
   `consume`, `export`, `backup`, `tmp`) of `external_storage_root`;
4. with `remove_sftp_chroot`: unmount the scanner inbox when it is a mount
   point, then remove the chroot;
5. `userdel` of the Paperless user (`-r` when `remove_site_root`), its group,
   `userdel` of the scanner user (`-r` when `remove_sftp_chroot`); a failing
   `userdel` stops the removal;
6. `DROP DATABASE`/`DROP ROLE` as `postgres_become_user` on the local socket
   (the role's modules get no host or port), only for what exists; an
   unreadable state fails.

Like the role, the storage root itself, every Echoport archive and the
scanner inbox's `/etc/fstab` bind line stay (and the scanner group, unless
`userdel` of the scanner user removes it as its private group, as on Ubuntu), and neither sshd
nor Traefik is reloaded. That fstab line has no `nofail`: once its source
(`<storage>/consume`) is gone, remove the line before the next boot.
