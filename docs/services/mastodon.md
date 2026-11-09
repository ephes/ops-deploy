# Mastodon: selected-release deployment of an existing installation

The default nvm Git tag is [v0.41.0](https://github.com/nvm-sh/nvm/releases/tag/v0.41.0).
The pyinfra release path and Ansible rollback use the same tag. nvm is checked
out from Git; this release has no uploaded assets or checksum manifest.

`deploy_mastodon(cfg=MastodonReleaseConfig(...), secrets=...)` updates an existing
Git installation. It resolves a selected release, installs its Ruby/Node and
locked dependencies when needed, converges the secret environment, applies
pending migration identities, builds assets, and performs an ordered application
rollout. It does not provision the OS, service account, PostgreSQL/Redis instance
or storage. The roles' backup and restore are
[`deploy_mastodon_backup` and `deploy_mastodon_restore`](#backup-and-restore), the
role's removal is [`remove_mastodon`](#removal). Existing local media
and the `<home>/live` layout are retained.

The compatibility `MastodonConfig` API still performs immutable configuration-only
convergence. Callers must opt into the release API with the candidate description;
changing its old exact-source admission is not how routine updates are enabled.

## Candidate and runtime provenance

Resolve the configured Git ref with `core.git_source.fetch_source`, then call
`describe_candidate` on that immutable tree. The description includes the full
tracked path list, both lockfiles/runtime declarations, and migration identities
from **both** `db/migrate` and `db/post_migrate`. The read-only host inspection
compares those identities against the configured PostgreSQL database before any
write. It does not load new application code with old installed dependencies.

With `ruby_build_update=true`, the controller resolves ruby-build master once.
The returned `runtime_tool_commits` records the exact Git object fetched from its
configured repository. Preserve that explicit input for apply and its repeat;
an independent later invocation may resolve a newer master honestly. With update
false, the installed checkout is retained. rbenv and configured nvm tag semantics
follow the role. Existing matching Node is preserved; a missing partial-version
match is resolved to a concrete release before rendering service paths. Numeric
major/minor/patch selectors are supported; nvm aliases/LTS names are not part of
this typed existing-install API. Old
runtime directories are retained.

Git deployment fetches the configured ref as the service user, checks that it
still resolves to the controller-selected commit, and performs a forced detached
checkout. It never runs `git clean`. Candidate paths cannot overwrite retained
env/media/dependencies/runtime contents. Known tracked `log/.keep` and
`vendor/.keep` scaffolds are permitted; an untracked retained scaffold collision
is not overwritten. Ownership is not recursively changed over media or the site.
Local rsync source transport is not implemented by this Git release API.

## Build, migration and rollout

Role-compatible inputs include rbenv/ruby-build/nvm settings, Bundler and Yarn
flags, migrations/assets/cache-clear toggles, process sizing, delegated domains,
nginx federation cache/timing and discovery settings. Source, locks, runtime,
configuration and actual output checks determine whether work is necessary.
A completion marker alone does not prove installed dependencies or assets exist.
The selected pipeline determines asset verification: Propshaft and Vite builds
require their real manifests and referenced files; retained webpack/Sprockets
manifests cannot qualify a current Propshaft/Vite release.

Secret env bytes travel through redacted stdin to `secret_file` with service
ownership and mode 0600. Application commands run as the service user with an
explicit clean runtime environment. Credentials are never operation names or
arguments, and application stderr is not echoed by the host action runner.
Changing DB credentials does not provision or rotate a database role.

Before a potentially partial source/runtime/dependency/migration/asset mutation,
Mastodon-local durable rollout and cache-clear debt is stored under root-owned
`/var/lib/ops-deploy-mastodon` (0700, entries 0600). Env-only changes create rollout
debt without cache-clear debt. Failed commands never save successful build state;
retry pays surviving debt. Systemd reload precedes conditional tootctl cache clear,
then each application restarts once, then health verifies the rollout. No shared
Traefik restart, unrelated Redis flush or automatic DB rollback occurs.

The guarded Traefik writer remains unchanged. An unchanged route does not invoke
the guard; changed routes use the existing transaction coordination contract.
Maintenance script/service/timer templates are copied unchanged from the role;
converging the schedule does not execute cleanup. Maintenance command validation
preserves the role's full-name/scoped emoji-purge rules. `run_now=true` is an
explicit cleanup operation outside this release deployer, rather than silently
ignored or executed.

Federation cache priming uses the role's host/path/Accept expansion, including
configured extra and delegated discovery entries, and verifies the second
response cache status. Missing cache outputs or changed release inputs schedule
priming; a converged repeat only verifies existing cache responses. Such normal
read requests may still refresh nginx's derived cache/log state.

## Operational qualification

Read the selected release's upstream upgrade notes, including skipped releases.
For [v4.6.9](https://github.com/mastodon/mastodon/releases/tag/v4.6.9), instructions
call for locked dependencies, asset compilation and restarting the processes.
Its production Vite build retains old output (`emptyOutDir=false`). This does not
promise atomic deployment, zero downtime or a general cross-version rollback.
Pending schema effects and online compatibility must be inspected for the
selected release. Old runtime retention alone is not sufficient rollback.

Before live production, verify recovery evidence appropriate to actual source,
schema and storage effects. Do not claim media recovery from a DB-only archive.
Qualification needs an inspected plan, actual first apply, source/runtime/env/
migration/identity/media/health evidence, and a same-input real repeat with zero
builds, cache clears, restarts and mutating operations. Fake command tests prove
ordering and failure handling; real Linux tools plus an actual Mastodon build
are separate required evidence. This public API documentation does not claim
qualification of any particular operator's hosts.

The unchanged role environment is sourced by Bash for release commands and
maintenance. Unquoted credentials and SMTP login must be literal assignment
values: shell operators, ASCII whitespace, quotes, expansion/escape syntax and
assignment-position tilde expansion are rejected before host inspection. Quoted
SMTP From addresses retain spaces and address punctuation; valid environment
bytes are unchanged.

Dependency verification uses `bundle check --dry-run`: plain Bundler checks can
touch an unchanged lockfile and create false restart debt. Both planning and
post-install verification preserve lockfile bytes and timestamps; genuine
after-start changes retain the existing precise restart-debt behavior.

`bundle check` does not load native extensions, so it still passes after an OS
release upgrade replaced a shared library that a compiled gem links (for example
`charlock_holmes` and the libicu soname, 74 on Ubuntu 24.04 and 78 on 26.04). For an
otherwise current bundle the inspection therefore also runs one read-only `ldd`
pass, as the service user, over the native extensions of the current Ruby ABI
directory in `bundle_path`. A locked gem with a `not found` library makes the
bundle step due: after `bundle install` it runs `bundle pristine <gems>` for exactly
those gems (rebuilt from the cached `.gem` against the new libraries), then
`bundle check` and the `ldd` pass again, and fails without writing the bundle
marker if a library is still missing. The usual asset build, cache clear and
restart follow. The bundle key is unchanged and a healthy bundle reports no
missing library, so existing hosts do not rebuild. Leftover gem directories of
no locked spec, other Ruby ABI directories and `libruby` (already loaded by the
Ruby process) are ignored; a missing library in a Git-sourced or unrecognised
extension path stops the inspection instead of guessing. The rebuild needs the
build tools and the new `-dev` headers (such as `libicu-dev`), which a release
upgrade carries forward when they were installed. The planning log names the
gems before the rebuild.

## Removal

`remove_mastodon(MastodonRemoveConfig(confirm=True))` ports the
`mastodon_remove` role at ops-library `44a532ba` with `mastodon_shared`'s
paths and removal flags (both recorded under `tests/parity/mastodon/remove`).
Without `confirm` it fails before any host probe; a root account, `/`, a
top-level directory or a traversal as a path is refused.

In the role's order: stop and disable `mastodon-web`, `mastodon-sidekiq`,
`mastodon-streaming` and `mastodon-nginx` (one `systemd` task per unit,
disable before stop, failures ignored); remove their unit files
(`remove_systemd_units`); reload systemd (always, as the role); then, per
flag, `.env.production` (`remove_env_file`), the Traefik route (behind the
Traefik transaction guard), `/etc/mastodon/nginx.conf`, the logrotate entry,
the site directory `/home/mastodon/live` (the local media lives under it, in
`live/public/system`, so it goes with the site; `remove_media`, off by
default, matters only for a media directory outside the site) and the nginx
log directory (`remove_logs`, off by default); last `userdel -r mastodon` (the
whole home, with the default `remove_user=True`; a failure stops the removal)
and `groupdel` when the group still exists. PostgreSQL, Redis, the S3 bucket and backups are not
touched, as by the role. No secrets are read.

The removal, backup and restore configs share `mastodon_shared`'s account,
paths and units through `services.mastodon.shared.MastodonSite` (canonical
absolute paths only).

## Backup and restore

`ops_deploy.services.mastodon` ports `mastodon_backup` (ops-library `44a532ba`)
and `mastodon_restore` (ops-library `219146f0`, with its media excludes and empty-media guard),
with the `mastodon_shared` defaults; recorded in the drift manifest. Both take
the database password as `postgres_password` in their secrets (ops-control passes `mastodon_postgres_password`); it reaches the
host script on stdin and the PostgreSQL tools through a private `0600`
passfile in a fresh `0700` directory, removed after each command, as in the
roles. A password with a line break is refused before anything runs.

| Function | Config | Role |
|---|---|---|
| `deploy_mastodon_backup(cfg, secrets)` | `MastodonBackupConfig` | `mastodon_backup` (with `prune.yml`) |
| `deploy_mastodon_restore(cfg, secrets)` | `MastodonRestoreConfig` | `mastodon_restore` |

The fields are the roles' variables without `mastodon_`, `mastodon_backup_` or
`mastodon_restore_` (the backup's owner and group are `backup_owner`/`backup_group`,
`mastodon_restore_root` is `root`). Archives written by either tool restore
with the other.

**Backup.** One host script: it reads `<site>/VERSION` as the Mastodon user
(empty without the file, as the role's ignored `cat`), creates
`/opt/backups/mastodon/<prefix>-<timestamp>/` with `database`, `media`,
`config`, `systemd`, `traefik` and `nginx` (`root:root 0700`) and restricts
older archives in the root to `0600`. With `stop_services` it stops the four
units, then dumps the database (`pg_dump --format=custom --compress=9` as
`backup_owner`, connecting as `mastodon` on `localhost:5432`), copies the
local media with `rsync -a --delete --exclude=/cache/***`, the env file (a
missing one fails the backup), the unit files, the Traefik route and the
nginx config that exist (`0600`), and starts the units again with a daemon
reload whatever the capture did. It writes the role's `manifest.yml`, packs
`<dir>.tar.gz` (`0600`), fetches it into `~/backups/mastodon` (`0700`, the copy
`0600`) and then keeps the newest `retain` (`7`) archives and payload
directories by mtime: those with the prefix, or every non-hidden one with
`retain_all_prefixes`. It does not use the snapshot records of the other
backup ports ([Local backups](../concepts/local-backups.md)). The manifest
records the excludes (`media_rsync_excludes: ["/cache/***"]`); the restore
reads them back. With `include_media` off (or nothing outside the cache to
copy) the archive still has an empty `media/`: the restore refuses it while
the live media holds files outside the excludes, unless `empty_media_confirmed`.

**Restore.** One host script, in the role's order:

1. Pick `latest` (the newest `*.tar.gz` by mtime directly in the root) or a
   name below it, reset and unpack into `/var/tmp/mastodon-restore` (`0700`),
   find the payload directory, require `database/<db>.dump`, hand the staging
   path and the dump to the Postgres OS user (`postgres`) and validate the
   dump: `pg_restore --list` must list `TABLE DATA`, then a full
   `pg_restore --file=/dev/null`. The media excludes come from the
   manifest's `media_rsync_excludes` line (the paths the backup left out, by
   default the remote-media cache `/cache/***`); the media restore excludes
   them too, so the live paths they match are kept. No `manifest.yml`, or no
   such line: no excludes, as before the excludes (every live media file the
   archive lacks is deleted, and the guard below counts every live file). A
   manifest that is no regular file, more than one `media_rsync_excludes`
   line, or a value other than a JSON list of plain double-quoted strings (no
   quote or backslash inside; the backup config allows only printable ASCII
   without them, so its manifests hold no JSON escapes) stops the restore
   here. An archive whose
   `media/` holds no files outside the excludes (only directories, excluded
   paths or nothing; a backup taken with `include_media` off still has an
   empty `media/`) is `media=EMPTY` on the components line; it is refused
   here, before anything stops, while the live media holds files outside the
   excludes, unless `empty_media_confirmed` (ops-control:
   `MASTODON_RESTORE_EMPTY_MEDIA_CONFIRMED=true`): its `rsync --delete` would
   delete them. When the live media holds only excluded paths (a staging host
   whose media is all remote cache) nothing would be deleted, and the restore
   goes on without confirmation. Both counts use `rsync --list-only` with the
   excludes; a failing count stops the restore (files vanishing while the
   running instance's media is listed, rsync's exit 24, do not). The live
   media is counted before the services stop: a file uploaded outside the
   excludes in between is deleted by the restore (the media snapshot keeps
   it). With `dry_run` it stops here
   (the staging directory still goes, with `cleanup`); a dry run prints the
   components, the excludes and whether a restore would refuse (unless
   confirmed), and exits 0.
2. A Traefik route in the archive that differs from the live one needs a free
   Traefik transaction lock, checked before anything changes.
3. Ensure the media and site directories (`mastodon:mastodon 0750`) and ask
   PostgreSQL whether the live database exists (only "does not exist" counts
   as no database; any other error stops the restore).
4. Stop the installed units and require each to be `inactive` or `failed`;
   take the safety copies below a UTC timestamp: `pg_dump -Fc` of the live
   database into `/var/backups/mastodon-pre-restore/<ts>/database/` (checked
   with `pg_restore --list`), a hard-link snapshot (`cp -al`, a full copy across
   filesystems) of the media into `/home/mastodon/media-pre-restore/<ts>` and
   copies of the env file, the route, the nginx config and the units the archive
   replaces under `<ts>/files/`. A failure here drops nothing and reports that
   the services may be stopped.
5. Drop and recreate the database (as `postgres`; the host only when
   remote), `pg_restore --single-transaction --clean --if-exists --no-owner`,
   `rsync -a --delete --ignore-times` the media with its excludes (local storage), copy the env
   file (`0600`), the units, the route and the nginx config (`0644`), reload
   systemd, run `bundle exec rails db:migrate` as `mastodon` and enable and
   restart all four units.
6. Any failure in step 5 stops the units again and, only when every unit is
   confirmed down, restores the safety dump, the media snapshot and the
   copies, then fails naming the step, both rollbacks' results and the safety
   paths, with the services left stopped.

The staging directory goes in every case (`cleanup`); the safety copies are
never pruned. The config refuses a staging directory that holds or lies inside
the archives, a live path or a safety root, one that is `/tmp`, `/var/tmp` or a
top-level directory, and archives or safety copies inside the media directory
(which the restore syncs with `--delete`).

The media excludes and the empty-media refusal are the role's
(`mastodon_restore_empty_media_confirmed`, ops-library's guard against the
role's former behaviour of emptying the live media and reporting success).

The script's output (the archive, the components line, the media excludes,
the refusal or confirmation and the safety paths) is logged after the restore
by a "Show the restore report" step, so `just restore-check` (a dry run) shows
it at the default verbosity; pyinfra itself prints a command's output only at
`-vvv` or when the command fails.

Deliberate differences: archive names only (no absolute paths), a symlinked
archive is refused, `dry_run` is an addition (it also reports an empty
`media/`), the role parses the excludes line as any JSON while the script
accepts only plain double-quoted strings, the route lock as above (a lock
taken during the restore leaves the route, the restore finishes and then
fails; the rollback puts the route back only when the restore wrote it and
only while no transaction holds the lock), "installed" units are those whose
`LoadState` is not `not-found` or that still run (an unreadable state counts
as installed, so the unit must stop and be confirmed stopped), the payload directory is the one
named after the archive (else the first by name), and
the `tar.gz` format, `mastodon_backup_fetch_become` and `mastodon_nginx_enabled`
are not settings (pass `services`/`systemd_units` without nginx instead).
