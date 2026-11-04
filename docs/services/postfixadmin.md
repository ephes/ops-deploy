# PostfixAdmin ordinary deployment

`deploy_postfixadmin(config, secrets)` manages the selected PostfixAdmin 4.0.5
php84 release, PHP-FPM pool, nginx loopback site, application configuration,
Traefik route and configured superadmin. Supply `db_password`, `setup_password`
and `admin_password` through `SecretValues`; values travel on stdin, never in
remote process arguments. The shared mail database module owns the database and
login role. This API requires that foundation and never resets its password or
changes database/schema owners.

Existing installations must match the verified current or explicitly admitted
previous release manifest. Archive-owned internal symlinks are checked by target;
unrelated files and local data are retained. Unknown vendor modifications are
refused before replacement, rather than erased because a version marker matches.
The exact archive URL, digest and member manifest live in `_mail_web/releases`.
Only current 4.0.5 is selectable; the previous manifest supports an update fixture
and admission, not an implicit downgrade.

An existing database must already report schema 1851. Ordinary deployment does
not run the upstream upgrader on it. For an entirely empty application database,
the selected release's `public/upgrade.php` runs as the configured web user,
followed by an exact schema check. Missing original role privileges are granted
additively; owners and existing grants are preserved. Fresh schema creation and
additive grants are not destructively rolled back if later activation fails.
A retry admits only the exact resulting selected schema; unknown partial schemas
are reported for diagnosis.

The selected admin, reserved `ALL` pseudo-domain and its admin mapping belong to
this API. Mail-core reconciliation excludes those resources. No other application
rows are reconciled or pruned. Matching setup/admin credentials retain their
existing hashes and salts; an actual password change updates only the selected
credential, preserving TOTP fields and unrelated accounts.

Before replacing owned files, the helper validates complete staged nginx and FPM
include contexts, including existing unrelated sites and pools, plus PHP syntax.
Activation failures restore owned file bytes, mode, UID/GID and symlink targets,
then recover the prior runtime state. Restoration may change inode timestamps
and PIDs; it is not a crash/power-loss transaction. No on-host journal is created.
A no-op bypasses staging, helper uploads, SQL mutations and service restarts.

`traefik_sts_preload` defaults to false. Set it explicitly only when preserving or
selecting that route policy. It does not alter the shared HSTS defaults.
Backup/restore/remove and old-mail schema conversion are separate workflows.

The database/role foundation (including any requested role-password change) must
converge in a prior pyinfra run. Web admission is intentionally read-only during
planning, before this run's operations execute; composing fresh foundation and
web deployment in one state is unsupported. This ordering is technical, with no
manual acknowledgement requirement. The selected versioned PHP CLI is used for
all checks and fresh schema bootstrap, without changing system alternatives.

Stored credential encodings are admitted before verification: canonical bcrypt
for setup and SnappyMail, canonical SHA512-CRYPT for the PFA admin. Unsupported,
malformed, or unavailable verification refuses without replacing a stored hash.
A shared-runtime mutation also checks the configured peer's actual nginx loopback
listener with an independent bounded preservation probe (10s, three attempts),
even if this application's optional health check is disabled.

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

`ops_deploy.services.postfixadmin` also ports `postfixadmin_backup` and
`postfixadmin_restore` (with the restore playbook's pre tasks: `latest` and
the dry run). Backups written by either tool restore with the other.

| Function | Config | Role |
|---|---|---|
| `deploy_postfixadmin_backup` | `PostfixAdminBackupConfig(host_name=..., db_password=...)` | `postfixadmin_backup` |
| `deploy_postfixadmin_restore` | `PostfixAdminRestoreConfig(db_password=...)` | `postfixadmin_restore` |

`db_password` is the mail database password (`postfixadmin_db_password`);
it reaches the host only on stdin and `psql` only as PGPASSWORD. The other
fields are the roles' variables without their prefix (`root` is
`postfixadmin_backup_path`, default `/mnt/cryptdata/backups/postfixadmin`;
`archive` is the playbook's `restore_archive`, `latest` or a timestamp).

**Backup.** The role's fail-closed layout: `<root>/<timestamp>.tmp` with
`config.local.php`, `admin.json` (every column of every admin, at least one
required), `domain_admins.json`, the numeric schema version from `config`,
the optional `log.json` (newest 10000 rows; a failure is a warning) and, with
`include_templates_c`, `templates_c.tar.gz`; `manifest.yml` lists exactly the
parts on disk; then the directory is renamed to `<root>/<timestamp>`. Any
failure removes the `.tmp` directory and publishes nothing. An existing
directory of the same name is refused. Retention then keeps the newest
`keep_min` (5) completed backups and removes the others older than
`retention_days` (14), by modification time; other names in the root stay.

**Restore.** `latest` is the newest completed backup directory; the dry run
checks only that the directory exists. Otherwise it validates before any
change: the manifest (`backup_type`, every required part, only known parts),
each listed part on disk, `templates_c.tar.gz` when asked for, the target's
schema version not older than the backup's, and `admin.json`/`domain_admins.json`
(at least one admin with username and password, only columns the target's
`admin` table has). Then it puts back `config.local.php`
(`root:www-data 0640`, restarting `php<version>-fpm` only when it changed),
optionally `templates_c`, and upserts the admin rows (`ON CONFLICT (username)
DO UPDATE`) and the missing domain_admins rows in one transaction.

Deliberate differences: the JSON files are PostgreSQL's own row encoding
(`json_agg`), formatted like `to_nice_json`; `manifest.yml` is written as JSON
(valid YAML); the admin tables are restored in one transaction, the row data
in the SQL on psql's stdin (never its command line); PHP-FPM restarts only for
a content change of config.local.php; a non-numeric schema version is refused
(the role reads it as 0); the
controller reads the manifest before the run and the host refuses it when a
newer backup landed in between; `required_mount` guards the backup root.

Tests: `tests/test_postfixadmin_backup_restore.py` (planned settings, the
host program end to end against a fake `psql` with fixture rows, and a backup
and restore round trip against a throwaway local PostgreSQL 16/17 when
`initdb` is installed).

