# PostfixAdmin ordinary deployment

`deploy_postfixadmin(config, secrets)` manages the selected PostfixAdmin 4.0.7
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
Only current 4.0.7 is selectable; the previous manifests (4.0.4, 4.0.5) support
an update fixture and admission, not an implicit downgrade.

The selected PostfixAdmin manifest names its database schema (`schema`, 1852 for
4.0.7) and the older schemas its upstream upgrader may advance (`upgrade_from`,
1851). An existing database must report one of those; any other version is
refused before changes. At an admitted older schema, the apply stops PHP-FPM,
switches the code, runs the selected release's `public/upgrade.php` once as the
configured web user and requires the exact target schema afterwards; this also
happens when the code is already at the selected release. Upstream
`upgrade.php` exits 0 even when a database step fails, so only that schema check
decides. For an entirely empty application database the same upgrader performs
fresh initialization, followed by the same exact schema check. On PostgreSQL the
1851 to 1852 step only sets `config.version` (`upgrade_1852` exists only for
MySQL), and 4.0.5 code still runs against a 1852 database. A failure after the
upgrader restores the owned files and so leaves 4.0.5 code on a 1852 database;
the retry admits 1852 and finishes the update; nothing needs undoing. After a
successful apply, 4.0.7 files are on disk and the database is at 1852. A plain
git revert does not roll that back: the old deployment code admits neither the
4.0.7 files (no 4.0.7 manifest) nor schema 1852. Roll back forward instead:
select 4.0.5 again (`version` default), rebuild its manifest with
`"previous_only": false` and `"schema": "1852"` (a string; 4.0.5 runs on 1852),
and rebuild the 4.0.7 manifest with `"previous_only": true`, so the ordinary
deploy replaces the admitted 4.0.7 files; no database change or restore is
needed. Upstream 4.0.6 changed the
`password_expiration` default from YES to NO; `config.local.php` does not set
it. Missing original role privileges are granted
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
Backup/restore and old-mail schema conversion are separate workflows; the
removal (`remove_postfixadmin`) is documented in `docs/services/postfixadmin.md`.

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

Role templates are vendored byte-for-byte from ops-library commit `cf3a0c74b10ed83a43fa79c4d1f3a57fffc89641`
(version 2.75.2); public defaults remain false for explicit HSTS preload.
