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

Role templates are vendored byte-for-byte from ops-library commit `cf3a0c74b10ed83a43fa79c4d1f3a57fffc89641`
(version 2.75.2); public defaults remain false for explicit HSTS preload.
