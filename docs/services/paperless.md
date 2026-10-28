# Paperless migration preparation

The prepared `PaperlessConfig`, `PaperlessCredentials` and `deploy_paperless`
API composes the checksum-bound 3.2.1 release and current `paperless_deploy`
role behavior. It has not been adopted in the inventory. Native application
qualification is still outstanding; this is not a supported production entry point.

The initial typed configuration renders all eight original role templates byte
for byte in three synthetic Ansible oracle cases: defaults, authenticated Redis,
and a custom service account/storage root. Bash parsing of the resulting
environment is also tested. These local checks do not qualify systemd, database,
scanner or application behavior on Linux. The runtime remains pinned to the
declared 3.2.1 release and Python 3.14.

The approved search-index change replaces unconditional Ansible reindexing with
explicit release/package/migration/force triggers and bounded checks of index
metadata, schema/language sentinels and the live-document SQL count. The source
manager in the release's locked `django-soft-delete` 1.0.23 filters
`deleted_at IS NULL`; the final query still needs owned application proof. The schema fingerprint
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
actual systemd/application recovery still requires the native fixture. Abrupt
process or host loss cannot guarantee resumption. Application command output is
discarded to avoid logging document metadata. The helper retains the original
role's lack of a separate reindex timeout.

The prepared count command uses one fixed `COUNT(*)` with the release's
soft-delete predicate, a read-only PostgreSQL transaction and a 30-second
statement timeout. It returns only the aggregate and refuses query errors or
unexpected output. Actual application schema/manager parity remains unqualified
until the owned native fixture runs.

This preparation does not change the original Ansible role, which still rebuilds
on every deployment. Native application, OCR/SFTP, recovery and live qualification
remain outstanding. No production document or index contents were inspected.

## Prepared deployment and recovery

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
when those assets or their declared dependencies change. These checks may update
access metadata and do not claim global zero I/O.

Migrations check actual pending schema work. Administrator checks select only
the declared identities and flags. Existing password/email values are left
alone; strict missing-user failure can follow prior creation/promotions, as in
the original role. Management programs travel via protected stdin and application
output is suppressed. An explicit blocking stdin bootstrap avoids Django's
interactive-console race, and apply steps must emit their completion marker.
Actual Paperless Django initialization effects remain to
be measured in the owned native fixture; the local Django auth/static oracles
do not establish full application or PostgreSQL behavior.

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
health checks require all four units active and HTTP200 from loopback `/api/`.

## Qualification still required

The owned native plan uses a fresh public GitHub Ubuntu24 x86 VM with a systemd
Docker userspace. Its kernel is shared with that disposable VM; it is not a KVM
or hardware proof. No inventory, host-data, credential or Docker-socket mounts
are permitted. Actual OCR/SFTP, PostgreSQL manager/count, index recovery, yescrypt,
ACL/mount and service first/repeat/failure cases remain required before adoption.
The [concrete native fixture](https://github.com/ephes/ops-deploy/tree/main/tests/integration/paperless)
has separate fresh current-release and 3.0.4-to-3.2.1 upgrade legs. Its source
and local guard tests are preparation, not evidence that those cases have run.
Backup, restore, removal and the campaign's other lifecycle routes are tracked
separately; this normal-deploy preparation does not claim they are converted.
