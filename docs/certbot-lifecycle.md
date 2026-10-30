# Certbot state backup and restore

The source-backed `CertbotDnsBackupConfig`/`deploy_certbot_dns_backup` and
`CertbotDnsRestoreConfig`/`deploy_certbot_dns_restore` APIs cover the original
Certbot DNS/macmini and Certbot edge backup/restore plays. They do not issue a
new certificate or change normal certificate deployment. Inventory, paths and
transport bindings belong in the private control repository.

Tar backup includes the whole configured `src` directory, including Certbot's
relative `live` to `archive` links. Defaults are `/etc/letsencrypt`, root
`/opt/backups/certbot-dns`, prefix `manual`, local host timestamp, `gz` format
and `tar.gz` extension. Root owner/group and directory mode default root/root
and 0700. Every non-hidden regular archive directly in the backup root matching
`*.tar`, `*.tar.*` or `*.tgz` is corrected to 0600 when needed. Newly generated
and fetched archives are 0600 too. The controller reserves a new 0600 destination
before transfer, so a failed fetch retains a private partial archive even under
a permissive controller umask. The original backup file-mode variable is
unused by its tasks; these fixed 0600 requirements are retained.

`create_archive` and `fetch_local` default true and remain independent: local
backup directory creation can still occur when archive creation is disabled.
`local_dir` defaults to `~/backups/certbot-dns`; the edge binding selects
`~/backups/certbot-edge`. `local_dir_mode` defaults 0700. The public model exposes
`owner`, `group`, `dir_mode`, `archive_format`, `archive_extension` and literal
custom paths with spaces. There is no added snapshot retention or required
external mount policy. A normal backup creates managed timestamped work; no
zero-managed backup or upload-counter promise is made.

Restore requires a nonempty `archive`. The private plays choose `latest`, the
newest regular configured-extension archive by mtime under `root`; an absolute
or root-relative archive is also accepted. `directory` defaults
`/etc/letsencrypt`. The original vendored archive validator checks relative
members, the exact directory basename, duplicate paths, internal link graphs,
unsupported entries, members stored under symlinks and hardlinks to symlinks
before extraction. Original internal Certbot links remain supported.

Quiesce writers before normal restoration, as required by the original
preservation include. Extraction stages beside the live directory. The original
preservation script
retains the previous tree by atomic rename or a verified copy for a mount point,
refuses nested mounts and inadequate copy space, then empties only the live
contents. Pre-restore copies are never pruned. Publication uses the original
move semantics, including across filesystems. Staging is cleaned after success
or failure; genuine partial publication and the retained copy identity survive
as reported recovery evidence, without an invented rollback guarantee.

After publication, recursive owner/group default root/root, root mode 0700 and
existing `credentials_file`/`rfc2136_credentials_file` mode 0600 match the role.
The two file paths default to `/etc/letsencrypt/dns-credentials.ini` and
`/etc/letsencrypt/dns-rfc2136-credentials.ini`. Explicit `dry_run=True` validates
without staging, preservation, replacement, chmod/chown, renewal or mail reload.
Validation reads archive contents and is not a metadata-only inventory check.
Normal restores still perform managed staging/publication work when repeated.

`run_dry_renew=True` preserves the original `certbot renew --dry-run` command.
It can contact ACME and write Certbot state/logs, so it is managed work. As in
the original role, that command has no `--config-dir`: a custom restore directory
does not change Certbot's own default directory. Set `run_dry_renew=False` for
an offline publication-only restore. The edge binding's `reload_postfix=True`
preserves its original post-task after successful restore/renewal; other callers
default false. No normal backup/restore policy map is widened.

Owned native qualification uses synthetic state and the genuine Certbot binary
with no renewal lineages, with publication cases explicitly disabling renewal.
It does not establish real ACME/provider authentication, certificate issuance,
production restore, or whole-application parity. No real certificate or credential
body is exported for evidence and no deploy-default count follows from these
four lifecycle registrations.

The typed API refuses traversal, retained pre-restore targets and a finite set
of named system roots for source/root/local directories. Mutable targets cannot
be retained pre-restore copies; reading one as a backup source is allowed.
Source and backup root must be disjoint. An empty credential path disables that
entry. Backup formats mirror the original archive module; its zip output is still rejected
by the original tar-only restore validator. No conversion to a different
restore format is performed.

Archive creation publishes its final name only after a private hidden temporary
archive completes. A failed read or walk removes the temporary file and keeps any
prior same-name archive, so that failed creation cannot supply the next `latest`
restore. This process-failure protection makes no power-loss durability guarantee.
