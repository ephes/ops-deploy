# SnappyMail ordinary deployment

`deploy_snappymail(config, secrets)` manages selected SnappyMail 2.38.2 code,
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
local vendor/trust repairs. Current 2.38.2 is the only selected release; a previous
2.38.0 manifest admits an explicitly qualified update path. Unrelated old code
files remain untouched. TLS verification and the system CA store remain enabled;
this API introduces no certificate bypass or private CA replacement.

The shared mail-web helper validates the complete nginx/FPM candidate dependency
closure and PHP syntax before committing owned files. Runtime activation checks
the local page and the other configured mail web app. Exceptions restore owned
bytes, mode, ownership and links, then recover the previous runtime state. This
is bounded exception recovery, not recovery from power loss or a killed helper.
A no-op does not stage files, upload helpers, rotate hashes or restart services.

`traefik_sts_preload` defaults to false and can preserve an explicitly selected
existing route policy. Backup/restore/remove remain separate workflows.

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
