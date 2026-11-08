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
existing route policy. Backup/restore remain separate workflows; the removal
(`remove_snappymail`) is documented in `docs/services/snappymail.md`.

Existing admin hashes must have the canonical bcrypt encoding used by the selected
release and PHP. Malformed, unsupported or unavailable verification refuses
without replacing the stored credential. All checks use the selected versioned
PHP CLI; system alternatives are preserved. Shared-runtime changes also probe
the configured peer's actual loopback listener with an independent bounded
preservation check (10 seconds, three attempts).

Role templates are vendored byte-for-byte from ops-library commit `cf3a0c74b10ed83a43fa79c4d1f3a57fffc89641`
(version 2.75.2), except `traefik-snappymail.yml.j2` (the `ipAllowList`) and
`nginx-snappymail.conf.j2` (the `/snappymail/` restriction), which the
`snappymail_deploy` role does not have yet; public defaults remain false for
explicit HSTS preload.
