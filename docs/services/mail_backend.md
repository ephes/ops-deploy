# Mail backend

`MailBackendConfig` / `deploy_mail_backend` provision the original Postfix,
Dovecot, OpenDKIM, SQL maps, Sieve and vmail role. PostgreSQL must be installed
and running with its existing local postgres administrative connection. The
narrow mail foundation creates only a missing login role/database and preserves
existing database/schema ownership and grants. It conditionally reconciles the
requested SCRAM credential and preserves a matching verifier. As in the original
role, the mail login receives any missing CONNECT/CREATE/TEMPORARY database
privilege and SELECT on every relation in schema `public`, including relations of
other applications in that database (such as PostfixAdmin's administrator
tables); existing privileges are never revoked.

Pass `SecretValues` keys `postgres_password`, `relay_password` and
`initial_user_password`. Set `domains`, `hostname`, TLS certificate/key paths and
mail storage paths explicitly for your environment. The default `schema_mode`
is the legacy role schema; `postfixadmin` uses the existing upstream application
schema. The API does not install or bootstrap the PostfixAdmin application.
In legacy mode both sides of a `postfixadmin_domain_aliases` mapping must be
hosted `domains`. Dovecot always listens on implicit-TLS IMAPS (993) with
`ssl = required`; `tls_enabled` toggles Postfix TLS only, as in the role.

Ordinary domains, initial mailbox and declared aliases are insert/conditional
update operations. Existing hashes, SQL timestamps and unowned rows remain
unchanged when current. There is no catalog pruning. PostfixAdmin's `ALL`
pseudo-domain and `domain_admins` mappings belong to the web application. Existing
DKIM keys remain unchanged; only missing declared keys are generated. Sieve
compiles only when missing or changed. Map-only changes retain reload semantics.

The six role-owned SQL SELECT definitions are compared through PostgreSQL's own
parser using unique, connection-local temporary views in a bounded transaction.
**Check/dry-run also performs these transient PostgreSQL catalog validation
writes**, followed by rollback/close. They are not read-only or physical-zero
work. No persistent candidates/cache objects are created; permanent OID, owner,
ACL and row contents are retained when current. TEMP permission failure refuses
validation rather than changing grants for the probe.

Dovecot validation expands referenced files (`doveconf -n -x`) so missing TLS
material is rejected before any daemon restart. Expanded output stays captured
in memory and is never logged.

Initial-mailbox management supports the selected `SHA512-CRYPT` scheme; other
selectors are refused during typed preparation rather than silently ignored.
The initial mailbox accepts qualified SHA512-CRYPT verifiers before interpreting
Dovecot's mismatch status. Malformed, unsupported, tool-failure or timeout state
refuses password/row mutation. Valid matching hashes retain their original bytes.
The native Dovecot interface receives the stored verifier as a subprocess
argument; plaintext remains on stdin and captured diagnostics never emit either.

`local_delivery_clients` is a separate port-25 local-destination-only access
contract. It does not grant the outbound relay permission of `mynetworks`.
Submission requires TLS/authentication and retains sender/login binding.

These APIs translate the existing role variables and packaged templates. Package
operations ensure presence; an installed package is not opportunistically upgraded.
There is no remove/restore lifecycle in these deploy functions.

Configuration and credential mutations remember restart/reload intent before the
first known write in a root-owned 0600 service-specific marker under
`/var/lib/ops-deploy/mail-core`. Validation failure can leave changed files on
disk while the running daemon still uses its old configuration. A later ordinary
deploy revalidates and performs the owed restart even when file bytes already
match. Markers clear only after all owned validation and service health checks
succeed. This is recovery of restart intent, not transactional rollback.
Unknown credential/tool state refuses mutation; it never means “change password.”
Existing unrelated daemons, mail/queue contents and current CA trust remain owned
by their existing services. Plaintext credentials use protected stdin, never argv
or environment; fixed diagnostics do not disclose secrets or stored verifiers.


## Example

```python
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mail_backend import MailBackendConfig, deploy_mail_backend

config = MailBackendConfig(
    domains=("example.test",),
    hostname="backend.example.test",
    tls_cert="/etc/ssl/mail/backend.crt",
    tls_key="/etc/ssl/mail/backend.key",
)
# The controller supplies these values from its existing secret store.
secrets = SecretValues(
    SecretRef("mail-secrets.yml"),
    {
        "postgres_password": values["postgres_password"],
        "relay_password": values["relay_password"],
        "initial_user_password": values["initial_user_password"],
    },
)
deploy_mail_backend(cfg=config, secrets=secrets)
```

## Typed variables and defaults

Unknown fields are refused. The names below are Python model fields (the original
role prefix is omitted). `null` keeps the corresponding optional role behavior.

| Field | Default |
| --- | --- |
| `service_name` | `"mail-backend"` |
| `user` | `"vmail"` |
| `site_path` | `"/mnt/cryptdata/vmail"` |
| `domains` | `"required"` |
| `sender_only_domains` | `[]` |
| `postfixadmin_domain_aliases` | `[]` |
| `forward_aliases` | `[]` |
| `required_aliases` | `[{"localpart": "postmaster", "destination_localpart": ""}, {"localpart": "abuse", "destination_localpart": ""}]` |
| `initial_user` | `""` |
| `initial_user_domain` | `""` |
| `relay_user` | `"relay"` |
| `dovecot_mail_location` | `null` |
| `sieve_dir` | `null` |
| `sieve_active` | `null` |
| `hostname` | `"macmini.home.wersdoerfer.de"` |
| `mydomain` | `"wersdoerfer.de"` |
| `imap_hostname` | `"imap.home.wersdoerfer.de"` |
| `smtp_hostname` | `"smtp.home.wersdoerfer.de"` |
| `inet_interfaces` | `"all"` |
| `inet_protocols` | `"all"` |
| `mynetworks` | `["127.0.0.0/8", "[::1]/128", "213.239.212.206/32", "[2a01:4f8:a0:82dc::2]/128"]` |
| `local_delivery_clients` | `[]` |
| `relay_host` | `"mail.wersdoerfer.de"` |
| `relay_port` | `587` |
| `vmail_path` | `"/mnt/cryptdata/vmail"` |
| `vmail_user` | `"vmail"` |
| `vmail_group` | `"vmail"` |
| `vmail_uid` | `5000` |
| `vmail_gid` | `5000` |
| `maildir_format` | `"%d/%n/"` |
| `postgres_host` | `"localhost"` |
| `postgres_port` | `5432` |
| `postgres_database` | `"mail"` |
| `postgres_user` | `"mail"` |
| `tls_enabled` | `true` |
| `tls_cert` | `"/etc/letsencrypt/live/home.xn--wersdrfer-47a.de/fullchain.pem"` |
| `tls_key` | `"/etc/letsencrypt/live/home.xn--wersdrfer-47a.de/privkey.pem"` |
| `smtp_tls_security_level` | `"encrypt"` |
| `smtpd_tls_security_level` | `"encrypt"` |
| `tls_protocols` | `">=TLSv1.2"` |
| `dovecot_protocols` | `"imap lmtp sieve"` |
| `dovecot_auth_mechanisms` | `"plain login"` |
| `dovecot_disable_plaintext_auth` | `"yes"` |
| `sieve_enabled` | `true` |
| `spam_to_junk_enabled` | `false` |
| `spam_junk_mailbox` | `"Junk"` |
| `sieve_before_dir` | `"/etc/dovecot/sieve/before.d"` |
| `dkim_enabled` | `true` |
| `dkim_selector` | `"mail"` |
| `dkim_key_path` | `"/etc/opendkim/keys"` |
| `dkim_key_bits` | `2048` |
| `extra_milters` | `[]` |
| `password_scheme` | `"SHA512-CRYPT"` |
| `recipient_delimiter` | `"-"` |
| `submission_rate_limit` | `100` |
| `smtputf8_enable` | `false` |
| `maillog_file` | `"/var/log/mail.log"` |
| `schema_mode` | `"legacy"` |
| `packages` | `["postfix", "postfix-pgsql", "dovecot-core", "dovecot-imapd", "dovecot-lmtpd", "dovecot-pgsql", "dovecot-sieve", "dovecot-managesieved", "opendkim", "opendkim-tools", "libsasl2-modules", "ca-certificates"]` |
