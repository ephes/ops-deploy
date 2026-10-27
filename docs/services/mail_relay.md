# Mail edge relay

`MailRelayConfig` / `deploy_mail_relay` provision the original Postfix edge,
postscreen, recipient verification, Postgrey, Cyrus SASL, submission cleanup,
recipient rewrites, optional postsrsd and original resolved fragment. Pass
`SecretValues` keys `sasl_password` and, when SRS is enabled, `srs_secret`.
Configure domains, backend target, public hostname and existing TLS paths.

Native libsasl2 catalog/authentication controls distinguish a known absent
account and a known wrong password from a corrupt/unreadable/unknown store.
Only known creation/change writes sasldb. Matched credentials retain exact store
bytes. A new account preserves the original restart behavior; ordinary password
and map changes retain reload behavior. All credential diagnostics are fixed.
SRS keeps the configured stable secret and the original own-domain exclusion
rules. Turning the optional feature off does not silently retire its retained
secret installation.

Port 25 retains original postscreen/greylisting and backend recipient validation;
a known unknown recipient is rejected, while backend-unavailable verification
retains temporary failure semantics. Authenticated TLS submission is a separate
outbound relay contract. Submission spam-header discard keeps its original
specific top-level header behavior. The optional resolved fragment is owned in
isolation and does not enable or unconditionally restart the global resolver.

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
from ops_deploy.services.mail_relay import MailRelayConfig, deploy_mail_relay

config = MailRelayConfig(
    domains=("example.test",),
    hostname="edge.example.test",
    backend_host="backend.example.test",
    tls_cert="/etc/ssl/mail/edge.crt",
    tls_key="/etc/ssl/mail/edge.key",
)
# The controller supplies these values from its existing secret store.
secrets = SecretValues(
    SecretRef("mail-secrets.yml"),
    {
        "sasl_password": values["sasl_password"],
        "srs_secret": values["srs_secret"],
    },
)
deploy_mail_relay(cfg=config, secrets=secrets)
```

## Typed variables and defaults

Unknown fields are refused. The names below are Python model fields (the original
role prefix is omitted). `null` keeps the corresponding optional role behavior.

| Field | Default |
| --- | --- |
| `service_name` | `"mail-relay"` |
| `user` | `"postfix"` |
| `site_path` | `"/etc/postfix"` |
| `domains` | `"required"` |
| `srs_exclude_domains` | `null` |
| `tls_cert` | `null` |
| `tls_key` | `null` |
| `recipient_rewrites` | `[]` |
| `hostname` | `"mail.wersdoerfer.de"` |
| `mydomain` | `"wersdoerfer.de"` |
| `backend_host` | `"smtp.home.xn--wersdrfer-47a.de"` |
| `backend_port` | `25` |
| `inet_interfaces` | `"all"` |
| `inet_protocols` | `"all"` |
| `smtp_address_preference` | `"any"` |
| `mynetworks` | `["127.0.0.0/8", "[::1]/128"]` |
| `tls_enabled` | `true` |
| `smtp_tls_security_level` | `"may"` |
| `smtpd_tls_security_level` | `"may"` |
| `backend_tls_security_level` | `"encrypt"` |
| `smtputf8_enable` | `false` |
| `tls_protocols` | `">=TLSv1.2"` |
| `greylisting_enabled` | `true` |
| `greylisting_port` | `10024` |
| `greylisting_delay` | `300` |
| `greylisting_max_age` | `35` |
| `greylisting_retry_window` | `48` |
| `postgrey_whitelist_clients_extra` | `[]` |
| `verify_recipients` | `false` |
| `unverified_recipient_reject_code` | `550` |
| `verify_external_transport` | `"discard:verified-by-srs-reverse"` |
| `postscreen_enabled` | `false` |
| `postscreen_dnsbl_sites` | `["zen.spamhaus.org=127.0.0.[2..11]*3", "list.dnswl.org=127.0.[0..255].0*-2", "list.dnswl.org=127.0.[0..255].1*-4", "list.dnswl.org=127.0.[0..255].[2..3]*-6"]` |
| `postscreen_dnsbl_threshold` | `3` |
| `postscreen_dnsbl_action` | `"enforce"` |
| `postscreen_greet_action` | `"enforce"` |
| `postscreen_access_extra` | `[]` |
| `local_recursor_enabled` | `false` |
| `local_recursor_address` | `"127.0.0.1"` |
| `local_recursor_dropin` | `"/etc/systemd/resolved.conf.d/10-mail-relay-local-recursor.conf"` |
| `submission_enabled` | `true` |
| `sasl_user` | `"relay"` |
| `submission_discard_spam` | `false` |
| `submission_discard_spam_regexp` | `"/^X-Spam-Status:[[:space:]]*Yes,/"` |
| `client_connection_rate_limit` | `10` |
| `client_recipient_rate_limit` | `100` |
| `smtpd_recipient_limit` | `100` |
| `maillog_file` | `"/var/log/mail.log"` |
| `packages` | `["postfix", "postgrey", "libsasl2-modules", "sasl2-bin", "ca-certificates"]` |
| `srs_enabled` | `false` |
| `srs_domain` | `""` |
| `srs_listen_addr` | `"127.0.0.1"` |
| `srs_forward_port` | `10001` |
| `srs_reverse_port` | `10002` |
| `srs_secret_file` | `"/etc/postsrsd.secret"` |
