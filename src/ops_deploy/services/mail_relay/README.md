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


## postsrsd 1.x and 2.x

postsrsd 1.x (Ubuntu 24.04, Debian 13: 1.10) reads `/etc/default/postsrsd` and
answers Postfix `tcp:` lookup tables. postsrsd 2.x (Ubuntu 26.04: 2.0.11) reads
`/etc/postsrsd.conf` and answers only `socketmap:` tables. With `srs_enabled`
the deploy picks the layout by postsrsd's major version: the installed
package's (`dpkg -l`; an installed package is never upgraded here), otherwise
apt's candidate (`apt-cache policy postsrsd`). When apt knows no candidate yet
(empty package lists before the deploy's own `apt update`), the 1.x layout is
planned; a read-only check right after the package install then refuses a
different installed major before any configuration is written, and the next run
plans for the installed one. Any other major is refused.

**1.x** is unchanged: the same files, `tcp:<srs_listen_addr>:<port>` maps, op
order and listener waits as before 2.x support (byte-identical renders, pinned
by `tests/test_mail_relay_postsrsd.py`).

**2.x** renders `/etc/postsrsd.conf` from the same inputs:

| postsrsd 1.x (`/etc/default/postsrsd`) | postsrsd 2.x (`/etc/postsrsd.conf`) |
| --- | --- |
| `SRS_DOMAIN` (`srs_domain`) | `srs-domain` |
| `SRS_EXCLUDE_DOMAINS` (`srs_exclude_domains`, each as `.domain` and `domain`) | `domains`, the same list |
| `SRS_SECRET` (`srs_secret_file`) | `secrets-file`, the same file and secret |
| `SRS_SEPARATOR`, `SRS_HASHLENGTH`, `SRS_HASHMIN` (`=`, 4, 4) | `separator`, `hash-length`, `hash-minimum` |
| `RUN_AS`, `CHROOT` (`postsrsd`, `/var/lib/postsrsd`) | `unprivileged-user`, `chroot-dir` |
| `SRS_LISTEN_ADDR`, `SRS_FORWARD_PORT`, `SRS_REVERSE_PORT` | `socketmap = unix:/var/spool/postfix/srs` |

main.cf then names `socketmap:unix:srs:forward` and
`socketmap:unix:srs:reverse` (relative to the queue directory, where the
chrooted cleanup daemon finds the socket); everything else in main.cf stays the
same. `srs_listen_addr`, `srs_forward_port` and `srs_reverse_port` have no 2.x
meaning and are refused unless they keep their defaults; the SRS domains and the
secret path must be plain names (they are quoted into the file). The secret file
is the one 1.x used, so addresses 1.x issued still reverse: with the same secret,
1.10 and 2.0.11 issue identical SRS0/SRS1 addresses and each reverses the
other's. 2.x keeps `syslog = off` (its messages go to the journal) and
`original-envelope = embedded` (stateless, like 1.x).

On 2.x the deploy switches postsrsd before Postfix: the secret, `postsrsd.conf`,
removal of the 1.x `/etc/default/postsrsd`, postsrsd enable/start/restart, and a
read-only socketmap round trip (a foreign sender is rewritten into the SRS domain
and back; an own domain and its subdomains are not rewritten) all run before
main.cf names the socketmap and Postfix restarts. The foreign sender is
`ops-deploy-srs-probe@` the first of `srs-probe.invalid`, `srs-probe.example`,
`srs-probe.test` and `srs-probe.localhost` that is neither the SRS domain nor
an exclusion or below one; if none is left the deploy refuses before any change.

After a release upgrade from 24.04 to 26.04 the package's postinst starts
postsrsd 2.x on its packaged `/etc/postsrsd.conf` while main.cf still names the
1.x `tcp:` tables. Until `mail_relay` is deployed again, cleanup refuses every
message with a temporary error ("map lookup problem ... try again later"):
senders retry and local mail waits in the maildrop, nothing bounces. Deploy
`mail_relay` right after the upgrade.

`tests/test_mail_relay_postsrsd_docker.py` runs the 2.x deploy against real
Postfix 3.10 and postsrsd 2.0.11 under systemd. It is skipped unless
`MAIL_RELAY_POSTSRSD_DOCKER_CONTAINER` holds the full ID of a running container
named `ops-deploy-mail-relay-postsrsd2-20261029`, labelled
`ops-deploy.fixture=mail-relay-postsrsd2` and
`ops-deploy.run=mail-relay-postsrsd2-20261029`, with `--network none`, not
privileged, `--cgroupns private`, `SYS_ADMIN` and `SYS_PTRACE` (the Postfix
master check reads `/proc/<pid>/exe`) as the only added capabilities, no mounts,
ports or devices, `--security-opt apparmor=unconfined`, and tmpfs only on `/run`,
`/run/lock`, `/var/spool/postfix` and `/var/lib/postgrey` (owned by postgrey).
Build it from `ubuntu:26.04` with `postfix/main_mailer_type` preseeded to
`No configuration`, `systemd systemd-sysv python3 postfix postgrey
libsasl2-modules sasl2-bin ca-certificates postsrsd ssl-cert` installed,
`/etc/postsrsd.conf` copied to `/opt/postsrsd.conf.packaged`, postfix, postgrey
and postsrsd enabled, and as entry point `/sbin/init` after remounting
`/sys/fs/cgroup` read-write. Each test resets it to the shape a release upgrade
leaves (2.x on its packaged configuration, the 1.x defaults file, a 1.x main.cf
and the SRS secret). It covers the switch (socketmap round trip before the
Postfix restart, no 1.x file or listener left, secret bytes and inode kept),
`postmap -q` against the configured tables in the queue directory, a message
through `sendmail` and the chrooted cleanup daemon (sender rewritten, a bounce
to the SRS address reversed, an own sender untouched), a second run without a
managed change or a new daemon PID, and a drifted `postsrsd.conf` restored with
a postsrsd restart only.

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
