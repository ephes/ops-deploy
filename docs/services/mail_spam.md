# Mail spam filtering

`MailSpamConfig` / `deploy_mail_spam` provision the original Rspamd package
repository, configuration, Redis connection, controller, Postfix milter and
optional isolated Unbound resolver. Postfix must already exist. Pass
`SecretValues` keys `web_password` (when controller enabled) and `redis_password`
(the original role permits an empty value for an unprotected local Redis).

Repository/key migration is scoped to the declared original legacy line/key and
current signed repository. Installed packages remain at their current versions.
The service does not train, rebuild or flush Bayesian/Redis state. Existing
controller hashes are verified by the native `rspamadm pw --check` bounded PTY
interface: return status, prompt completion and terminal marker all have to agree.
Malformed/truncated/timed-out probes refuse mutation. A matching hash is retained.
Configuration validation requires both successful native exit and `syntax OK`.

The private resolver uses its own configuration, unit, state directory and port
(default 5335), and validates the DNSBL test point. It retains the original
fallback and DNSSEC policy and does not replace the host's global resolver.
`monitoring_probe` exempts only the configured exact source/sender/recipient and
subject prefix from score-based spam actions; other scans remain enabled. As in
the role, its source must not fall inside `local_addrs_default`,
`local_addrs_extra` or loopback: `external_relay` never reports such a hop as the
sender, and a trusted relay's address would extend the exemption to Internet mail.
Milter integration preserves other configured milters. Existing Rspamd aggregate
statistics RRD updates are normal daemon activity and can change file digests
through its shared mapping without metadata changes; a zero-managed-change deploy
is not a claim that all physical filesystem bytes remain fixed.

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
from ops_deploy.services.mail_spam import MailSpamConfig, deploy_mail_spam

config = MailSpamConfig(
    resolver_enabled=True,
    resolver_install_packages=True,
)
# The controller supplies these values from its existing secret store.
secrets = SecretValues(
    SecretRef("mail-secrets.yml"),
    {
        "web_password": values["web_password"],
        "redis_password": values["redis_password"],
    },
)
deploy_mail_spam(cfg=config, secrets=secrets)
```

## Typed variables and defaults

Unknown fields are refused. The names below are Python model fields (the original
role prefix is omitted). `null` keeps the corresponding optional role behavior.

| Field | Default |
| --- | --- |
| `service_name` | `"mail-spam"` |
| `user` | `"_rspamd"` |
| `site_path` | `"/etc/rspamd"` |
| `monitoring_probe` | `null` |
| `milter_socket` | `null` |
| `milter_socket_postfix` | `null` |
| `redis_enabled` | `true` |
| `install_redis` | `false` |
| `redis_host` | `"localhost"` |
| `redis_port` | `6379` |
| `web_enabled` | `true` |
| `web_bind` | `"127.0.0.1"` |
| `web_port` | `11334` |
| `milter_socket_dir` | `"/var/spool/postfix/rspamd"` |
| `milter_socket_name` | `"milter.sock"` |
| `milter_mode` | `"0660"` |
| `reject_score` | `15` |
| `add_header_score` | `6` |
| `greylist_score` | `4` |
| `rewrite_subject_score` | `8` |
| `subject_prefix` | `"[SPAM]"` |
| `dkim_signing_enabled` | `false` |
| `learn_spam_header` | `"X-Spam-Learn: spam"` |
| `learn_ham_header` | `"X-Spam-Learn: ham"` |
| `milter_headers` | `["x-spamd-bar", "x-spam-level", "x-spam-status", "authentication-results"]` |
| `local_addrs_default` | `["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "fd00::/8", "169.254.0.0/16", "fe80::/10"]` |
| `local_addrs_extra` | `[]` |
| `resolver_enabled` | `false` |
| `resolver_install_packages` | `false` |
| `resolver_listen` | `"127.0.0.1"` |
| `resolver_port` | `5335` |
| `resolver_fallback` | `"127.0.0.1:53"` |
| `resolver_service` | `"unbound-rspamd"` |
| `resolver_config` | `"/etc/unbound/rspamd-resolver.conf"` |
| `resolver_state_dir` | `"/var/lib/unbound/rspamd"` |
| `external_relay_enabled` | `false` |
| `local_config_path` | `"/etc/rspamd/local.d"` |
| `override_config_path` | `"/etc/rspamd/override.d"` |
| `rspamd_repo_url` | `"https://rspamd.com/apt-stable/"` |
| `rspamd_legacy_repo_url` | `"http://rspamd.com/apt-stable/"` |
| `rspamd_repo_key_url` | `"https://rspamd.com/apt-stable/gpg.key"` |
| `rspamd_repo_keyring` | `"/etc/apt/keyrings/rspamd.asc"` |
| `rspamd_repo_legacy_key_id` | `"BF21E25E"` |
| `rspamd_cleanup_legacy_key` | `true` |
| `packages` | `["rspamd"]` |
