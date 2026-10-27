# Mail monitoring

`MailMonitoringConfig` and `deploy_mail_monitoring` provision the existing
monitor mailbox, Maildir, cleanup timer and optional Mailgun HTTP relay probe.
They require an already provisioned local PostgreSQL mail database (PostfixAdmin
or legacy schema), Dovecot's `doveadm`, Python psycopg2 and the vmail account.
They do not install or reconfigure shared mail authentication or schemas.

The configuration names the mailbox address, schema, database and vmail path,
user/group. Cleanup defaults to one day and a daily timer. Probe settings map
the original role's URL, domain, sender, recipient, subject, timeout/retries,
calendar and service/user names. All six original scripts/unit templates ship
in the package. The probe uses `/v3/<domain>/messages`, curl stdin authentication,
a 0600 token and an unprivileged system account. Its state is readable by the
existing metrics endpoint. Disabling the probe removes only its resources;
disabling cleanup leaves installed cleanup resources as the original role does.

Pass `SecretValues` containing `monitor_password` and, when the relay is enabled,
`relay_probe_token`. No secret is generated automatically. Passwords travel over
stdin; CR, LF and NUL cannot be represented by Dovecot's interactive password
input and are rejected. Dovecot's existing `pw -t` verification interface still
requires the stored password hash as a subprocess argument; local process-list
readers can observe that verifier while the process runs. Plaintext is kept off
argv, and neither plaintext nor hashes are emitted in deploy logs. This port
retains the Dovecot interface rather than introducing a different hash verifier.
A missing stored hash is diagnosed rather than silently replacing it. Dovecot verifies the existing password hash; no-op
reconciliation preserves it. Changed password/active state uses the existing
role SQL. Missing domains and ambiguous identities fail without row changes.
PostgreSQL operations run as postgres and emit only a changed-state indicator.

Maildir directories are vmail-owned 0700. Existing mail messages, other mailbox
rows and shared Dovecot/Postfix configuration are never reconciled here.

The private umbrella composes this module with `metrics_endpoint` and two
`nyxmon_site_checks`. That helper accepts IMAP hostnames and offers opt-in
`managed_safety`: database/regular sidecar ownership and 0600 validation,
required columns, unambiguous identities, and processing-lease checks. It runs
as the configured Nyxmon user with umask 077. Unchanged checks preserve runtime
state; configuration changes retain the original managed-task update semantics.
Removal is prohibited in managed mode. Other consumers retain default behavior.

## Disposable Linux qualification

`smoke/mail-monitoring-bootstrap.sh` is exclusively for an empty disposable
Ubuntu VM: it creates synthetic mail schemas/accounts and replaces that VM's
Dovecot configuration. Never run it against an inventory host. After bootstrap,
set the usual `SMOKE_SSH_*` variables and `MAIL_MONITORING_FIXTURE=1`, then run
`pytest tests/smoke/test_mail_monitoring_smoke.py`. The test verifies real
PostgreSQL reconciliation, Dovecot authentication, password rotation, Maildir
identity, missing-domain failure and zero-change repeats. Default tests skip
this integration test unless explicitly selected for an owned fixture.
