# Owned mail core integration fixture

`.github/workflows/mail-core-integration.yml` runs on pull requests that touch the
mail core packages (and on manual dispatch with an exact implementation commit)
on a disposable GitHub-hosted Ubuntu 24.04 x86_64 VM. `run.sh` requires root,
systemd, the exact implementation/harness commit IDs and a runner without any
mail stack. It proves that the controller imports the immutable non-editable
implementation and that every installed package file equals its Git bytes.
It never connects to inventory.

Two minimal Ubuntu 24.04 systems (`mc-backend`, `mc-edge`) are built with
`debootstrap` and booted with `systemd-nspawn` on a private bridge. The unit binds
no host path: no home, workspace, credential, agent or socket directory, no
journal link, no host resolver or timezone. Each system receives only a fresh
per-run controller public key, its own host key (pinned in a known-hosts file)
and an owned CA plus leaf certificate. The host NATs package-mirror and DNS
traffic but rejects forwarded SMTP (25/465/587/2525) and all IPv6 from the
bridge; a host `dnsmasq` on the bridge serves only the synthetic `.test` names
and MX records. The owned sink on edge accepts only `@remote.fixture.test`.

Mail packages stay absent until the APIs install them; the harness records
their `dpkg` state before and after each phase. Fixture prerequisites that the
APIs do not own are installed first: PostgreSQL 17 (PGDG), Redis with
`requirepass`, PHP CLI and the real upstream PostfixAdmin 4.0.5 release
(checksum-verified) whose `upgrade.php` creates schema 1851 with its own
database role. The `mail` login role is left absent for the backend foundation.

Phases:

1. A package fault (an apt pin makes `postfix` uninstallable) must refuse before
   any substitute account, configuration, marker, database role or daemon exists.
2. The corrected ordinary first install runs backend, relay and spam in the
   umbrella order. Every daemon whose package was absent (including apt-started
   defaults) must run with a start time after its managed configuration; the
   effective Postfix/Dovecot values are read back natively.
3. Owned synthetic mail: edge port 25 from the owned external address to the
   backend mailbox (postscreen, postgrey, recipient verification, Rspamd milter,
   LMTP, IMAPS), and backend authenticated submission relayed through edge's
   SASL submission to the owned sink (TLS, DKIM, no SRS for the own domain).
4. The actual repeat of each stage must have zero managed changes and keep every
   daemon PID.

Credentials are generated per run, sent on stdin and never written to the
uploaded evidence (`/var/tmp/mail-core-evidence`). The Rspamd private resolver
performs real recursion, so its DNSBL test point depends on the runner's network.
Scope: one x86_64 Ubuntu 24.04 package set at run time (installed versions are
recorded); not package-update support, other OS releases or production state.
