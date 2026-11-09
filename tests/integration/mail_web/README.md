# Owned mail web integration fixture

This manual workflow runs only on a disposable GitHub-hosted Ubuntu 24.04 x86_64
VM. `run.sh` requires systemd, root, exact implementation/harness commit IDs and
absent application/data roots; it records an exclusive VM ownership marker.
It never connects to inventory or reads real mailbox/session content.

The fixture uses real PostgreSQL, PHP 8.3/FPM, nginx, Postfix and Dovecot with
runtime-generated synthetic credentials, loopback listeners and an owned TLS
trust certificate. SMTP accepts only the synthetic local domain and the fixture
sends only to its own local mailbox. No external delivery test is involved.

The production API performs fresh installation and actual upstream PostfixAdmin
schema initialization. Subsequent phases cover config and credential changes,
real app authentication, locally delivered mail over verified TLS, invalid nginx
candidate refusal, a real one-shot systemd FPM restart failure and owned-file
recovery, and previous-to-selected release updates. Each repeat compares complete
resource metadata and runtime PIDs, rejects uploads and traces actual command
filesystem activity. Fixture preparation, synthetic logins/mail and intentional
old-release seeding are separate from deployment/no-op accounting.

Recovery checks compare bytes, mode, UID/GID and links; inode timestamps and PIDs
may change during a failed activation and recovery. No-op comparisons include
those timestamps/PIDs. Failed operations may create staging or perform recovery even when pyinfra
reports no successful changed operation; their zero reported managed count is
never a no-write claim. Only successful traced repeats assert no filesystem
mutations. Raw phase results and traces are retained even on failure.
A passing summary is written only after all assertions complete. The current
harness is implementation work; no native success is claimed before an actual
immutable workflow run completes.
