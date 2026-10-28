# Owned software-live qualification

The workflow runs only in disposable GitHub Ubuntu 24 VMs and their isolated Debian 13
systemd guests. Debian has its own userspace/filesystem and shares the Ubuntu host kernel.
Public source is copied into the guest; no inventory, host data, credentials or Docker
socket is mounted. The runner verifies every installed resource name and byte against the
exact selected Git artifact and rejects editable installation.

The real deployment creates accounts, units, credentials, state, HTTP endpoints and released
Rust 0.1.1 binaries. Its collectors perform real read-only OS/package observations; the
fixture never runs upgrade/reboot jobs. Only the collection calendar moves to 2099 to avoid
expiry during strict snapshots; original schedules/templates have independent actual
Ansible rendering evidence. Existing OnBootSec behavior is retained and collectors settle
before snapshots. Original-role coexistence always collects and rewrites state; that phase
is explicitly not a physical no-op.

Phases cover bootstrap, authenticated/anonymous health, strict repeats with shell/fish,
actual cf3 Ansible coexistence, stale/missing-state collection, policy-only changes,
fixture credential rotation, real Python/Rust switching, shadow comparison and removal,
rollback before invalid shadow input, owned SQLite creation/current/re-enabled/disabled
checks, and removal with retained/default or explicitly removed production data.
All failures retain raw phase operations, logs and before/after state. Managed zero and
upload zero are required alongside strict filesystem/unit/PID/package/policy equality for
healthy repeats. SQLite main file and owned rows remain strict; sidecar bookkeeping is
observed separately. No production keeper or blanket zero-I/O assertion is used.

Native execution, review and inventory qualification are pending. Run via the
`Software live integration` workflow after the feature implementation is reviewed.
