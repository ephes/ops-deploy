# Voice Memo Inbox components

The typed Inbox installer ports the original
`daybook_voice_memo_inbox_deploy` declaration. This implementation slice is
undergoing source review and disposable-host qualification; it does not change
inventory engines or qualify a default deployment.

`DaybookInboxConfig` retains the original defaults and fixed protected root
checkout, shared root Python tree, GUI account layout, two launchd labels,
policy and separate owner-only credential resource. Credentials are separate
`SecretContent` expectations sent over stdin. Inspection compares only declared
resource bodies in memory and code/package metadata; it does not publish
credential hashes or open recordings, importer ledger, activation markers or a
Journal. The original optional `voice-memos status --summary-only` command reads
an importer ledger despite its name; it is not a read-only deployment fact in
this port and has not been invoked on an inventory host.

`install_daybook_inbox(config, secrets, source_tree, bundle, ...)` is the explicit
disabled-first installer substage. It never activates or baselines an Inbox.
The existing activation, first-scan proof and credential-rotation workflows are
separate lifecycle work still requiring typed conversion; no permanent Ansible
fallback is introduced here. Normal runtime updates retain their original
stop/window → Inbox-only install → replacement → cutover → verify sequence.
Sessions and Photos source convergence do not become new update dependencies.

When the declared source, locked Python and final resources are already current,
installation queues pure verification and preserves an enabled operations keeper.
The keeper's declared live plist is the final resource projection; the installer
still writes only its original disabled-first plist. After managed installation,
`verify-installed` requires the original disabled/quiescent install set. It does
not compare that intermediate handoff against the later keeper plist or change
the existing profile's enabled bit. Ordinary already-current verification keeps
using the final keeper projection. Drift under a live keeper
requires the existing runtime update sequence before this installer can mutate
anything. This is the original running-code guard, not a new acknowledgement.

Managed installation disables both original lanes before bootout. It preserves
the original twelve-observation, five-second launchd termination window and
refuses unavailable/domain/permission errors rather than interpreting them as
absence. It then prepares the original directories and logs, stages one exact
Main bundle using the existing SSH identity in a per-run private directory,
checks descriptor metadata and bytes before root publication, verifies the
bundle before replacing a drifted checkout, and installs the original pinned
root Python with frozen dependencies and a regular protected interpreter copy.
The original service-user import and CLI-help smoke is managed application work
following Python convergence; it never runs inside a fact. Resource writes are
atomic; logs retain their contents, inode and timestamps. Transfer failures remain
failures and trigger cleanup of only the owned temporary transfer.

Desired Main is resolved once by the normal controller source workflow. No
installed-old-ref pin, new activation marker, bypass flag or engine confirmation
is added. A source transition for an active keeper needs its existing functional
window and a concrete source/lock/effect review before inventory execution.

Paired declaration/resource checks use the actual collection:

```sh
OPS_LIBRARY_PATH=../ops-library uv run --locked --with ansible-core pytest \
  tests/test_daybook_inbox_declaration.py tests/test_daybook_inbox_controls.py
```

Owned fixtures use inert code and unusable credentials. They do not read real
Voice Memos, call private app status, activate an Inbox or change TCC/auth policy.
Mechanism and source proofs are recorded separately from actual inventory
qualification.
