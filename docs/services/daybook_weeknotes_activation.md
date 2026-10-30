# Weeknotes schedule activation

`WeeknotesActivationConfig` and `activate_weeknotes_schedule` preserve the
separate original fresh-apply-bound system timer activation. The timer must be
unretired, and confirmation must equal
`ENABLE monday-after-v1 draft schedule`. General Sessions deployments cannot
activate it. The operations source `weeknotes` remains independent; retirement
must never be bypassed to exercise this API.

The hidden `identity` field is the existing `WeeknotesIdentityConfig` for action
`apply`, with its original apply phrase, exact Main and private ordered intent.
`retired` is a strict boolean defaulting false; true refuses. The fixed
`reconcile_launcher` is `/etc/daybook-sessions/reconcile-weeknotes.sh` and
`launchctl_bin` is `/bin/launchctl`; production values cannot be retargeted.
Identity paths, user, environment, checksum, code bytes and seed binding keep
all original identity operator constraints. Hidden data travels only in
protected stdin and target RAM.

The original root/Darwin connection and all seven privilege-clearing fields
are retained. Each admitted call first executes the exact emergency disable,
then a single managed sequence runs original apply and verify. Their plan hashes
must match before root proof publication. Activation loads the packaged
identity helper as a named module, without running its stdin main, and uses a
trusted after-verified callback in the same remote process. The callback always
re-reads the proof against the fresh plan hash/Main, including unchanged-proof
repeats; it never decides freshness from a write flag.

The callback checks original single-link regular-file owner/modes, the exact
epoch environment line, and disabled/unloaded state. Before enable, only
launchctl status 113 is admitted as known absent; other unexpected failures
refuse with a fixed state-unavailable category. It then enables and
bootstraps the exact system plist and proves loaded/persistently enabled state.
It never kickstarts. The original schedule and `RunAtLoad=false` declaration
remain managed by Sessions; no reconciliation is intentionally started here.
There are two managed operations and zero uploads on every successful call,
including repeats. Application actions are never facts.

Original partial activation effects are retained and reported honestly:

- `weeknotes_activation_enabled_bootstrap_failed`: enable succeeded; bootstrap
  failed, so the persistent override may already be enabled.
- `weeknotes_activation_loaded_verification_failed`: bootstrap succeeded but
  final loaded/enabled verification failed; the unit may remain loaded.

Both failures require the existing emergency disable recipe to establish
safe disabled/unloaded state before recovery. No automatic rollback or lock
removal is invented, and no partial failure is reported as a pre-enable refusal.
Raw application output and private hashes are never included in diagnostics.

Owned native qualification uses real root/owner SSH and launchctl with inert
UV/app reports and unique fixture paths/labels. An owned proxy injects exact
post-enable faults while forwarding successful commands to real launchctl;
production config is validated before disclosed unvalidated fixture
substitutions. The full nineteen-case identity fixture is also re-qualified
because the embedded identity helper bytes change. No actual app, posts,
credentials, auth rotation or inventory activation is qualified by this proof.
