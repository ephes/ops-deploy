# Daybook Sessions resources

This staged port preserves the original `daybook_sessions_deploy` declaration and
its Sessions, Archive classifier and Weeknotes reconciler resources. The guarded
host controller is undergoing owned qualification; normal inventory routing is
still pending. These APIs do not switch an engine or authorize a live update.

`DaybookSessionsConfig` retains the original 105 nonsecret variable names and
resolves their original dependent defaults. Seven private fields stay separate
from the config: the AWS access/secret keys, Archive/Cast/Weeknotes tokens, public
repository JSON and confidential-name JSON. Rendered environments and the existing
managed environment checksum are wrapped in `SecretContent`; resource reprs do
not disclose them. The eleven templates and complete defaults are compared to the
actual paired ops-library cf3a0c74 role.

Installation remains separate from activation. Retired legacy timers have no
rendered plist, while their command, environment and source resources remain
available to the operations supervisor. A retired timer does not mean its
component is disabled. Weeknotes installation refuses activation; its existing
identity proof must verify before a declared post-identity epoch can be rendered.
The original SHA-256 environment checksum guard remains a managed resource;
observers must not export its credential-bearing digest as an attestation.

The original separate auth source and refreshed managed auth destination remain
distinct. `daybook_weeknotes_reconcile_pi_auth_rotate` defaults to false. Host
deployment must preserve an existing refreshed credential and retain the role's
real-path, ownership, mode and single-link checks before any seeding.

Normal desired source remains the once-per-run resolved head of Daybook Main.
An installed old revision is not an alternative pin. A change to active Inbox
runtime source needs its guarded update and attended window. Legacy Sessions
checkout convergence retains its original scoped guards; shared environment
effects are assessed against the active adapters separately. Python stays at the declared
3.14.7 unless a separate reviewed declaration changes it. The existing classifier
command/model selection is opaque operator configuration and remains unchanged.
Its original synthetic `Return exactly OK.` probe is an actual external command
when enabled; rendering or metadata inspection never invokes that command.

Run exact role-resource and guard checks with the paired collection available:

```sh
OPS_LIBRARY_PATH=../ops-library uv run --locked --with ansible-core pytest \
  tests/test_daybook_sessions_resources.py tests/test_daybook_runtime_guards.py
```

No tests read personal sessions, photos, audio, transcripts or application record
bodies. Synthetic fixtures use unusable credentials and explicit metadata.

`install_sessions_source(config, source_tree, bundle)` implements the source and
locked-environment stage independently of resource installation. The source tree
and controller bundle must bind the same once-resolved Main commit. Existing
no-fetch mode requires a real service-user-owned Git checkout; update mode can
initialize a checkout under an already prepared parent. Both use the controller
bundle, so hosts need no GitHub credentials, key enrollment or host-key changes.
The configured repository URL remains the origin on a fresh checkout.

The stage retains tracked-force semantics and no-fetch mode’s untracked refusal
(update mode retains unrelated untracked files), exact managed
Python, original frozen sync inputs and the original service-user login context
for managed Git/build commands. Explicit environment reaches that context after
sudo. It neither imports the application nor runs the classifier probe. The dedicated
Sessions checkout may converge while an unrelated Inbox-backed supervisor runs.
Its source stage does not mutate that supervisor’s code, policy or resources.
There is no user-wide operations-serving barrier or force/ack bypass. Shared
environment/config changes are a separate resource-composition concern; the
original runtime update remains Inbox-only. For managed system scope, the source stage
also requires the original exact reconcile daemon to be persistently disabled
and unloaded before any source drift: the complete role must run its original
early reconcile quiesce first. This standalone component refuses that missing
precondition at managed preparation (before creating the transfer directory)
and apply without unloading or disabling anything itself. Status reports readiness
without refusing a still-loaded daemon, so the original earlier quiesce operation
can satisfy the precondition during the same pyinfra run. A failed fresh update
checkout with an unborn HEAD can retry the same controller bundle normally,
restoring a missing declared origin; no-fetch mode refuses unborn checkouts.
Target/Python overrides in sync arguments are refused before work begins.

A missing commit explicitly prepares a per-run private temporary directory and
transfers one mode-0600 code bundle with the existing SSH identity. Descriptor
checks publish that file to the service account without pyinfra sudo uploads;
the directory stays owned by the connecting identity. The configured bundle
basename is retained, while its temporary directory is outside app/config/data
trees. Both file and directory are removed on completion or failure while the
connector remains usable. The existing pyinfra state callback also cleans a failed upload
before host failure skips later operations; a cleanup transport failure remains
an explicit error, and never changes the original failed result. Preparation
is a managed operation: a source first has three managed operations and one
actual SFTP transfer; a current repeat has zero of both. SFTP-setup connection
errors are normalized to a failed operation so the ordinary failure cleanup
callback runs while SSH remains usable; they never become success. An already present commit
needs no transfer. Git/uv output stays in memory and fixed error categories reach logs. A
failed synchronization remains a failure after checkout; no rollback is claimed.
Source parents are prepared by the complete role, which is still being ported.
This stage does not install resources, enable timers, change Pi auth or qualify a
default inventory deployment.

The resource substage under `daybook_sessions.deploy` is being qualified
independently of the complete role. Its protected stdin carries expected resource
contents; arguments and JSON results contain no credentials or identity fields.
The original conditional directory/log layout is compared to the paired role.
Existing logs are inspected through metadata and retain their inode, contents and
modification time. Config publication uses private temporary files in the declared
parent and atomic replacement. Standard root-owned Darwin `/etc`, `/var` and
`/tmp` aliases retain their original declarations; arbitrary linked ancestors are
refused. Browser profiles must be dedicated direct children of `~/.daybook`, as
the original role requires, and existing unmarked nonempty profiles are refused.

Weeknotes control preflight inspects only type, owner, mode, link count and the
dedicated auth directory's names. Existing refreshed auth is retained without
reading its body. A missing destination is explicitly seeded through private
atomic no-replace publication; a concurrent destination wins. Explicit rotation
retains the disabled/unloaded precondition. Seeding is managed work, never a fact.

For a requested identity epoch, the resource stage binds the exact helper and
twelve application module hashes before running the direct existing interpreter
with `-I -B -S`. Source is compiled from the verified bytes in memory, avoiding
site startup hooks and stale bytecode. The loader reads only the declared
operational seed, plan and attestation through the reviewed verifier. Its plan
hash stays in the remote parent's memory for comparison to the original private
root proof and Git ancestry check. Only `schema_version` and `identity_verified`
leave that gate. The managed helper rails/directories may already have changed if
verification fails; environment, checksum and auth publication follow success.
No rollback or remote identity migration is implied.

The standalone resource substage requires early exact system reconcile
quiescence. The draft full-role controller wires its separate managed primitive
before source/config work, while the resource API only verifies the precondition.
Retired timers refuse a running/spawning job before
resource mutation. Enabled Sessions/classifier schedules retain the original
explicit start/run-at-load flags and conditional kickstart behavior; Weeknotes
ordinary installation remains disabled. No inventory adapter uses this draft
substage yet. `deploy_daybook_sessions(config, secrets, source_tree, bundle)` and
`install_sessions_resources(config, secrets, source_tree)` are exported with
inventory adoption still pending review/native proof.

The draft full controller orders original system reconcile quiescence, uv and
Homebrew prerequisites, explicit directory preparation, source/environment
convergence, the configured synthetic classifier probe, then resource/timer
convergence and verification. Homebrew installs only missing packages; it does
not upgrade existing packages, and explicit `brew_update` retains its separate
update request. Source status can plan an absent parent without creating it;
actual transfer preparation/apply still require the earlier explicit directory
operation to have succeeded. Pending source work defers application imports
until apply binds the installed code.

Pure identity, repository-policy and Git/test probes use the existing direct
metadata execution pattern with bound environment/interpreter and no login
profile. Managed source, Homebrew and model commands retain their original login
context. The original pinned `public_repository_policy_from_env` is invoked only
from the same hash-bound twelve-module closure, with the supplied repository
declaration; it never opens a Journal or contacts a client. Its result is reduced
to a boolean. A configured classifier probe remains actual managed application
work on every deployment, including repeats. Its original bounded synthetic
input, model command and timeout remain intact; it is not disabled to manufacture
a zero-work repeat. A timeout terminates the probe's owned process group and
remains a genuine failure. The GUI account creates that exact child group/session
with `start_new_session`, checks queryable PGID/SID metadata, and retains the
creation proof when macOS cannot query an unreaped exited leader. Its reserved
PID/group ID cannot be reused before cleanup. Sudo's optional pseudo-terminal
does not own the model deadline. Post-signal pipe/reaping waits are bounded; wrapper
startup/report transport has a separate five-second allowance, without extending
the configured model execution budget. An absent or incomplete cleanup report
fails the deployment. No real model/probe or source/profile transition is
authorized by these APIs or owned proofs.

The separate `daybook-resources-native.yml` case confines system/GUI timer and
filesystem mechanisms to a wholly disposable hosted ARM VM. It uses unique owned
labels, real root/GUI ownership and unusable fake auth. Idle and missing-plist
jobs retire through the installed shared `Launchd` methods; running jobs must
refuse with their exact PID and plist preserved. A repeat must make no timer
mutations. Cleanup unloads only those labels and resets only actually disabled entries to
enabled; macOS may retain explicit enabled rows. This is explicit fixture I/O,
not global launchd-database absence or a read-only setup claim.

That case separately exercises original rendered root/user resource modes,
root-to-GUI browser access without launching a browser, unsafe profile/control
refusals, refreshed-auth preservation without body reads, one fake missing-auth
seed and its strict repeat. A synthetic root operational proof checks only the
metadata mechanism. The exact private twelve-module Weeknotes semantics retain
separate bound-code evidence; no private application source is published in the
fixture. It does not replay the source/stop/model fixture, create a fixed global
reconcile label, qualify inventory defaults or authorize real source/model work.

The original `repo_update: false` contract disables network fetching on the
target, rather than pinning its installed checkout. The normal controller still
resolves remote Main once and supplies its bundle; the original role explicitly
checks out that resolved commit locally when HEAD differs. Existing checkouts
therefore retain the normal Main convergence semantics and its transition review.

The resource fixture also invokes the production `/usr/bin/python3 -I -B`
interpreter with the same installed helper bytes for root-to-GUI browser/auth
metadata checks and an actual system retirement/repeat. Other mechanism
assertions execute those installed bytes in the controller's Python3.13; the
receipt distinguishes both interpreter scopes.

The native workflow's feature-branch package path filter follows all installed
package resources. It installs the immutable noneditable Git package and records
actual dependency behavior; listing `uv.lock` as a trigger does not claim that
its Git-package installation resolves every transitive dependency from that lock.
