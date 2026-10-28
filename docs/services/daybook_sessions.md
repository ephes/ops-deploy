# Daybook Sessions resources

This staged port preserves the original `daybook_sessions_deploy` declaration and
its Sessions, Archive classifier and Weeknotes reconciler resources. The guarded
host deployment and normal routing are still being implemented and qualified;
these resource APIs do not switch an inventory engine or authorize an update.

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
An installed old revision is not an alternative pin. A source/lock change needs
the guarded update and its attended runtime window; Python stays at the declared
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
sudo. It neither imports the application nor runs the classifier probe. Current
source/environment can verify while the supervisor runs; changes require the
original update fanout to quiesce it first, with a second check before mutation. For managed system scope, the source stage
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
actual SFTP transfer; a current repeat has zero of both. An already present commit
needs no transfer. Git/uv output stays in memory and fixed error categories reach logs. A
failed synchronization remains a failure after checkout; no rollback is claimed.
Source parents are prepared by the complete role, which is still being ported.
This stage does not install resources, enable timers, change Pi auth or qualify a
default inventory deployment.
