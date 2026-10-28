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
