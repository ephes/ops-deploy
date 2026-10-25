# Mastodon: selected-release deployment of an existing installation

`deploy_mastodon(cfg=MastodonReleaseConfig(...), secrets=...)` updates an existing
Git installation. It resolves a selected release, installs its Ruby/Node and
locked dependencies when needed, converges the secret environment, applies
pending migration identities, builds assets, and performs an ordered application
rollout. It does not provision the OS, service account, PostgreSQL/Redis instance
or storage, and does not implement backup/restore/remove. Existing local media
and the `<home>/live` layout are retained.

The compatibility `MastodonConfig` API still performs immutable configuration-only
convergence. Callers must opt into the release API with the candidate description;
changing its old exact-source admission is not how routine updates are enabled.

## Candidate and runtime provenance

Resolve the configured Git ref with `core.git_source.fetch_source`, then call
`describe_candidate` on that immutable tree. The description includes the full
tracked path list, both lockfiles/runtime declarations, and migration identities
from **both** `db/migrate` and `db/post_migrate`. The read-only host inspection
compares those identities against the configured PostgreSQL database before any
write. It does not load new application code with old installed dependencies.

With `ruby_build_update=true`, the controller resolves ruby-build master once.
The returned `runtime_tool_commits` records the exact Git object fetched from its
configured repository. Preserve that explicit input for apply and its repeat;
an independent later invocation may resolve a newer master honestly. With update
false, the installed checkout is retained. rbenv and configured nvm tag semantics
follow the role. Existing matching Node is preserved; a missing partial-version
match is resolved to a concrete release before rendering service paths. Numeric
major/minor/patch selectors are supported; nvm aliases/LTS names are not part of
this typed existing-install API. Old
runtime directories are retained.

Git deployment fetches the configured ref as the service user, checks that it
still resolves to the controller-selected commit, and performs a forced detached
checkout. It never runs `git clean`. Candidate paths cannot overwrite retained
env/media/dependencies/runtime contents. Known tracked `log/.keep` and
`vendor/.keep` scaffolds are permitted; an untracked retained scaffold collision
is not overwritten. Ownership is not recursively changed over media or the site.
Local rsync source transport is not implemented by this Git release API.

## Build, migration and rollout

Role-compatible inputs include rbenv/ruby-build/nvm settings, Bundler and Yarn
flags, migrations/assets/cache-clear toggles, process sizing, delegated domains,
nginx federation cache/timing and discovery settings. Source, locks, runtime,
configuration and actual output checks determine whether work is necessary.
A completion marker alone does not prove installed dependencies or assets exist.
The selected pipeline determines asset verification: Propshaft and Vite builds
require their real manifests and referenced files; retained webpack/Sprockets
manifests cannot qualify a current Propshaft/Vite release.

Secret env bytes travel through redacted stdin to `secret_file` with service
ownership and mode 0600. Application commands run as the service user with an
explicit clean runtime environment. Credentials are never operation names or
arguments, and application stderr is not echoed by the host action runner.
Changing DB credentials does not provision or rotate a database role.

Before a potentially partial source/runtime/dependency/migration/asset mutation,
Mastodon-local durable rollout and cache-clear debt is stored under root-owned
`/var/lib/ops-deploy-mastodon` (0700, entries 0600). Env-only changes create rollout
debt without cache-clear debt. Failed commands never save successful build state;
retry pays surviving debt. Systemd reload precedes conditional tootctl cache clear,
then each application restarts once, then health verifies the rollout. No shared
Traefik restart, unrelated Redis flush or automatic DB rollback occurs.

The guarded Traefik writer remains unchanged. An unchanged route does not invoke
the guard; changed routes use the existing transaction coordination contract.
Maintenance script/service/timer templates are copied unchanged from the role;
converging the schedule does not execute cleanup. Maintenance command validation
preserves the role's full-name/scoped emoji-purge rules. `run_now=true` is an
explicit cleanup operation outside this release deployer, rather than silently
ignored or executed.

Federation cache priming uses the role's host/path/Accept expansion, including
configured extra and delegated discovery entries, and verifies the second
response cache status. Missing cache outputs or changed release inputs schedule
priming; a converged repeat only verifies existing cache responses. Such normal
read requests may still refresh nginx's derived cache/log state.

## Operational qualification

Read the selected release's upstream upgrade notes, including skipped releases.
For [v4.6.9](https://github.com/mastodon/mastodon/releases/tag/v4.6.9), instructions
call for locked dependencies, asset compilation and restarting the processes.
Its production Vite build retains old output (`emptyOutDir=false`). This does not
promise atomic deployment, zero downtime or a general cross-version rollback.
Pending schema effects and online compatibility must be inspected for the
selected release. Old runtime retention alone is not sufficient rollback.

Before live production, verify recovery evidence appropriate to actual source,
schema and storage effects. Do not claim media recovery from a DB-only archive.
Qualification needs an inspected plan, actual first apply, source/runtime/env/
migration/identity/media/health evidence, and a same-input real repeat with zero
builds, cache clears, restarts and mutating operations. Fake command tests prove
ordering and failure handling; real Linux tools plus an actual Mastodon build
are separate required evidence. This public API documentation does not claim
qualification of any particular operator's hosts.
