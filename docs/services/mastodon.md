# Mastodon: existing installation only

`ops_deploy.services.mastodon` is a deliberately bounded configuration convergence
entrypoint, **not full `mastodon_deploy` parity**. It supports the role's default
single-domain, local-storage layout and four existing running systemd services.

The controller resolves the desired upstream git ref with `core.git_source`.
Before planning any operation, admission requires that exact clean commit,
matching Gemfile/Yarn lockfiles, package manifest and Ruby/Node declarations,
existing Ruby and an unambiguous installed Node matching `.nvmrc`, dependency
and compiled-asset directories, the existing environment and active Redis and
maintenance timer. Any mismatch refuses the plan. The environment comparison
uses redacted stdin and reports no values or digests. Even changes to SMTP,
account encryption keys, database or Redis credentials are refused.

The parity checkpoint is ops-library `3110a0f1` / `2.68.0`. Behaviour digests for
`mastodon_deploy` and `mastodon_shared` are recorded in the drift manifest; this
checkpoint does not imply parity with the unported role tasks.

The seven role templates are shipped unchanged from ops-library. With the admitted
defaults the deploy converges the four units, nginx config and Traefik route.
Services restart only when their inputs change or a prior failed rollout owes
a restart. Systemd reload debt is also repaid. No maintenance commands run;
the existing timer/script/configuration are preserved. No directory trees are
recursively chowned or deleted. Media, PostgreSQL data, Redis and source files
are never written by this entrypoint.

This package does not bootstrap, update refs, install Ruby/Node/PostgreSQL/Redis,
install gems or Yarn dependencies, compile assets, migrate the database, clear
Rails/Redis caches, rotate keys, alter SMTP or implement backup/restore/remove.
Existing build products are admission evidence, not a proof that every gem or
asset is healthy. Source/schema/runtime upgrades remain future work. A partial
previous source/build rollout requires operator assessment before admission.

No live qualification has been performed. A future staging window needs a
reviewed manifest, verified synchronous Echoport backup, read-only baseline,
plan, first run, application health and data/key invariants, and an actual
second run with zero mutations. Registration alone must not switch an engine.

A changed Traefik route uses the shared guarded writer and refuses while a
Traefik transaction holds or waits for its host lock. An unchanged route runs
no guard and stays free of mutating operations. This is a read-only check with
the same bounded race as the other service route writers; coordinate deployment
and transaction windows as described in the Traefik guide.
