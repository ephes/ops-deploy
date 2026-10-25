# Mastodon release Linux integration

This **manual-only** workflow uses a disposable GitHub-hosted Ubuntu24.04 VM,
not inventory or production credentials. Dispatch `Mastodon release integration`
with the exact40-character candidate `implementation_sha`. The workflow itself
must first be registered on the default branch; Root/main worker owns that
integration. A feature checkout supplies the actual service API. Normal pushes
and pull requests do not run this expensive job.

`run.sh` refuses non-GitHub-hosted/non-systemd environments and existing Mastodon users before provisioning. It creates a root0600 marker binding this VM machine-id to the exact GitHub run. Direct `harness.py` execution requires the same marker and host checks before destructive fixture reset. It provisions only
that disposable VM's mastodon user, PostgreSQL/Redis and build prerequisites. A real service login profile initializes rbenv/nvm because the existing units use `bash -lc`; it does not stub binaries or change service templates.
Never run it on an inventory host. It does not use or prune local Docker.

The two independent workloads are:

1. A small **real Rails** app with Puma/Sidekiq, Node HTTP streaming, PostgreSQL
   migrations, Propshaft assets and Rails Redis cache clear. Retained real
   managed Ruby4.0.4/Node24.16.0 generate source lockfiles and bootstrap an
   existing app with the rendered dummy env, actual Rails `db:migrate`, real
   assets and reviewed unit templates. HTTP200 and managed processes must pass
   before the actual public deployer installs the still-absent selected runtimes. A changed source adds a migration and real asset-task
   failure; retry must converge and a real second execution must mutate nothing.
2. The **actual Mastodon v4.6.9** source at
   `32e8e7c70af88c7ff12d2db03fcc93aa777a8cfc`, with its own Gemfile/yarn locks,
   Ruby4.0.5 and Node24.17 selector. The API builds dependencies and assets and
   runs real services after baseline schema load. Its regular/post migration
   history must remain complete and unchanged; pending migration execution is
   exercised by the separate minimal Rails fixture, not the full Mastodon pair.
   The VM DB/source is deliberately reset between workloads. Full Mastodon is
   first provisioned as a real existing installation using its locked dependencies,
   generated fixture env, standard Rails schema load/seed and genuine assets.
   Both regular/post migration history and actual instance HTTP200 must pass
   before the API controlled build/repeat; no fabricated migration rows. This is not a live
   upgrade/recovery qualification or a backup/restore test.

Each workload starts from a seeded Git checkout (existing-install contract).
Protected ignored media/vendor-bundle sentinels must survive. Root-owned0700 state `/var/lib/ops-deploy-mastodon` is an explicit agreed API contract, asserted before resetting only this fixture state. The repeat compares actual
operation results (only explicit read-only tags excluded), active service
PID/Invocation/NRestarts, env hash, migration history and protected content.
The workflow harness SHA is recorded separately from the immutable implementation
checkout SHA, imported module path/hash and controller executable/proc path.
Actual source and runtime-tool commits are recorded. Old Ruby4.0.4 and
Node24.16.0 binaries must still execute after the update. The fixture records the
initial old Node default alias, requires the selected Node to be absent before
the API installs it, then checks the API-selected alias and actual web/streaming
`/proc/PID/exe --version` from managed runtime stores. Login-profile use of the
default alias is deliberate role-faithful behavior; a stale alias or system
Node/Ruby executable fails the integration.

Actions are pinned to official upstream commits; runtime tools are pinned to
recorded official Git object IDs. Application tooling uses actual registry
packages/lockfiles; no stub binary returns success. The fixture uses dummy DB,
SMTP and generated signing secrets; operation argument dumps are intentionally
excluded. Artifact operation JSON/proofs and service journal are diagnostic
fixture data only. No production env, database or media is copied.

A job is qualified only when `SUCCESS.json` exists and the job succeeds. An
uploaded failure artifact is not passing integration evidence. CI failure causes
must be reported honestly; never weaken trust guards to make a fixture pass.


Failure repair notes: the first real run40177167605 stopped before the API because
an existing nonempty `.nvm` blocked clone. Its contents were **not retained**, so
no original image-cause claim is made. Setup now clones official pinned nvm into
a unique service-user-owned sibling, records the preexisting leaf metadata/names
without following links, preserves that leaf by rename, then installs the verified
checkout. No retained runtime is deleted. Failure diagnostics always make only
the generated evidence directory uploadable even when no service journal exists.

The subsequent real jobs40179143906 and40179835040 also stopped before the API,
in fixture lock generation: Yarn4.16 accepts `--mode=skip-build` (singular),
and GitHub CI defaults prohibit creating a missing lockfile. Only that initial
fixture-source command sets `YARN_ENABLE_IMMUTABLE_INSTALLS=false`; both existing
app bootstraps and the reviewed release API retain actual `yarn install
--immutable`. Bootstrap uses the retained managed Ruby rather than Ubuntu's
system Ruby and never inserts migration-history rows manually. The original
SQL-seeded minimal baseline also omitted the required existing env file; both
workloads now establish the same real existing-install prerequisites. The
minimal fixture contains a Propshaft asset, without a legacy Sprockets manifest.

Real P-256 fixture keys are generated by the locked controller crypto library
before any runtime compile, so early compiler diagnostics can use the same
known-key filter. Failed fixture commands retain bounded stdout/stderr diagnostics after filtering
known dummy keys, env assignments and credential-bearing lines. Missing or
unreadable generated-key metadata withholds tool output while preserving the
original command label and exit code. Local CLI/boot tests qualify those
bootstrap assumptions; only a successful changed Ubuntu VM job with
`SUCCESS.json` qualifies the complete Linux chain.


Job40182269154 used harness`aebff23` and reviewed API`aac262b` but stopped before
any API call. Ruby4.0.4 configured, compiled and installed, then ruby-build's
return to the inherited controller checkout failed with permission denied.
Every fixture service-user command now starts in that user's accessible home;
this matches the API executor's explicit service-owned working-directory
contract. Runner checkout permissions remain unchanged. A real Bash
pushd/popd permission reproduction and caller-boundary regression cover this
context. Before any tool clone or compile, actual service-user `pwd -P` and
`id -u` must match the new user/home and are recorded alongside the controller
cwd in `fixture-execution-context.json`. Only a later successful changed Linux
job qualifies the entire chain.
