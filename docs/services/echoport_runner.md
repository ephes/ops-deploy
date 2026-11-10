# Echoport backup runners (generic parts)

`ops_deploy.services._echoport_runner` holds what the Echoport backup runners
that FastDeploy starts have in common: the port of ops-library's
`fastdeploy_runner` role, the runner templates of its `echoport_backup` role,
and the pieces the ops-control register playbooks share
(`playbooks/common/*.yml`). Each runner is ported in a slice of its own,
which adds its config in ops-control and its own entry point (design note
`ECHOPORT-FASTDEPLOY-REGISTRATIONS-20261105` on ops-meta's `pyinfra-port`
branch, §3 and §3.8). The same-host root runners (class A1) use
`registration.register_runner` below. The deploy-user runners (classes A2
and A3, and heis-production and villakunterbunt-staging) use
`registration.register_deploy_runner`. The generic runner `echoport-backup`,
which serves many Echoport targets, uses `generic.register_generic_runner`.

## Runner installation (`RunnerConfig`, `deploy_runner`)

`RunnerConfig` carries the `fastdeploy_runner_*` variables a playbook passes;
`None` means the role's default, derived from the other values as the role
derives it. Validation is the role's first task: a service name of
`[a-z0-9][a-z0-9_-]*`, steps, exactly one of `template` (a vendored runner
template) and `content` (the literal script), a script directory directly
below `libexec_root` and outside the FastDeploy site, plain user names, a
sudoers file directly in `/etc/sudoers.d` and mode `0750` or `0755`.

```python
from ops_deploy.services._echoport_runner import RunnerConfig, install_runner

cfg = RunnerConfig(
    service="paperless-backup",
    description="Paperless backup - same-host PostgreSQL + filesystem backup/restore",
    steps=("init", "dump_database", "upload", "result"),
    template="paperless_backup.py.j2",
    run_as="root",
)
install_runner(cfg, template_vars)  # inside a deploy; deploy_runner is the @deploy wrapper
```

The steps, in the role's order:

| # | Role task | Port |
|---|---|---|
| 2 | parent of the libexec root `root:root 0755`; every directory above it root-owned and writable only by root | the directories above the parent are read while planning (`stat`, no link followed); anything else refuses before any write; the parent is then made `root:root 0755` |
| 3 | libexec root and script directory `root:root 0755` | `files.directory` |
| 4 | the script, `root:<deploy group>` with the configured mode | `files.put` of the rendered template or the content |
| 5 | services root and service directory `root:root 0755` | `files.directory` |
| 6 | `config.json` (`root:root 0644`): `to_nice_json` of name, description, `deploy_script`, steps, plus a newline | byte-identical (`indent=4`, sorted keys, ASCII escapes) |
| 7 | sudoers: `fastdeploy ALL=(deploy) NOPASSWD:NOSETENV: <script> *`, plus `deploy ALL=(<run_as>) ...` with `run_as` | `helpers.users.sudoers_file`: staged, `visudo -cqf`, then moved in place |
| 8 | `commands.py syncservices` as the fastdeploy user in the site | the same command, but only when `config.json` changed or FastDeploy's stored service (`select data::text from service where name = ...` as `postgres`, read while planning) differs from it; a failed read syncs and reads again |
| 9 | remove the legacy copies (default `<service dir>/backup.py`) | after the sync, never the installed script |

On a host the role (or an earlier run) left in place, a run plans no
mutating operation.

## Runner templates (`render`)

`templates/` holds the role's `templates/*.py.j2` unchanged, with the
includes `_work_dir.py.j2` and `_sqlite_backup.py.j2`, except the ones in
`render.FORKED`: `unifi_backup.py.j2` and `minecraft_java_backup.py.j2`
moved on here after their registration moved to pyinfra (2026-11-09,
restores onto a fresh install, below), and
`villakunterbunt_staging_backup.py.j2` (2026-11-10: the restart of the
staging services is armed before the first stop and tries every service,
so a failed Django stop or start no longer leaves Next.js down). ops-deploy is their source;
ops-library's copies stay as they were and serve only the Ansible rollback
of the register playbooks.
`render.render_runner(template, variables)` renders one as Ansible's
`template` module does (`trim_blocks`, the final newline restored,
`StrictUndefined`) with ansible-core's `to_json`, `bool` and
`regex_replace`. `variables` are the playbook's values, already resolved; a
name the template reads with `default(...)` may be left out.
`render.render_text` renders a playbook's inline text (a task's `content:`)
the same way, with ansible-core's `quote` (`shlex.quote`) as well.

## Object-store access (`access.minio_access`)

The port of `common/backup_minio_account.yml`. ops-control resolves the
target from `playbooks/vars/backup_minio_accounts.yml` into a `MinioAccess`
(target, OS user, alias, store URL, whether it is switched, store, retired
aliases) and passes the access key and secret. When `mc` is needed and
missing, the run refuses while planning, as the playbooks' "Ensure mc is
installed" does. The MinIO deploy (`bootstrap_with_mc`) installs the
pinned `mc`. `register-echoport-backup.yml` installs it too, but its port
(`generic`) refuses without it, like the other runners.

- a switched target on MinIO gets its scoped account through root's MinIO
  admin alias (`minio_deploy`'s `backup_account`, as the echoport deploy ports
  it): policy `backup-<target>` (read, write and list `backups/<prefix>/`,
  no delete), user `bk-<sha256(target)[:17]>`; the secret goes to
  `mc admin user add` on stdin. The policy and user are written only when the
  probe finds them missing or different, or when the runner's alias does not
  hold the secret yet or cannot list `backups/<prefix>/` with it (for a runner
  without an alias, every run, as the role);
- the runner user's `mc` alias is imported from a private file in a
  root-owned `0711` temporary directory when its stored URL, access key or
  secret differs (`mc alias import`; the credentials never reach argv), and
  the retired aliases are removed when present;
- `store: rustfs` needs a switched target with `rustfs_account: true`; the
  RustFS deploy creates that account, and the run proves it with
  `mc ls <alias>/backups/<target>/` as the runner user.

The registry's own refusals (an unmanaged entry, retiring the shared alias
while one of the user's targets is not switched) stay with ops-control's
resolution.

## Work dir (`access.work_dir`)

The port of `common/backup_work_dir.yml` for runners that run as a non-root
user. The work dir must be a normalized path strictly below the mount
(default `/mnt/cryptdata`) and the owner must not be root. While planning,
the run refuses when the mount is not mounted or a path on the way is a link
or not a directory. Missing parents are created `root:root 0700` (existing
ones keep owner and mode, so the ACL mask stays); each parent gets the ACL
entry `user:<owner>:--x`; the work dir itself is `<owner>:<owner> 0700`.

## Known host (`access.known_host`)

The port of `common/deploy_known_host_ed25519.yml`: exactly one ed25519 key
for the name, either the inventory host's pin (used only when that host's
`ansible_host` is the name) or the controller's `ssh-keyscan -q -t ed25519`
(trust on first use; a scan that gives no answer within 60 s, or an
`ssh-keyscan` that cannot run, refuses cleanly). Anything else refuses while
planning. The line is written as `known_hosts` `state: present` writes it (an
entry of the same type replaced in place, anything else appended); the file
keeps its owner and mode. `known_hosts_entries` takes several names for one
file (the production-db playbooks include the task twice): every key is
resolved first, then the names are applied in order, each to the file the
previous one left (the host's `ssh-keygen -F` answers are read once and moved
past a replaced line), and the result is written in one upload. With
several names, a file without a final newline that would change refuses (the
module would append to its last line, so the answers read once would not
describe the file); an unchanged one is left alone.

Unlike the include, the result keeps one copy of each name's key line and
drops those names' `# <name>:22 SSH-...` banner comments. Until 2026-10-22
every register run appended the controller's `ssh-keyscan` output again
(on 2026-11-10 deploy's known_hosts on macmini held 51 copies of staging's
line, 21 of production's and 70 banners), so the next `just register-one` of
a runner with these names removes the leftovers in the same upload. Only exact
(whitespace-normalized) copies of the wanted line go: hashed and multi-host
entries, other hosts and a different key of the same type stay; a file
without duplicates is unchanged. The Ansible playbook (the rollback) still
leaves duplicates alone.

## Same-host root runners (`registration`)

`RunnerRegistration` is one register playbook of class A1 (snappymail,
delve, echoport-self, fastdeploy, homeassistant, weeknotes-home, paperless):
the runner's `RunnerConfig`, the target's `MinioAccess`, the playbook's
packages and its template variables, resolved. `register_runner(cfg,
secret_key=...)` runs the playbook's tasks in its order:

1. the packages (`ansible.builtin.package`: `apt`, no cache update);
2. "Ensure mc is installed": a missing `mc` refuses while planning;
3. `backup_minio_account.yml` (`access.minio_access`) with the target's
   scoped account (`secret_key`, never in an argument);
4. `fastdeploy_runner` (`install_runner`) with the rendered template.

The config refuses what the playbooks refuse or never do: a template that is
no vendored runner, or one without `_work_dir.py.j2` (their "Require a
runner that works on the external disk only"), a runner that does not run
as root with root's alias, a target without its scoped account (root's
shared `minio` alias is retired, so the playbook refuses that too), and
template variables that name another alias, `mc` or bucket than the access.
The include's first task, the ops-library version assert, is not ported:
the templates are vendored and `tests/test_ops_library_drift.py` pins
ops-library. Variables named in `default_ipv4_variables`
(homeassistant's `homeassistant_backup_health_forwarded_for`) get the host's
`ansible_default_ipv4.address`, the source address of
`ip -4 route get 8.8.8.8` read while planning, and `192.168.0.1` without a
route, as the playbook's `default(...)`; the template sees
`ansible_default_ipv4` with that `address`, the only key it reads. Like the
playbook's gathered fact, a changed default route renders a changed runner
on the next run (design note §3.3 proposed a fixed config value checked
against the fact; reading the fact keeps the playbook's behaviour).

The Echoport target row is not written: the A1 rows are kept by hand
(weeknotes-home's comes from the `weeknotes_home` deploy). On a converged
host the deploy plans no mutating operation.

unifi-backup and minecraft-java-backup are A1 with their playbooks' own
steps:

- unifi's MongoDB login (`/etc/echoport-backups/unifi-mongodb.json`, a
  `CredentialFile` as below) with `check="mongodump"`, the playbook's
  "Validate MongoDB backup credentials and auth DB": `mongodump
  --archive=/dev/null --gzip` of the database with that login. The check
  (`credential_check_command`) gets the file's text on stdin and hands the
  password to mongodump on its stdin (mongodump asks for one when it gets
  `--username` without `--password`); the password is on no command line,
  where the playbook had it under `no_log`. It runs while planning when
  `python3` and `mongodump` are installed, so a refused login stops the run
  before any write, and as a read-only step right after the file, as the
  playbook runs it;
- minecraft's "Ensure mcrcon is installed": `required_files`
  (`RequiredFile`), a missing `/usr/local/bin/mcrcon` refuses while
  planning with the playbook's message (the `minecraft_java` deploy
  installs it).

### The unifi runner's MongoDB password (never on argv)

The rendered unifi runner reads the login from
`/etc/echoport-backups/unifi-mongodb.json` and never puts the password on a
command line (`ps`) or in a tool's environment. For every MongoDB call it
creates a private `0700` directory below its work dir (prefix
`unifi_backup_mongo_auth_`, so one left by a killed run is pruned with the
run dirs) and removes it when the call returns:

- `mongodump` (backup, safety snapshot, the restore's health check) and
  `mongorestore` read the password from a `0600` `--config` file there
  (`password: "<...>"`); host, port, user and authentication database stay
  on argv;
- `mongosh` (the collection count and `dropDatabase`) gets a script on stdin
  (`--file /dev/stdin`) that authenticates against the authentication
  database first; it runs with a private `HOME` whose mongosh config disables
  logging and telemetry, and the script quits before authenticating when
  that config is not in effect. The drop must print a confirmation marker.

Tool output in an error is reported with the password replaced by `********`.

### Restores onto a fresh install (unifi, minecraft-java)

Both runners take a safety snapshot before a restore changes anything. On a
fresh install there was nothing to snapshot and the restore failed before any
change (Echoport restore runs 306 and 307 on 2026-11-09): `mongodump --db=unifi`
writes no dump directory for a database without collections, and the
Minecraft world directory does not exist. Now:

- unifi asks `mongosh` for the database's collection count first; with none
  the `safety_snapshot` step logs "Database unifi has no collections:
  nothing to snapshot (fresh install)" and the restore goes on, and a
  restore that fails after the database changed drops the database again
  (the empty state) instead of restoring a snapshot. A count that cannot be
  read, or a snapshot of a database with collections that fails, still
  fails the restore before any change;
- minecraft-java logs "World <name> not present: nothing to snapshot (fresh
  install, or a world this server does not have yet); runtime directories
  and config snapshotted" and goes on (the target is the archive's world, so
  this also covers restoring a world under a new name next to a live one); a
  restore that fails later removes the restored world and puts the
  snapshotted runtime directories and config back, then starts the server
  as the rollback with a world does. Any rollback now also removes the
  runtime directories and optional server files (`mods`, `ops.json`, ...)
  that did not exist before the restore (`absent.json` in the snapshot). A
  world target that exists but is no directory still fails before any
  change.

### Class B: the playbook's own target, credential and Nyxmon steps

The same-host root runners of class B (mail-db-backup, postfixadmin-backup,
graphyard-backup) are the same registration with the playbook's own steps
(all optional fields):

- `template_markers`: texts the vendored template must contain (the
  playbooks' "Require the ... runner in the ops-library checkout");
- `credential_files` (`CredentialFile`): a file the playbook writes with
  `copy: content:` from a secret. `template` is the task's content text
  unchanged, `variables` the names it reads that hold no secret, `secrets`
  the names whose values `install_registration(..., credentials=...)`
  passes. The directory is made with the configured owner and mode (root
  `0700`), the file is written with `ops.secret_file` (root `0600`), after
  the object-store access as the playbook writes it. `render.render_text`
  renders it as Ansible renders a module argument (the final newline kept,
  `to_json` with ASCII escapes);
- `target` (`RunnerTarget`, see below): after the runner, through
  `upsert_runner_target`, or `token_and_target` with
  `install_registration(..., token_user=...)` when it has a `ServiceToken`;
- `nyxmon` (`nyxmon.NyxmonScript`): last, graphyard's own Nyxmon check
  script (below).

A target with a token but no `token_user`, and credentials that are not
exactly the files' secrets, refuse while planning.

The kept scripts are the playbooks' texts with their Jinja values read from
`VALUES[...]` (the variable without the runner's prefix) and the issued
token from `SERVICE_TOKEN`; nothing else differs, and ops-control's
`tests/test_pyinfra_echoport_runners_classb.py` compares them byte for byte:

| `files/targets/` | Playbooks |
|---|---|
| `service_owned.py` | register-mail-db-backup, register-django-chat-staging-db-backup and register-ggs-lennestrasse-staging-db-backup (the same text) |
| `postfixadmin.py` | register-postfixadmin-backup (converges an existing row only) |
| `graphyard.py` | register-graphyard-backup (no reactivation guard) |
| `mastodon_production_db.py` | register-mastodon-production-db-backup (saves only when a field differs) |
| `marina_production.py` | register-marina-production-backup (saves only when a field differs; database path, files and owner) |
| `gotosocial.py` | register-gotosocial-backup (refuses a schedule that is not plain daily or within 10 minutes of another active daily target, and a row wired to another FastDeploy service) |

`target.target_script(name)` and `target.target_scripts()` read them.

## Playbook Nyxmon scripts (`nyxmon`)

graphyard's register playbook upserts its Nyxmon backup freshness check with
a script of its own (`python3 -` as the `nyxmon` user, the database and
service name in the environment). It differs from `nyxmon_site_checks` and
`_nyxmon_json_metrics` (it re-enables a disabled check only when another
field differs), so it is kept as `files/nyxmon/graphyard.py` and
`files/runner_nyxmon.py` runs it with `python3 -I`:

- while planning, the playbook's `stat` of the database: without it nothing
  is planned and the deploy logs that it skips the step, as the playbook
  does;
- **check**: the script runs with `sqlite3.connect` opening the database read
  only; `unchanged` when it ends with `changed=false`, `pending` when it
  would write, `refused: <reason>` when it fails otherwise (the deploy then
  stops before any write);
- **apply**: only when the check did not say `unchanged`; the script runs as
  the playbook runs it, then the check must say `unchanged`.

The script and its values (the check data, which may carry a monitor login
under a harmless name) travel on stdin, never in argv; only the playbook's
environment (database path, service name) is in argv. `NyxmonScript` also
refuses top-level value names that look like a secret. The read-only check replaces
`sqlite3.connect`, so `NyxmonScript` requires a script that opens its
database with `sqlite3.connect(...)`.

## Deploy-user runners (`registration`)

`DeployRunnerRegistration` is one register playbook of classes A2 (the
remote runners homepage-staging, python-podcast-staging, marina-staging,
homepage-production-db and python-podcast-production-db, which reach their
hosts over SSH as the deploy user) and A3 (homepage-media and
python-podcast-media, rclone from S3 to the backup store). The runner runs as
the deploy user: its sudoers file has the `fastdeploy -> deploy` line only.
`tasks` is the playbook's order of its parts, each exactly once:

| Task | Playbook | Port |
|---|---|---|
| `ssh_key` | `/home/deploy/.ssh` (`deploy 0700`), `id_ed25519` (`0600`, `no_log`) and `id_ed25519.pub` (`0644`) from `deploy_ssh_keys.yml` | `files.directory` and `ops.secret_file` with the secret as it is (`copy` adds nothing) |
| `known_hosts` | `deploy_known_host_ed25519.yml` per name, then "Ensure known_hosts ownership" (`deploy:deploy 0644`) | `access.known_hosts_entries`, then `files.file` |
| `mc` | "Ensure mc is installed" | `access.require_mc`, while planning |
| `packages` | `ansible.builtin.package` | `apt.packages`, no cache update |
| `access` | `backup_minio_account.yml` | `access.minio_access`: the scoped account and the deploy user's alias; a media runner (`os_user` `none`) gets the account only, upserted on every run as the role does (no alias proves its secret current) |
| `work_dir` | `backup_work_dir.yml` | `access.work_dir` |
| `credentials` | the media credentials directory (`root:deploy 0750`) and file (`root:deploy 0640`, `no_log`) | `files.directory` and `ops.secret_file`; the content is the playbook's `copy` content (`media_credentials`: four `to_json` values, the block's final newline); the directory must not be `/` or a top-level one |
| `runner` | `fastdeploy_runner` | `install_runner` |

`register_deploy_runner(cfg, secret_key=..., ssh_key=..., source=...)` takes
the target's account secret, the deploy key pair (`DeployKey`) exactly when
the playbook installs it, and a media runner's source (`MediaSource`: the
bucket, which becomes the template's `<prefix>_source_bucket`, and the S3
credentials); a missing or extra one refuses. The config refuses what the
playbooks refuse or never do: a template that is no vendored runner or lacks
`_work_dir.py.j2`, a media template without `--no-check-dest` (their
"Require a media runner that works with a scoped MinIO account"), a `run_as`
rule, an access or work dir of another user, a target without its scoped
account (the media playbooks' fallback to the MinIO root credentials stays
with the playbook), known hosts in another file, and template variables that
differ from what the registration provisions (`echoport_backup_*` as for A1,
and every `*_work_dir`, `*_work_mount`, `*_credentials_file`, `*_minio_url`
and `*_default_bucket`). A variable the registration leaves out is checked
with the template's `| default(...)`, which is what the runner then gets; one
without a default refuses. The source bucket variable must be one the template
reads, and the source bucket must be an S3 bucket name (the template writes it
into a Python string unescaped). Every refusal comes while
planning, before any write; the playbooks fail at their task instead, after
the earlier tasks wrote. On a converged host the plan has no mutating
operation, apart from a media runner's MinIO user upsert. No Echoport row is
written: the rows stay managed by hand.

Class B part 2 (django-chat-staging-db, ggs-lennestrasse-staging-db,
mastodon-production-db, marina-production, gotosocial) are deploy-user
runners whose playbook writes its Echoport target. Their registration has
these fields as well:

- `target` (task `target`, after `runner` in each playbook's order): the
  playbook's own target script as for the same-host class B runners, with
  `register_deploy_runner(..., token_user=...)` for the token step;
- `ssh_key_public` false (django-chat, ggs-lennestrasse and mastodon; the
  other two install no key): those playbooks install the private key only
  (`DeployKey(private=...)`, no `id_ed25519.pub`);
- `template_markers`: as for `RunnerRegistration`;
- `min_pg_restore_major` (task `pg_restore`, mastodon): the playbook's
  "Require a pg_restore that reads production's dumps", a read-only step
  after the packages (as the playbook reads the version after installing
  `postgresql-client`), failing when `pg_restore --version`'s PostgreSQL
  major is lower; a pg_restore that is already installed and too old
  refuses while planning when the packages are already installed (the
  package step cannot change it then), so a dry run shows it.

These two steps are the exceptions to "every refusal comes while planning"
and "no Echoport row is written" above: the pg_restore check runs after the
packages, and the target step writes the row as the playbook does (only
when its check is not `unchanged`). gotosocial's, django-chat's and
ggs-lennestrasse's scripts save on every run in the playbook; the port saves
only when a field differs.

A target with a token but no `token_user`, or a public key given where the
playbook installs none, refuses while planning; so does a target whose bucket
is not the access's. The config refuses a `pg_restore` task before
`packages` and a `target` task before `runner` (the playbooks' order).

heis-production and villakunterbunt-staging are class B deploy-user runners
whose templates predate the work dir on the external disk (no
`_work_dir.py.j2`). Their playbooks wrote the runner into FastDeploy's
services root (`services/<service>/backup.py`, `"deploy_script":
"backup.py"`, a sudoers rule for that path); the port installs it as every
other runner (`install_runner`: the libexec layout, then the old copy is
removed). Their registration has, in place of `work_dir`:

- `temp_dir` (task `temp_dir`, `TempDir`): the playbooks' temp dir
  (`/tmp/<service>`, `deploy:deploy 0755`), which the template reads as
  `echoport_backup_temp_dir` and uses when it exists (the system temp dir
  otherwise). A template that includes `_work_dir.py.j2` gets no temp dir.

Both write their target with the kept `remote_sqlite_site` script (the two
playbooks' scripts differ only in their values; it reactivates a paused
target and clears `service_name` and `restore_owner`, as they do).
heis-production also has

- `token_rotation` (task `token_rotation`, after `target`,
  `rotation.TokenRotation`): the playbook's monthly rotation of the
  target's token. `files/token_rotation/heis_production_backup/` keeps the
  playbook's three `copy` contents unchanged: the helper
  (`/usr/local/sbin/rotate-heis-production-backup-token`, root `0700`,
  written with `ops.secret_file` because it names the FastDeploy token
  user, the deploy's `token_user`), the oneshot service and the monthly
  timer (`root:root 0644`). systemd is reloaded only when a unit changed
  (the playbook reloads on every run); the timer is enabled and started.

## Playbook target scripts (`target`)

Several register playbooks upsert their Echoport target with a script of
their own, which differs from the shared upsert (`services._echoport`) in
scope, owned fields, save behaviour and refusals. A port keeps that script
(its values from `VALUES`, a newly issued token from `SERVICE_TOKEN`) in a
`RunnerTarget`; `files/runner_target.py` runs it inside Echoport's
`manage.py shell`:

- **check**: the script runs in a transaction that is always rolled back, so
  nothing it writes stays (its saves still run Echoport's validation). The
  rows of every model it writes to are read before its first write and again
  after the script. The answer is `unchanged` when they are the same apart
  from `auto_now` fields such as `updated_at` and no token is due, `pending`
  otherwise, and `refused: <reason>` when the script raises (for example
  "Refusing implicit reactivation") or exits with a status other than 0;
- **apply**: when a token is due and none arrives on stdin it answers
  `need-token` and runs nothing; otherwise it runs the script as the
  playbook does.

`upsert_runner_target` (no token) and `token_and_target` (with a
`ServiceToken`, the inputs of `common/fastdeploy_service_token.yml`) run the
check while planning: a refusal stops the deploy before any write and
`unchanged` adds no operation. Otherwise the script runs once, after
`issueservicetoken` when a token is due (only then; the token goes through a
pipe on the host, the FastDeploy user name on stdin, and it must be exactly
one JWT line), and the check runs again and must say `unchanged` (without
`force_rotate`, which a forced rotation has just satisfied). A token is due when the first existing target
has none, or one that is undecodable, scoped to another service, without
`jti`, without expiry or inside the renewal window, or when `force_rotate` is
set (the decision of the shared upsert and of ops-control's
`files/fastdeploy/echoport_service_token_status.py`).

A check that fails instead of answering (Echoport broken, a migration
missing) follows the probe convention: the apply runs and refuses the way the
script does; a due token is then issued before the script runs, as the
playbook issues it before its upsert. Only
ORM writes are watched; a script that writes through `connection.cursor()`
is not supported.

Where a playbook's script saves on every run, the port saves only when a
field differs: a converged row keeps its `updated_at` and skips Echoport's
`full_clean` on that run. The script and its values reach the host in
`manage.py shell -c`'s argument, so `RunnerTarget` refuses value names that
look like a secret.

## The Daybook operations backup bridge (`daybook_operations`)

ops-library's `daybook_operations_api_backup` role (`tasks_from:
register_echoport`) registers a fixed-source bridge, not a
`fastdeploy_runner` script. `DaybookOperationsBackup` holds the role
variables ops-control's playbook passes (with the target's `MinioAccess`)
and copies the role's asserts (fixed runner and policy paths, the access
must be the target's, renewal window below the token lifetime).
`install_daybook_operations_backup` (`register_daybook_operations_backup`
as a deploy) runs, in the role's order after the playbook's
`backup_minio_account.yml` (`access.minio_access`):

- `/usr/local/libexec` (`0755`), the upload dir (`0700`) and FastDeploy's
  service dir (`0755`), all `root:root`;
- the bridge `/usr/local/libexec/daybook-operations-backup` (`root:root
  0755`): `files/daybook_operations/echoport_runner.py`, the role's file
  byte for byte;
- the policy `/etc/daybook-operations-backup.json` (`0600`) and
  `config.json` (`0644`) as `to_nice_json` writes them through `copy:
  content:` (no final newline);
- the sudoers rule (`fastdeploy` to `deploy` and `deploy` to `root`, only
  `--config *`), validated with `visudo` first;
- FastDeploy's `service` row, with the role's query, only when the stored
  data differs (read while planning). Like the role it does not run
  `syncservices`;
- the token and the Echoport target with the role's script
  (`files/targets/daybook_operations.py`, `token_and_target`). A new target
  gets `schedule` and status `active`; an existing one keeps its schedule
  and status unless `update_schedule` is set. The token user reaches
  `issueservicetoken` on stdin (the role passes it in argv).

`registered_schedule` reads, while planning, the schedule the target will
have after the run (the role's `daybook_operations_api_backup_registered_schedule`);
ops-control upserts its Nyxmon checks with it.
`tests/test_echoport_runner_daybook_operations.py` compares the files with
what the role wrote on macmini (2026-11-10), plans no mutating operation on
that host, and runs the target script against the stand-in model.

## The generic runner (`generic`)

ops-control's `register-echoport-backup.yml` runs ops-library's
`echoport_backup` role and then `common/backup_minio_account.yml` once for
every target the generic runner `echoport-backup` serves. The runner picks
the `mc` alias by the first segment of the object key
(`MINIO_PREFIX_ALIASES`), so each target has its own scoped MinIO account
and root alias. `GenericRunnerRegistration` holds the role's
`fastdeploy_runner` settings (`backup.py.j2`, run as root, sudoers file
`/etc/sudoers.d/echoport_backup`), one `MinioAccess` per target in the
playbook's loop order, and the template variables. It refuses a prefix alias
map that is not exactly the targets and their aliases in that order, a target
without its scoped account, and an `mc` path or bucket other than the
accesses'. `install_generic_registration` (`register_generic_runner` as a
deploy) runs, in the playbook's order:

- the role's `sqlite3` package (no cache update);
- the role's pinned `mc` through the MinIO deploy's `binary` helper: kept
  when its sha256 is the pinned one, else downloaded and verified before it
  replaces the file (`root:root 0755`, as `get_url` with the checksum);
- the runner (`install_runner`);
- per target, `access.minio_access`: the scoped MinIO account (or, for a
  target with `store: rustfs`, only the proof through its alias) and root's
  alias.

Two differences from the playbook: the accesses read the accounts and
aliases through `mc` while planning, so a host without `mc` is refused
before any write (`just deploy-one minio` installs the same pinned client);
and the retired shared alias is looked up and removed once, with the first
target, not once per target. The role's own `minio_alias` include is not
ported: the playbook passes it no credentials, so it never runs.
`tests/test_echoport_runner_generic.py` compares the runner, `config.json`
and the sudoers rule with what the role wrote on macmini (2026-11-10, sixteen
targets) and plans no mutating operation on that host.

## Not here yet

Design note §3.1 also lists these parts; they come with the slices that use
them:

- vaultwarden's Nyxmon upsert (slice 9); graphyard's is `nyxmon` above;
- the deploy key and the media JSON are parts of `DeployRunnerRegistration`;
  unifi's and postfixadmin's logins are `CredentialFile`s above.

## Parity

- `tests/test_echoport_runner_parity.py`: every runner script of the 28
  register playbooks that use these templates (plus one synthetic variant
  and the generic runner as it is rendered for macmini's sixteen targets,
  `echoport-backup-macmini`)
  renders to the sha256 `ansible-playbook` produced
  (`tests/parity/echoport_runner/expected.json`, written by `generate.py`
  from `inputs.json`), and `config.json` and the sudoers rule equal the
  role's own tasks' output for three settings. With `OPS_LIBRARY_PATH`,
  `ansible-playbook` and `community.general`, the oracle test renders all of
  it again.
- `tests/test_echoport_runner_registration.py`: the seven A1 runners render
  through `RunnerRegistration` to the same sha256 (homeassistant with the
  fixtures' address), a host the playbook left plans no mutating operation
  (homeassistant's address read from the fake host's route), and the runner
  the deploy uploads carries the host's address or the fallback.
- `tests/test_echoport_runner_deploy_registration.py`: the seven A2 and A3
  runners render through `DeployRunnerRegistration` to the same sha256 (the
  media source bucket from the fixtures' secret), a host the playbook left
  plans no mutating operation (a media runner: only its MinIO user upsert),
  the parts run in each playbook's order, two known hosts end as two
  `known_hosts` tasks leave the file (checked against the real `ssh-keygen`),
  and the credentials file is the playbooks' `copy` content.
- `tests/test_echoport_runner_temp_dir.py`: heis-production and
  villakunterbunt-staging render to the same sha256, a host the port left
  plans no mutating operation, the old copy in the services root is removed
  and the parts run in the playbooks' order, and heis's rotation helper is
  the playbook's `copy` content (`quote`, `to_json`) with systemd reloaded
  only when a unit changed.
- `tests/test_ops_library_drift.py` records `fastdeploy_runner`,
  `echoport_backup` and `minio_backup` and fails when a vendored template
  differs from ops-library's or ops-library gains or loses one. For a
  template in `render.FORKED` the runners' recorded sha256 is ops-deploy's
  own rendering, and the drift and oracle tests check instead that
  ops-library's copy is still the one recorded in `expected.json`'s
  `forked_from`.
- `tests/test_echoport_runner_unifi_minecraft.py`: unifi's login file and
  its mongodump check (run against a stand-in `mongodump` to show the
  password reaches only its stdin), minecraft's mcrcon refusal.
- `tests/test_echoport_runner_fresh_install.py`: the two runners' restores
  onto a fresh install, rendered from the fixtures and run with the host's
  commands replaced.
