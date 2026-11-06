# Echoport backup runners (generic parts)

`ops_deploy.services._echoport_runner` holds what the Echoport backup runners
that FastDeploy starts have in common: the port of ops-library's
`fastdeploy_runner` role, the runner templates of its `echoport_backup` role,
and the pieces the ops-control register playbooks share
(`playbooks/common/*.yml`). Each runner is ported in a slice of its own,
which adds its config in ops-control and its own entry point (design note
`ECHOPORT-FASTDEPLOY-REGISTRATIONS-20261105` on ops-meta's `pyinfra-port`
branch, §3 and §3.8). The same-host root runners (class A1) use
`registration.register_runner` below. heis-production and
villakunterbunt-staging stay on Ansible; their templates are not vendored.
The deploy-user runners (classes A2 and A3) use
`registration.register_deploy_runner`.

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
includes `_work_dir.py.j2` and `_sqlite_backup.py.j2`.
`render.render_runner(template, variables)` renders one as Ansible's
`template` module does (`trim_blocks`, the final newline restored,
`StrictUndefined`) with ansible-core's `to_json`, `bool` and
`regex_replace`. `variables` are the playbook's values, already resolved; a
name the template reads with `default(...)` may be left out.

## Object-store access (`access.minio_access`)

The port of `common/backup_minio_account.yml`. ops-control resolves the
target from `playbooks/vars/backup_minio_accounts.yml` into a `MinioAccess`
(target, OS user, alias, store URL, whether it is switched, store, retired
aliases) and passes the access key and secret. When `mc` is needed and
missing, the run refuses while planning, as the playbooks' "Ensure mc is
installed" does (`register-echoport-backup.yml` installs it).

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

## Not here yet

Design note §3.1 also lists these parts; they come with the slices that use
them:

- `nyxmon_check`: graphyard's and vaultwarden's Nyxmon upserts differ from
  `nyxmon_site_checks` (they re-enable a disabled check and skip without a
  Nyxmon database), so they are ported with their runners (slices 6 and 9);
- `credential_file` for unifi and postfixadmin: a plain `ops.secret_file`
  call (`root 0600`), written by the runner slices that need them. The deploy
  key and the media JSON are parts of `DeployRunnerRegistration`.

## Parity

- `tests/test_echoport_runner_parity.py`: every runner script of the 26
  register playbooks that use these templates (plus one synthetic variant)
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
- `tests/test_ops_library_drift.py` records `fastdeploy_runner`,
  `echoport_backup` and `minio_backup` and fails when a vendored template
  differs from ops-library's or ops-library gains or loses one.
