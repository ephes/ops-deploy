# Echoport backup runners (generic parts)

`ops_deploy.services._echoport_runner` holds what the Echoport backup runners
that FastDeploy starts have in common: the port of ops-library's
`fastdeploy_runner` role, the runner templates of its `echoport_backup` role,
and the pieces the ops-control register playbooks share
(`playbooks/common/*.yml`). Nothing calls it yet: each runner is ported in a
slice of its own, which adds its config in ops-control and its own entry
point (design note `ECHOPORT-FASTDEPLOY-REGISTRATIONS-20261105` on ops-meta's
`pyinfra-port` branch, §3 and §3.8). heis-production and
villakunterbunt-staging stay on Ansible; their templates are not vendored.

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
aliases) and passes the access key and secret:

- a switched target on MinIO gets its scoped account through root's MinIO
  admin alias (`minio_deploy`'s `backup_account`, as the echoport deploy ports
  it): policy `backup-<target>` (read, write and list `backups/<prefix>/`,
  no delete), user `bk-<sha256(target)[:17]>`; the secret goes to
  `mc admin user add` on stdin. The policy and user are written only when the
  probe finds them missing or different, or when the runner's alias does not
  hold the secret yet (for a runner without an alias, every run, as the role);
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
(trust on first use). Anything else refuses while planning. The line is
written as `known_hosts` `state: present` writes it (an entry of the same type
replaced in place, anything else appended); the file keeps its owner and mode.

## Playbook target scripts (`target`)

Several register playbooks upsert their Echoport target with a script of
their own, which differs from the shared upsert (`services._echoport`) in
scope, owned fields, save behaviour and refusals. A port keeps that script
(its values from `VALUES`, a newly issued token from `SERVICE_TOKEN`) in a
`RunnerTarget`; `files/runner_target.py` runs it inside Echoport's
`manage.py shell`:

- **check**: the script runs without writing. Each model save is recorded
  after the model's own validation, other writes are skipped, and the
  transaction is rolled back. The answer is `unchanged` when no save would
  change a stored field (only `update_fields` when the script names them) and
  no token is due, `pending` otherwise, and `refused: <reason>` when the
  script raises (for example "Refusing implicit reactivation");
- **apply**: when a token is due and none arrives on stdin it answers
  `need-token` and runs nothing; otherwise it runs the script as the
  playbook does.

`upsert_runner_target` (no token) and `token_and_target` (with a
`ServiceToken`, the inputs of `common/fastdeploy_service_token.yml`) run the
check while planning: a refusal stops the deploy before any write and
`unchanged` adds no operation. Otherwise the script runs once, after
`issueservicetoken` when a token is due (only then; the token goes through a
pipe on the host, the FastDeploy user name on stdin), and the check runs
again and must say `unchanged`. A token is due when the first existing target
has none, or one that is undecodable, scoped to another service, without
`jti`, without expiry or inside the renewal window, or when `force_rotate` is
set (the decision of the shared upsert and of ops-control's
`files/fastdeploy/echoport_service_token_status.py`).

Where a playbook's script saves on every run, the port saves only when a
field differs: a converged row keeps its `updated_at` and skips Echoport's
`full_clean` on that run. The script and its values reach the host in
`manage.py shell -c`'s argument, so `RunnerTarget` refuses value names that
look like a secret.

## Parity

- `tests/test_echoport_runner_parity.py`: every runner script of the 26
  register playbooks that use these templates (plus one synthetic variant)
  renders to the sha256 `ansible-playbook` produced
  (`tests/parity/echoport_runner/expected.json`, written by `generate.py`
  from `inputs.json`), and `config.json` and the sudoers rule equal the
  role's own tasks' output for three settings. With `OPS_LIBRARY_PATH`,
  `ansible-playbook` and `community.general`, the oracle test renders all of
  it again.
- `tests/test_ops_library_drift.py` records `fastdeploy_runner`,
  `echoport_backup` and `minio_backup` and fails when a vendored template
  differs from ops-library's or ops-library gains or loses one.
