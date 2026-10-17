# minio

Port of the `minio_deploy` Ansible role and of the steps of ops-control's
`playbooks/deploy-minio.yml` that belong to MinIO itself: the port preflight
on the API and console ports and, in place of the encrypted-volume play the
playbook imports first, a read-only check that the data volume is mounted.
MinIO runs as a hardened systemd service from a pinned binary, on loopback,
optionally behind Traefik (S3 API on one host, the web console on another,
with basic auth for clients outside the internal ranges), and the bootstrap
installs a pinned `mc`, root's admin alias and the buckets.

`backup_account` is the role's `tasks_from: backup_account`: one scoped MinIO
user per backup target, managed through root's admin alias, optionally with
the backup runner's `mc` alias.

```python
from ops_deploy.services.minio import Bucket, MinioConfig, deploy_minio

cfg = MinioConfig(
    secrets=SecretRef("secrets/prod/minio.yml"),
    data_dirs=("/mnt/cryptdata/minio/data",),
    required_mounts=("/mnt/cryptdata",),
    port_preflight=True,
    expose_via_traefik=True,
    traefik_host="minio.example.com",
    traefik_api_host="s3.example.com",
    bootstrap_with_mc=True,
    buckets=(Bucket(name="voxhelm", policy="private"),),
)
deploy_minio(cfg, store.load(cfg.secrets))
```

ops-control registers it as `minio` (see its `docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `root_user`, `root_password` | yes | `/etc/default/minio` and root's admin alias (stdin only) |
| `console_basic_auth_password` | with `expose_via_traefik` and `console_basic_auth_enabled` | the console route's bcrypt hash (computed on the controller) |

None may be empty or `CHANGEME` (the role's asserts). `root_user` and
`root_password` must not contain double quotes, backslashes or line breaks:
the env file holds them in double quotes. Errors name keys, never values.

## Configuration (`MinioConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `user`, `group`, `home` | `minio`, `minio`, `/home/minio` | `site_path` is the home (the unit's `WorkingDirectory`) |
| `bin_path` | `/usr/local/bin/minio` | |
| `version`, `checksum` | the role's pinned hotfix build and its `sha256:` | a `RELEASE.<date>` name, optionally `.hotfix.<hex>`; `sha256:<64 hex>` |
| `download_url` | the role's `minio_download_url` | release or hotfix track, derived from `version` |
| `data_dirs` | `/var/lib/minio/data` | at least one |
| `required_mounts` | none | mount points that must be mounted before anything changes |
| `port_preflight` | `false` | the playbook's preflight on the two ports |
| `bind_host`, `api_port`, `console_port` | `127.0.0.1`, `9001`, `9002` | |
| `expose_via_traefik`, `traefik_host`, `traefik_api_host`, `traefik_cert_resolver` | `false`, `minio.home.example.com`, `s3.<traefik_host>`, none | the console host must be set when exposed |
| `console_basic_auth_enabled`, `console_basic_auth_user`, `internal_ip_ranges` | `true`, `admin`, the role's five ranges | dual router on the console |
| `systemd_restart`, `systemd_memory_max`, `systemd_limit_nofile`, `systemd_tasks_max`, `healthcheck_timeout` | `always`, none, `65536`, `infinity`, `30` | |
| `bootstrap_with_mc`, `mc_version`, `mc_checksum`, `mc_download_url`, `mc_bin_path` | `false`, the role's pinned `mc`, its `sha256:`, derived, `/usr/local/bin/mc` | |
| `host_alias` | `local` | root's admin alias (`minio_host_alias`) |
| `buckets` | none | `Bucket(name, versioning, policy)`; needs `bootstrap_with_mc` |

`Bucket.policy` is `private`, `public` or `None` (leave anonymous access
alone). The role also lists `readonly` and `writeonly`, which the pinned `mc`
rejects (`mc anonymous set` knows `private`, `public`, `download`, `upload`),
so the role would fail on them; the config refuses them instead.

Not ported (refused as unknown fields): TLS (`minio_tls_*`, certificates),
server-side encryption (`minio_sse_*`), `minio_service_accounts` (the role
passes their keys on the command line), `minio_backup_config_*`, and other
paths for the env file, the unit and the config directory. ops-control uses
none of them.

## What the deploy does

1. Checks secrets and renders the env file; fails before any operation.
2. Read-only checks before any change: each of `required_mounts` is mounted
   (ops-control: the encrypted volume the playbook's first play opens and
   mounts), and with `port_preflight` nothing but `minio.service` listens on
   the API or console port at a loopback or wildcard address.
3. `system_user`: group, user (`/usr/sbin/nologin`), the home (`0750`). An
   existing user is not modified.
4. `/etc/minio` (`root`, `0755`); each data directory (`minio:minio`,
   `0750`). If anything below a data directory has another owner or group, a
   recursive `chown` runs (the role's `recurse`). The role's recursive mode is
   not applied (see below).
5. The MinIO binary: downloaded only when its sha256 differs from `checksum`,
   into a private temporary directory, checked, staged next to the binary and
   renamed over it; owner and mode (`root`, `0755`) reconciled either way.
6. `/etc/default/minio` (`0600`) through `secret_file`, the unit
   `minio.service`, then `service_rollout`: reload on a unit change, enable,
   start, and restart when the binary, the env file or the unit changed (not
   right after this run started it). Then the API and console ports and the
   health endpoint `/minio/health/live` must answer.
7. With `expose_via_traefik`: `/etc/traefik/dynamic/minio.yml` from the role's
   template. The bcrypt hash is computed on the controller and the hash in the
   deployed file is reused while it still verifies. Traefik is not restarted
   (it watches the directory; the role has no handler for it either).
8. With `bootstrap_with_mc`: the `mc` binary like step 5 (no restart); root's
   admin alias, imported with `mc alias import` (JSON on stdin) when a
   read-only probe finds its URL or credentials differ (the probe prints only
   a digest); per bucket `mc mb --ignore-existing`, `mc version enable` and
   `mc anonymous set` only where a read-only probe finds them missing (before
   `mc` is installed, or when the probe fails, all of them run and the probe
   runs again after them). Then the role's verify: the admin alias and
   `mc ls` of each bucket.

### Differences from the role

- Steps that would change nothing are skipped: the role re-runs
  `mc alias set`, `mc mb`, `mc version enable` and `mc anonymous set` and
  re-hashes the console password on every run, so Ansible reports changes on
  every run.
- The root credentials never appear on a command line (`mc alias set` in the
  role).
- The health check runs before the bootstrap, because a restart happens right
  after the change here; the role's handler restarts MinIO only at the end of
  the play, after its bootstrap and verify ran against the old process.
- The data directories: the role's `file` with `recurse` sets `0750` on every
  file and directory below on every run. MinIO writes new objects `0644`, so
  each Ansible run rewrites the modes of every object stored since the last
  one (on macmini about 20,000 entries of the backup store). The port only
  sets the mode of the data directory itself and keeps the recursive owner.
  Files only `minio` reads stay readable either way.
- The binaries are verified before they replace the installed ones (as
  `get_url` does), and a mode-only fix of a binary does not restart MinIO.

## Backup accounts

```python
from ops_deploy.services.minio import BackupAccount, RunnerAlias, deploy_backup_account

account = BackupAccount(name="delve", alias=RunnerAlias(name="backup-delve"))
deploy_backup_account(account, SecretStr(secret))
```

| Field | Default | Notes |
|---|---|---|
| `name` | required | target name; the policy is `backup-<name>`, the user `bk-` + 17 hex digits of its SHA-256 (MinIO allows 20 characters) |
| `bucket`, `prefixes` | `backups`, `(<name>,)` | plain key prefixes without wildcards |
| `allow_put`, `allow_delete`, `whole_bucket` | `true`, `false`, `false` | as the role (Echoport's retention account: no put, delete, whole bucket) |
| `mc`, `admin_alias`, `policy_dir` | `/usr/local/bin/mc`, `local`, `/etc/minio/policies` | |
| `alias` | `None` | `RunnerAlias(name, os_user="root", home="/root", url="http://127.0.0.1:9001")`: the runner's `mc` alias; for root it must not be `admin_alias` |

The secret is 32 to 40 characters, one line, not `CHANGEME` (the role's input
check). Steps: a read-only `mc admin info <admin_alias>` (nothing changes on
MinIO without root's admin alias); `/etc/minio/policies` (`0750`) and the
policy document from the role's template (`0640`); `mc admin policy create`
when the file changed or the server's policy is missing or differs; `mc admin
user add` (user and secret on stdin, output withheld); `mc admin policy
attach` when the user does not hold the policy; with `alias`, the runner's
alias through `mc alias import` (as `echoport_backup`'s `tasks_from:
minio_alias`, via `runuser` for a user other than root) and a read-only `mc
ls` of the account's first prefix with it; finally the role's last assert
(enabled, exactly `backup-<name>`, no group).

The role upserts the user on every run. Here the upsert is skipped while the
runner's alias holds the configured secret and can list with it (so MinIO has
that secret); without `alias` it runs on every run, as in the role.

## Parity with the role

The deploy ships the role's templates unchanged (`minio.env.j2`,
`minio.service.j2`, `traefik-minio.yml.j2`, `backup-account-policy.json.j2`)
and renders them with Ansible's template options, so the env file, the unit,
the route (given the same hash) and the policy documents are
**byte-identical** to what Ansible writes (`tests/test_minio_parity.py`,
against the vendored copies in `tests/parity/ansible/minio_deploy__*`). The
role's digest is recorded in `tests/parity/ops_library_roles.json`.

## Tests

- `tests/test_minio.py` (fake connector): first run, converged second run,
  checks that fail before any change, env, unit, binary and `mc` changes,
  binary mode drift, route drift, each bucket step, a failing bucket probe,
  foreign-owned data, a server-only config, leak checks, secret and config
  validation, download URLs; for backup accounts the first run through the
  admin alias, a converged rerun, each probe state, a secret the alias cannot
  log in with, rotation, no runner alias, a missing admin alias, a failed
  verification, a runner other than root, the input check.
- `tests/test_minio_parity.py`: byte parity with the role's templates.
- `tests/test_echoport_scripts.py` runs the shared account and alias probes
  (`services/minio/files/`) against a stand-in `mc`.
- `tests/smoke/test_minio_smoke.py` (`just smoke`, needs `MINIO_BIN_DIR` with
  the pinned linux-amd64 `minio` and `mc`, which the VM serves as the download
  URL): a foreign listener and an unmounted volume refused before any change,
  a fresh deploy, a converged rerun, a unit change with one restart, the
  files, the route's basic auth, no secret on disk outside its files; a backup
  account created, converged, rotated and converged again, with an upload and
  download through its alias and another prefix, the bucket root, another
  bucket, deletes and the admin API refused.
- Coexistence with Ansible runs from ops-control:
  `just smoke-minio-coexistence MINIO_BIN_DIR`.
