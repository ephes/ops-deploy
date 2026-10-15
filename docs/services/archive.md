# archive

Port of the `archive_deploy` Ansible role (rsync method) and of the steps
ops-control's `playbooks/deploy-archive.yml` runs around it: the Django app
`archive` (gunicorn) and the enrichment worker `archive-metadata-worker` on
one SQLite database, behind Traefik, with media in MinIO.

```python
from ops_deploy.services.archive import ArchiveConfig, EchoportTarget, MinioBootstrap, deploy_archive

cfg = ArchiveConfig(
    source_path=Path("~/projects/archive").expanduser(),
    secrets=SecretRef("secrets/prod/archive.yml"),
    media_storage_backend="storages.backends.s3.S3Storage",
    media_storage_bucket_name="archive-media",
    media_storage_endpoint_url="http://127.0.0.1:9001",
    media_storage_access_key_id="archive-media",
    minio=MinioBootstrap(),
    echoport=EchoportTarget(),
)
deploy_archive(cfg, store.load(cfg.secrets))
```

ops-control registers it with secrets from `secrets/prod/archive.yml` (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `django_secret_key`, `api_token`, `summary_api_key` | yes, more than 20 characters | `.env` |
| `admin_username`, `admin_password` | yes | admin account (stdin only) |
| `admin_email` | no (empty) | admin account |
| `transcription_api_key` | no (the summary key) | `.env` |
| `media_storage_secret_access_key` | with S3 storage | `.env`, MinIO account (stdin only) |

The MinIO root credentials are not used: the bucket, policy and account are
managed through root's MinIO admin alias on the host (`MinioBootstrap.admin_alias`,
`local`), as `deploy-archive.yml` does. `minio_root_user` and
`minio_root_password` are refused if passed.

These keys of the secrets file override the config when present, as the
playbook's `archive_secrets.<key> | default(...)` does: `summary_api_base`,
`summary_model`, `transcription_api_base`, `transcription_model` and the
`media_storage_*` settings (backend, location, bucket, endpoint, region,
access key id, addressing style). They are validated like config fields.

Values must be single lines (this includes the playbook's assert that the
media secret has no CR or LF: it reaches the MinIO scripts as one line on
stdin); `CHANGEME` is refused. Errors name keys, never values.

## Configuration (`ArchiveConfig`)

Defaults follow the role's `defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required | archive checkout; must contain `src/django/manage.py`, `pyproject.toml`, `uv.lock` |
| `service_name`, `worker_service_name` | `archive`, `archive-metadata-worker` | |
| `user` / `site_path` | `archive` / `/home/archive/site` | home is `/home/<user>` |
| `source_excludes` | the role's rsync excludes | VCS/caches, `.env`, `/.env.shell`, `db.sqlite3*`, `archive-media/`, `staticfiles/`, `src/django/gunicorn.ctl` |
| `python_version` | `3.12` | `uv sync --python` |
| `app_host`, `app_port`, `workers` | `127.0.0.1`, `10041`, `2` | gunicorn |
| `metadata_worker_*`, `*_request_timeout` | `10`, `10`, `15`, `60`, `300` | worker arguments |
| `django_settings_module`, `django_debug` | `config.settings.production`, `false` | |
| `django_allowed_hosts`, `django_csrf_trusted_origins` | `127.0.0.1`, none | |
| `summary_api_base`, `summary_model`, `transcription_api_base`, `transcription_model` | OpenAI, `gpt-4o-mini`, the summary base, `gpt-4o-mini-transcribe` | |
| `media_storage_backend` | `FileSystemStorage` | or `storages.backends.s3.S3Storage` (needs bucket, endpoint, access key and the secret) |
| `media_storage_location` | `<site>/archive-media` | also the local tree the S3 migration reads; a normalized absolute path of letters, digits, `._-/` (inside the site it becomes a sync exclude) |
| `traefik_host`, `traefik_entrypoints`, `traefik_cert_resolver`, `traefik_middlewares` | role defaults | |
| `minio` | `None` | `MinioBootstrap(policy_name, mc, admin_alias)`: the playbook's bucket and service-account step, through root's admin alias (`local`) |
| `echoport` | `None` | `EchoportTarget(name, schedule, update_schedule, user, site_path)`: the playbook's backup target |

## What the deploy does

1. Checks secrets and settings (the role's and playbook's asserts) and
   renders both env files; fails before any operation.
2. `system_user`: user, group, `/home/archive`, `site`, `site/staticfiles`;
   runtime packages `python3`, `python3-venv`, `sqlite3`, `rsync` (the MinIO
   scripts use `python3`).
3. `.env` (systemd format) and `.env.shell` (double-quoted) through
   `secret_file`, `0600`. Written before the MinIO step (the role writes them
   later) so a new app secret also reruns the MinIO bootstrap.
4. With S3 storage and `minio`: a read-only check that `mc admin info local`
   succeeds (the playbook's "Require the MinIO admin alias of root"; the
   deploy fails here, before any MinIO change, without it). A read-only probe
   (admin calls through `local`, the app's credentials from `.env`, parsed
   and never sourced) checks the bucket, private anonymous access, the policy
   document, the account's only policy and that the app can list the bucket.
   Only if something differs, or `.env` changed, the playbook's bootstrap
   script runs through `local`, with the app secret and the app's alias
   (JSON for `mc alias import` into a temporary mc configuration) on stdin,
   as the playbook passes them. No credential is ever an `mc` argument or in
   its environment; besides the built-in policies the playbook detaches, any
   other policy attached to the account is detached.
5. With S3 storage: the playbook's local media migration (`mc mirror` and the
   `.minio-migrated` marker, the app's alias imported from stdin into a
   temporary mc configuration), only when the local tree has files newer than
   the marker.
6. `sync_tree` of the checkout to `site/` (with `--delete`, owned by the
   service user).
7. `uv sync --no-dev --python 3.12` if the source changed, the venv is missing
   or runs another Python version.
8. `python manage.py migrate` and `collectstatic` (in `src/django`, env from
   `.env.shell`, as the service user) if source, dependencies or env changed.
9. Admin account: a read-only probe (`manage.py shell`) prints, per staff or
   superuser account, digests of name, email and password hash plus the
   hash's algorithm, iterations and salt. The deploy rehashes the configured
   password (pbkdf2_sha256) and runs `ensure_admin_user --password-stdin`
   only if the account is missing or differs. Names and passwords travel on
   stdin.
10. Both units (`service_rollout`: reload on unit change, restart on code,
    dependency or `.env` change); removes the retired
    `archive-quote-classifier` timer/service if present.
11. Traefik route `/etc/traefik/dynamic/archive.yml` from the role's template;
    Traefik restarts only if it changed.
12. Read-only checks: port, then HTTP 200 on `/` (20 tries, 3 s apart).
13. With `echoport`: requires `<echoport site>/manage.py`, then a dry run of
    the playbook's upsert (`manage.py shell` as `echoport`); writes only if
    the target differs. A schedule set in the Echoport UI is kept unless
    `update_schedule`.

## Parity with the role

The deploy ships the role's four templates unchanged and renders them with
Ansible's template options, so `.env`, `.env.shell`, both units and the
Traefik route are **byte-identical** to what Ansible writes
(`tests/test_archive_parity.py`, against the vendored copies in
`tests/parity/ansible/archive_deploy__*`). The route has no basic-auth hash,
so unlike nyxmon even the Traefik file stays untouched on a tool switch.

Differences, all on the "change only what differs" side:

- migrate, collectstatic, the admin account, the MinIO bootstrap and the
  Echoport upsert run only when needed (the role and playbook run them on
  every deploy);
- the role's recursive `chown` of the site is replaced by `--chown` on synced
  files;
- a media location inside the site other than `archive-media/` is excluded
  from the sync too, so `--delete` cannot remove uploads;
- `db.sqlite3*` (also `-journal`/`-wal`) is excluded from the sync, where the
  role excludes only `db.sqlite3`.

Not ported: the git deploy method, `archive_traefik_enabled: false`, and the
`uv_install` role (uv must already be at `/usr/local/bin/uv`).

## Tests

- `tests/test_archive.py` (fake connector): first run, converged second run
  (filesystem and S3), code change, `.env` rotation, admin password rotation,
  worker unit change, route drift, retired units, MinIO probe verdicts and app
  secret rotation, a missing admin alias of root, refused MinIO root
  credentials and CR/LF in the media secret, pending media migration, Echoport upsert and missing
  Echoport, settings from the secrets file, validation, leak checks.
- `tests/test_archive_parity.py`: byte parity with the role's templates.
- `tests/smoke/test_archive_smoke.py` (`just smoke`, needs `ARCHIVE_SOURCE` or
  `PROJECTS_ROOT`): two real deploys plus a fresh-clone run of the committed
  `HEAD`; converged reruns, units active, env files private, migrations
  applied, the admin can authenticate, Traefik serves the app, no secret
  outside its files. Filesystem storage only.
- MinIO, Echoport and Ansible coexistence run from ops-control:
  `just smoke-archive-coexistence`.
