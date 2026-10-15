# recorder

Port of the `recorder_deploy` Ansible role plus the controller-side build and
smoke steps of ops-control's `playbooks/recorder/deploy.yml`: the podcast
recording backend, one static Go binary (`recorderd`) with an embedded
frontend, SQLite for state, MinIO (or the local filesystem) for media, behind
Traefik.

```python
from ops_deploy.services.recorder import RecorderConfig, deploy_recorder

cfg = RecorderConfig(
    source_path=Path("~/projects/podcast/apps/recorder").expanduser(),
    secrets=SecretRef("secrets/prod/recorder.yml"),
    public_url="https://recorder.example.com",
    traefik_host="recorder.example.com",
)
deploy_recorder(cfg, secrets)
```

ops-control registers it with secrets from two SOPS files (see its
`docs/PYINFRA.md`).

## Secrets

| Key | Required | Used for |
|---|---|---|
| `session_secret` | yes | `RECORDER_SESSION_SECRET` (host accounts; the binary does not boot without it) |
| `admin_emails` | yes | `RECORDER_ADMIN_EMAILS`, comma-separated operator admins |
| `mail_token` | no | enables `RECORDER_MAIL_*`; empty disables email verification |
| `mail_api_url`, `mail_domain`, `mail_from` | no | override the config's mail defaults |
| `s3_access_key`, `s3_secret_key` | when `s3_endpoint` is set | `RECORDER_S3_*` |
| `livekit_api_key` | no | enables the live path (`RECORDER_LIVEKIT_*`) |
| `livekit_url`, `livekit_api_secret` | with `livekit_api_key` | |
| `livekit_host_url` | no | empty or missing: `http://127.0.0.1:7880` |

Values are written inside double quotes into a systemd `EnvironmentFile`, so
double quotes, backslashes and line breaks are refused. Errors name keys,
never values.

## Configuration (`RecorderConfig`)

Defaults follow the role's `defaults/main.yml` and the playbook.

| Field | Default | Notes |
|---|---|---|
| `source_path` | required (relative paths are made absolute) | recorder checkout; must contain `cmd/recorderd`, `web/package.json`, `scripts/smoke.sh` |
| `artifact_path` | `/tmp/recorderd-linux-amd64` | where the controller writes the binary (the playbook's path) |
| `goarch` | `amd64` | `arm64` for an Apple-silicon smoke VM |
| `public_url`, `traefik_host` | required | |
| `service_name`, `user` | `recorder` | the group has the user's name |
| `site_path` | `/opt/recorder` | the binary is `<site_path>/recorderd` |
| `data_dir`, `config_dir` | `/var/lib/recorder`, `/etc/recorder` | env file `<config_dir>/recorder.env` |
| `listen_address`, `port` | `127.0.0.1`, `10015` | |
| `traefik_entrypoints`, `traefik_cert_resolver` | `("web-secure",)`, `""` | empty resolver: `tls: {}` (wildcard cert) |
| `live_room_prefix` | `rec-` | |
| `max_chunk_bytes` | `None` | `None` leaves `RECORDER_MAX_CHUNK_BYTES` out |
| `s3_endpoint`, `s3_bucket`, `s3_use_ssl` | `""`, `recorder`, `false` | empty endpoint: local object store under `data_dir` |
| `mail_api_url`, `mail_domain`, `mail_from` | role defaults | used when the secrets do not set them |
| `systemd_nofile` | `65536` | |
| `healthcheck_retries`, `healthcheck_timeout` | `10`, `30` | |
| `smoke_url` | `None` | the playbook's post-deploy gate; `None` skips it |
| `expect_accounts` | `true` | passes `--expect-accounts` to the smoke script |

## What the deploy does

1. Checks secrets and renders the env file (fails before anything else).
2. Builds on the controller, as the playbook's `pre_tasks` do on every run:
   `npm ci --no-audit --no-fund` and `npm run build` in `web/`, then
   `go build -trimpath -ldflags=-s -ldflags=-w -o <artifact_path> ./cmd/recorderd`
   with `GOOS=linux GOARCH=<goarch> CGO_ENABLED=0`. A failing step stops the
   run before any host operation. The build also runs for a `--dry` check,
   since the binary's checksum decides whether it changes. An unchanged
   source builds the same bytes, so the upload is a no-op.
3. `ca-certificates` (apt cache refreshed when older than an hour).
4. `system_user`: group and system user `recorder`, shell
   `/usr/sbin/nologin`, home = `data_dir` (`0750 recorder:recorder`);
   `site_path` `0755 root:root`, `config_dir` `0750 root:recorder`.
5. The binary (`0755 root:root`): a changed one is uploaded as
   `recorderd.ops-deploy-new` and renamed over the old one (writing over a
   running executable fails with `ETXTBSY`; this also keeps pyinfra's
   text diff away from it). `recorder.env` through `secret_file`
   (`0640 root:recorder`).
6. Unit file and the Traefik route (`/etc/traefik/dynamic/recorder.yml`, the
   role's own template with security headers, no basic auth). Traefik is not
   restarted: the role's `reload traefik` handler fails on a unit without
   `ExecReload` and is ignored, and the file provider watches the directory.
7. `service_rollout`: daemon-reload on unit change; restart when the unit,
   binary or env file changed (not right after this run started it).
8. Read-only checks: port open, then `/health` answers 200 with
   `status: ok`.
9. With `smoke_url`: `scripts/smoke.sh <smoke_url> [--expect-accounts]` on
   the controller, through the external URL (read-only; a failure fails the
   run).

The database (`data_dir/recorder.db`) and the object store
(`data_dir/objects`) are never written by the deploy.

## Differences from the role

- The service restarts before the health check (the role's handlers run at
  the end of the play, after it), and on a first install it is started once,
  not started and then restarted.
- `systemctl daemon-reload` only runs when the unit changed.
- The role's `recorder_traefik_enabled` and `recorder_healthcheck_enabled`
  switches are not ported; the playbook never turns them off.

## Tests

`tests/test_recorder_parity.py` (env file, unit and route against the
vendored role templates), `tests/test_recorder.py` (fake connector: first
run, converged no-op, binary (staged rename), env, unit and route changes, build and smoke
failures, secret handling) and `tests/smoke/test_recorder_smoke.py` (fresh
install, converged rerun, and a new binary replacing the running one on the
smoke VM; needs Go, npm and `RECORDER_SOURCE` or
`$PROJECTS_ROOT/podcast/apps/recorder`).
