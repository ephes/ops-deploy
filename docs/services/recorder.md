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
| any other key | no | ignored; only values that are written to the env file must fit its quoting |
| `livekit_host_url` | no | empty or missing: `http://127.0.0.1:7880` |

Values are written inside double quotes into a systemd `EnvironmentFile`, so
double quotes, backslashes and line breaks are refused. Errors name keys,
never values.

## Configuration (`RecorderConfig`)

Defaults follow the role's `defaults/main.yml` and the playbook, except
`systemd_memory_max`, which the role did not have.

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
| `guest_basic_auth`, `internal_ip_ranges`, `external_guests` | `None`, the helper's internal ranges, `True` | see "Guests from the internet" |
| `livekit_signal_port`, `livekit_url` | `None`, `""` | see "Guests from the internet"; `livekit_url` overrides the secrets' value and must be `wss://<traefik_host>` with a signal port |
| `live_room_prefix` | `rec-` | |
| `max_chunk_bytes` | `None` | `None` leaves `RECORDER_MAX_CHUNK_BYTES` out |
| `upload_buffer_bytes` | `None` | `None` leaves `RECORDER_UPLOAD_BUFFER_BYTES` out (the binary's 64 MiB): chunk-upload bytes buffered at once over all takes |
| `s3_endpoint`, `s3_bucket`, `s3_use_ssl` | `""`, `recorder`, `false` | empty endpoint: local object store under `data_dir` |
| `mail_api_url`, `mail_domain`, `mail_from` | role defaults | used when the secrets do not set them |
| `systemd_nofile` | `65536` | |
| `systemd_memory_max` | `1G` | the unit's `MemoryMax=`; empty leaves it out. A backstop: recorderd idles below 10 MB and bounds its own upload buffers |
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

`tests/test_recorder_golden.py` (env file, unit and route against their
goldens), `tests/test_recorder.py` (fake connector: first
run, converged no-op, binary (staged rename), env, unit and route changes, build and smoke
failures, secret handling) and `tests/smoke/test_recorder_smoke.py` (fresh
install, converged rerun, and a new binary replacing the running one on the
smoke VM; needs Go, npm and `RECORDER_SOURCE` or
`$PROJECTS_ROOT/podcast/apps/recorder`).

## Guests from the internet

Without `guest_basic_auth` the route is the role's single router: every client
that reaches Traefik reaches the whole app, the host dashboard and its login
included.

With `guest_basic_auth` (a `BasicAuth`, as for `TraefikRoute`) the route file
holds:

| Router | Matches | Auth |
|---|---|---|
| `recorder-int` (priority 120) | the host, clients in `internal_ip_ranges` | none; everything |
| `recorder-ext` (priority 100) | the host and a guest path: `/r/…`, `/studio`, `/api/join`, `/api/takes/<id>/upload`, `/app.js`, `/worklet.js`, `/health` | basic auth |

Any other path from outside `internal_ip_ranges` has no router and gets
Traefik's 404: the dashboard (`/`), the account pages (`/activate`, `/reset`,
`/verify`) and the host and admin API. The guest paths are the recording pages
and what they call; an invite token in the link remains the per-person
capability, basic auth is the shared outer door. The middleware removes the
`Authorization` header before the request reaches recorderd. The bcrypt hash
is computed on the controller and the file is written without a diff, as for
every route with basic auth.

`external_guests=False` (only with `guest_basic_auth`) drops `recorder-ext`
and `recorder-live-ext`: clients outside `internal_ip_ranges` then reach
nothing, while the internal routers stay. It takes guest access away without
going back to the single public router; a deploy with `external_guests=False`
and no `guest_basic_auth` is refused when the route is rendered. It stops new
requests only: a WebSocket that is already open (a guest's signalling
connection) can outlive Traefik's reload of the route file, so a call in
progress may continue until it ends or LiveKit is restarted.

`livekit_signal_port` adds `recorder-live-int` and `recorder-live-ext` for
`PathPrefix(/rtc)` on the same host, in front of `http://127.0.0.1:<port>`
(LiveKit's signalling); without `guest_basic_auth` it adds one public
`recorder-live` router next to the single app router, so `/rtc` reaches
LiveKit in every mode. `livekit_url` must be `wss://<traefik_host>` with it
(anything else is refused: browsers would be sent to a host without `/rtc`).
The routers without basic auth carry `recorder-live-headers`, which deletes
the `Authorization` header: LiveKit takes its join token from the URL and
refuses a request with any other `Authorization`, and a browser that once
entered the guest credentials keeps sending them, also from the home network
(on the external router the basic-auth middleware removes the header itself).
The browser's signalling WebSocket is then same-origin with the recording page
and carries the basic-auth credentials the guest entered for the page. A
WebSocket to another host would not: browsers neither reuse credentials across
origins nor prompt for a WebSocket. The media itself is not HTTP; see the
livekit page ("Media from outside the LAN").

Add a new browser-reachable path of the recorder to the `recorder-ext` rule in
`recorder-traefik.yml.j2` when guests need it; `tests/test_recorder.py` pins
the list.
