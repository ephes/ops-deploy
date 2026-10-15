# delve

Port of the `delve_deploy` Ansible role: the Delve backend, one static Go
binary (`delved`) run as a systemd unit behind Traefik, with its state in one
SQLite database under `data_dir`. Also installs the Discovery collector
oneshot and timer (the timer stays disabled unless configured).

```python
from ops_deploy.services.delve import DelveConfig, build_delved, deploy_delve

binary = build_delved(Path("~/projects/podcast/apps/delve-backend").expanduser(), Path(tmp) / "delved")
cfg = DelveConfig(binary_path=binary, secrets=SecretRef("secrets/prod/delve.yml"), traefik_host="delve.example.org")
deploy_delve(cfg, store.load(cfg.secrets))
```

ops-control registers it for macmini (see its `docs/PYINFRA.md`).

## Building the binary

`build_delved(source_path, output, goarch="amd64")` runs the playbook's
pre-task on the controller: `go build -trimpath -ldflags=-s -ldflags=-w -o
OUTPUT ./cmd/delved` with `GOOS=linux`, `CGO_ENABLED=0`. Go builds are
reproducible, so the same source and toolchain give the same bytes and an
unchanged checkout uploads nothing and restarts nothing. `goarch="arm64"`
exists for the arm64 lima smoke VM.

## Secrets

| Key | Required | Used for |
|---|---|---|
| `session_secret` | yes | `DELVE_SESSION_SECRET`; at least 16 characters (the binary refuses less) |
| `dogfood_token` | no | `DELVE_DOGFOOD_TOKEN`; left out when missing or empty |

Values must be single lines without `"` or `\` (they are written inside
double quotes in the env file); errors name keys, never values.

## Configuration (`DelveConfig`)

The role's variables without the `delve_` prefix; defaults follow its
`defaults/main.yml`.

| Field | Default | Notes |
|---|---|---|
| `binary_path` | required | the built binary on the controller |
| `service_name`, `user`, `group` | `delve` | |
| `site_path` | `/opt/delve` | the role's `install_dir`; the binary is `<site_path>/delved` |
| `data_dir`, `config_dir` | `/var/lib/delve`, `/etc/delve` | env file `<config_dir>/delve.env` |
| `listen_address`, `port` | `127.0.0.1`, `10026` | |
| `public_url`, `traefik_host` | `https://delve.example.com`, `delve.example.com` | |
| `traefik_enabled`, `traefik_entrypoints`, `traefik_cert_resolver` | `true`, `("web-secure",)`, `""` | empty resolver: `tls: {}` |
| `admin_emails`, `apple_client_id`, `env` | `""` | left out of the env file when empty |
| `apple_server_notifications`, `profile_legacy_reregister`, `apple_signin_legacy_no_nonce` | `None` | `None` leaves the variable out (the role's empty string); notifications need `apple_client_id` |
| `storekit_root_certs_path` | `None` | a host path enables StoreKit; then `storekit_bundle_id` and `storekit_product_ids` are required |
| `storekit_root_certs_src` | bundled Apple Root CA - G3 PEM | |
| `discovery_collector_timer_enabled`, `discovery_collector_timer_state` | `false`, `started` | |
| `discovery_collector_calendar`, `discovery_collector_randomized_delay_sec` | `*-*-* 03,15:17:00`, `3600` | |
| `discovery_collector_concurrency` | `2` | 2-8 |
| `discovery_poll_interval_seconds`, `discovery_poll_jitter_seconds` | `43200`, `3600` | interval 6-24 h |
| `discovery_episode_ttl_seconds`, `discovery_max_items_per_feed`, `discovery_max_sources_per_run` | `7776000`, `100`, `100` | items ≤ 500, sources ≤ 100 |
| `systemd_nofile` | `65536` | |
| `healthcheck_enabled`, `healthcheck_timeout`, `healthcheck_retries` | `true`, `30`, `10` | |
| `public_health_check` | `false` | also check `/health` through Traefik (see below) |
| `packages` | `("ca-certificates",)` | |

The role's `delve_service_enabled`/`delve_service_state` are not ported: the
service is always enabled and started.

## What the deploy does

1. `ca-certificates`, and `curl` for the read-only checks (apt cache
   refreshed when older than an hour).
2. Group and system user (`/usr/sbin/nologin`, home `data_dir`, not created
   by `useradd`); `data_dir` `delve:delve 0750`, `site_path` `root:root 0755`,
   `config_dir` `root:delve 0750`.
3. The binary as `root:root 0755`. New bytes are uploaded next to it and
   renamed over the old file: writing into a running executable fails with
   `ETXTBSY`, and pyinfra's `files.put` writes in place.
4. With StoreKit, the PEM as `root:delve 0644`.
5. `delve.env` (`root:delve 0640`) through `secret_file`.
6. `delve.service`, the collector `.service` and `.timer`; systemd is
   reloaded when a unit changed; the timer is enabled and started only when
   configured, otherwise disabled and stopped.
7. The Traefik route `/etc/traefik/dynamic/delve.yml` from the role's own
   template. Traefik is not restarted: the role's `reload traefik` handler
   fails on a unit without `ExecReload` and is ignored, and the file
   provider's watcher applies the route.
8. `delve` enabled and started; restarted when the binary, the PEM, the env
   file or the unit changed (not right after this run started it).
9. Read-only checks: the port opens, `GET /health` answers 200 with
   `"status": "ok"`. With `public_health_check`, the same through Traefik on
   the host (`curl --resolve <traefik_host>:443:127.0.0.1`, TLS verified):
   the playbook's post-deploy smoke gate ran this from the controller.

The unit, env and route files are byte-identical to the role's, including its
`# Managed by Ansible (delve_deploy)` header (`tests/test_delve_parity.py`), so
switching between the tools rewrites nothing and restarts nothing. Neither
tool touches the database.

## Tests

- `tests/test_delve_parity.py`: rendered files against the vendored role
  templates for the role defaults, the ops-control playbook's settings and
  every optional branch.
- `tests/test_delve.py`: fake connector runs (first run, converged no-op,
  binary/PEM/secret/unit/collector/route changes, staged binary rename,
  secrets never recorded, the role's validations, the build command).
- `tests/smoke/test_delve_smoke.py`: needs the Delve backend source
  (`DELVE_SOURCE_PATH`, else `$PROJECTS_ROOT/podcast/apps/delve-backend`) and
  Go. Four runs on the smoke VM: first, converged, a rebuilt binary (no-op),
  and a changed binary over the running one (install + restart).
