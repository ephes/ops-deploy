# gotosocial

Port of the `gotosocial_deploy` Ansible role (deploy only), checked against
ops-library main `540ede2b` (2.56.0): [GoToSocial](https://docs.gotosocial.org/)
from a pinned upstream release, SQLite and local media storage under
`/var/lib/gotosocial`, the role's hardened systemd unit, a loopback listener,
the `gotosocial-admin` wrapper and a public Traefik route. Backup, restore and
removal stay with the Ansible roles.

```python
from pydantic import SecretStr
from ops_deploy.services.gotosocial import GotosocialConfig, deploy_gotosocial

cfg = GotosocialConfig(
    host="fedi.example.org",  # the DNS name GoToSocial is served on
    account_domain="example.org",  # handles are @user@example.org
    traefik_cert_resolver="letsencrypt",
)
deploy_gotosocial(cfg)  # or deploy_gotosocial(cfg, SecretStr(smtp_password))
```

The config is a `RoleConfig` (no secrets file of its own). The optional SMTP
password is the deploy's second argument; ops-control reads it from an
optional SOPS file, as its playbook does (see its `docs/PYINFRA.md`).

## Configuration (`GotosocialConfig`)

Fields are the role's `gotosocial_*` variables without the prefix, with the
role's defaults (`tests/test_gotosocial_parity.py` compares them with
`defaults/main.yml` when `OPS_LIBRARY_PATH` is set).

| Field | Default | Notes |
|---|---|---|
| `host` | required | lower-case DNS name (the role's pattern); the role's `CHANGEME` fails it |
| `account_domain` | `""` | handle domain; empty means `host`. `host` must equal it or be a subdomain of it |
| `allow_domain_layout_change` | `false` | only for a wiped data directory (see below) |
| `version`, `release_checksums` | `0.22.2`, amd64 + arm64 | `X.Y.Z` and `sha256:<64 hex>`; bump together |
| `download_base_url` | Codeberg releases | http(s), no credentials, query or trailing slash; the archive is always checksum-verified |
| `user`, `group`, `service_name` | `gotosocial` | |
| `install_root`, `config_dir`, `data_dir` | `/opt/gotosocial`, `/etc/gotosocial`, `/var/lib/gotosocial` | the role's derived paths (`releases/<version>`, `current`, `config.yaml`, `sqlite.db`, `storage`, `.cache`, `.ops-domain-layout`) follow from them |
| `admin_wrapper_path` | `/usr/local/sbin/gotosocial-admin` | |
| `bind_address`, `port` | `127.0.0.1`, `10070` | loopback only (`127.0.0.1` or `::1`), port 1025-65535 |
| `trusted_proxies` | `127.0.0.1/32`, `::1` | IP addresses or networks |
| instance settings | role defaults | `application_name`, `landing_page_user`, `instance_languages`, `accounts_registration_open`, `instance_expose_public_timeline`, `instance_robots_allow_indexing`, `media_remote_cache_duration`, `cache_memory_target`, `log_level`, `log_client_ip` |
| `smtp_host`, `smtp_port`, `smtp_username`, `smtp_from` | disabled, `587` | `smtp_from` is required when `smtp_host` is set |
| `extra_config` | `{}` | merged over the rendered settings (recursively, as `combine(recursive=True)`); keys containing `password`, `secret` or `key` and the role's guarded keys (`GUARDED_CONFIG_KEYS`: host, account-domain, protocol, listener, trusted proxies, database, storage, Let's Encrypt, web asset paths, registrations) are refused |
| `packages` | `ca-certificates`, `sqlite3`, `tar` | |
| `service_enabled`, `service_state` | `true`, `started` | `stopped` prepares an instance without running it |
| `systemd_memory_max` | `1G` | empty removes the limit |
| `traefik_enabled` | `true` | `false` removes the route file |
| `traefik_host` | `host` | |
| `traefik_entrypoints`, `traefik_http_entrypoint` | `web-secure`, `web` | non-empty plain names |
| `traefik_cert_resolver`, `traefik_middlewares` | `""`, none | empty resolver: `tls: {}` |
| `traefik_config_path` | `/etc/traefik/dynamic/gotosocial.yml` | |
| `healthcheck_enabled`, `healthcheck_retries`, `healthcheck_delay` | `true`, `30`, `2` | |

Not configurable, unlike in the role: the derived paths one by one (they
follow the three roots), `gotosocial_guarded_config_keys` and
`gotosocial_download_url`. Values that land unquoted in the unit, the
wrapper (a `sh` script) or the route are restricted to characters those
files carry safely (paths, names, the memory limit); text settings must be
single lines. Every check runs when the config is built, before any
connection; errors never quote the value.

## What the deploy does

The role's task files, in the role's order:

1. Renders `config.yaml`, the unit, the wrapper and the route on the
   controller; requires Linux with systemd and a release checksum for the
   host architecture (`uname -m`: `x86_64` -> `amd64`, `aarch64` -> `arm64`).
2. **Domain layout guard** (`layout.yml`), while planning: reads
   `<data_dir>/.ops-domain-layout` as raw bytes (like `slurp`) and refuses the
   deploy when it records another `"<host> <account-domain>"` pair than the
   one asked for (both sides trimmed, as the role compares them), unless
   `allow_domain_layout_change`. A missing marker passes (first deploy, or an
   instance deployed before the guard). The refusal names both pairs and
   happens before any operation, so nothing changes at all.
3. Packages (`packages.yml`): `apt` install (with the role's cache refresh
   when older than an hour) of the ones `dpkg` does not list as installed.
4. `user.yml`: system group and user (`/usr/sbin/nologin`, home
   `data_dir`, no home created; like `ansible.builtin.user`, an existing
   user's shell, home and primary group are set to these), the install
   root and `releases/` (`root:root 0755`), the config directory
   (`root:<group> 0750`) and the data, storage and cache directories
   (`<user> 0700`).
5. `binary.yml`: when `releases/<version>/gotosocial` does not exist, a
   host-side installer (`files/release_host.py`, `python3 -I`) downloads the
   archive, checks its sha256, unpacks it with `tar --no-same-owner` in a
   private staging directory below `releases/` and renames the tree into
   place (`root:root 0755`). A present release is never downloaded again.
   Then `current` -> `releases/<version>` and the admin wrapper
   (`root:root 0750`).
6. `config.yml`: `config.yaml` (`root:<group> 0640`) through
   [`secret_file`](../concepts/helpers.md), so the SMTP password travels
   only on stdin.
7. `systemd.yml`/`service.yml`: the unit; `daemon-reload` when it changed
   or systemd reports a reload owed; enable (or disable); then started:
   start if not running, restart when the `current` link, `config.yaml` or
   the unit changed (never right after the start), or stopped.
8. `health.yml`: `GET /readyz` on the listener (30 tries, 2 s apart) when
   the service is started and `healthcheck_enabled`: a read-only operation
   that runs `files/ready_host.py` with `python3 -I`, like the role's
   `uri` (the host needs no curl).
9. `layout_record.yml`: writes `"<host> <account-domain>\n"` to the marker
   (`root:root 0644`); unchanged content is not rewritten.
10. `traefik.yml`: the route (`root:root 0644`) in its directory
    (`root:root 0755`), or removes it when routing is disabled.

A converged host (whether the role or this deploy wrote it) gets read-only
probes and the readiness check only.

## The domain layout guard

GoToSocial cannot change `host`/`account-domain` once it has federated:
remote servers cache the mapping, and the instance actor and its keys are
bound to it. The marker records the pair of the first deploy. The guard is
the role's: same file, same content, same comparison, same override, the
record written after the health check. Two cases refuse here where the role
would not:

- a marker that exists but is not a regular file (a directory, any symlink):
  the role's `slurp` fails, so its guard passes and the role fails later
  when it records the layout; here the deploy stops before anything changes,
  also with `allow_domain_layout_change`;
- a failing probe (the host cannot answer) stops the deploy instead of
  reading as "no marker".

## Parity with the role

`tests/test_gotosocial_parity.py` renders the four shipped templates (the
role's, byte for byte, also vendored under `tests/parity/ansible`) and
compares them with files **Ansible itself rendered** from the role for three
input sets (`tests/parity/gotosocial_deploy/<case>/`, ansible-core 2.21): the
defaults, a full set (SMTP, nested `extra_config`, languages, middlewares,
no memory limit, another route host) and an IPv6 listener with other users
and roots. They must be byte-identical: `config.yaml` is Ansible's
`to_nice_yaml(indent=2, sort_keys=True)` over the role's settings merged with
`extra_config`, including the template module's final-newline handling.
`tests/parity/ops_library_roles.json` records `gotosocial_deploy` at
`540ede2b`.

Differences, all on the side of changing less:

- Packages are only installed (and the apt cache only refreshed) when one is
  missing; the role refreshes an hour-old cache on every run.
- The release is unpacked in a staging directory and renamed into place; an
  interrupted run leaves no release directory that looks installed. An
  existing release directory without the binary is refused, not unpacked
  over (review it, then remove it). The role downloads to a fixed name in
  `/tmp`.
- Traefik is never reloaded: its file provider watches the directory. The
  role's `reload traefik` handler ignores its own failure.
- GoToSocial is also restarted when `config.yaml`, the unit or the `current`
  link is newer than the running process: an earlier run that wrote one of
  them and failed before its restart. The role loses that restart with its
  handlers. The read-only probe (`files/restart_host.py`) compares the files'
  nanosecond mtimes with the unit's `ActiveEnterTimestamp` in microseconds
  (`systemctl show --timestamp=us+utc`, systemd 248 or newer), so a write in
  the same second as the start still counts; a timestamp it cannot read
  fails the deploy while planning.
- The two stricter layout-guard cases above.

## Tests

- `tests/test_gotosocial.py`: fake-connector scenarios: first run (order,
  commands, uploads), converged host (no mutating operation), drift of each
  file (restart only for config, unit and link), a new version, the
  lost-restart probe (and its sub-second comparison), the Python readiness
  check, stopped/disabled states, every layout-guard case (a failing marker
  read fails the probe),
  disabled routing, the SMTP password only on stdin, the role's assertions,
  and the host-side installer (unpack, bad checksum, missing binary, partial
  or group-writable directories, fixed error messages).
- `tests/test_gotosocial_parity.py`: byte parity with Ansible's output and
  the role's defaults.
- `tests/test_gotosocial_docker.py`: a real install in an owned systemd
  container, skipped unless `GOTOSOCIAL_DOCKER_CONTAINER` holds the full ID
  of a running container named `ops-deploy-gotosocial-20261021`, labelled
  `ops-deploy.fixture=gotosocial-systemd` and
  `ops-deploy.run=gotosocial-20261021`, with `--network none`, not
  privileged, `--cgroupns private`, `SYS_ADMIN` as the only added
  capability, no mounts, ports or devices and systemd as PID 1. Built from
  `debian:trixie` with `systemd systemd-sysv python3 python3-apt ansible-core
  ca-certificates sqlite3 tar curl iproute2` and the checksum-verified
  release archive copied to `/srv/gts-release/v<version>/` (the test serves
  it on the container's loopback), `--tmpfs /run --tmpfs /run/lock`, an entry
  point that remounts its cgroup2 tree writable before `exec /sbin/init`
  (AppArmor unconfined). It covers the fresh install (file owners and modes,
  `/readyz`, a loopback-only listener, an account created with the wrapper
  and resolved through WebFinger), an actual second run without a mutating
  operation or restart, the refused layout change, drift and a lost restart
  (one restart each), and with `OPS_LIBRARY_PATH` the role and this deploy
  taking turns on one instance without a restart or a file change (and the
  role refusing a layout the deploy recorded).
