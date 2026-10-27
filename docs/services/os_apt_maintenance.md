# OS apt maintenance

`ops_deploy.services.os_apt_maintenance` ports the host-local maintenance runner,
weekly maintenance timer, daily index-refresh timer and authenticated state
endpoint from the `os_apt_maintenance` role. A separate Nyxmon deployment retains
the original orchestration playbook's check-update semantics.

```python
from ops_deploy.services.os_apt_maintenance import (
    OsAptMaintenanceConfig,
    deploy_os_apt_maintenance,
)

config = OsAptMaintenanceConfig(
    host_id="example-host",
    auth_user="nyxmon",
    secrets="secrets/example.yml",
)
# Prepared SecretValues must provide endpoint_password.
deploy_os_apt_maintenance(cfg=config, secrets=prepared_secrets)
```

## Ownership and repeat behavior

The deploy manages the maintenance/HTTP scripts, five systemd units, endpoint
credentials and account, the state directory's ownership and permissions, and
the endpoint implementation selection. Dependencies are installed as present;
it does not request package upgrades. It does not manage unattended-upgrades,
apt sources or `/etc/apt` security policy.

An existing `state.json` is retained. Missing state is initialized through the
runner's `--init-state`, then the original first-deploy maintenance run occurs
when `run_on_first_deploy` is true. `run_on_deploy` explicitly requests a run
even with existing state. A failure to determine whether state exists fails
before initialization or a maintenance run. Automatic reboot defaults to false.

Unlike the Ansible role's unconditional daemon reloads, systemd reloads only
when a unit or implementation drop-in changes. A changed timer restarts that
timer; changed endpoint code, credentials, unit or implementation restarts the
endpoint once. A converged host with existing state runs no apt maintenance and
requests no managed file change, daemon reload or restart. Disabling refresh
stops/disables its timer and removes its units. Setting `enabled=false` skips
host resource management while retaining the playbook's endpoint URL pre-task.

## Configuration

The defaults follow the orchestration playbook's weekly policy, rather than
the role's standalone daily-maintenance defaults.

| Fields | Defaults / purpose |
| --- | --- |
| `host_id`, `auth_user`, `secrets` | Required host identity, non-placeholder HTTP user and secret reference. |
| `enabled` | `true`; manage host resources. |
| `state_dir`, `state_file` | `/var/lib/os-apt-maintenance`; file defaults to `state_dir/state.json`. |
| `lock_file`, `script_path` | `/run/os-apt-maintenance.lock`, `/usr/local/sbin/os-apt-maintenance`. |
| `maintenance_service_name` | `os-apt-maintenance`. |
| `update_cache`, `dist_upgrade`, `autoremove`, `autoclean` | `true`; actions of the scheduled runner, not actions of a converged deploy. |
| `auto_reboot`, `run_on_deploy`, `run_on_first_deploy` | `false`, `false`, `true`. |
| `apt_get_path`, `systemctl_path` | `/usr/bin/apt-get`, `/usr/bin/systemctl`; explicit executable overrides also support owned fixtures. |
| `command_timeout`, `freshness_max_age_seconds` | `7200`, `1209600` seconds. |
| `timer_on_calendar`, `timer_randomized_delay_sec`, `timer_accuracy_sec` | `Sun *-*-* 04:00:00`, `4h`, `1h`. |
| `timer_enabled`, `timer_persistent`, `timer_state` | `true`, `true`, `started`. |
| `refresh_enabled`, `refresh_service_name` | `true`, `os-apt-maintenance-refresh`. |
| `refresh_timer_on_calendar`, `refresh_timer_randomized_delay_sec`, `refresh_timer_accuracy_sec` | `*-*-* 06:00:00`, `1h`, `10m`. |
| `refresh_timer_enabled`, `refresh_timer_persistent`, `refresh_timer_state` | `true`, `true`, `started`. |
| `refresh_command_timeout` | `900` seconds. |
| `service_name`, `bind`, `port`, `path` | `os-apt-maintenance-endpoint`, host's own `tailscale ip --4`, `9106`, `/.well-known/os-apt-maintenance`. |
| `user`, `group` | `metrics`; group defaults to user. |
| `server_path`, `htpasswd_dir`, `htpasswd_file` | `/usr/local/bin/os_apt_maintenance_httpd.py`, `/etc/os-apt-maintenance-endpoint`; credential file defaults to that directory's `htpasswd`. |
| `endpoint_timeout`, `endpoint_state_max_age_seconds` | `10`, `1296000` seconds. |
| `ip_allow` | `100.64.0.0/10`, with localhost allowed by the unit. |
| `maintenance_packages`, `packages` | `python3`; endpoint adds `apache2-utils`. |
| `httpd_impl`, `httpd_rust_version`, `httpd_rust_sha256` | Existing metrics-httpd Python/Rust selection and immutable release inputs. |

The optional `on_endpoint` callback receives the endpoint URL during planning,
after the host's bind is resolved. It permits orchestration to retain the
original pre-task fact even when later endpoint work fails.

## Nyxmon checks

`OsAptNyxmonConfig` and `deploy_os_apt_maintenance_nyxmon` accept a fixed-order
list of `{display_name, url}` targets. Defaults are user `nyxmon`, database
`/home/nyxmon/site/db.sqlite3`, service `OS package maintenance`, check interval
3600 seconds and auth user `nyxmon`. The secret is `endpoint_password`.

Only type, URL, interval and normalized data determine whether a named check
needs an update. A current manually disabled check remains disabled. A real
update re-enables it but preserves status, schedule and processing fields.
Missing checks begin idle; unrelated checks are untouched. No new 0600 guard or
processing refusal is introduced. An absent database skips provisioning as in
the playbook.

The comparison probe reads only the named checks and returns digests. Passwords
are sent only through masked stdin when an upsert is needed. Skipping an upsert
means zero managed row changes; SQLite reader bookkeeping is not a global
zero-I/O guarantee.

If an active refresh timer’s unit files have already been removed outside the
deploy, stopping it can succeed before systemd’s disable command reports a
missing unit. The role and port both tolerate that error; the combined pyinfra
operation may report failed/unchanged despite the physical stop. Ansible’s
unconditional reload and pyinfra’s conditional reload leave different cached
unit metadata in this damaged state. This is a separately recorded fault,
not a healthy zero-change repeat. Restoring the declared configuration recovers
the units; normal refresh disable and its repeat are qualified separately.

## Qualification status

Actual `ansible.builtin.template` output from ops-library
`cf3a0c74b10ed83a43fa79c4d1f3a57fffc89641` matches all seven rendered files in
weekly and custom cases, including timer booleans and newline behavior.
The immutable source/template hashes are retained with those fixtures.
The owned `os-apt-maintenance-integration` workflow exercises real systemd and
HTTP on Ubuntu 24 (Python) and Debian 13 userspace (pinned Rust binary, sharing
the Ubuntu runner kernel). Synthetic apt/reboot executables exercise the
runner's argument and state transitions without performing upgrades or reboots.
The harness includes strict repeats, credential/timer changes, Nyxmon ownership
and actual cf3 role coexistence. Its code and limits are documented in
`tests/integration/os_apt_maintenance/README.md`.

Native execution evidence and inventory rollout qualification are still pending.
