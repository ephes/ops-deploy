# os_lifecycle

A read-only OS lifecycle report for every Debian or Ubuntu host, the way it
reaches Nyxmon, and the Nyxmon checks that watch it. Native to ops-deploy (no
Ansible role behind it). The report answers:

- how long the installed release is supported (regular support, final end of
  life), whether a newer stable release exists and whether an upgrade is due;
- how many security updates are pending and how old the oldest one is, how
  old the security package index is, which packages are held;
- whether unattended-upgrades is installed and enabled, and when it last ran
  successfully;
- whether a reboot is required (marker file or a newer installed kernel than
  the running one), since when, and the uptime.

Nothing on the host is changed by the report. `apt-get` only simulates
(`-s`, `Debug::NoLocking=1`, package caches disabled), and the collector unit
runs with `ProtectSystem=strict`, writing only its state directory.

```python
from ops_deploy.services.os_lifecycle import (
    OsLifecycleChecksConfig,
    OsLifecycleConfig,
    Thresholds,
    deploy_os_lifecycle,
    deploy_os_lifecycle_checks,
    endpoint_rules,
    lifecycle_check,
    remote_rules,
)

snapshot = {"fetched_at": "2026-10-22", "debian": [...], "ubuntu": [...]}  # endoflife.date, trimmed

# A host on the monitoring network: collector + endpoint (and here also the remote pull).
monitor = OsLifecycleConfig(
    secrets="secrets/example.yml",  # endpoint_password, collector_ssh_private_key
    host_label="monitor",
    exposure="endpoint",
    reboot_class="A",
    auth_user="nyxmon",
    endoflife=snapshot,
    remote={"hosts": [{"name": "web", "address": "web.example.invalid", "host_keys": ["ssh-ed25519 AAAA..."]}]},
)
deploy_os_lifecycle(monitor, secrets)

# A host that must not join that network: collector + a restricted SSH key, no listener.
web = OsLifecycleConfig(
    host_label="web",
    exposure="ssh",
    reboot_class="C",
    user="os-lifecycle",
    endoflife=snapshot,
    ssh={"public_key": "ssh-ed25519 AAAA..."},
)
deploy_os_lifecycle(web, None)

# On the Nyxmon host: one json-metrics check per host.
checks = OsLifecycleChecksConfig(
    secrets="secrets/example.yml",
    checks=[
        lifecycle_check(
            service_name="OS lifecycle",
            name="OS Lifecycle (monitor)",
            url="http://monitor.example.invalid:9113/.well-known/os-lifecycle",
            rules=endpoint_rules(Thresholds()),
            auth_username="nyxmon",
        ),
        lifecycle_check(
            service_name="OS lifecycle",
            name="OS Lifecycle (web)",
            url="http://monitor.example.invalid:9114/.well-known/os-lifecycle-remote",
            rules=remote_rules(Thresholds(), "web"),
            auth_username="nyxmon",
        ),
    ],
)
deploy_os_lifecycle_checks(checks, secrets)
```

## What is installed

| Path | Owner, mode | Purpose |
|---|---|---|
| `/usr/local/lib/os-lifecycle/os_lifecycle_status.py` | `root 0644` | the status script (`collect`, `show`), run with `python3 -I` |
| `/etc/os-lifecycle/policy.json` | `root 0644` | host label, reboot class, horizon, tolerance, the endoflife.date snapshot |
| `/var/lib/os-lifecycle/state.json` | `root:<group> 0640` | the report, written atomically by the collector |
| `/var/lib/os-lifecycle/pending-security-seen.json` | `root 0600` | when each pending security or third-party update was first seen |
| `os-lifecycle-collector.service` / `.timer` | | hourly (`OnCalendar=hourly`, 10 min jitter, `Persistent=true`, 5 min after boot) |

Packages: `python3` and `distro-info-data` (the primary lifecycle source),
plus `apache2-utils` (`htpasswd`) for an endpoint.

Unit names (`os-lifecycle-collector`, `os-lifecycle-endpoint`,
`os-lifecycle-remote-endpoint`, `os-lifecycle-pull`) and the configuration
directory `/etc/os-lifecycle` are fixed, not configurable: a later deploy
finds whatever an earlier one created (see
[Changing the exposure](#changing-the-exposure-or-dropping-remote)).

### `exposure: endpoint`

`os-lifecycle-endpoint.service` serves `state.json` at
`http://<bind>:9113/.well-known/os-lifecycle` with basic auth (realm
`os-lifecycle`, `/etc/os-lifecycle/htpasswd`, `root:<group> 0640`, bcrypt;
rewritten only when the password does not verify). `bind` is an IPv4 address
or `tailscale` (the address `tailscale ip --4` prints; one address or the
deploy stops). The unit accepts only `localhost` and `100.64.0.0/10`.

The HTTP server is metrics-httpd's `json-file` mode through the shared
[metrics-httpd switch](metrics_httpd.md) (`httpd_impl`, reused unchanged) or
the Python fallback `os_lifecycle_httpd.py` with the same command line and
answer (a `meta` object with `age_seconds` of the file). With `httpd_impl:
python` the pinned Rust release is not installed or checked: this service
never stages metrics-httpd ahead of the fleet's own rollout.

`remote` (only on an endpoint host): `os-lifecycle-pull.timer` (hourly) runs
`os_lifecycle_pull.py`, which opens one SSH session per remote host with the
collector key `/etc/os-lifecycle/collector_ed25519` (`root 0600`, from the
secret `collector_ssh_private_key` via `secret_file`), trusting only the
pinned host keys (`/etc/os-lifecycle/known_hosts`, alias
`os-lifecycle-<name>`, `StrictHostKeyChecking=yes`, no agent, no forwarding,
no command sent). The combined file `remote.json` is served by
`os-lifecycle-remote-endpoint.service` on port 9114,
`/.well-known/os-lifecycle-remote`:

```json
{"schema_version": 1, "generated_at_epoch": 0,
 "hosts": {"web": {"pull_ok": true, "pull_error": null, "last_attempt_epoch": 0,
                   "last_pull_success_epoch": 0, "last_pull_success_age_hours": 0.0,
                   "report_age_hours": 0.4, "report": {"schema_version": 1, "host": "web", "...": "..."}}}}
```

A failed pull keeps the last good report next to `pull_ok: false` and the
error; a report that is not schema 1 or names another host is refused.

### `exposure: ssh`

No listener. The reading account (`user`, e.g. `os-lifecycle`, shell
`/bin/sh` because sshd runs a forced command through it, home
`/var/lib/os-lifecycle-ssh`) gets a root-owned `.ssh/authorized_keys` with a
single line:

```
restrict,command="/usr/bin/python3 -I /usr/local/lib/os-lifecycle/os_lifecycle_status.py show --state-dir /var/lib/os-lifecycle" ssh-ed25519 AAAA... os-lifecycle-collector
```

`restrict` turns off forwarding, PTY, agent and X11; the forced command
ignores whatever the client asks for (`SSH_ORIGINAL_COMMAND`) and prints the
cached report. `ssh.from_sources` adds a `from="..."` list when the
collector's source addresses are fixed. An existing account with another
shell, home or primary group is refused, not changed, and so is a host that
still has units or secrets of the endpoint exposure (below): no listener
stays behind.

### Changing the exposure or dropping `remote`

Before any change, a deploy refuses a host that keeps parts of a mode its
configuration leaves. Because the names are fixed, they are found whatever
else changed in between (`script_dir`, `site_path`, ports):

| Configuration | Refused while the host keeps |
|---|---|
| `exposure: ssh` | `os-lifecycle-endpoint.service`, `os-lifecycle-remote-endpoint.service`, `os-lifecycle-pull.service` / `.timer`, `/etc/os-lifecycle/htpasswd`, `/etc/os-lifecycle/collector_ed25519` |
| `exposure: endpoint` without `remote` | `os-lifecycle-remote-endpoint.service`, `os-lifecycle-pull.service` / `.timer`, `/etc/os-lifecycle/collector_ed25519` |

A unit counts while systemd knows it in any state other than `not-found` and
`inactive` (loaded, masked, failed, or still running after its unit file was
removed) or while its unit file exists in `/etc/systemd/system`; a file
counts while it exists (a dangling symlink too). A probe without a complete
answer (`systemctl` failing) refuses as well. Switching an endpoint host to
`ssh`, on the host:

```sh
systemctl disable --now os-lifecycle-endpoint.service os-lifecycle-remote-endpoint.service os-lifecycle-pull.timer
systemctl stop os-lifecycle-pull.service
cd /etc/systemd/system
rm -f os-lifecycle-endpoint.service os-lifecycle-remote-endpoint.service os-lifecycle-pull.service os-lifecycle-pull.timer
rm -rf os-lifecycle-endpoint.service.d os-lifecycle-remote-endpoint.service.d
rm -f /etc/os-lifecycle/htpasswd /etc/os-lifecycle/collector_ed25519 /etc/os-lifecycle/remote-hosts.json /etc/os-lifecycle/known_hosts
systemctl daemon-reload
systemctl reset-failed 'os-lifecycle-*'
```

Dropping `remote` from an endpoint host is the same without the
`os-lifecycle-endpoint` unit and `htpasswd`. The other direction (`ssh` to
`endpoint`) is not refused: the account's key can only print the report that
the endpoint then serves anyway; remove the account and its home when the
host leaves `ssh`.

## The report (`schema_version` 1)

```json
{"schema_version": 1, "host": "web", "generated_at_epoch": 0, "generated_at": "...",
 "os": {"id": "debian", "cycle": "12", "codename": "bookworm", "support_end": "2026-07-11",
        "eol": "2028-06-30", "support_days_remaining": -103, "eol_days_remaining": 617,
        "phase": "extended", "latest_stable_cycle": "13", "releases_behind": 1,
        "releases_behind_data": 1, "archive_suite": "oldstable", "upgrade_due": true, "release_upgrade_available": true, "lifecycle_source": "distro-info",
        "lifecycle_sources_agree": true, "lifecycle_data_age_days": 12},
 "apt": {"security_index_age_hours": 5.0, "pending_total": 3, "pending_security_count": 0,
         "pending_security_max_age_hours": 0, "pending_security": [], "pending_third_party_count": 1,
         "pending_third_party_max_age_hours": 26.0,
         "pending_third_party": ["vector 0.60.0-1 (apt.vector.dev)"], "held": []},
 "uu": {"installed": true, "enabled": true, "periodic_value": "1", "last_success_epoch": 0,
        "last_success_age_hours": 9.0, "last_run_epoch": 0, "last_result": "ok", "service_result": "success"},
 "reboot": {"required": true, "reasons": ["stale_kernel"], "required_age_hours": 40.0, "packages": [],
            "running_kernel": "...", "newest_installed_kernel": "6.1.0-40", "kernel_check": "compared", "uptime_days": 540.0,
            "boot_epoch": 0, "reboot_class": "C"},
 "errors": []}
```

- **Lifecycle:** `distro-info-data` on the host first (Debian `eol` is the end
  of regular support, `eol-lts` the final end; Ubuntu `eol`/`eol-server` is
  both), the policy's endoflife.date snapshot when the host has no entry.
  `lifecycle_sources_agree` is true when both have the cycle and their dates
  differ by at most `lifecycle_tolerance_days` (default 31: Debian's security
  end and its last point release are a month apart).
  `latest_stable_cycle` is the newest released cycle in either source (Ubuntu:
  LTS only). `releases_behind` counts the released stable cycles newer than
  the host's: a cycle counts from its release day (release date on or before
  the report's UTC date). On Debian it is at least what the archive itself
  says (`archive_suite`): the Release file of the host's codename in apt's
  lists (`Origin` and `Label` `Debian`) says `stable`, then `oldstable` (1)
  or `oldoldstable` (2) from the day the next release is out, before any
  lifecycle data is refreshed (the daily `apt-daily` index refresh brings it
  in). `releases_behind_data` is the count from the lifecycle data alone;
  `archive_suite` is `null` without such a file (or on Ubuntu). `upgrade_due`: Debian once regular support has ended, Ubuntu
  within `upgrade_horizon_days` (365) of its end. `phase`: `standard`,
  `extended` (LTS/after regular support), `eol` or `unknown`.
- **Security updates:** the `Inst` lines of the simulation whose origin is a
  `*-security` suite (Ubuntu) or `Debian-Security`. Their age comes from the
  first-seen file; an update that is no longer pending is forgotten. The
  index age is the newest `*security*InRelease` under `/var/lib/apt/lists`.
- **Third-party updates:** `Inst` lines none of whose origins is the
  distribution's own (`Debian`, `Debian-Security`, `Ubuntu*` labels): vendor
  repositories (Vector's prints only its site, `apt.vector.dev`, having no
  `Label`), Docker, PGDG, and backports. unattended-upgrades never takes them.
  `pending_third_party` lists them with their origins; their age comes from
  the same first-seen file as the security updates.
- **unattended-upgrades:** `enabled` is `APT::Periodic::Unattended-Upgrade`
  (from `apt-config dump`) set and not `0`, with the package installed.
  `last_success_*` is the mtime of `unattended-upgrades-stamp`, which
  `apt.systemd.daily` only touches after a successful run. `last_result` is
  the last run's block in `unattended-upgrades.log` (`error` if it logged an
  `ERROR`).
- **Reboot:** `/var/run/reboot-required` or a newer installed `linux-image-*`
  than the running kernel (the same comparison as `os_apt_maintenance`; a
  deliberately pinned older kernel therefore reports `stale_kernel`). The age
  is the marker's mtime or the newest kernel's dpkg `.list` mtime.
  `kernel_check` says whether the kernels were compared (`compared`) or why
  not: `no-dpkg-kernels` (`dpkg-query` matched no `linux-image-*`, a kernel
  installed outside dpkg) or `no-version` (the running release has no
  version to compare). Any other `dpkg-query` failure makes the section
  unknown instead of reporting "no reboot".

A section whose probe fails is `null` and named in `errors`; every rule on
it then fails, so "unknown" is visible.

## Nyxmon rules (`checks.py`)

`Thresholds()` holds the defaults below; `endpoint_rules` prefixes `$`,
`remote_rules` `$.hosts.<name>.report` and adds the pull rules.

| Rule | Warning | Critical |
|---|---|---|
| `$.meta.age_seconds` (report/pull file fresh) | | not `< 7200` |
| `$.hosts.<name>.pull_ok` | `false` | |
| `$.hosts.<name>.last_pull_success_age_hours`, `.report_age_hours` | | `> 3` |
| `uu.enabled` (with `unattended_upgrades`) | | `false` |
| `uu.last_success_age_hours` (with `unattended_upgrades`) | `> 48` | `> 168` |
| `apt.security_index_age_hours` (with `security_index`) | `> 48` | `> 168` |
| `apt.pending_security_max_age_hours` | `> 72` | `> 168` |
| `reboot.required_age_hours` | `> 168` | `> 504` |
| ... with `reboot_window` (host reboots itself) | `> 192` | `> 360` |
| `reboot.uptime_days` | `> 120` | `> 240` |
| `apt.pending_third_party_max_age_hours` (with `third_party_updates`) | `> 720` | |
| `os.upgrade_due` (without `track_latest_stable`) | `true` | |
| `os.support_days_remaining` (without `track_latest_stable`) | `< 365` | |
| `os.releases_behind` (with `track_latest_stable`) | `> 0` (or `null`) | |
| `os.eol_days_remaining` | `< 180` | `< 60` |
| `os.lifecycle_sources_agree` | `false` | |
| `os.lifecycle_data_age_days` (snapshot age) | `> 120` | |

`track_latest_stable` is for hosts that always run the newest stable release:
the warning starts on the day a newer stable cycle is released, with no grace
period, and replaces the two planning rules on the support horizon; the EOL
deadlines stay as a backstop. `third_party_updates` warns once a pending
third-party update is older than 30 days (`pending_third_party_warning_hours`):
one missed monthly maintenance pass. Shorter would keep the check yellow after
every release of a tool with a monthly cadence (Vector); there is no critical
level, since such an update can need a configuration change and is never
automatic.

`lifecycle_check` wraps the rules into a `JsonMetricsCheck` (interval
1800 s, timeout 15 s, one retry). `deploy_os_lifecycle_checks` upserts each
check as the Nyxmon user with the shared json-metrics upsert
(`services._nyxmon_json_metrics`): the login travels only on stdin, a current
row is left alone.

## Configuration

`OsLifecycleConfig`: `host_label` (lower-case, digits, `_`; the report's
`host`), `exposure` (`endpoint` | `ssh`), `reboot_class` (`A` | `B` | `C`,
reported only), `endoflife` (`fetched_at` and the trimmed `debian`/`ubuntu`
cycle lists: `cycle`, `codename`, `releaseDate`, `support`, `eol`, `lts`),
`upgrade_horizon_days` (365), `lifecycle_tolerance_days` (31), `user`
(`metrics`), `group` (the user's), `site_path` (`/var/lib/os-lifecycle`),
`script_dir` (`/usr/local/lib/os-lifecycle`), `packages`; for `endpoint`:
`bind`, `port` (9113), `path`, `auth_user`, `httpd_impl` /
`httpd_rust_version` / `httpd_rust_sha256`, `remote` (`hosts` with `name`,
`address`, `port` 22, `user` `os-lifecycle`, `host_keys`; `port` 9114,
`path`, `timeout` 60); for `ssh`: `ssh` (`public_key`, `from_sources`,
`home`, `key_comment`). `service_name` can only be `os-lifecycle-endpoint`;
the other unit names and `/etc/os-lifecycle` are not configurable.

## Tests

`tests/test_os_lifecycle_scripts.py` runs the status script on fixture
`os-release`, distro-info CSVs, Debian Release files (the archive suite,
foreign origins and mirrors), a newer stable cycle the day before and on its
release day, `apt-get -s` output (Debian and Ubuntu, third-party origins), the
unattended-upgrades log and dpkg kernel lists in a fixture root; the pull
with a fake SSH (success, refusals, keeping the last good report); the
fallback server over HTTP. `tests/test_os_lifecycle.py` covers config
refusals, the rules (also evaluated on reports as Nyxmon does: the latest-stable
rule before and on the release day, the third-party age), the rendered files and the plans on the fake connector
(fresh, converged, key handling, the SSH account, the refusals of a host
that keeps parts of another mode, the checks upsert), and runs the leftover
probe on a real shell with a stand-in `systemctl`.
