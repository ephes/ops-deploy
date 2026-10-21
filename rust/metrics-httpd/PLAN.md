# metrics-httpd: Rust port of the small Python HTTP endpoint daemons — plan

Status: plan, not yet implemented. Campaign "Rust-Ports Runde 2" (umbrella
item `rust-ports-campaign`), stream `rust-metrics-httpd`. Foundation (workspace,
CI, release, install helpers): `rust/PLAN-foundation.md` (slices F1–F4).

This document is the contract for replacing the family of small Python HTTP
servers that ops-library roles (and one ops-control role) deploy as
long-running systemd units, with one Rust binary `metrics-httpd`. It is
written for the implementers of the slices in section 11 and for the
reviewers of each slice. Every behavioural statement cites the Python code
that defines it; when this document and the Python code disagree, the Python
code wins and this document must be corrected — except where section 5 lists
an allowed difference.

Python is the oracle for the contract and the decisions, not for bytes: the
contract is status codes, header semantics, JSON documents (parsed), file
paths, permissions, users, units and logs as listed in section 4.

---

## 1. Live facts (read-only, 2026-10-21)

Gathered with `ssh root@<host>` and read-only commands (`ps`, `ss -ltnp`,
`systemctl show/cat`, `stat`, `/proc/<pid>/status`), plus the ops-library,
ops-control and ops-deploy sources at `origin/main` (ops-library `6b505fa1`,
ops-control `93368405`, ops-deploy `a017f56`). Bind addresses are written as
"TS" (the host's Tailscale IPv4) or "LAN" instead of the literal address.

### 1.1 Processes in scope (20 on 4 hosts)

Memory: `VmRSS` / `RssAnon` from `/proc/<pid>/status`, cgroup `MemoryCurrent`
from `systemctl show`. Every process is `/usr/bin/python3 <script>` with one
task (thread).

| Host | Unit | User | Listen | Path | Python script (source) | Mode (sec. 4) | VmRSS | RssAnon | cgroup |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| macmini | `metrics-endpoint` | metrics | TS:9100 | `/.well-known/health` | `/usr/local/bin/metrics_httpd.py` (`roles/metrics_endpoint/templates/metrics_httpd.py.j2`) | script | 17.1 MiB | 8.6 MiB | 11.6 MiB |
| macmini | `ddns-status-endpoint` | ddns | TS:9112 | `/.well-known/ddns` | `/usr/local/bin/ddns_status_httpd.py` (`roles/dns_deploy/files/ddns_status_httpd.py`) | json-file | 18.7 MiB | 10.1 MiB | 10.5 MiB |
| macmini | `dns-metrics-endpoint` | metrics | TS:9108 | `/.well-known/dns` | `/usr/local/bin/dns_metrics_httpd.py` (`roles/dns_metrics_endpoint/templates/dns_metrics_httpd.py.j2`) | json-file (meta merge) | 18.4 MiB | 10.3 MiB | 10.6 MiB |
| macmini | `tailscale-metrics-endpoint` | metrics | TS:9107 | `/.well-known/tailscale` | `/usr/local/bin/tailscale_metrics_httpd.py` (`roles/tailscale_metrics_endpoint/templates/…`) | json-file (path-only match) | 14.7 MiB | 6.6 MiB | 6.9 MiB |
| macmini | `thermal-metrics-endpoint` | metrics | TS:9104 | `/.well-known/thermal` | `/usr/local/bin/thermal_metrics_httpd.py` (`roles/thermal_metrics_endpoint/templates/…`; on macmini rendered by ops-deploy) | json-file | 16.2 MiB | 8.2 MiB | 8.5 MiB |
| macmini | `openclaw-metrics-endpoint` | metrics | 127.0.0.1:9104 | `/.well-known/openclaw-health` | `/usr/local/bin/openclaw_metrics_httpd.py` (`roles/openclaw_deploy/templates/openclaw-metrics-httpd.py.j2`) | json-file | 18.5 MiB | 10.6 MiB | 11.3 MiB |
| macmini | `os-apt-maintenance-endpoint` | metrics | TS:9106 | `/.well-known/os-apt-maintenance` | `/usr/local/bin/os_apt_maintenance_httpd.py` (`roles/os_apt_maintenance/templates/os_apt_maintenance_httpd.py.j2`) | apt-state | 15.6 MiB | 7.5 MiB | 7.9 MiB |
| macmini | `logyard-health-endpoint` | logyard | 127.0.0.1:9105 | `/.well-known/logyard` | `/usr/local/bin/logyard_health_httpd.py` (`roles/logyard_deploy/templates/logyard_health_httpd.py.j2`; rendered by ops-deploy) | logyard-health | 18.3 MiB | 9.0 MiB | 9.6 MiB |
| macmini | `torrent-vpn-metrics-endpoint` | metrics | TS:9102 | `/.well-known/vpn-egress` | `/usr/local/bin/torrent_vpn_metrics_httpd.py` (**ops-control** `roles/torrent_vpn_metrics_endpoint/templates/torrent_vpn_metrics_httpd.py.j2`) | json-file | 16.7 MiB | 8.5 MiB | 8.8 MiB |
| fractal | `storage-metrics-endpoint` | metrics | TS:9101 | `/.well-known/storage` | `storage_metrics_httpd.py` (`roles/storage_metrics_endpoint`) | json-file | 20.6 MiB | 10.1 MiB | 10.4 MiB |
| fractal | `backup-metrics-endpoint` | metrics | TS:9103 | `/.well-known/backup` | `backup_metrics_httpd.py` (`roles/backup_metrics_endpoint`) | json-file | 20.6 MiB | 10.2 MiB | 10.5 MiB |
| fractal | `thermal-metrics-endpoint` | metrics | TS:9104 | `/.well-known/thermal` | `thermal_metrics_httpd.py` | json-file | 20.6 MiB | 10.1 MiB | 10.4 MiB |
| fractal | `tailscale-metrics-endpoint` | metrics | LAN:9107 | `/.well-known/tailscale` | `tailscale_metrics_httpd.py` | json-file (path-only) | 20.6 MiB | 10.0 MiB | 10.3 MiB |
| fractal | `os-apt-maintenance-endpoint` | metrics | TS:9106 | `/.well-known/os-apt-maintenance` | `os_apt_maintenance_httpd.py` | apt-state | 20.5 MiB | 10.1 MiB | 10.4 MiB |
| staging | `tailscale-metrics-endpoint` | metrics | TS:9107 | `/.well-known/tailscale` | `tailscale_metrics_httpd.py` | json-file (path-only) | 20.2 MiB | 10.5 MiB | 10.8 MiB |
| staging | `os-apt-maintenance-endpoint` | metrics | TS:9106 | `/.well-known/os-apt-maintenance` | `os_apt_maintenance_httpd.py` | apt-state | 19.9 MiB | 10.3 MiB | 10.6 MiB |
| staging | `benchmarks-static` | benchmarks-static | 127.0.0.1:10061 (behind Traefik) | site root `/srv/benchmarks-static/site` | `/usr/local/libexec/benchmarks-static-httpd.py` (`roles/static_site_deploy/templates/static-site-httpd.py.j2`; rendered by ops-deploy) | static | 19.6 MiB | 9.8 MiB | 10.2 MiB |
| production | `metrics-endpoint` | metrics | TS:9100 | `/.well-known/health` | `metrics_httpd.py` | script | 20.1 MiB | 9.9 MiB | 11.0 MiB |
| production | `os-apt-maintenance-endpoint` | metrics | TS:9106 | `/.well-known/os-apt-maintenance` | `os_apt_maintenance_httpd.py` | apt-state | 20.6 MiB | 10.3 MiB | 11.0 MiB |
| production | `tailscale-metrics-endpoint` | metrics | TS:9107 | `/.well-known/tailscale` | `tailscale_metrics_httpd.py` | json-file (path-only) | 20.3 MiB | 10.0 MiB | 10.4 MiB |

Totals: macmini 9 processes, 154.0 MiB VmRSS / 85.7 MiB cgroup; fractal 5,
102.8 / 52.0 MiB; staging 3, 59.7 / 31.6 MiB; production 3, 61.1 / 32.4 MiB.
**Fleet: 20 processes, 377.6 MiB VmRSS, 201.7 MiB cgroup memory.** heis and
marina run none of them. About half of each VmRSS is file-backed (the
interpreter and its libraries); the anonymous part is ~6.5–10.5 MiB per
process.

Other facts:

- Hosts: macmini, fractal, production — Ubuntu 24.04.5, glibc 2.39, Python
  3.12.3; staging — Debian 13, glibc 2.41, Python 3.13.5; all `x86_64`.
- Every htpasswd file in scope has exactly one line and a bcrypt `$2y$` hash
  (scheme prefix checked only), mode `0640`, owner `root:<service group>`
  (`root:ddns` for DDNS, `root:metrics` otherwise).
- Every JSON file in scope is `0640 root:metrics` (DDNS: `0644 ddns:ddns`),
  ≤ 24 KB, and none contains a `NaN`/`Infinity` token.
- No unit in scope has a drop-in today.
- The JSON files are written by root (or `ddns`) **oneshot** timer services
  (`*-collector.service`, `ddns-update.service`, `os-apt-maintenance*.service`)
  as `… > f.tmp && mv f.tmp f` (atomic rename); the servers only read them.
  This privilege separation (root writer, unprivileged reader) stays.

### 1.2 Searched and out of scope

Searched: `grep -E 'http.server|BaseHTTPRequestHandler|ThreadingHTTPServer|serve_forever'`
over ops-library `roles/`, ops-control (`roles/`, `playbooks/`, `files/`,
`templates/`), ops-deploy `src/ops_deploy/services/`, and `ss -ltnp` for
every `python3` listener on all six Linux hosts. Besides the 20 above:

- `software-live-endpoint` (`roles/software_live/files/software_live.py
  serve`, port 9110, on macmini, fractal, staging, production): owned by the
  parallel stream `rust/software-live/PLAN.md`.
- `metube` (`/opt/metube/app/main.py`, 127.0.0.1:8083): an application, not
  an endpoint daemon.
- Molecule/test-only servers (`fastdeploy_restore`, `unifi_restore`,
  `mail_monitoring`, `ssh_restricted_forwarding_account` molecule files).
- `ops-control/scripts/experiments/vector_inventory_probe.py`,
  `smoke/nyxmon_coexistence.py`: tools, not deployed daemons.

### 1.3 Consumers of the endpoints

- Nyxmon json-metrics checks (JSONPath rules on the payload, e.g.
  `$.meta.age_seconds`; basic auth from the checks' data), upserted by the
  same playbooks/pyinfra modules that deploy the endpoints (e.g.
  `ops-control/pyinfra_support/macmini_monitoring.py` `CHECK_DATA`).
- Nyxmon maintenance suppression reads `os-apt-maintenance` (`suppression_url`
  in `ops-control/pyinfra_support/services.py` logyard config, `deploy-openclaw.yml`,
  `deploy-logyard-core.yml`); it reads `Content-Length` and
  `Content-Encoding` (`nyxmon/src/nyxmon/service_layer/notification_suppression.py`).
- Graphyard `http_json_metric` specs on macmini read fractal storage and
  thermal endpoints (`ops-control/inventories/prod/host_vars/macmini.yml`,
  `fractal_storage_metrics_url`, `fractal_thermal_metrics_url`) and macmini
  thermal (`macmini_thermal_metrics_url`).
- Traefik routes the static site (`static-site.traefik.yml.j2`).

All consumers are HTTP clients that parse JSON; none depends on the `Server`
header, the reason phrase or the byte layout of the JSON.

---

## 2. Deploy mechanism today (per unit)

All production deploys run from the controller under the shared deploy lock
(section 10.1). Engine per `ops-control/services-metadata.yml` at
`origin/main`:

| Unit(s) | Hosts | Engine | Entry point | Renders the unit |
| --- | --- | --- | --- | --- |
| `metrics-endpoint` | macmini, production (group `mail_monitoring`) | Ansible | `just deploy-one metrics_endpoint` → `playbooks/deploy-metrics-endpoint.yml` (also in `deploy-mail-monitoring.yml`) | ops-library `metrics_endpoint` |
| `ddns-status-endpoint` | macmini | Ansible | `playbooks/deploy-dns.yml --tags ddns` (`dns` service; the playbook's own `ddns` tag) | ops-library `dns_deploy` (`tasks/ddns.yml`) |
| `dns-metrics-endpoint` | macmini | Ansible | `ansible-playbook -i inventories/prod/hosts.yml playbooks/deploy-dns-monitoring.yml` (`docs/DNS_MONITORING_NYXMON_CHECKS.md`) | ops-library `dns_metrics_endpoint` |
| `tailscale-metrics-endpoint` | macmini, fractal, staging, production | Ansible | `just deploy-one tailscale [host]` → `playbooks/tailscale/deploy.yml` | ops-library `tailscale_metrics_endpoint` |
| `thermal-metrics-endpoint` | macmini | **pyinfra** (since 2026-10-20) | `just deploy-one macmini_monitoring` → `ops_deploy.services.thermal_monitoring` via `pyinfra_support/macmini_monitoring.py`; Ansible rollback `-e macmini_monitoring_ansible_rollback=true` | ops-deploy (renders the ops-library role templates byte-identically) |
| `thermal-metrics-endpoint`, `storage-metrics-endpoint`, `backup-metrics-endpoint` | fractal | Ansible | `just deploy-one fractal_monitoring` → `playbooks/deploy-fractal-monitoring.yml` | ops-library roles |
| `openclaw-metrics-endpoint` | macmini | Ansible | `playbooks/deploy-openclaw.yml` (entry point per `docs/OPENCLAW_RUNBOOK.md`) | ops-library `openclaw_deploy` (`tasks/metrics.yml`) |
| `os-apt-maintenance-endpoint` | fractal, macmini, staging, production (one play) | Ansible | `just deploy-one os_apt_maintenance` → `playbooks/deploy-os-apt-maintenance.yml` (all four hosts, no `-l`) | ops-library `os_apt_maintenance` |
| `logyard-health-endpoint` | macmini | **pyinfra** (`logyard_core`, `logyard`) | `just deploy-one logyard_core` → `ops_deploy.services.logyard` | ops-deploy (vendored `logyard_health_httpd.py`) |
| `torrent-vpn-metrics-endpoint` | macmini | Ansible | `just deploy-one torrent_vpn_metrics_endpoint` → `playbooks/torrent/deploy-vpn-metrics.yml` | **ops-control** `roles/torrent_vpn_metrics_endpoint` |
| `benchmarks-static` | staging | **pyinfra** (`benchmarks_static`) | `just deploy-one benchmarks_static` | ops-deploy `services/static_site` |

Deploys of role changes need the collection version that contains them:
ops-control installs ops-library from a local checkout and refuses mismatched
versions (`scripts/check-collection-version.py`), and `~/projects` is
read-only for agents, so deploy slices use a fresh ops-library worktree at
`origin/main` with `OPS_LIBRARY_PATH=<worktree> just install-local-library`.
pyinfra deploys use the ops-deploy commit pinned in ops-control
`requirements-ops-deploy.txt`.

The pyinfra migration is in progress (45/112 roles). Every switch and cutover
slice re-reads `services-metadata.yml` at its start; if a unit's engine changed
since this plan, the slice deploys through the new engine (and, if that means
an ops-deploy port that does not exist yet, stops and reports to the
coordinator instead of inventing a path).

---

## 3. Architecture decision: one binary, one process per endpoint unit

**Decision:** one binary `metrics-httpd` with one subcommand per endpoint
family (`json-file`, `script`, `apt-state`, `logyard-health`, `static`). Every
existing unit keeps its name, user, group, sandbox, IP filter, restart policy
and ordering; only its `ExecStart` changes, through a drop-in
(`metrics-httpd-impl.conf`) that is present iff the role selects Rust.

Rejected: one process per host serving all endpoints of the host.

| Criterion | Per-unit (chosen) | One process per host |
| --- | --- | --- |
| Privilege separation | kept: `ddns` reads only DDNS state, `logyard` only calls Loki/systemctl, `benchmarks-static` only reads its site, `metrics` the rest; per-unit `ReadOnlyPaths`, `IPAddressAllow`, `RestrictAddressFamilies`, `MemoryDenyWriteExecute` stay as they are | one user must read every JSON file and htpasswd file of every role (group juggling across `ddns`, `metrics`, `logyard`, `benchmarks-static`) and the sandbox is the union of all units' needs |
| Role independence | each role owns its unit and adds only a drop-in; roles deploy independently, through different engines (Ansible and pyinfra on the same host) | a host-level config must be assembled from 4–9 roles on two engines; every role deploy rewrites a shared config and restarts all endpoints of the host |
| Failure isolation | one endpoint's crash/restart loop does not affect others (today's behaviour) | one bug or one bad config takes all endpoints of the host down |
| Rollback | per endpoint (drop-in) | all or nothing per host |
| Memory | Rust ~1.5–3 MiB cgroup per process (goal, section 9) → ≤ 60 MiB fleet-wide; the binary's text pages are shared page cache across all processes of the same binary | ~5 MiB per host → ~20 MiB fleet-wide |
| Saving vs Python (201.7 MiB cgroup) | ≥ 140 MiB | ≥ 180 MiB |

The extra ~40 MiB fleet-wide of the per-unit design does not justify giving
up privilege separation, role independence and failure isolation.

One binary instead of one binary per family: the families share the server
core, auth, JSON and file handling (≥ 70 % of the code); one release, one pin
and one install directory per host. Per-endpoint parameters (bind, port,
path, htpasswd file, realm, error texts) are command-line flags in the
drop-in, as they are today in the Python units; no new config files.

---

## 4. Contract to preserve

### 4.1 Common HTTP behaviour (all modes except `logyard-health` and `static`)

Source: the eight json-file scripts, `metrics_httpd.py.j2`,
`os_apt_maintenance_httpd.py.j2` (citations below are for
`backup_metrics_httpd.py.j2` unless stated; the others are line-for-line the
same apart from the differences in the variant table 4.3).

1. Only `GET` is handled (`do_GET`, l.33). Any other method, including
   `HEAD`, gets **501** (BaseHTTPRequestHandler's "Unsupported method").
2. Path check first, before auth (l.35): the raw request-target must equal
   `--path` exactly (`self.path != cfg["path"]`), so a query string or an
   absolute-form target gives 404. Exception: the tailscale variant compares
   `urlsplit(self.path).path` (`tailscale_metrics_httpd.py.j2` l.24), i.e. it
   ignores query and fragment. Wrong path → **404** with the JSON error body
   of 4.2 (`not_found`, "Endpoint not found"); `metrics_endpoint` instead
   uses `send_error(404, "Not found")` (HTML body, `metrics_httpd.py.j2` l.18).
3. Auth second (l.38–47): `Authorization` must start with `Basic ` (case
   sensitive); the token is `header.split()[1]`, base64-decoded, UTF-8
   decoded, split at the first `:`; the password is verified against the
   htpasswd file for that user (`htpasswd -vi <file> <user>` with the
   password on stdin, l.131–138; `metrics_endpoint`: `htpasswd -vb` with the
   password in argv, l.66–70). Any failure (missing header, malformed,
   unknown user, wrong password, unreadable htpasswd file) → **401**, headers
   `WWW-Authenticate: Basic realm="<realm>"` and `Content-Length: 0`, empty
   body. The htpasswd file is consulted on every request (rotation without a
   restart works).
4. Responses carry `Content-Type: application/json` and a correct
   `Content-Length` (l.97–100); `Server` and `Date` headers exist.
5. HTTP/1.1 with keep-alive (`protocol_version = "HTTP/1.1"`, l.31).
6. Access log on stderr, one line per request: `<client ip> - - [<dd/Mon/YYYY
   HH:MM:SS local>] "<request line>" <status> -` (`log_message`, l.116–120,
   `log_date_time_string`). No credentials in any log line.
7. Bind: `--bind`/`--port`, `SO_REUSEADDR` (`allow_reuse_address`, l.168);
   IPv4 only except the dns variant (IPv6 if `:` in bind,
   `dns_metrics_httpd.py.j2` l.186–190). A bind failure exits non-zero
   (traceback) and systemd restarts after `RestartSec`.

### 4.2 Mode `json-file` (backup, storage, thermal, tailscale, dns, openclaw, ddns, torrent-vpn)

Request flow after 4.1 (`backup_metrics_httpd.py.j2` l.49–101):

1. `os.path.isfile(json_path)` false (missing, directory, broken symlink,
   `stat` denied) → **503** `{"error": true, "error_type":
   "metrics_file_missing", "message": <variant text>}`.
2. `generated_at_epoch = int(st_mtime)` (truncation), `served_at_epoch =
   int(now)`, `age_seconds = served − generated` (may be negative).
3. Read and parse as UTF-8 JSON. Parse error → **502** `error_type
   "invalid_json"`, message `"Invalid JSON in metrics file: <detail>"`;
   `OSError` → **503** `"read_error"`, `"Cannot read metrics file: <detail>"`.
4. `meta` (replace mode, all variants but dns): `data["meta"] =
   {"generated_at": <UTC ISO-8601 with "+00:00", seconds precision, e.g.
   "2026-10-21T10:00:00+00:00">, "generated_at_epoch", "served_at_epoch",
   "age_seconds"}` replacing any `meta` in the file. Merge mode (dns,
   `dns_metrics_httpd.py.j2` l.90–103): if the file's `meta` is an object, the
   four keys are set into it (other keys such as `collector_ipv6_capable`
   stay); otherwise it is replaced by an object with the four keys.
5. **200**, body `json.dumps(data, sort_keys=True)`: keys sorted at every
   level, separators `", "`/`": "`, non-ASCII escaped as `\uXXXX`.

Error bodies are `json.dumps({"error": true, "error_type": …, "message":
…})` (not sorted; key order error, error_type, message), `Content-Type:
application/json`.

### 4.3 Variant table (json-file and the others)

| Variant (unit) | realm | server_version | path match | meta | missing-file `error_type` / message | Python concurrency / timeout |
| --- | --- | --- | --- | --- | --- | --- |
| backup | `backup-metrics` | `backup-metrics-httpd/0.1` | exact | replace | `metrics_file_missing` / "Metrics file not found - timer may not have run yet" | single-threaded, none |
| storage | `storage-metrics` | `storage-metrics-httpd/0.1` | exact | replace | same | single, none |
| thermal | `thermal-metrics` | `thermal-metrics-httpd/0.1` | exact | replace | same | single, none |
| tailscale | `tailscale-metrics` | `tailscale-metrics-httpd/0.1` | **path-only** | replace | same | single, none |
| dns | `dns-metrics` | `dns-metrics-httpd/0.1` | exact | **merge** | same | threaded, 15 s (`dns_metrics_endpoint_request_timeout`), IPv6 |
| openclaw | `openclaw-metrics` | `openclaw-metrics-httpd/0.1` | exact | replace | `metrics_file_missing` / "Metrics file not found - collector timer may not have run yet" | single, none; htpasswd timeout 5 s |
| ddns | `ddns-status` | `ddns-status-httpd/0.1` | exact | replace | `metrics_file_missing` / "Status file not found - updater may not have run yet" | threaded, 10 s |
| torrent-vpn | `torrent-vpn-metrics` | `torrent-vpn-metrics-httpd/0.1` | exact | replace | `metrics_file_missing` / "Metrics file not found - timer may not have run yet" | threaded, 10 s |
| metrics_endpoint (script) | `metrics` | `metrics-httpd/0.1` | exact | — | — | single, none |
| os_apt (apt-state) | `os-apt-maintenance` | `os-apt-maintenance-httpd/0.1` | exact | replace + computed | `state_file_missing` / "Apt maintenance state file not found" | single, none; htpasswd timeout 5 s |

### 4.4 Mode `script` (`metrics_endpoint`, `metrics_httpd.py.j2` l.30–52)

After 4.1: run `--script` (no shell, no arguments, inherited environment,
working directory from the unit, `/usr/local/bin`) with `--script-timeout`
seconds. Timeout → **504** (`send_error(504, "Metrics script timeout")`).
Exit ≠ 0 → **502** (`send_error(502, stderr.strip() or "Metrics script
failed")`). Exit 0 → **200**, body = the script's stdout unchanged (no JSON
validation), `Content-Type: application/json`. The script itself
(`mail-metrics.sh.j2`) is unchanged and out of scope.

### 4.5 Mode `apt-state` (`os_apt_maintenance_httpd.py.j2`)

After 4.1 and the file steps of 4.2 (with `state_file_missing`, and the
messages "Invalid JSON in state file: …", "Cannot read state file: …"),
l.95–133, with `served`, `age_seconds` as in 4.2 and the two constants
`FRESHNESS_MAX_AGE_SECONDS` and `STATE_MAX_AGE_SECONDS` (template-baked,
l.17–18; flags `--freshness-max-age`, `--state-max-age` in Rust):

- `last_success_age_seconds = max(0, served − v)` iff `v =
  data.get("last_success_epoch")` is a Python `int` — **booleans count**
  (`isinstance(True, int)`), floats and strings do not; else `None`.
- `state_reboot_required = bool(data.get("reboot_required"))` (Python
  truthiness on any JSON value).
- `reboot_state(data, flag_present=os.path.exists("/var/run/reboot-required"),
  running_release=os.uname().release)` (l.22–53): `details =
  {"flag_present"}`; reason `reboot_required_flag` if the flag exists;
  reason `stale_kernel` iff `reboot_required_details` is an object, `"stale_kernel"
  in (persisted.get("reasons") or [])` (Python `in`: list element equality,
  substring for a string, key for an object) and `persisted["running_kernel"]
  == running_release`; then the keys `running_kernel`,
  `running_kernel_version`, `newest_installed_kernel` are copied when present;
  `required = bool(reasons)`, `reasons` list. The flag and `uname` are read
  per request.
- `state_file_fresh = age_seconds <= STATE_MAX`, `last_success_fresh =
  age is not None and age <= FRESHNESS_MAX`, `currently_running = last_status
  == "running"`, `last_run_ok = last_status == "success" or (running and
  fresh)`.
- Output: `data["meta"]` = the four keys of 4.2 plus `state_file_fresh`,
  `state_max_age_seconds`, `state_reboot_required`; `data["reboot_required"]
  = details["required"]`; `data["reboot_required_details"] = details`;
  `data["summary"] = {last_run_ok, currently_running, last_success_fresh,
  last_success_age_seconds, freshness_max_age_seconds, reboot_required,
  overall_ok = last_run_ok and last_success_fresh and state_file_fresh}`.
- Existing tests that pin this: `tests/test_monitoring_pipeline_repair.py`
  `EndpointRebootStateTests` (6 tests).

### 4.6 Mode `logyard-health` (`logyard_health_httpd.py.j2`)

Configuration from the environment the unit already sets
(`logyard-health-endpoint.service.j2`): `LOGYARD_HEALTH_BIND` (default
127.0.0.1), `_PORT` (9105), `_PATH` (`/.well-known/logyard`),
`LOGYARD_LOKI_URL` (`http://127.0.0.1:3101`, trailing `/` stripped),
`LOGYARD_HEALTH_SELECTOR`, `LOGYARD_WARNING_WINDOW_SECONDS` (900),
`LOGYARD_CRITICAL_WINDOW_SECONDS` (3600), `LOGYARD_REQUEST_TIMEOUT_SECONDS`
(10, float), `LOGYARD_HEALTH_SYSTEMCTL_TIMEOUT_SECONDS` (5, float),
`LOGYARD_HEALTH_UNITS_B64` (base64 of a JSON list of `{"id","unit"}`) —
l.19–28. Invalid integers abort startup (module-level `int()`).

- Units list (l.33–83, parsed once at startup): strict base64 → else
  rejected `invalid_base64`; JSON → else `invalid_json`; must be a list →
  `not_a_list`; per entry: object (`not_an_object`), `unit` non-empty string
  (`missing_unit`), `id` non-empty string (`missing_id`), no `.` in id
  (`id_contains_dot`), unique (`duplicate_id`). Rejected entries carry the
  fields shown in the source.
- No auth. Path ≠ `PATH` → **404**, `Content-Type: application/json`, body
  `{"error":"not_found"}` (l.236–242). Path = `PATH` → always **200** with
  the payload (l.244–250), HTTP/1.0 semantics (no `protocol_version`).
- Payload per request (l.163–229): `generated_at` (UTC now, seconds,
  `+00:00`), `selector`, `status`; `loki = {ready, ready_status,
  ready_body}` from `GET {LOKI}/ready` (ready iff status 200 and
  `body.strip().lower() == "ready"`; on `HTTPError`/`URLError`/`TimeoutError`
  ready false, status `None`, body = error text); `ingest` with the two
  windows, `*_window_entries` = `float` of `data.result[0].value[1]` of
  `GET {LOKI}/loki/api/v1/query?query=sum(count_over_time(<selector>[<n>s]))`
  (0.0 when the result is empty or malformed), `*_fresh = entries > 0`,
  `error` only on a query exception (warning query first; an exception skips
  the critical query); `units = {id: {unit, exists, load_state,
  active_state, sub_state, result, error}}` from `systemctl show -p LoadState
  -p ActiveState -p SubState -p Result -- <unit>` per unit with the systemctl
  timeout (unknown-shape entry with `exists: null` and `error` on failure or
  non-zero exit; `exists = load_state not in ("", "not-found")`);
  `units_rejected` only when non-empty. `status = critical` if not ready or
  ingest error or critical entries ≤ 0, else `warning` if warning entries ≤ 0,
  else `ok`. Floats serialise as floats (`12.0`).
- **No access log** (`log_message` returns, l.252) — important because Logyard
  ingests this host's journal.
- Threaded server (`ThreadingHTTPServer`).

### 4.7 Mode `static` (`static-site-httpd.py.j2`)

`SimpleHTTPRequestHandler` with `directory=<site root>`, bind/port baked into
the template (127.0.0.1:10061 for `benchmarks-static`), threaded, `timeout =
10`, HTTP/1.0. GET and HEAD; other methods 501. Files served with a guessed
`Content-Type`, `Content-Length`, `Last-Modified`, conditional
`If-Modified-Since` → 304; a directory without trailing `/` → 301 redirect;
a directory with `index.html`/`index.htm` → that file; a directory without
index → 404 (`list_directory` overridden: "Directory listing is disabled");
`..` cannot escape the root. Every response, including errors and redirects,
carries `Cache-Control: no-cache`, `Referrer-Policy: no-referrer`,
`X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`
(`end_headers` override). Access log to **stdout**: `<client> - <message>`.
Pinned by `tests/test_static_site_deploy.py`
(`test_rendered_server_serves_files_without_listing_or_writes`,
`test_server_binds_loopback_and_disables_directory_listing`).

### 4.8 Process, systemd, files

- Units, users, groups, `Type`, `Restart`/`RestartSec`, hardening,
  `IPAddressDeny/Allow`, `ReadOnlyPaths`, `Environment=` lines, `TasksMax`,
  `MemoryMax` are unchanged; the Rust binary must run under each of them
  (notably `MemoryDenyWriteExecute=true` and `RestrictAddressFamilies=AF_UNIX
  AF_INET` of the static unit, `ProtectSystem=strict` everywhere).
- Files read: JSON file, htpasswd file, `/var/run/reboot-required`, `uname`
  (apt-state), the site root (static). Nothing is written, no temp files.
- Exit codes: 0 after SIGTERM/SIGINT (graceful: stop accepting, finish
  in-flight requests for up to 5 s); 2 for usage/configuration errors
  (Python argparse: 2); 1 for runtime errors such as a failed bind (Python:
  1 with a traceback). systemd's restart behaviour is therefore unchanged.
- JSON files, htpasswd files, permissions, writers, timers: unchanged.

### 4.9 Command line (Rust)

```
metrics-httpd --version                       # "metrics-httpd <version> (<commit>)"
metrics-httpd json-file --bind A --port N --path P --json-path F --htpasswd-file H
    --realm R --server-name S [--meta replace|merge] [--path-match exact|path-only]
    [--missing-message TEXT] [--request-timeout SECS] [--check-config]
metrics-httpd script    --bind A --port N --path P --script X --script-timeout SECS
    --htpasswd-file H --realm R --server-name S [--request-timeout SECS] [--check-config]
metrics-httpd apt-state --bind A --port N --path P --json-path F --htpasswd-file H
    --freshness-max-age SECS --state-max-age SECS [--reboot-flag PATH]
    --realm R --server-name S [--request-timeout SECS] [--check-config]
metrics-httpd logyard-health [--check-config]  # LOGYARD_* environment as 4.6
metrics-httpd static --bind A --port N --root DIR [--check-config]
```

Defaults: `--meta replace`, `--path-match exact`, `--missing-message` the
backup text, `--request-timeout 10`, `--reboot-flag /var/run/reboot-required`.
`--check-config` validates everything the process would need (flags, bind
address syntax, htpasswd file readable with only bcrypt entries, JSON
file's directory or script executable present, site root a directory, Loki URL
`http://`, units list) **without binding**, prints a one-line summary (never
a hash or password) and exits 0 or 2. At normal startup the binary is as
lenient as Python: an unreadable htpasswd file or missing JSON file is a
per-request 401/503, not a startup failure.

---

## 5. Non-goals and allowed differences

### 5.1 Non-goals

- The JSON writers (exporters/collectors run by timers, `ddns-update`,
  `os-apt-maintenance` itself, `mail-metrics.sh`): short-lived oneshots, not
  long-running processes; they stay Python/shell.
- `software-live-endpoint` (parallel stream).
- Changing ports, paths, realms, users, units, timers, IP allow lists, nyxmon
  checks, graphyard specs or credentials. No change to `graphyard_vector` or
  ingest tokens (the Atlas step is open).
- htpasswd generation in the roles (`htpasswd -niB`/`-viB` from
  `apache2-utils` stays; the roles still need the package).
- Consolidating endpoints into fewer processes (section 3).
- macOS hosts; musl builds.
- Moving `mailgun_relay_deploy`/`nyxmon_deploy` onto the shared install helper.
- New features (Prometheus format, TLS, more auth schemes).

### 5.2 Allowed differences (exhaustive; each needs a fixture or test that pins the Rust side)

- **D-1 Concurrency and timeouts.** Rust serves connections concurrently in
  every mode (Python is single-threaded in seven variants, so one idle
  keep-alive client blocks the endpoint today). Header-read and keep-alive
  idle timeout = `--request-timeout` (10 s; dns 15 s via the flag; static
  10 s); at most 64 concurrent connections per process (more wait in the
  accept queue).
- **D-2 Python crash paths get answers.** Where Python raises inside the
  handler and drops the connection without a response, Rust answers:
  top-level JSON not an object (json-file, apt-state) → 502 `invalid_json`;
  apt-state type errors (e.g. `reasons` a number) → 500 `{"error": true,
  "error_type": "internal_error", …}`; script stdout not UTF-8 → passed
  through with 200; logyard unexpected Loki responses (non-object body,
  disconnects not covered by the caught exceptions) → the caught-error path
  (ready false / ingest `error`) with the error text; openclaw/os_apt htpasswd
  timeout → not applicable (in-process verification).
- **D-3 Texts.** Status codes, `error_type` values and JSON keys are equal;
  `message` texts after the fixed prefixes (parser error details, OS error
  details), HTML bodies of `send_error`, reason phrases and the 501 body may
  differ. `metrics_endpoint` 502: Python puts the script's stderr into the
  status line's reason phrase; Rust uses the standard reason phrase and puts
  the stderr text (≤ 1 KiB, control characters replaced) into the body.
- **D-4 JSON input strictness.** Python accepts `NaN`, `Infinity`,
  `-Infinity`, lone surrogates and float literals that overflow to
  infinity (`1e400`, which Python then serves as `Infinity`); Rust rejects
  all of them → 502 `invalid_json`. No live file contains them (1.1); S2a
  lists every writer and whether it can emit them
  (`json.dumps(..., allow_nan=True)` default).
- **D-5 JSON output bytes: none.** Rust reproduces sorted keys, Python
  separators and `\uXXXX` escaping, and Python's number round trip
  (`json.loads` then `json.dumps`): a number lexeme without `.`, `e`, `E`
  is a Python `int` and is written verbatim, at any size (`serde_json`
  `arbitrary_precision` keeps the lexeme), except `-0`, which Python
  writes as `0`; an int lexeme longer than 4300 digits (CPython's
  `int_max_str_digits` default, a `ValueError` in Python) → 502
  `invalid_json` in Rust; every other
  lexeme is a Python `float`: parsed to the nearest `f64` and written with
  Python's `float.__repr__` rules — the shortest round-trip digits (Rust's
  `{:e}` formatting yields them) laid out fixed-point with at least one
  fractional digit when the decimal exponent is in −4 ≤ e < 16, else as
  `<d>[.<ddd>]e<sign><at least two digits>` (`1e2` → `100.0`, `1.00` →
  `1.0`, `9007199254740993.0` → `9007199254740992.0`, `1e16` → `1e+16`,
  `0.0001` → `0.0001`, `0.00001` → `1e-05`, `-0.0` → `-0.0`). The same
  formatter writes computed floats (logyard counts). The int/float split
  also drives the apt-state type checks (`isinstance(v, int)`: `1e9` and
  `5.0` are floats there, as in Python); integers used in apt-state
  arithmetic are exact (i128; a lexeme outside i128 there → 500
  `internal_error`, D-2 style, never a wrong number). S1 has a fixture
  with exactly these cases; the parity harness compares bytes for every
  200 response and parsed JSON plus the D-3 rules for errors.
- **D-6 Auth.** In-process bcrypt verification (no subprocess; fixes the
  password in argv of `metrics_endpoint`'s `htpasswd -vb`). Only `$2a$`,
  `$2b$`, `$2y$` hashes (all live files are `$2y$`); other schemes → 401 and
  `--check-config` fails, so a role never switches to Rust with such a file.
  Base64 decoding is strict (Python silently drops non-alphabet characters).
  The file is re-read per request (keeps rotation without restart).
- **D-7 Headers/protocol.** `Server: <server-name> metrics-httpd/<version>`
  instead of `<server-name> Python/3.x`; logyard-health and static answer
  HTTP/1.1 with `Content-Length` and keep-alive (Python: HTTP/1.0, the
  logyard 404 without `Content-Length`).
- **D-8 Script timeout** kills the script's whole process group (Python
  kills only the direct child and can then hang on a grandchild holding the
  pipe).
- **D-9 Logs.** The access line format of 4.1.6 is kept; Python's extra
  `code 404, message …` lines of `send_error` are not reproduced; Rust adds
  one line at startup (mode, bind, version) and one error line per 5xx
  cause. logyard-health stays silent per request; static logs to stdout.
- **D-10 Bind.** IPv6 bind addresses work in every mode (Python: dns only).
- **D-11 Static.** Behaviour comes from `tower-http`'s `ServeDir`: MIME
  types from `mime_guess` (Python: `mimetypes` + `/etc/mime.types`), `Range`
  requests supported (Python 3.13 ignores `Range`), and the directory
  redirect may use 307 instead of 301 if `ServeDir` offers no 301; S2e pins
  the actual differences on the real benchmark site content and the parity
  harness requires identical status and body for every published file.
- **D-12 Size limits.** JSON files larger than 64 MiB → 502 `invalid_json`
  (Python: unbounded; live ≤ 24 KB); script stdout capped at 64 MiB → 502;
  request headers capped by hyper's defaults.
- **D-13 Loki query encoding.** The query string is
  `application/x-www-form-urlencoded` by `form_urlencoded` (Python
  `urlencode`/`quote_plus`): `*` and `~` may be encoded differently; Loki
  decodes both the same. Redirects from Loki are not followed (Python's
  `urlopen` follows them; Loki's endpoints do not redirect). Only `http://`
  Loki URLs (live: `http://127.0.0.1:3101`); `https` fails `--check-config`.

---

## 6. Crate design

```
rust/metrics-httpd/
  Cargo.toml  build.rs                 # build.rs: commit for --version (as mailgun-relay)
  src/main.rs                          # CLI (clap), mode dispatch, exit codes
  src/server.rs                        # hyper http1 server: bind, timeouts, conn limit, SIGTERM, access log, 501/404/401 helpers
  src/auth.rs                          # Basic header parsing, htpasswd parsing, bcrypt verify
  src/pyjson.rs                        # PyCompat serde_json Formatter (sorted keys via BTreeMap, ", "/": ", ensure_ascii), py truthiness, `in`, isinstance-int
  src/meta.rs                          # file stat/read, mtime/served/age, ISO formatting, meta replace/merge
  src/modes/{json_file,script,apt_state,logyard_health,static_site}.rs
  src/clock.rs                         # injectable clock for tests
  tests/                               # fixture replay, process e2e
  fixtures/generate.py, fixtures/*.json, fixtures/htpasswd
  parity/run_parity.py, parity/shadow_compare.py
  TESTMAP.md
```

Runtime: tokio `current_thread` runtime; blocking work (bcrypt, file reads
are small and may stay async via `tokio::fs`, subprocesses via
`tokio::process`) on the blocking pool limited to 4 threads.

| Need | Crate | Why |
| --- | --- | --- |
| HTTP server | `hyper` 1 (`server`, `http1`) + `hyper-util` (`tokio`, `server`) + `http-body-util` | one route per process, raw request-target access for the exact path match, `header_read_timeout`; no router needed |
| runtime | `tokio` (`rt`, `net`, `time`, `signal`, `process`, `fs`, `io-util`, `macros`) | |
| HTTP client (Loki) | `hyper-util` `client-legacy` (http only) | already in the tree; no TLS needed (D-13) |
| static files | `tower-http` (`fs`, `set-header`) + `tower` | maintained file serving with conditional requests and path sanitising (D-11) |
| JSON | `serde_json` (`arbitrary_precision`; default `BTreeMap` map = sorted keys) with a custom `Formatter` | D-5 |
| bcrypt | `bcrypt` (verify only) | D-6 |
| base64 | `base64` | |
| URL query encoding | `form_urlencoded` | D-13 |
| CLI | `clap` 4 (derive, minimal features) | as the precedents |
| time | `chrono` (`clock`, `std`) | UTC ISO strings, local time for the access log |
| uname, process-group kill | `rustix` (`system`, `process`) | `os.uname().release` equivalent; D-8 |
| tests | `tempfile`, `tokio` test-util | |

No hand-rolled HTTP, base64, bcrypt or JSON parsing.

---

## 7. Role and service switch design

### 7.1 Variables

Fleet level (ops-control `inventories/prod/group_vars/all.yml`, so one pin
covers all roles and both engines):

```yaml
metrics_httpd_impl: python            # python | rust; fleet default
metrics_httpd_rust_version: ""        # e.g. "0.1.0"
metrics_httpd_rust_sha256: ""         # sha256 of the release archive
```

Per role, in role defaults (overridable per host for canaries), e.g.
`backup_metrics_endpoint_impl: "{{ metrics_httpd_impl | default('python') }}"`,
likewise `storage_metrics_endpoint_impl`, `thermal_metrics_endpoint_impl`,
`tailscale_metrics_endpoint_impl`, `dns_metrics_endpoint_impl`,
`metrics_endpoint_impl`, `os_apt_maintenance_endpoint_impl`,
`dns_ddns_status_endpoint_impl`, `openclaw_metrics_endpoint_impl`,
`logyard_health_impl`, `static_site_impl`, and in ops-control
`torrent_vpn_metrics_endpoint_impl`.

### 7.2 Internal helper role `metrics_httpd_switch` (ops-library, S5a)

Used by each consumer role with `include_role` (`tasks_from`):

- `select.yml` (before the role's "enable and start" task). Inputs: `impl`,
  `service_name` (= consumer for the pin), `argv` (list after the binary,
  e.g. `["json-file", "--bind", …]`), `validate_user`, `validate_group`,
  `unit_sandbox` (the `systemd-run --property` list mirroring the unit: user,
  group, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `NoNewPrivileges`,
  `ReadOnlyPaths`, `Environment` for logyard), `notify` (the caller's
  `reload systemd` and restart handlers). Steps:
  1. assert `impl in ['python', 'rust']`; for `rust` a version with a 64-hex
     sha256 (or a local archive); `argv` elements contain no newline, no `%`
     (systemd specifier) and no `"`/`\`;
  2. when a version is set (independent of `impl`, so the binary can be
     installed ahead of the switch): F3 `rust_release_binary` `install`
     (`name: metrics-httpd`, `fail_hard: impl == 'rust'`);
  3. if installed: run `<versioned binary> <argv> --check-config` through
     `systemd-run --wait --pipe --collect` with `unit_sandbox` (as
     mailgun-relay's `--check-config` task); failure stops the play for
     `rust`, warns and continues for `python`;
  4. template `/etc/systemd/system/<service>.service.d/metrics-httpd-impl.conf`
     (root 0644) iff `impl == rust`, else `state: absent`:

     ```ini
     # Managed by ops-library metrics_httpd_switch: selects the Rust metrics-httpd.
     # Remove this file (daemon-reload, restart) to fall back to Python.
     [Service]
     ExecStart=
     ExecStart=/opt/metrics-httpd/<version>/metrics-httpd <argv, systemd-quoted>
     ```

     A change notifies `reload systemd` and the unit's restart handler. The
     role's base unit template and its Python script stay untouched, so a
     deploy with `impl: python` renders exactly what it renders today (this
     keeps ops-deploy's byte-identical parity copies valid).
- `verify.yml` (after `meta: flush_handlers`): retry up to 30 s: unit
  active, `MainPID > 0`; `rust`: `readlink /proc/<pid>/exe` equals the
  versioned binary; `python`: `/proc/<pid>/cmdline` contains the role's
  Python script path. Then an unauthenticated `GET http://<bind>:<port><path>`
  from the host: 401 with the role's realm (json-file, script, apt-state), 200
  with a JSON object containing `status` (logyard-health), 200 for `/`
  (static) — skipped with a message when the unit's `IPAddressAllow` does not
  cover the bind address as a source. No credentials are used anywhere in the
  role switch. On success: F3 `pin` (rust) or pin `state: absent` (python),
  then F3 `prune`.

### 7.3 Consumer roles (argv per role)

| Role (repo) | argv after the binary |
| --- | --- |
| `backup_metrics_endpoint`, `storage_metrics_endpoint`, `thermal_metrics_endpoint` | `json-file --bind <bind> --port <port> --path <path> --json-path <json> --htpasswd-file <htpasswd> --realm <x>-metrics --server-name <x>-metrics-httpd/0.1` |
| `tailscale_metrics_endpoint` | the same + `--path-match path-only` |
| `dns_metrics_endpoint` | the same + `--meta merge --request-timeout <dns_metrics_endpoint_request_timeout>` |
| `openclaw_deploy` (`tasks/metrics.yml`) | json-file … `--realm openclaw-metrics --server-name openclaw-metrics-httpd/0.1 --missing-message "Metrics file not found - collector timer may not have run yet"` |
| `dns_deploy` (`tasks/ddns.yml`) | json-file … `--realm ddns-status --server-name ddns-status-httpd/0.1 --missing-message "Status file not found - updater may not have run yet" --request-timeout 10` |
| `torrent_vpn_metrics_endpoint` (ops-control) | json-file … `--realm torrent-vpn-metrics --server-name torrent-vpn-metrics-httpd/0.1 --request-timeout 10` |
| `metrics_endpoint` | `script --bind … --path … --script <script> --script-timeout <n> --htpasswd-file … --realm metrics --server-name metrics-httpd/0.1` |
| `os_apt_maintenance` | `apt-state --bind … --path … --json-path <state file> --htpasswd-file … --freshness-max-age <os_apt_maintenance_freshness_max_age_seconds> --state-max-age <os_apt_maintenance_endpoint_state_max_age_seconds> --realm os-apt-maintenance --server-name os-apt-maintenance-httpd/0.1` |
| `logyard_deploy` | `logyard-health` (environment from the unit) |
| `static_site_deploy` | `static --bind <static_site_bind_host> --port <static_site_port> --root <static_site_path>` |

`--missing-message` values with spaces are passed as one systemd-quoted
argument. Each role's README documents `<role>_impl` and the fleet variables;
CHANGELOG under "Unreleased"; role tests render the drop-in for both impls.

### 7.4 pyinfra services (ops-deploy + ops-control, S5e)

`thermal_monitoring` (macmini), `logyard` (macmini) and `static_site`
(staging) get config fields `httpd_impl`, `httpd_rust_version`,
`httpd_rust_sha256` and call F4 `helpers/rust_release` plus a byte-identical
rendering of the role's `metrics-httpd-impl.conf.j2` (vendored under
`tests/parity/ansible/metrics_httpd_switch__metrics-httpd-impl.conf.j2`, checked
like the other vendored copies), with the same verify steps. ops-control maps
the variables in `pyinfra_support/macmini_monitoring.py` (its
`ROLE_PREFIXES` check refuses unmapped `thermal_metrics_endpoint_*` vars, so
`thermal_metrics_endpoint_impl` must be mapped, not refused) and in
`pyinfra_support/services.py` (logyard, benchmarks_static), resolving
`<role>_impl` → `metrics_httpd_impl` → `python` exactly as the role
defaults do. A test in ops-control fails if a pyinfra-registered service that
renders a metrics-httpd role ignores `metrics_httpd_*` (no silent ignore).
ops-control bumps its ops-deploy pin (`requirements-ops-deploy.txt`) in the
same slice, announced to the pyinfra session through the coordinator.

### 7.5 Rollback

- Normal: set `<role>_impl: python` (or `metrics_httpd_impl: python`) and
  deploy the unit through its engine (section 2). The drop-in disappears,
  systemd restarts the Python script that every deploy keeps installed.
- Emergency, on the host as root: `rm /etc/systemd/system/<unit>.service.d/metrics-httpd-impl.conf
  && systemctl daemon-reload && systemctl restart <unit>`; then flip the
  inventory before the next deploy.
- Rust to Rust: pin the previous version and sha256; the versioned directory
  is still installed (pins + `keep_versions`), the drop-in changes, the unit
  restarts.

---

## 8. Test strategy

### 8.1 Python tests → Rust tests (TESTMAP, created in S1, extended per slice)

| Python behaviour / test | Rust counterpart | Slice |
| --- | --- | --- |
| `tests/test_monitoring_pipeline_repair.py::EndpointRebootStateTests` (persisted kernel signal served; reboot into new kernel clears it; live marker alone; both reasons; old state files; handler serves merged state) | `apt_state` unit tests + `fixtures/apt_state.json` cases with the same inputs | S2c |
| `tests/test_static_site_deploy.py::test_rendered_server_serves_files_without_listing_or_writes`, `::test_server_binds_loopback_and_disables_directory_listing` | `static` fixture cases + e2e test (GET file, dir listing 404, PUT/POST 501, headers on errors) | S2e |
| `tests/test_logyard_deploy.yml` (template list rendering) | stays (role test); S5c adds the drop-in template | S5c |
| Molecule verify scenarios that curl endpoints (`metrics_endpoint`, `tailscale_metrics_endpoint`, `mail_monitoring`) | unchanged with `impl: python`; S5a/S5b add drop-in render tests for `impl: rust` | S5a, S5b |
| No Python tests exist for the json-file and script handlers | fixtures generated from the eight json-file scripts and `metrics_httpd.py.j2` (8.2) | S2a, S2b |

`TESTMAP.md` lists every fixture family with its Python source and the Rust
test that replays it; reviewers check coverage per slice.

### 8.2 Fixtures (Python as the oracle)

`rust/metrics-httpd/fixtures/generate.py` (run with the ops-library venv,
which has jinja2): renders every Python template with its role defaults (as
`test_monitoring_pipeline_repair.py` does), imports it, starts its server
class on an ephemeral loopback port in a thread, and drives a case matrix with
`http.client`: right/wrong/query/absolute path, no/malformed/wrong/right auth
(a committed test-only htpasswd file with a bcrypt entry, cost 4, verified by
the real `htpasswd` binary that the scripts call), missing file, directory,
unreadable file, invalid JSON, non-object JSON, `meta` present/absent/non-object,
unicode and big numbers, every apt-state branch, script stdout/exit/stderr/
timeout (fixture scripts), logyard against a fake Loki (`http.server` thread)
and a fake `systemctl` on `PATH` (canned output, non-zero exit, sleep past the
timeout), static against a small site tree. The clock is frozen by patching
the module's `datetime`; file mtimes are set with `os.utime`. Each case
records the request, the input state, status, `Content-Type`,
`Content-Length`, `WWW-Authenticate`, body, and a `compare` mode (`bytes`,
`json`, `error_type_only` for D-3, `status_only` for D-2 crash paths with the
Rust expectation written next to it). `tests/test_metrics_httpd_fixtures.py`
(in `just test`) regenerates and fails on drift, so a change to a Python
script without regenerated fixtures is caught. Rust `tests/fixtures.rs`
replays every case against the Rust service in-process with the same clock.

### 8.3 Parity harness (process level)

`rust/metrics-httpd/parity/run_parity.py` (stdlib) starts the rendered Python
script and the Rust binary side by side on loopback with identical inputs and
runs the matrix over real sockets, plus: keep-alive reuse, a slow client
holding a connection while another request arrives (expected D-1
difference), concurrent requests, SIGTERM exit code. Time fields
(`served_at_epoch`, `age_seconds`, logyard `generated_at`) are compared with
±1 s tolerance; everything else per the case's `compare` mode. `just
rust-parity-metrics-httpd`; the `rust` CI job runs it (installs
`apache2-utils`).

### 8.4 Process e2e (Rust only)

Exit codes (2 for bad flags, 1 for a taken port, 0 after SIGTERM),
`--check-config` cases (missing/unsupported htpasswd hash, https Loki URL,
bad units list), access log line format, no credential in any output.

---

## 9. Lean goals (measured as nyxmon PLAN.md 4.4)

- Stripped release binary ≤ 4 MiB (all five modes).
- Per process, steady state: cgroup `MemoryCurrent` ≤ 3 MiB, `RssAnon` ≤ 2
  MiB; `MemoryPeak` ≤ 6 MiB after the shadow matrix. Python today: 6.9–11.6
  MiB cgroup, 6.6–10.6 MiB `RssAnon` (1.1). `ps` RSS also counts the
  file-backed binary mapping, which is shared page cache across all
  `metrics-httpd` processes on a host; it is reported separately.
- Threads: one runtime thread plus at most 4 blocking-pool threads, spawned
  on demand (Python: 1, but serialised).
- Startup to listening ≤ 100 ms; a json-file request ≤ 5 ms on macmini
  (excluding bcrypt cost of the existing hashes).
- Fleet target: ≤ 60 MiB cgroup memory for the 20 processes (Python: 201.7
  MiB).
- Measured: binary size in the release job summary (S4); per-process
  `MemoryCurrent`/`MemoryPeak`/`RssAnon`/`RssFile`/threads during the shadow
  run (S7) and 24 h after each cutover (S9a–S9e), recorded in the reports.

---

## 10. Rollout

### 10.1 Deploy lock (every production step)

On the controller, before any production deploy, shadow setup/teardown or
emergency rollback: `mkdir /tmp/ops-control-deploy.lock` (fails if held →
wait and retry; never remove a lock you did not create), then write
`/tmp/ops-control-deploy.lock/owner` (`rust-metrics-httpd <slice> <host>
<ISO time>`); release with `rm owner && rmdir` after the step's verification.
One lock per step, not per slice.

Before each deploy: the engine's preview (pyinfra: `just pyinfra-check
<service> <host>`; Ansible: the playbook in `--check --diff`), proceeding
only if the diff touches the metrics-httpd install, the drop-in and the
restart of the switched units. For `deploy-openclaw.yml` and `deploy-dns.yml`
(large playbooks) this preview is mandatory; anything else in the diff stops
the step and goes to the coordinator.

### 10.2 Install without switching (S6)

Fleet pin `metrics_httpd_rust_version`/`_sha256` set, `metrics_httpd_impl:
python`. One deploy installs the binary on all four hosts:
`just deploy-one os_apt_maintenance` (its play covers fractal, macmini,
staging, production). Expected: `/opt/metrics-httpd/<v>/` on each host,
`--check-config` passed as `metrics` in the os_apt unit's sandbox, no unit
restarted, no drop-in.

### 10.3 Shadow (S7, 24 h, no production change)

Per host (macmini, fractal, staging, production), under the lock for setup
and teardown: for every endpoint in 1.1, two transient units via
`systemd-run` with the production unit's `User`/`Group` and sandbox
properties plus `IPAddressAllow=localhost`: the deployed Python script
(with flags or, for scripts with baked settings, a copy with the port and
the htpasswd path substituted) and the installed Rust binary with the argv
of 7.3 (bind, port and htpasswd path replaced). Ports: on each host the
endpoints are numbered in the order of table 1.1 (i = 0, 1, …); the Python
shadow binds `127.0.0.1:<39000 + 2i>`, the Rust shadow `127.0.0.1:<39001 +
2i>`, so no two shadows share a socket even where production ports repeat
on different addresses (macmini thermal TS:9104 and OpenClaw
127.0.0.1:9104). Setup refuses to start if any of these ports is already
listening (`ss -ltn`). Both read the **production** JSON/state files and a
shadow htpasswd file with a random throwaway credential generated on the
host, so no production secret is used: `/run/metrics-httpd-shadow/` is
`0711 root:root`; the plaintext throwaway password lives in
`/run/metrics-httpd-shadow/secret/` (`0700 root:root`, read only by the
root-run comparer); each service group gets
`/run/metrics-httpd-shadow/<group>/` (`0750 root:<group>`) holding
`htpasswd` (`0640 root:<group>`), and the shadow units get that directory
in `ReadOnlyPaths`. Before the first comparison, setup asserts that an
authenticated request to every authenticated shadow (Python and Rust)
returns 200 or the expected file-state status, never 401; the comparer
counts any 401 on an authenticated probe as a difference.
logyard-health shadow uses the unit's environment with the port changed. `parity/shadow_compare.py`
(stdlib, copied to the host) runs every 5 min from a transient timer and
writes a JSONL report (counts and differing keys only, no payloads) to
`/var/lib/metrics-httpd-shadow/`. Teardown removes units, timer, files.
Pass: zero differences outside section 5.2 over 24 h, and the lean numbers
of section 9 recorded per host. Report in ops-control
`docs/deployments/<date>-metrics-httpd-shadow.md`.

### 10.4 Canary (S8, staging)

`tailscale_metrics_endpoint_impl: rust` and
`os_apt_maintenance_endpoint_impl: rust` in `host_vars/staging.yml`; deploy
`just deploy-one tailscale staging` and `just deploy-one os_apt_maintenance`
(the other hosts get no change). Verify: role verify tasks; the staging
Nyxmon checks for both endpoints stay OK for ≥ 3 check intervals; access log
lines in the journal; memory per section 9. Rollback drill (Ansible): flip
tailscale staging back to `python`, deploy, verify the Python process and
the check, flip forward again. Emergency drill on `os-apt-maintenance-endpoint`
(staging): the manual drop-in removal of 7.5, verify Python, then redeploy to
restore Rust. 24 h soak before S9.

### 10.5 Cutover (S9a–S9e, per host)

Per host: set `metrics_httpd_impl: rust` in that host's `host_vars` (or the
per-role variables), preview, deploy each entry point of section 2 for the
host under the lock, verify (role verify, Nyxmon checks OK ≥ 3 intervals,
graphyard metrics for fractal storage/thermal and macmini thermal keep
arriving, os-apt-maintenance suppression still evaluates), record memory.

- S9a fractal (5): `fractal_monitoring`, `tailscale fractal`,
  `os_apt_maintenance`. Check with the coordinator first (planned fractal
  MinIO TLS/replication work).
- S9b production (3): `metrics_endpoint production`, `tailscale production`,
  `os_apt_maintenance`. Check with the coordinator first (Traefik ACME move,
  window until 2026-10-30).
- S9c macmini Ansible (7): `metrics_endpoint`, `dns --tags ddns`,
  `deploy-dns-monitoring.yml`, `tailscale`, openclaw, `os_apt_maintenance`,
  `torrent_vpn_metrics_endpoint`.
- S9d macmini pyinfra (2): `macmini_monitoring`, `logyard_core`; pyinfra
  rollback drill on `thermal-metrics-endpoint` (flip, deploy, verify Python,
  flip forward).
- S9e staging static: `benchmarks_static`, the **last** cutover (owner
  decision Q3, section 13), after S9a–S9d. It is dropped together with
  S2e only if the parity run on the real site content (D-11) shows a
  status or body difference that `ServeDir` cannot avoid. The S2e worker
  reports that to the coordinator before S4; then S4 releases without the
  `static` mode, the `static_site` parts of S5c/S5e and S9e fall away, the
  static unit stays Python and outside S10, and the coordinator records it
  as a separate item.

Two entry points always cover several hosts: `just deploy-one tailscale
macmini` targets the whole `tailscale` group, and `os_apt_maintenance` always
runs on all four hosts. That is safe because the selection is per host in the
inventory: hosts not yet flipped get no change (drop-in stays absent), which
the preview of 10.1 must confirm.

When all hosts run Rust, `metrics_httpd_impl: rust` moves to
`group_vars/all.yml` and the per-host/per-role overrides are removed (last
step of the last S9 slice, S9e).

No metrics-httpd production or staging step (S6–S10b) runs while an
`echoport-command-guard` production/staging step is in progress: the
owner scheduled that port last in the campaign and never alongside other
production/staging changes; the coordinator sequences the two streams.

### 10.6 Python retirement (S10, ≥ 7 days after the last cutover, Q4)

Owner decision Q4 (section 13): S10a starts no earlier than 7 days after
the last cutover (S9e, or the last of S9a–S9d if S9e was dropped). Until S10b deploys the retirement, every role still
has both implementations, so a rollback is one inventory flip away. The
retirement is its own collection release (the coordinator's release commit
right before S10b; never bundled with the release the cutovers ran on).
The `*_impl` variables survive that release: they are still read, accept
only `rust`, and `python` fails with the message below, so inventories
keep working unchanged. S10c removes the variables in the next collection
release.

ops-library: each role's base unit `ExecStart` becomes the Rust binary (the
drop-in disappears), the Python scripts are removed from templates/files and
from hosts (`file: absent` on the old script path), `<role>_impl` accepts
only `rust` (a clear failure message names the last collection version that
had Python), READMEs/CHANGELOG; ops-control torrent role likewise; ops-deploy
updates its vendored copies and services. `python3` and `apache2-utils`
packages stay (writers and htpasswd generation need them). Deploy every entry
point of section 2 under the lock. Split in S10a (code, three repos), S10b
(deploys) and S10c (code only, after the next collection release: remove the
`<role>_impl` variables, `metrics_httpd_impl` and the pyinfra mappings of
7.4 from ops-library, ops-control inventories/`pyinfra_support` and
ops-deploy; renders nothing different, so no deploy beyond the next normal
one).

---

## 11. Slices

Rules: one branch and worktree per slice, codex review loop with
`gpt-6.1-sol` (high) before merge, at most three rounds (round 1 over the
slice, rounds 2 and 3 over the repair delta; if round 3 is not clean, stop
and report to the coordinator — owner rule 2026-10-21), merge to the
default branch and push.
Merging Rust code is always safe (nothing deploys `rust/`). Each slice keeps
`just test`, `just lint` and the `rust` CI job green, updates `TESTMAP.md`
and lists the Python code it ports in its review context.

| Id | Repo | Scope | Depends on | Parallel with | Prod | Est. |
| --- | --- | --- | --- | --- | --- | --- |
| F1–F4 | see `rust/PLAN-foundation.md` | workspace/CI, release, Ansible helper, pyinfra helper | — | — | no | 8–12 h |
| S1 | ops-library | core: CLI skeleton for all modes, `server.rs` (bind v4/v6, timeouts, conn limit, SIGTERM, access log, 501/404/401), `auth.rs`, `pyjson.rs` formatter + truthiness/`in`, `meta.rs`, clock, `--check-config` framework, fixture generator skeleton + drift test, `TESTMAP.md` | F1 | F2, F3, F4 | no | 3–4 h |
| S2a | ops-library | `json-file` mode, all 8 variants; fixtures from the 8 scripts; writer audit for D-4 | S1 | S2b–S2e, S5a | no | 3 h |
| S2b | ops-library | `script` mode; fixtures from `metrics_httpd.py.j2` | S1 | S2a, S2c–S2e | no | 2 h |
| S2c | ops-library | `apt-state` mode; port of `EndpointRebootStateTests`; fixtures | S1 | S2a, S2b, S2d, S2e | no | 3 h |
| S2d | ops-library | `logyard-health` mode; fake Loki/systemctl fixtures | S1 | S2a–S2c, S2e | no | 3–4 h |
| S2e | ops-library | `static` mode (tower-http) + fixtures on a sample tree and the D-11 list | S1 | S2a–S2d | no | 2–3 h |
| S3 | ops-library | parity harness + CI step + `just rust-parity-metrics-httpd`; `shadow_compare.py` | S2a (grows with S2b–S2e) | S2b–S2e | no | 3 h |
| S4 | ops-library | release `metrics-httpd-v0.1.0` (version bump in the crate, tag, verify release + sha256, record size) | F2, S2a–S2e, S3 | S5a–S5c | no | 1 h |
| S5a | ops-library | `roles/metrics_httpd_switch` (select/verify, drop-in template) + the five `*_metrics_endpoint` roles; tests; READMEs | F3, S1 (CLI frozen) | S2*, S3, S5d prep | no | 4 h |
| S5b | ops-library | `metrics_endpoint`, `os_apt_maintenance`, `dns_deploy` (ddns), `openclaw_deploy` | S5a | S5c, S5e | no | 3–4 h |
| S5c | ops-library | `logyard_deploy`, `static_site_deploy` (Ansible path, also the rollback engine of the pyinfra services) | S5a | S5b, S5e | no | 2 h |
| S5d | ops-control | `torrent_vpn_metrics_endpoint` switch; fleet vars in `group_vars/all.yml` (impl python, version/sha from S4); runbook `docs/METRICS_HTTPD_RUST.md`; playbook asserts for the collection version | S4, S5a | S5b, S5c, S5e | no | 2–3 h |
| S5e | ops-deploy + ops-control | pyinfra ports for `thermal_monitoring`, `logyard`, `static_site` (7.4); ops-control mappings + no-silent-ignore test; ops-deploy pin bump | F4, S5a, S5c | S5b, S5d | no | 3–4 h |
| S6 | ops-control (deploy) | install without switch (10.2) | S4, S5b, S5c, S5d (+ coordinator's collection release, Q2) | — | **yes** | 1 h |
| S7 | hosts (manual, lock) | shadow 24 h (10.3) on macmini, fractal, staging, production | S6, S3 | — | **yes** (read-only to production units) | 2 h + 24 h |
| S8 | ops-control (deploy) | canary on staging + Ansible rollback drill + emergency drill + 24 h soak (10.4) | S7 | — | **yes** | 2 h + 24 h |
| S9a | ops-control (deploy) | cutover fractal | S8, coordinator OK | S9b–S9d (deploy steps serialised by the lock) | **yes** | 1–2 h |
| S9b | ops-control (deploy) | cutover production | S8, coordinator OK | S9a, S9c, S9d | **yes** | 1 h |
| S9c | ops-control (deploy) | cutover macmini Ansible units | S8 | S9a, S9b, S9d | **yes** | 2 h |
| S9d | ops-control (deploy) | cutover macmini pyinfra units + pyinfra rollback drill | S8, S5e | S9a–S9c | **yes** | 1–2 h |
| S9e | ops-control (deploy) | cutover staging static (last cutover, Q3) | S9a–S9d, S5e, S2e | — | **yes** | 1 h |
| S10a | ops-library, ops-control, ops-deploy | Python retirement code (10.6) | S9a–S9e + 7 days | — | no | 3–4 h |
| S10b | ops-control (deploy) | retirement deploys on all hosts | S10a (+ coordinator's collection release) | — | **yes** | 2 h |
| S10c | ops-library, ops-control, ops-deploy | remove the `*_impl` / `metrics_httpd_impl` variables and mappings (10.6) | S10b + the next collection release | — | no | 1–2 h |

Maximum parallelism: after F1, S1 runs with F2/F3/F4; after S1, S2a–S2e and
S5a run concurrently (six workers), S3 starts with S2a; S5b, S5c, S5e run
concurrently after S5a; S5d after S4. Production slices are sequential up to
S8, then S9a–S9d run in parallel (each deploy step under the lock); S9e
follows as the last cutover.

Acceptance criteria (beyond the green checks):

- **S1**: server answers 404/401/501 per 4.1 for every mode stub;
  `--check-config` exit codes; formatter fixture (sorted keys, separators,
  `\uXXXX` incl. astral characters as surrogate pairs, big ints verbatim,
  the float cases of D-5) matches Python `json.dumps(sort_keys=True)` of
  `json.loads(<input>)` byte for byte.
- **S2a–S2e**: every fixture case of the mode passes; D-items of the mode
  pinned by named tests.
- **S3**: harness green for all modes on Linux CI; slow-client case shows
  the D-1 difference and nothing else.
- **S4**: release exists with archive + sha256; glibc ≤ 2.35; size ≤ 4 MiB.
- **S5a–S5e**: `impl: python` renders byte-identical files to today (test);
  `impl: rust` renders the drop-in; verify tasks covered by tests; no secret
  in `environment:` under `become_user`.
- **S6–S10b**: reports in ops-control `docs/deployments/` with the exact
  commands, lock times, verification output and memory numbers.
- **S10c**: no `metrics_httpd_impl`/`*_impl` reference left in the three
  repos (grep test); rendered units unchanged against S10b.

---

## 12. Risks

| Risk | Mitigation |
| --- | --- |
| pyinfra migration moves a role to a new engine during the campaign | slices re-read `services-metadata.yml`; `impl: python` changes no rendered file, so pyinfra ports stay byte-identical; S5e and later go through the coordinator to the pyinfra session |
| pyinfra silently ignores `metrics_httpd_*` (no prefix check) | explicit mapping + ops-control test (7.4) |
| Shared install root: one role prunes a version another unit runs | `.pins/<unit>` + prune honours pins (foundation 6.1, F3 test) |
| Large playbooks (openclaw, dns) touch more than the endpoint | mandatory preview; `--tags ddns` for DNS; stop on unexpected diff |
| Cutover windows collide with ops coordination plans (fractal MinIO TLS, production Traefik ACME until 2026-10-30) | S9a/S9b require the coordinator's OK first |
| Collection version guard blocks deploys (workers must not bump `galaxy.yml`) | Q2 (decided): coordinator release commit right before S6, S10b and any other production slice whose role change is not yet in a released collection version |
| Rust stricter than Python on odd inputs (D-4, D-6) | live inputs checked; writer audit (S2a); `--check-config` blocks the switch for non-bcrypt htpasswd |
| Tailscale address not yet up at boot → bind fails | same as Python: exit 1, `Restart=` retries |
| `ubuntu-22.04` runner retired | container fallback (foundation 2) |
| ops-control CI red at `test-software-inventory` (unrelated eMudhra work) | not ours to fix; S5d/S5e note it in their reports if it shows up; local `just test` targets of the touched areas must be green |
| Logyard journal volume if access logs were added to logyard-health | contract 4.6: no per-request log; e2e test asserts silence |

## 13. Owner decisions (2026-10-21)

The owner answered the questions of this plan on 2026-10-21 (given in chat
to the coordinator of the campaign) and accepted every recommended answer:

1. **Q1 GitHub Actions in ops-library: yes.** F1/F2 add the repository's
   first workflows: `rust.yml` (CI for `rust/` only) and `rust-release.yml`
   with `contents: write` only in the publish job; binary releases are
   published on the public ops-library repository
   (`rust/PLAN-foundation.md` sections 3, 4, 9).
2. **Q2 Collection releases for deploys: the coordinator releases.** The
   coordinator makes a collection release commit (`galaxy.yml` bump +
   CHANGELOG heading) on ops-library `main` right before the production
   deploys that need it: S6 (the S5a–S5c role changes), S10b (the
   retirement), and any other production slice whose role change is not yet
   in a released version (each such slice checks the installed collection
   version first and asks the coordinator if it is missing). Workers never
   bump `galaxy.yml`. S10c's variable removal ships in the release after
   S10b's.
3. **Q3 Static site in scope: yes, as the last cutover (S9e).** S2e and S9e
   are dropped only if the parity run on the real site shows a status or
   body difference that `ServeDir` cannot avoid (10.5); S4 therefore waits
   for S2e.
4. **Q4 Retirement soak: 7 days.** Python is retired 7 days after the last
   cutover (S10a/S10b), keeping the `*_impl` variables for one more
   collection release (S10c removes them; 10.6).

Further owner decisions of the same day that affect this stream:

- **Review rounds:** a slice and a plan may get a third review round over
  the repair delta; if round 3 is not clean, stop and report (section 11).
- **echoport-command-guard** is scheduled last in the campaign and never
  alongside other production/staging changes; metrics-httpd production
  steps do not overlap with it (10.5).
- **software-live** keeps its GPL `rust-apt` code in a separate helper
  binary `software-live-apt`; the foundation's license, CI and release
  rules for that are in `rust/PLAN-foundation.md` section 9. metrics-httpd
  stays MIT and must not depend on `rust-apt` (the foundation's CI check).
