# Rust port of `software_live` — implementation plan

Status: plan, not yet implemented; owner questions decided on 2026-10-21
(section 12). Campaign "Rust-Ports Runde 2", stream `rust-software-live`
(umbrella item `rust-ports-campaign`).

This document is the contract for porting the Python program of the
ops-library role `software_live` (`roles/software_live/files/software_live.py`,
931 lines) to Rust. It is written for the implementers of the slices in
section 9 and for the reviewers of each slice. Every behavioural statement
cites the Python code at ops-library `6b505fa1` (`software_live.py:<line>`).
When this document and the Python code disagree, the Python code wins and
this document must be corrected in the same slice.

The method follows the two ports already in production: mailgun-relay
(`mailgun-relay/rust/PLAN.md`) and the nyxmon agent (`nyxmon/agent-rs/PLAN.md`,
lean goals in its section 4.4, release in 8.2, role switch in 8.3, rollback
in 8.5). Python is the oracle for the contract and decisions, not for byte
parity. Maintained crates are used instead of re-implementing Python
libraries or protocols. Fixtures are generated from the Python code. A
parity harness runs both implementations. A shadow run precedes the cutover.
The cutover includes a rollback drill. Python retirement is its own, later
slice.

The shared foundation is designed by the stream `rust-metrics-httpd` in
`rust/PLAN-foundation.md` (its section 7): **F1** Cargo workspace under
`rust/`, toolchain pin, `cargo-deny`, `rust.yml` CI, `build_ignore`;
**F2** `rust-release.yml` with per-binary tag prefixes and
`rust/scripts/release_checks.py`; **F3** the internal role
`rust_release_binary` (install/pin/prune, on-host layout of its 6.1);
**F4** the pyinfra helper in ops-deploy, which this stream does not need
(the role is Ansible, section 2). F1 has no shared library crate. This
plan depends on F1, F2 and F3 by those ids and does not design a release
pipeline or install mechanism of its own. Section 7.4 lists the
requirements this stream adds to F2 and F3.

---

## 1. Live facts (read-only, 2026-10-21)

Gathered with `ssh root@<host>` and read-only commands only (`ps`,
`systemctl show/cat/list-*`, `ls`, `ss`, `sha256sum`, `/proc/<pid>/status`,
non-secret configuration). No secret was printed: of `htpasswd`, only the
hash prefix `$2y$` was read.

### 1.1 Hosts and scope

The scope is fixed by ops-control `playbooks/deploy-software-live.yml`
(`hosts: fractal:macmini:staging:production`), `software-live.yml` (scope,
desired OS cycles, PostgreSQL and Traefik expectations; `heis` is
explicitly excluded) and `playbooks/remove-software-live.yml` (asserts the
same four hosts). No other host runs the role.

| Host | SSH address (inventory) | OS | glibc | libapt-pkg | python3 / python3-apt | systemd |
| --- | --- | --- | --- | --- | --- | --- |
| macmini | macmini.tailde2ec.ts.net | Ubuntu 24.04.5 LTS, x86_64 | 2.39 | `libapt-pkg6.0t64` 2.8.3 | 3.12.3 / 2.7.7ubuntu5.3 | 255 |
| fractal | fractal.tailde2ec.ts.net | Ubuntu 24.04.5 LTS, x86_64 | 2.39 | `libapt-pkg6.0t64` 2.8.3 | 3.12.3 / 2.7.7ubuntu5.3 | 255 |
| staging | staging.wersdoerfer.de | Debian 13 (trixie), x86_64 | 2.41 | `libapt-pkg7.0` 3.0.3 | 3.13.5 / 3.0.0 | 257 |
| production | wersdoerfer.de | Ubuntu 24.04.5 LTS, x86_64 | 2.39 | `libapt-pkg6.0t64` 2.8.3 | 3.12.3 / 2.7.7ubuntu5.3 | 255 |

All four hosts run the same programs: `software_live.py` sha256
`1c9fdfc8a9b9c0b5adbcf506c4dcd45ba86f19c9b7ef2f4fae4fe3351918caf4` and
`nyxmon_checks.py` `425fd52e6d00ff4648a8194db875662a4686fc9bfc011cdbb9f972e94a222633` (identical to ops-library `main`).
All four have `software_live_inventory_export: true` (set in the playbook),
so the collector unit has the `ExecStartPost` export.

### 1.2 Python processes this stream replaces

| Host | Unit | Kind | Command | Measured |
| --- | --- | --- | --- | --- |
| all 4 | `software-live-endpoint.service` | long-running, `Type=exec`, user `metrics` | `/usr/bin/python3 /usr/local/lib/software-live/software_live.py serve --config /etc/software-live/endpoint.json` | see 1.3 |
| all 4 | `software-live-collector.service` (via `software-live-collector.timer`, `*:0/15`) | oneshot, root, sandboxed | `… software_live.py collect --config /etc/software-live/policy.json --output /var/lib/software-live/state.json --cache /var/lib/software-live/upstream.json --group metrics` | CPU per run (collect plus export): macmini 1.88 s, production 1.44 s, staging 1.58 s, fractal 0.50 s; staging cgroup memory peak 80.7 MB (systemd 257 journal line; systemd 255 does not report a peak for a finished oneshot) |
| all 4 | same unit, `ExecStartPost=-` | oneshot, second interpreter start | `… software_live.py export-inventory --config /var/lib/software-live/state.json --output /var/lib/software-estate-observations/software-health.json --group software-estate-publisher` | included above |

That is four long-running Python processes plus 2 × 4 short Python
interpreter starts every 15 minutes (768 starts per day across the fleet).

### 1.3 Endpoint memory today

| Host | PID | `ps` RSS | `RssAnon` | `RssFile` | cgroup `MemoryCurrent` | cgroup `MemoryPeak` |
| --- | --- | --- | --- | --- | --- | --- |
| macmini | 2253 | 17.6 MiB | 8.9 MiB | 8.7 MiB | 9.2 MiB | 14.4 MiB |
| fractal | 1218134 | 24.1 MiB | 12.9 MiB | 11.2 MiB | 13.2 MiB | 13.9 MiB |
| staging | 3765004 | 25.6 MiB | 13.7 MiB | 11.8 MiB | 14.0 MiB | 15.5 MiB |
| production | 1728 | 24.2 MiB | 13.0 MiB | 11.2 MiB | 13.9 MiB | 15.2 MiB |

Listeners are on each host's Tailscale IPv4, port 9110 only (`ss -ltn`).
Port 9119 is free on all four hosts (used for the loopback shadow endpoint,
section 8.1). On macmini, 9112 is taken by another endpoint.

### 1.4 Files on the hosts

- `/etc/software-live/` root:metrics 0750: `policy.json`, `endpoint.json`
  (keys `auth_user, bind, htpasswd, path, port, state`; `port` is a JSON
  integer), `htpasswd` (one bcrypt `$2y$` entry), all root:metrics 0640.
- `/var/lib/software-live/` root:metrics 0750: `state.json` root:metrics
  0640, caches `upstream.json` (only where Traefik is expected),
  `upstream-ubuntu.json` or `upstream-debian.json`, `upstream-postgresql.json`
  (where PostgreSQL is expected), each root:root 0640.
- `/usr/local/lib/software-live/` root:root 0755: both programs and a
  `__pycache__/`.
- `/var/lib/software-estate-observations/` root:software-estate-publisher
  0750, `software-health.json` root:software-estate-publisher 0640.

### 1.5 Consumers

| Consumer | What it reads | Where it is defined |
| --- | --- | --- |
| Nyxmon (macmini), service "Live software health", one `json-metrics` check per host, hourly | `GET http://<tailscale-ip>:9110/.well-known/software-live` with Basic auth user `nyxmon`; asserts `$.host`, `$.schema_version == 2`, `$.summary.fresh`, `$.summary.observation_ok` (critical); `os_ok`, `postgresql_ok`, `traefik_ok`, `security_updates_ok`, `apt_indexes_fresh` (warning) | ops-control `playbooks/deploy-software-live.yml` (second play) |
| Deploy verification | anonymous request must get 401; authenticated JSON must have `schema_version == 2`, `host == inventory_hostname`, `summary.fresh`, `os.observed`, `postgresql.observed` | same playbook, `post_tasks` |
| software_estate collector (`software-estate-publisher` group, weekly push to graphyard) | `/var/lib/software-estate-observations/software-health.json`, strict key sets, `source == "software-live/2"`, age ≤ 1800 s | ops-library `roles/software_estate/files/collect.py:376-470`, README "Existing software-health metadata" |
| software_estate unit probe | `systemctl show software-live-endpoint.service` (LoadState, ActiveState, MainPID) | ops-control `software-estate.yml` (`software_live.probe.unit`) |
| Graphyard | renders the pushed `software_health` items; never contacts the hosts | ops-control `docs/SOFTWARE_ESTATE_HEALTH.md` |
| Manual CLI `just software-live --host H` | streams `software_live.py` over SSH to `/usr/bin/python3 - collect --config-json '<policy>'` and parses stdout (`summary`, `os`, `postgresql`, `traefik`, `apt` fields) | ops-control `scripts/software-live.py:105-147, 150-249` |
| `software_live` `tasks_from: nyxmon` / `nyxmon_disable` | runs `/usr/local/lib/software-live/nyxmon_checks.py` on macmini as user `nyxmon` with JSON on stdin (deploy time only) | used by ops-control `deploy-software-live.yml`, `deploy-software-estate-monitor.yml`, `register-daybook-operations-backup.yml`, `register-daybook-operations-monitoring.yml`, `remove-software-live.yml` |
| `os_apt_maintenance` | documents the 48-hour index budget this monitor enforces | ops-library `roles/os_apt_maintenance/README.md`; ops-control `tests/test_os_apt_maintenance_refresh_config.py` |

---

## 2. Deploy mechanism today

- Engine: **Ansible**. `services-metadata.yml` entry `software_live` has no
  `engine:` line (so `playbooks/common/refuse_if_pyinfra.yml` would route it
  to Ansible), and no pyinfra module exists for it. The pyinfra migration
  (45/112 roles) does not cover this role. This plan does not port it to
  pyinfra.
- Full fleet: `just deploy-software-live` →
  `ansible-playbook -i inventories/prod/hosts.yml playbooks/deploy-software-live.yml`
  (with `_check-collection-version`, SOPS key file for `secrets/prod/nyxmon.yml`).
- One host (canary): `just deploy-one software_live <host>` → the same
  playbook with `-l <host>`. Nyxmon registration runs only when macmini is
  in the run.
- Removal: `just remove-software-live HOST` / `just remove software_live HOST`
  → `playbooks/remove-software-live.yml` (disables the Nyxmon check first,
  then `local.ops_library.software_live_remove`).
- The ops-library collection is installed into ops-control with
  `just install-local-library` (see `scripts/show-path-overrides.sh`).
  `_check-collection-version` must pass. Agents deploy from worktrees, as in
  the nyxmon S16 precedent; `~/projects` stays read-only.
- **Shared deploy lock (binding for every production step in this plan):**
  before any `just deploy-*`/`ansible-playbook` against production hosts run
  `mkdir /tmp/ops-control-deploy.lock` on the controller and write an owner
  file into it (`software-live <slice> <worker> <UTC time>`). If `mkdir`
  fails, wait and retry; never remove a lock you did not create. Remove
  only your own lock (check the owner file first) when the step is done.
  Long runs go into tmux.

New mechanisms: none. The shadow units (8.1) and the impl selector (7.3)
are role variables deployed by the same playbook and recipes.

---

## 3. The contract to preserve

Classes, as in the precedents: **P1** must match semantically (values,
types, key sets, exit codes, permissions, unit behaviour). **P2** may differ
in value because they depend on time or environment (timestamps, ages, OS
error texts). **P3** are the intentional divergences, listed exhaustively
in section 4.2.

### 3.1 Command line (P1)

`software-live <mode> [--config PATH] [--config-json JSON] [--output PATH] [--cache PATH] [--group NAME]`
with modes `collect | serve | validate | export-inventory`
(`software_live.py:884-931`).

| Mode | Behaviour | Exit code |
| --- | --- | --- |
| `validate --config P` | read the policy JSON, run `validate_policy` | 0 valid; 1 invalid or unreadable |
| `collect --config P\|--config-json J --output O --cache C --group G` | collect, then `atomic_json(O, report, gid(G))`; nothing on stdout | 0 for every valid report, even when software needs attention (README "Observation contract"); 1 for invalid policy, unknown group, write failure |
| `collect` without `--output` | print `with_freshness(report)` as JSON on stdout (manual SSH mode; `--cache` absent means no cache read or write) | as above |
| `serve --config P` | validate `bind` (IPv4 loopback or 100.64.0.0/10), listen on `bind:int(port)`, serve forever | 1 on invalid configuration or bind failure |
| `export-inventory --config STATE --output O --group G` | project the state (3.6) and write it atomically | 0; 1 with stderr `inventory export failed: <Class>` |
| argument errors | argparse usage error | 2 |

`--config-json` takes precedence over `--config` (`:904-906`). New and only
additive: `--version` (prints `software-live <version> (<commit>)`), and
`collect --report-usage` (one stderr line with wall time, CPU time and
`maxrss` of self plus children; used only by the shadow units, section
6.2).

### 3.2 Policy and validation (P1, `validate_policy`, `:607-641`)

Required keys and rules, unchanged: `host` non-empty string;
`traefik.expected` bool, `traefik.unit == "traefik.service"`,
`traefik.binary_path ∈ {/usr/bin/traefik, /usr/local/bin/traefik}`,
`traefik.desired_version` null or `v?N.N.N`; `os.expected_id ∈ {debian,
ubuntu}`, `os.product == os.expected_id`, `os.desired_cycle` matches
`\d+(\.\d+)?` (after `str()`); `postgresql.expected` bool and, when true,
`desired_major` `\d+` (after `str()`), `cluster` `[a-zA-Z_][a-zA-Z0-9_-]*`,
`port` int (not bool) 1–65535; `apt_max_age_seconds` int (not bool)
3600–1209600, default 172800. Missing mapping keys are errors (Python
`KeyError`). Extra keys are allowed and go into the policy hash.

`policy_sha256` (`:666-668`) is the sha256 of
`json.dumps(policy, sort_keys=True)`, which uses the separators `", "` and
`": "`, `ensure_ascii=True` and Python's `repr` for floats. **This value
must be byte-identical** between the implementations, because operators
compare it across hosts and implementations (ops-control
`docs/SOFTWARE_LIVE.md`). Rust parses JSON losslessly (`serde_json` with
`arbitrary_precision`, so an extra policy value such as
`18446744073709551617` is not turned into a float) and hashes a key-sorted
value through a custom `serde_json::ser::Formatter` that canonicalises
numbers the way Python re-serialises them: an integer token (no `.`, `e`
or `E`) is written as its canonical decimal integer (`-0` → `0`), any other
number is parsed as `f64` and written as Python's float `repr` (`1E2` →
`100.0`, `1e16` → `1e+16`, `1e-05`); separators and ASCII escaping with
surrogate pairs as above. It is fixture-tested against Python for strings
with non-ASCII and control characters, small and big integers
(`18446744073709551617`, `-0`), floats (`1E2`, `1.0`, `1e16`, `1e-05`,
`0.1`), bools, null, and nested mappings. The same lossless parsing applies
wherever Rust reads JSON that Python could have written (state, caches,
endpoint configuration), so no integer is silently rounded.

### 3.3 Report shape (P1, `collect`, `:644-684`)

Top-level keys: `schema_version` (2), `host`, `generated_at_epoch` (float
seconds), `policy_sha256`, `os`, `postgresql`, `traefik`, `apt`, `summary`.
The order of the observations is part of the contract: Traefik upstream,
Traefik, OS lifecycle upstream, OS, PostgreSQL lifecycle upstream (only if
expected, otherwise `{"status": "not_applicable"}`), PostgreSQL, APT. The
Traefik upstream is `{"status": "not_applicable"}` when Traefik is not
expected. `generated_at_epoch` is taken **after** all observations (`:665`).

`summary` (`:673-683`): `observation_ok = traefik.observed and
os.observed and postgresql.observed and apt.status != "unknown"`;
`os_ok`, `postgresql_ok`, `traefik_ok` are `status == "ok"`;
`security_updates_ok = apt.pending_security_count == 0` (false when the
count is `null`); `apt_indexes_fresh = apt.indexes_fresh`.

Partial results are part of the contract: every `observe_*` function
catches all exceptions at its boundary and returns the fields set so far
plus `status: "unknown"` and `error: "<Class>: <message>"[:240]`. Fields
and issues appended before the failure stay in the result (for example a
`desired_major_drift` issue and `server_version` survive a later lifecycle
failure, `:492-527`). The Rust code keeps this "accumulate, then fail with
what is known" structure.

#### Traefik (`observe_traefik`, `:242-319`; `binary_info`, `:90-125`)

- `MainPID` from `systemctl show <unit> --property=MainPID --value`
  (`systemctl` looked up in `PATH`, 15 s timeout, `:68-77, 128-129`).
- `expected: false`: present if `MainPID != 0` or either
  `/usr/bin/traefik` or `/usr/local/bin/traefik` exists; `status` warning
  with issue `unexpected_installation`, else ok; `observed: true`,
  `present` bool. No upstream lookup.
- `expected: true`: stopped service or missing binary →
  `ValueError: service stopped or managed binary missing`.
  `readlink /proc/<pid>/exe`; suffix `(deleted)` after a space → issue
  `deleted_running_executable`; target (without the suffix) ≠
  `realpath(binary_path)` → `running_path_mismatch`. Execution is refused
  whenever the raw target ≠ `realpath(binary_path)`.
- Installed: hash the file at `binary_path` (sha256 of the full file) and
  run `<binary_path> version` (15 s). Running: when refused, hash
  `/proc/<pid>/exe` only (`version: null`); otherwise open
  `/proc/<pid>/exe`, require `readlink /proc/self/fd/<fd> ==
  realpath(binary_path)`, hash through the descriptor, and execute
  `/proc/self/fd/<fd> version` with that descriptor inherited by the child.
  Never execute through the mutable `/proc/<pid>/exe` link.
- The identity `(st_dev, st_ino, st_mtime_ns, st_ctime_ns, st_size)` must be
  equal before hashing, after the probe, and in a final `stat` of the path;
  else `binary changed during observation`. The version is the first
  `^Version:\s*(v?\d+\.\d+\.\d+)\s*$` line of stdout (multiline), `v`
  stripped; missing → `unparseable binary version`.
- Two attempts: the observation is accepted if `MainPID` and the link target
  are unchanged afterwards; a second change → `MainPID changed during
  observation`. `issues` is reset at the start of each attempt.
- Result keys on success: `expected, observed, binary_path,
  desired_version, issues, installed{version, sha256}, running{version,
  sha256}, main_pid, running_path, upstream, status`. Issues:
  `installed_running_drift` (hash differs, or both versions known and
  different), `desired_version_unassigned`, `desired_installed_drift`,
  `upstream_unknown` (then `status: unknown`), `outdated_running_version`
  (running version known and lower than upstream). Otherwise `warning` if
  any issue, else `ok`.

Rust: open with `std::fs::File` (which sets `O_CLOEXEC`); right before
spawning the probe, clear `FD_CLOEXEC` on exactly that descriptor in the
parent (`rustix::io::fcntl_setfd`, a safe API) and close the descriptor
after the child has exited — the equivalent of `pass_fds`. This needs no
`unsafe` (`pre_exec` is unsafe, and F1's workspace lints set
`unsafe_code = "forbid"`); it is race-free because `collect` is
single-threaded and spawns no other child while the descriptor is
inheritable. Timeouts kill the child (as `subprocess.run(timeout=…)`
does). Hashing uses `sha2`.

#### OS (`observe_os`, `:346-390`)

- `platform.freedesktop_os_release()`: `/etc/os-release`, else
  `/usr/lib/os-release`, shell-style quoting and escapes. `ID` lowercased,
  `VERSION_ID` required, `VERSION_CODENAME`/`PRETTY_NAME` optional (`null`).
- ID ≠ `expected_id` → `ValueError: operating system does not match
  policy` (observed stays false). Cycle ≠ `desired_cycle` →
  `desired_cycle_drift`. Lifecycle upstream not ok → `upstream_unknown`,
  `status: unknown`, return (observed stays true, no `error`).
- `lifecycle {latest_release, support_end, eol, newest_cycle}` from the
  matching cycle; `newest_cycle` is `cycles[0].cycle` (upstream order).
  `cycle_eol` when EOL reached (`true` means ended), else
  `standard_support_ended` when support ended (`true` means still
  supported) — `lifecycle_ended`, `:55-59`; "today" is the UTC date of
  `now`. Key `upstream` holds `lifecycle_evidence(latest)` (`:334-343`).

#### PostgreSQL (`postgres_clusters`, `postgresql_server_version`, `observe_postgresql`, `:393-527`)

- `/usr/bin/pg_lsclusters --no-header`; each line split on whitespace into
  at most 8 fields; fewer than 6 → error; `major` `\d+`, `name`
  `[a-zA-Z_][a-zA-Z0-9_-]*`, port 1–65535; keep `major, name, port, status,
  owner` (data and log paths are dropped). A missing `pg_lsclusters`
  executable means "no clusters" only when PostgreSQL is not expected.
- Not expected: `present`, `status` warning plus `unexpected_cluster` when
  clusters exist.
- Expected: select the cluster with the policy name and port and a status
  starting with `online`; none → `expected PostgreSQL cluster is not
  online`. Server version: PID file
  `/var/run/postgresql/<major>-<name>.pid`, first line (≤ 32 bytes)
  `[1-9]\d*`; open `/proc/<pid>/exe`, require the descriptor target ==
  `realpath(/usr/lib/postgresql/<major>/bin/postgres)`, execute the
  descriptor with `--version`, re-read the PID file and compare identities
  as for Traefik; parse `postgres \(PostgreSQL\) (\d+(\.\d+)+)( .*)?`.
- Issues `desired_major_drift`, `unexpected_cluster` (any other listed
  cluster, including stopped ones), `upstream_unknown`, `cycle_eol`,
  `outdated_minor` (numeric tuple comparison with the cycle's `latest`,
  which must be a string). `lifecycle {latest_minor, eol, newest_major}`.

#### Upstream lookups and caches (`upstream`, `lifecycle_upstream`, `:149-239`)

- Traefik: `GET https://api.github.com/repos/traefik/traefik/releases/latest`,
  headers `User-Agent: ops-library-software-live/1`,
  `Accept: application/vnd.github+json`, 10 s timeout, body ≤ 1 MiB;
  `tag_name` must match `v?N.N.N`, drafts and prereleases rejected.
- Lifecycle: `GET https://endoflife.date/api/<product>.json`
  (`ubuntu`, `debian`, `postgresql`), same User-Agent, 10 s, ≤ 1 MiB; a
  non-empty list; keep each cycle that is an object with a string `cycle`,
  an `eol` that is bool/null/ISO date, and a `support` that is absent/null
  or bool/ISO date; no valid cycle → error. Cycle objects are stored
  **whole** (all upstream keys, e.g. `latest`, `lts`, `releaseDate`).
- Caches: `<cache>` for Traefik (`{"version", "checked_at_epoch"}`) and
  `<cache stem>-<product><suffix>` for lifecycle (`{"product", "cycles",
  "checked_at_epoch"}`), TTL 86400 s, used only if `0 <= now - checked <
  86400`. A cache is "valid evidence" only if it parses and validates;
  invalid caches are ignored. A failed refresh returns
  `{"status": "unknown", "error": "<Class>", "last_success": <valid stale
  cache or null>}` and never rewrites or re-dates the cache. A successful
  answer is `{…, "status": "ok", "cached": true|false}`.
- **Cache files are shared state across implementations (P1):** Rust must
  read caches Python wrote and Python must read caches Rust wrote, so a
  rollback or a roll-forward does not trigger extra upstream requests or
  lose `last_success` evidence.
- TLS trust: the system store (`/etc/ssl/certs`), like Python's `urllib`
  with OpenSSL defaults. The ongoing CA-trust work in the fleet
  (eMudhra distrust) therefore applies to both implementations equally.

#### APT (`security_origin`, `security_packages`, `observe_apt`, `:530-604`)

- Indexes: every `/var/lib/apt/lists/*InRelease` whose name contains
  `security` (case-insensitive); ages `now - mtime`; `indexes_fresh` =
  at least one index and all ages in `[0, max_age]`;
  `oldest_security_index_age_seconds` = max age or `null`;
  `index_age_limit_seconds`; `index_source` (fixed text).
- Packages: an in-memory APT cache (`apt.Cache(memonly=True)`: no index
  refresh, no write of `pkgcache.bin`). For each installed package, the
  candidates are all versions newer than the installed one
  (`apt_pkg.version_compare`) with at least one origin that is trusted and
  (origin `Ubuntu`/`Debian` with `security` in the archive, or origin
  starting with `UbuntuESM`, or label `Debian-Security`). The newest
  candidate wins. Entry: `package` (full name `name:arch`), `installed`,
  `security_version`, `candidate` (the APT policy candidate or `null`),
  `held` (`apt-mark showhold` lists the pretty name or the full name).
  Sorted by `package`.
- Success: `{status: ok, pending_security_count, pending_security_updates,
  indexes_fresh, oldest_security_index_age_seconds,
  index_age_limit_seconds, index_source}`. Any failure: `{status: unknown,
  error: "APT observation failed (<Class>)", indexes_fresh: false,
  pending_security_count: null}` (no package list).

### 3.4 Endpoint (P1, `Handler`, `with_freshness`, `:687-761`)

- Only `GET` of the exact request target `config.path`
  (`/.well-known/software-live`; a query string or any other target → 404
  `{"error": "not_found"}`). The 404 check comes before authentication.
- Authentication: header `Authorization` must start with `Basic` plus one space and be
  ≤ 4096 bytes; strict base64 (`validate=True`), UTF-8, split at the first
  `:`; user must equal `config.auth_user`; a password containing `\n` is
  rejected; the password must verify against the user's entry in
  `config.htpasswd`. Every failure → 401 `{"error": "unauthorized"}` with
  `WWW-Authenticate: Basic realm="software-live"`.
- Then read `config.state`, `with_freshness`: `schema_version == 2`
  (Python equality, so `2.0` also passes), `summary` an object whose six
  keys are bools, `generated_at_epoch` an int or float (not bool), finite;
  add `meta {age_seconds, max_age_seconds: 1800}` and `summary.fresh =
  0 <= age <= 1800`. A stale report is still 200 with `fresh: false`.
  Any failure → 503 `{"error": "missing_or_invalid_observation"}`.
- Every response: `Content-Type: application/json`, `Content-Length`,
  `Cache-Control: no-store`, sorted keys. The state is re-read on every
  request (no caching).
- No request logging at all (`log_message` is a no-op, `:760-761`):
  no paths, headers or credentials in the journal.
- Socket timeout 5 s per connection (`:714-716`). Bind is validated
  at startup (`:911-915`).

### 3.5 Atomic writes and permissions (P1, `atomic_json`, `:132-146`)

Temporary file in the target directory with prefix `.software-live-`,
mode 0640, group set by `fchown` when a group is given (state: `metrics`;
projection: `software-estate-publisher`; caches: none, so root:root),
JSON plus trailing newline, `fsync`, `rename` over the target; the
temporary file is removed on failure, and the previous target stays.
On failure the previous `state.json` stays untouched (test
`test_atomic_state_permissions_and_failure_preserves_previous`).

### 3.6 Inventory projection (P1, `inventory_projection`, `export_inventory`, `:764-881`)

- Source safety: parent directory of the output is a directory, owned by
  uid 0, not group/world-writable (`lstat`); the source is opened
  `O_RDONLY|O_NOFOLLOW|O_NONBLOCK` and must be a regular file, uid 0,
  `nlink == 1`, not group/world-writable; at most 1 MiB.
- Output keys exactly `schema_version` (1), `source`
  (`"software-live/2"`), `host` (`[A-Za-z0-9_.-]{1,128}`),
  `observed_at_epoch` (positive finite number, unchanged from the source),
  `max_age_seconds` (1800), `checks` with exactly `os`, `postgresql`,
  `traefik`, each with exactly `status, observed, expected,
  installed_version, running_version, upstream_version, issues,
  issues_truncated` (texts ≤ 160 chars, ≤ 20 issues), and `apt` with exactly
  `status, indexes_fresh, pending_security_count`. The reader in
  `software_estate/files/collect.py:379-470` rejects any other key set, so
  this is a hard contract.
- Failure: stderr `inventory export failed: <Class>`, exit 1, no change to
  the existing projection. The unit ignores the exit status (`-` prefix).

### 3.7 systemd units (P1)

Unit names, timer schedule (`OnBootSec=30s`, `OnCalendar=*:0/15`,
`RandomizedDelaySec=30s`, `AccuracySec=10s`, `Persistent=true`), users
(collector root, endpoint `metrics:metrics`), and all hardening in
`roles/software_live/templates/*.j2` stay unchanged. The Rust programs must
work inside them: the collector under `ProtectSystem=strict`,
`ReadWritePaths=/var/lib/software-live -/var/lib/software-estate-observations`,
`PrivateTmp`, `UMask=0027`, `TimeoutStartSec=90`, `Nice=10`; the endpoint
with an empty `CapabilityBoundingSet`,
`RestrictAddressFamilies=AF_INET AF_UNIX`, `IPAddressDeny=any` plus
`IPAddressAllow=localhost 100.64.0.0/10`, `Type=exec`,
`Restart=on-failure`, `RestartSec=5`. The endpoint must not need
`AF_NETLINK` or any other address family, and libapt-pkg must not try to
write under `/var/cache/apt`.

### 3.8 Logging (P1 in content, P3 in form)

Python logs nothing on success, a traceback on unexpected errors and the
single export line. Rust logs nothing on success, one line per fatal error
to stderr (journald), never a credential, an `Authorization` header, a
request path or a policy value other than the host.

---

## 4. Non-goals and allowed differences

### 4.1 Non-goals

- `nyxmon_checks.py` stays Python. It is a deploy-time helper that runs only
  during Ansible plays as `become_user: nyxmon`, with its input on stdin
  (the ops-control 836b01d / ops-library 2.55.0 pattern). It is not a
  process of the fleet, and five ops-control playbooks use it. The role
  keeps installing it in every mode, also after the Python retirement (S12).
- Ansible-time Python (the `python3 -c` bind check in `tasks/main.yml:31-42`,
  Ansible modules) stays: Ansible needs `/usr/bin/python3` on the hosts anyway.
- No package is uninstalled. `python3-apt` is a dependency of
  `unattended-upgrades` on the Ubuntu hosts and is used by the Python
  rollback path until S12.
- No change to the schema (`schema_version` 2), JSON shape, issue codes,
  Nyxmon checks, port, path, credentials, unit names, file paths or modes.
- No new observations, no CVE applicability scanning, no new hosts
  (`heis` stays excluded), no macOS.
- No pyinfra port of the role (2), no change to `graphyard_vector`, the
  graphyard ingest tokens or the software_estate collector/publisher (the
  latter is its own Python timer, `software-estate-publisher.timer`, and is
  not part of this stream).
- No HTTP proxy support (Python's `urllib` would honour `*_proxy` variables;
  none are set in the units).
- The controller-side `scripts/software-live.py --policies` mode stays
  Python (ops-control tooling, not a fleet process).

### 4.2 Intentional divergences (P3, exhaustive)

1. **Password verification in process.** Python runs `htpasswd -vi` per
   request (`:732-739`). Rust verifies bcrypt in process with the `bcrypt`
   crate (`$2y$`/`$2b$`/`$2a$`, 72-byte truncation as Apache does). The role
   only writes bcrypt entries (`htpasswd -niB`, `tasks/main.yml:121-128`) and
   all four hosts have `$2y$` entries. An entry in another htpasswd format
   (MD5/SHA/crypt) yields 401 instead of a successful check. Fixtures for
   empty, 72+ byte, non-ASCII and `\r` passwords are generated with the real
   `htpasswd -vi` in a container (S4).
2. **HTTP framing.** Python answers `HTTP/1.0` with a `Server: BaseHTTP/…`
   banner and a `Date` header and closes the connection. Rust answers
   `HTTP/1.1` with `Connection: close`, `Date`, and no `Server` banner.
   Non-GET methods give 501 with `{"error": "unsupported_method"}` (Python:
   501 with an HTML body). Malformed request lines give 400 (Python: 400 HTML).
3. **JSON formatting.** State, caches, projection and responses use compact
   separators (Python: `", "`, `": "`). Keys stay sorted. Floats use the
   shortest round-trip form (same digits as Python's `repr`, possibly
   different exponent spelling). Exception: `policy_sha256` input (3.2) is
   byte-identical.
4. **Non-standard JSON** (`NaN`, `Infinity`) in state, caches, policy or
   endpoint configuration is rejected (Python accepts it). Our writers
   never produce it.
5. **Error texts.** Messages the Python code raises itself are reproduced
   verbatim with the Python class name (`ValueError: service stopped or
   managed binary missing`, `ValueError: MainPID changed during
   observation`, …; a fixture lists them). OS-level and library error
   texts (file not found, timeouts, TLS, HTTP status) use a stable Rust
   category name in place of the Python class (`OSError`, `Timeout`,
   `HTTPError`, `InvalidJSON`, …), same 240-character bound. Consumers
   read only `status`, `issues`, `observed` and `summary`.
6. **Dates** in lifecycle data: only `YYYY-MM-DD` is accepted. Python 3.11+
   `date.fromisoformat` also accepts `YYYYMMDD` and ISO week dates; a cycle
   with such a value is skipped as invalid. endoflife.date emits
   `YYYY-MM-DD` only.
7. **Fatal errors** print one line instead of a traceback; exit codes stay.
8. **APT failure classes** in `"APT observation failed (<Class>)"` are Rust
   categories (`HelperExit`, `HelperTimeout`, `InvalidHelperOutput`,
   `CacheOpen`, …).
9. **New flags** `--version` and `collect --report-usage` (3.1).
10. **Manual SSH mode on Rust hosts** (S11): `just software-live --host H`
    runs the installed release binary instead of streaming the checkout's
    Python file. It therefore reports with the deployed program, not with
    the ops-library checkout.

---

## 5. Architecture and crate choices

### 5.1 Layout (in the shared `rust/` workspace of ops-library)

```text
rust/software-live/            crate `software-live` (MIT), binary `software-live`
  PLAN.md  TESTMAP.md  README.md
  src/main.rs                  CLI (clap), exit codes, --version
  src/policy.rs                validate, policy hash (python-compatible formatter)
  src/report.rs                types, summary, freshness
  src/probe.rs                 trait System (clock, fs, readlink, stat, commands, fd exec, HTTP)
  src/traefik.rs  src/os.rs  src/postgresql.rs  src/upstream.rs  src/apt.rs (helper invocation)
  src/export.rs                inventory projection + safe source read
  src/atomic.rs                atomic JSON write with group
  src/serve.rs                 endpoint (hyper behind an `Endpoint` boundary, 5.4)
  fixtures/generate.py         fixture generator (imports the Python oracle)
  fixtures/*.json
  parity/run_parity.py         process-level parity harness
  parity/shadow_compare.py     live shadow comparison
rust/software-live-apt/        crate `software-live-apt` (GPL-3.0-or-later), binary `software-live-apt`
  LICENSE.GPL-3.0              the helper's own license file (section 12)
  src/main.rs                  prints the `apt` observation object (3.3) as JSON
```

### 5.2 APT: a separate helper binary (decided 2026-10-21, section 12)

The APT observation needs libapt-pkg semantics (origins, trust, version
comparison, candidate policy). The maintained binding is **`rust-apt`**
(0.11.3, 2026-09, gitlab.com/volian/rust-apt; the equivalent of python-apt).
Re-implementing APT's index, trust and candidate logic on raw `Packages` and
`Release` files would be exactly the kind of re-implementation this campaign
avoids. `rust-apt` has two consequences:

1. It links the distribution's `libapt-pkg` dynamically, and the soname
   differs between the targets: Ubuntu 24.04 has `libapt-pkg.so.6.0`
   (`libapt-pkg6.0t64`), Debian 13 has `libapt-pkg.so.7.0`. One binary
   cannot run on both, so the APT code is built **per distribution variant**
   (`ubuntu24.04`, `debian13`) inside the matching container image.
2. It is licensed **GPL-3.0-or-later** (libapt-pkg itself is GPL-2.0+,
   python-apt GPL-2.0+). ops-library is MIT.

To contain both, the APT code is a small separate executable,
`software-live-apt`, which `software-live collect` runs as a child process
(the same pattern as today's `apt-mark`, `pg_lsclusters` and `systemctl`
calls). The main binary `software-live` (serve, validate, collect,
export-inventory) stays MIT, links no C++ and no libapt-pkg, and is one
portable glibc build for all hosts. The long-running endpoint therefore maps
neither libapt-pkg nor libstdc++. An OS upgrade that changes the libapt-pkg
soname breaks only the helper: the collector then reports
`apt.status: unknown` (critical `observation_ok` in Nyxmon) until a matching
variant is released, while the endpoint keeps serving.

Helper contract (P1 for its output): argv
`software-live-apt observe --max-age <seconds> --now <epoch>`, no stdin,
JSON object of 3.3 "APT" on stdout (≤ 4 MiB), exit 0 also for
`status: unknown` results it could produce itself; any other exit,
a timeout (60 s; the unit allows 90 s for everything), or invalid JSON
makes the main binary emit the "unknown" object (4.2 item 8). The main
binary finds the helper next to its own executable (`/proc/self/exe`
directory) and refuses to run it unless it is root-owned and not
group/world-writable. The helper sets `Dir::Cache::pkgcache ""` (exactly
what python-apt's `memonly=True` does, `apt/cache.py` of python-apt 2.7.7),
so it never writes under `/var/cache/apt`; S1 checks with `strace` in the
containers that no write is attempted (and additionally clears
`Dir::Cache::srcpkgcache` only if one is). It takes no APT lock and keeps the
`apt-mark showhold` subprocess for holds. `name` (pretty, native architecture
omitted) and `fullname` (`name:arch`) follow python-apt's
`Package.name`/`Package.fullname`; S1 confirms this against python-apt.

The rejected alternative was a `deb822`-based re-implementation in the
main crate (`debian-control`, `deb822-lossless`, `debversion`, with
`apt-cache policy` for the candidate). The owner chose `rust-apt` in the
separate helper (section 12); the alternative is not built.

### 5.3 Crates

| Need | Crate | Notes |
| --- | --- | --- |
| CLI | `clap` (derive) | usage errors exit 2 |
| JSON | `serde`, `serde_json` (`arbitrary_precision`) | sorted maps by default; lossless numbers; custom `Formatter` for the policy hash (3.2) |
| sha256 | `sha2`, `hex` | |
| upstream HTTPS | `ureq` 3 (rustls, `rustls-native-certs` for the system store) | synchronous; the collector has no async runtime |
| child processes with timeout | `std::process` plus `wait-timeout` | kill on timeout like `subprocess.run` |
| fd and stat details | `rustix` (`fcntl_setfd`, `fstat`, `fchown`, `fchmod`, `O_NOFOLLOW`) | |
| atomic file | `tempfile` (`Builder::prefix(".software-live-")`, `persist`) | plus `fsync` |
| users/groups | `nix::unistd::Group::from_name` or `uzers` | `grp.getgrnam` |
| os-release | a maintained parser crate if one matches Python's unquoting (fixture-tested); otherwise a 30-line parser with fixtures from `platform._parse_os_release` | decision recorded in S3c |
| regex | `regex` | the patterns of 3.3 |
| dates | `time` or `chrono` (date only, UTC) | |
| endpoint HTTP | `hyper` 1 (`server::conn::http1`) + `tokio` current-thread | see 5.4 |
| bcrypt | `bcrypt` (MIT) | 4.2 item 1 |
| base64 | `base64` (strict standard engine, padding required) | `b64decode(validate=True)` |
| APT (helper) | `rust-apt` | 5.2 |

### 5.4 Shared HTTP server crate

The metrics endpoints of the fleet (`backup_metrics_endpoint`,
`storage_metrics_endpoint`, `metrics_endpoint`, …) share the shape of this
endpoint: a fixed path, Basic auth against a role-written bcrypt
`htpasswd`, JSON, Tailscale or loopback bind, no request logging.
`rust/PLAN-foundation.md` has no shared library crate in F1 (its section 1;
`metrics-httpd` is a binary crate, not a library). S4 therefore implements
`serve.rs` on hyper 1 behind a small `Endpoint` boundary (bind check, auth,
handler), so that moving it into a shared crate, if a later foundation
slice extracts one, is mechanical. If such a crate is on `main` when S4 is
dispatched, the coordinator may tell S4 to use it; S4 then adds only the
software-live handler (404-before-auth order, the 503/401 bodies,
`with_freshness`).

---

## 6. Test strategy

### 6.1 Fixtures and TESTMAP (Python is the oracle)

- `fixtures/generate.py` imports `roles/software_live/files/software_live.py`
  and runs every scenario through the Python functions with the same kind
  of patches the Python tests use (`main_pid`, `binary_info`, `os.readlink`,
  `os.path.realpath`, `Path.exists`, `command`, `urllib.request.urlopen`,
  `time.time`, `platform.freedesktop_os_release`), recording the fake world
  and the Python result. The Rust code reads the world through the `System`
  trait (5.1), so a test replays the same world and compares the result
  under the P1/P2 classes.
- A CI test (`tests/test_software_live_rust_fixtures.py`, Python) fails when
  a committed fixture no longer matches the Python code (precedent:
  nyxmon `test_agent_rs_fixtures.py`).
- `TESTMAP.md` (created in S2) maps every Python test to its Rust
  counterpart and records the status per slice (`done`, `pending S<n>`,
  `n/a` with reason). Initial map:

| Python test (`tests/test_software_live.py`, `tests/test_software_health_bridge.py`) | Rust counterpart | Slice |
| --- | --- | --- |
| `test_deployed_programs_support_python_311` | n/a (Python only; the Python file stays the oracle) | — |
| `test_numeric_release_comparison` | `version`/`numeric_version` fixtures | S2 |
| `test_matching_process_and_binary`, `test_replaced_disk_binary_is_not_a_completed_update`, `test_same_version_different_bytes_is_drift`, `test_unknown_upstream_never_passes`, `test_new_upstream_and_unassigned_desired_are_visible`, `test_deleted_and_wrong_paths_are_visible`, `test_unexpected_process_image_is_never_executed`, `test_bounded_pid_retry`, `test_stopped_service_and_probe_errors_are_unknown`, `test_expected_absence_and_unexpected_other_path`, `test_binary_identity_and_in_place_change` | `traefik` fixtures plus a Linux-only test that executes a real fake binary through a pinned descriptor | S3b |
| `test_upstream_failure_warns_without_claiming_local_collection_failed`, `test_failed_upstream_refresh_retains_old_timestamp_only_as_evidence`, `test_upstream_daily_cache_and_unparseable_release`, `test_lifecycle_daily_cache_and_failed_refresh_preserves_evidence`, `test_lifecycle_refresh_skips_malformed_irrelevant_cycles`, `test_cached_timestamp_is_used_not_file_touch` | `upstream` fixtures plus a local HTTPS fake server; cross-implementation cache tests | S3a |
| `test_os_lifecycle_reports_desired_drift_and_lts_phase`, `test_os_boolean_support_state_is_applied_at_observation_boundary`, `test_boolean_lifecycle_fields_preserve_known_support_state` | `os` fixtures | S3c |
| `test_postgresql_minor_and_extra_clusters_are_visible`, `test_expected_postgresql_absence_is_healthy`, `test_postgresql_cluster_parser_omits_data_paths`, `test_postgresql_cluster_parser_rejects_unsafe_identity` | `postgresql` fixtures | S3c |
| `test_security_packages_include_held_and_pinned_versions` | helper tests on a fake APT root in the variant containers; python-apt vs helper comparison | S3d |
| `test_atomic_state_permissions_and_failure_preserves_previous` | `atomic` tests (mode, group, failure keeps the old file) | S3f |
| `test_invalid_policy_and_public_bind_fail` | `policy` fixtures, `serve` bind tests | S2, S4 |
| `EndpointTests.test_http_auth_freshness_and_malformed_state` | `serve` integration tests plus endpoint parity (6.2) | S4, S5 |
| `NyxmonTests.test_idempotent_targeted_upsert_and_reenable` | n/a (`nyxmon_checks.py` stays Python, 4.1) | — |
| `test_allowlisted_projection_roundtrip_preserves_time_and_unknowns`, `test_projection_rejects_invalid_source_not_manufacture_success`, `test_export_atomic_permissions_and_failure_preserves_prior_file`, `test_export_mode_never_collects_or_connects` | `export` fixtures and tests; Rust output read by the Python reader | S3e |
| `test_reader_rejects_stale_future_cross_host_and_extra_fields`, `test_reader_refuses_nonroot_writable_or_linked_paths`, `test_unavailable_health_is_explicit_partial_failure_and_opt_in` | n/a (reader side, software_estate; S3e adds a test that runs this reader on Rust output) | S3e |

### 6.2 Parity harness (both implementations, identical inputs)

`parity/run_parity.py` (stdlib Python, runs in CI and locally on Linux):

- **validate**: a policy matrix (valid, each invalid rule, extra keys,
  non-ASCII) → equal exit codes; equal `policy_sha256` via
  `collect --config-json` in a fake world.
- **endpoint**: start Python `serve` and Rust `serve` on loopback with the
  same `endpoint.json`, `htpasswd` (generated with `htpasswd -niB`) and
  state file; a request matrix (paths, query string, missing/malformed/
  wrong auth, oversized header, wrong user, `\n` in password, valid auth;
  states: valid, stale, future, schema 1, `2.0`, missing summary key, bool
  timestamp, missing file, malformed JSON) → equal status codes, equal JSON
  bodies except `meta.age_seconds` (P2), the 401 header present; P3 item 2
  differences are expected.
- **export-inventory**: the same source files (valid, each rejection,
  unsafe modes, symlink, hard link, oversized) → equal exit codes and
  identical projection objects; the Python reader from software_estate
  accepts the Rust output.
- **cross-reads**: Python `serve` on a Rust-written state, Rust `serve` on
  a Python-written state; each implementation consumes the other's caches
  (fresh, stale, invalid) with the same `cached`/`last_success` outcome.
- **collect in a container**: in `ubuntu:24.04` and `debian:13` images with
  real APT lists, a fake ELF `traefik` (built by the test, prints
  `Version: 3.7.9`) started as a process whose PID a `systemctl` shim in
  `PATH` reports, a `pg_lsclusters` shim, and a local fake upstream server
  via a test-only base-URL override available only in test builds: run
  Python `collect` and Rust `collect` on the same policy and compare under
  P1/P2 (`generated_at_epoch`, ages, upstream `checked_at_epoch` are P2;
  `apt.pending_security_updates` must be identical).

### 6.3 Shadow comparison (live)

`parity/shadow_compare.py` (controller side) takes the production
`state.json` and the shadow `state.json` (fetched read-only with
`ssh root@<host> cat …`; they contain versions and package names, no
secrets) and compares them: P1 fields must match unless the difference is
explained by a change between the two observation times (an APT list
refresh, a Traefik or PostgreSQL restart, an upstream release); each such
case is listed with its evidence. `policy_sha256` must be identical. The
projections (`software-health.json` vs the shadow projection) are
compared the same way.

### 6.4 CI and just recipes

`just rs-software-live` (fmt, clippy `-D warnings`, tests),
`just rs-software-live-fixtures` (regenerate fixtures),
`just rs-software-live-parity` (parity harness; needs Docker for the
container cases), wired into the F1 CI workflow. `just test-software-live`
keeps running the Python tests unchanged.

---

## 7. Build, release, role switch

### 7.1 Targets

- `software-live`: `x86_64-unknown-linux-gnu`, built by the F2 pipeline
  on `ubuntu-22.04` with the foundation's glibc floor 2.35
  (`PLAN-foundation.md` section 2), `--locked` and the pinned toolchain;
  `NEEDED` only glibc/libgcc.
- `software-live-apt`: built inside `ubuntu:24.04` (links
  `libapt-pkg.so.6.0`) and `debian:13` (links `libapt-pkg.so.7.0`);
  `NEEDED` only glibc, libgcc, libstdc++ and the expected libapt-pkg soname;
  its glibc floor is the variant's own (2.39 and 2.41), since each variant
  runs only on its distribution.

### 7.2 Release artifacts

Per release tag (F2 grammar `<crate>-v<semver>`, e.g.
`software-live-v0.1.0`), one archive per variant:
`software-live-<ver>-x86_64-unknown-linux-gnu-<variant>.tar.gz` with exactly
the regular files `software-live`, `software-live-apt`, `LICENSE` (MIT, the
workspace's `rust/LICENSE`) and `LICENSE.GPL-3.0` (the helper's), plus
`.sha256` files. The tag is cut from the `software-live` crate version; the
helper crate carries the same version. The `software-live` binary is the same
build in both archives. Deterministic archives, `--version` smoke test
against the tag commit, as in nyxmon 8.2.

### 7.3 Role `software_live` (ops-library)

New defaults:

```yaml
software_live_impl: python            # python | rust
software_live_rust_version: ""        # e.g. "0.1.0"; required for impl rust or shadow
software_live_rust_sha256: {}         # {ubuntu24.04: <64 hex>, debian13: <64 hex>}
software_live_rust_release_url: >-    # F2 naming plus the variant suffix (7.2)
  https://github.com/ephes/ops-library/releases/download/software-live-v{{ software_live_rust_version }}/software-live-{{ software_live_rust_version }}-x86_64-unknown-linux-gnu-{{ _software_live_variant }}.tar.gz
software_live_rust_local_archive: ""  # controller path, development only
software_live_rust_keep_versions: 3
software_live_rust_shadow: false      # shadow units, section 8.1
```

Tasks (`tasks/rust.yml`, `tasks/impl.yml`, `tasks/verify_impl.yml`,
`tasks/rust_pins.yml`, after the policy and endpoint configuration and
before the units):

0. **Live state** (read only, before any task of this list changes
   anything): `_software_live_protect` collects every version this host
   runs or is configured to run right now, each parsed from a path of the
   form `{{ software_live_install_dir }}/releases/<version>/software-live`:
   the `ExecStart=` of the existing production drop-ins of step 4 (endpoint
   and collector `impl.conf`), the `ExecStart=` of the existing shadow units
   (8.1), `readlink /proc/<MainPID>/exe` of the running production and
   shadow endpoints, and the executables of the running production and
   shadow **collector** runs. A collector run (oneshot, up to 90 s) can
   still execute vN after its unit, the endpoint and the pin moved to a
   newer version, so its `ExecStart=` alone does not name what runs: for
   each collector unit whose `ActiveState` is `activating`, `active`,
   `deactivating` or `reloading`, step 0 reads every PID in the unit's
   cgroup (`ControlGroup=` → `cgroup.procs`; this covers the `MainPID` of
   `collect`, its `software-live-apt` child, and the `ControlPID` of the
   `ExecStartPost=` export) and adds the version of each
   `readlink /proc/<pid>/exe` (a ` (deleted)` suffix is stripped before
   parsing; the binary and `software-live-apt` lie in the same
   `releases/<version>/` directory). A PID that exited between listing and
   reading contributes nothing. A Python command contributes nothing. A
   drop-in or shadow unit that exists but cannot be read, a command or
   executable that names a path under `releases/` that does not parse, a
   collector unit in one of those states whose cgroup cannot be listed, or
   a listed PID that still exists but whose executable cannot be resolved,
   sets `_software_live_live_unknown`; then step 7 does not prune in this
   play (fail closed: unknown live state never leads to a deletion). A
   collector run that starts after step 0 executes the drop-in's version,
   which step 0 already protects (old drop-in) or which is pinned (new
   drop-in, step 4).
   `_software_live_last_live` is the version in the existing
   `.pins/software-live` (the version last verified live in the production
   units, step 7), or, when that pin is absent, the version of the running
   production endpoint's executable, if it is a Rust release.
1. Assert `software_live_impl in ['python', 'rust']`. **Rollback first:**
   when impl is `python`, the drop-ins of step 4 are removed and the
   handlers are flushed right away (`meta: flush_handlers`: daemon reload,
   restart of the endpoint and the timer), so the production units run
   Python **before** any Rust task. Only then do shadow tasks (8.1) run, if
   the shadow is on; they touch only the shadow units and directory, so
   their failure cannot leave or put a Rust process in the production
   units. A pinned but broken release (does not start, reports `unknown`,
   wrong checksum, missing variant) therefore never blocks the Python
   rollback. S6 tests both cases: impl `python` with shadow off and with
   shadow on, each with a pinned version whose archive is missing or whose
   candidate fails validation, converge to Python in the production units.
2. For impl `rust` or shadow `true`: a version and a 64-hex checksum for
   this host's variant (or a local archive). The variant comes from
   `/etc/os-release` (`ubuntu` + `24.04` → `ubuntu24.04`, `debian` + `13` →
   `debian13`); anything else fails the play before any change. Install the
   release with the **F3 role** (`include_role: rust_release_binary`,
   `tasks_from: install`; `name: software-live`, the variant's
   `release_url` and `sha256`, `local_archive`, `fail_hard: true`, the extra
   archive members of 7.4) with `install_root:
   {{ software_live_install_dir }}/releases`, so the F3 layout
   (`<version>/software-live`, `.archive-sha256`, `.pins/`) lies inside the
   dedicated directory the path guard of `tasks/main.yml:21-29` demands and
   is removed by `software_live_remove` without changes (root:root 0755). An
   existing version directory is never modified; a different archive for an
   installed version fails the run (F3). The binary is put in place ahead of the
   switch by deploying with the shadow on (S9), not by impl `python`.
3. Validate the candidate by its versioned path before anything points at
   it: `--version` reports the pinned version; `validate --config
   policy.json` succeeds; `software-live-apt observe` exits 0 and prints
   `status: ok` (run as root, read-only). A failure stops the play with the
   running units, the drop-ins and every installed version untouched.
4. Drop-ins, present iff impl is `rust`, naming the versioned binary (no
   `current` symlink):
   `/etc/systemd/system/software-live-endpoint.service.d/impl.conf`
   (`ExecStart=` reset, then `ExecStart=<bin> serve --config …`) and
   `/etc/systemd/system/software-live-collector.service.d/impl.conf`
   (`ExecStart=` reset plus the Rust `collect` with the same arguments;
   `ExecStartPost=` reset plus the Rust `export-inventory` with the `-`
   prefix when the export is enabled). The base templates stay as they are
   (Python commands) until S12. Any drop-in change notifies the existing
   handlers (daemon reload, restart endpoint, restart timer).
5. The task "Validate software observation policy" (`tasks/main.yml:101-110`)
   uses the Rust candidate when impl is `rust`.
6. After the handlers and the initial collection (`tasks/main.yml:214-219`):
   verify the running implementation, retrying up to 30 s: endpoint active
   and `readlink /proc/<MainPID>/exe` equals the versioned binary (rust), or
   `/proc/<MainPID>/cmdline` contains `software_live.py serve` (python);
   collector `ExecMainStatus=0` and `state.json` newer than the run start.
7. Only after 6 succeeded, pin and prune with F3 (`tasks/rust_pins.yml`;
   it executes no release binary, so with impl `python` it runs after the
   units already run Python and cannot block the rollback):
   - **Rollback pin first.** When `_software_live_last_live` (step 0) is
     set and differs from the version now verified live (or impl is
     `python`), F3's `previous` rollback pin of consumer `software-live`
     moves to `_software_live_last_live`; otherwise it stays as it is. It
     never moves in a play whose verification (step 6) failed, so it
     always names a version that really ran in the production units
     before the current one. Example: v1 live; switch to v2 → previous v1;
     roll back to v1 → previous v2; switch to v3 → previous v1. The version
     a Rust-to-Rust rollback returns to is therefore always installed,
     independent of `keep_versions` and of the order of installs.
   - **Pins.** `tasks_from: pin` writes `.pins/software-live` with the
     version the production units run (impl `rust`) or removes it (impl
     `python`); with the shadow on, `.pins/software-live-shadow` names the
     shadow units' version and is removed when the shadow is turned off.
   - **Prune.** Unless `_software_live_live_unknown` is set,
     `tasks_from: prune` with `keep_versions` (asserted ≥ 2) and
     `protect: {{ _software_live_protect }}` (step 0). F3 keeps the newest
     `keep_versions` versions, every pinned version, the `previous` pin
     and every protected version, and never prunes after a failure in the
     same play. The protect list covers live state that no pin names yet,
     e.g. a drop-in left by an earlier play whose verification failed.

   The mechanism (the `protect` input and the `previous` pin, their file
   format and F3's own tests) is F3's (7.4, owner decision 2026-10-21);
   this role only fills them from the live state and moves `previous` only
   after verification.
8. `software_live_remove` also removes both drop-in directories and the
   shadow units.
9. Secrets: no new secret, no `environment:` under `become_user`
   (`tests/test_become_environment_secrets.py`); the Nyxmon helper keeps
   its stdin input.

README (variables, switch, rollback, variants), `docs/source/roles/…`
include files unchanged, CHANGELOG entry under "Unreleased" (never bump
`galaxy.yml`). Tests in `tests/test_software_live_impl.py` render the
templates and drop-ins for both impls and both variants, check the
variable validation, and that `nyxmon_checks.py` is installed in every mode.
An `ansible-playbook` run against localhost (as F3's test, with a temporary
install directory and fake versioned archives) runs step 0 and
`tasks/rust_pins.yml` with given drop-ins and verification results and
asserts:

- the sequence v1 → v2 → v1 (rollback) → v3 with `keep_versions: 2`
  keeps v1 (the `previous` pin) next to v3 and v2; continuing with v4,
  v3 stays as `previous` and v1 and v2 are pruned;
- a production drop-in naming a version that no pin names (left by a play
  whose verification failed) protects that version from the prune of a
  later successful play;
- a failed verification moves neither `.pins/software-live` nor the
  `previous` pin and prunes nothing;
- an unreadable or unparseable drop-in or shadow unit skips the prune;
- **(mandatory, owner decision 2026-10-21)** a production or shadow
  collector run still executing vN (and its `software-live-apt` child)
  after its unit, the endpoint and both pins moved on keeps vN from being
  pruned: v1 live, a collector run of v1 still active, switch to v2, then
  v3 with `keep_versions: 2` while that run is active → v1 stays
  installed; a collector unit in a running state whose executable cannot
  be resolved skips the prune;
- switching from `rust` to `python` removes the production pin, sets
  `previous` to the last Rust version, and keeps that version installed;
- a re-run with the same version moves nothing and reports no change.

### 7.4 Requirements on F1, F2 and F3 (to be agreed with the foundation stream)

- **F1** (workspace): this stream appends `software-live` and
  `software-live-apt` to `members` in S2/S3d (foundation section 1). The
  helper crate sets its own `license = "GPL-3.0-or-later"` instead of the
  workspace's MIT. S3d adds the `cargo-deny` exceptions in `rust/deny.toml`
  scoped to `rust-apt` (and to the helper crate itself unless
  `[licenses.private] ignore` already covers unpublished members), as the
  foundation's "explicit line with the crate that brings it" rule demands.
  `rust/` is excluded from the collection build by F1, not by this stream.
- **Dependency-graph check** (foundation sections 2 and 9, assigned to
  this stream; S3d delivers it together with the deny exception). The
  exception is scoped by crate, not by consumer, so `cargo deny` alone
  would let any member depend on `rust-apt`. S3d adds a subcommand to
  F2's `rust/scripts/release_checks.py` (e.g. `apt-isolation`) that reads
  the `resolve` graph of `cargo metadata --format-version 1 --locked
  --all-features` (no `--filter-platform`; normal, build and dev edges)
  and fails when `rust-apt` is reachable from any workspace member other
  than `software-live-apt`, including through a member that depends on
  `software-live-apt` itself. CI rejects such a change: the default `rust`
  job runs the check (`cargo metadata` needs no libapt-pkg, so it runs on
  `ubuntu-22.04` although that job does not build the helper), and the F2
  release job runs it before packing. Unit tests with metadata fixtures:
  a direct, a transitive, a build-only, a dev-only and a feature-gated
  path from another member each fail; `rust-apt` reachable only from the
  helper passes; a graph without `rust-apt` passes.
- **F1** (CI): a job that builds and tests `software-live-apt` inside
  `ubuntu:24.04` and `debian:13` with `libapt-pkg-dev` and a C++ compiler
  (S3d adds it to `rust.yml`); the default `rust` job on `ubuntu-22.04`
  excludes the helper (`--workspace --exclude software-live-apt`), since
  Ubuntu 22.04's libapt-pkg is not a target.
- **F2** (release): the tag prefix `software-live-v*` in the trigger list;
  a build matrix that builds the helper inside the two variant images and
  packs one archive per variant with the members of 7.2; per-binary
  `NEEDED` allowlists and glibc floors in `release_checks.py` (7.1); the
  release job's workspace checks exclude the helper as the CI job does (it
  is built and tested in its variant images).
- **F3** (install role): an input for additional archive members (here
  `software-live-apt` and `LICENSE.GPL-3.0`) next to `<name>` and `LICENSE`,
  installed with the same ownership and modes.
- **F3** (version protection, owner decision 2026-10-21, given to F3):
  `prune` never deletes (a) a version in an explicit `protect` list that
  the consuming role fills from the live state, or (b) the consumer's
  separate `previous` rollback pin, which the consumer moves only after a
  new version is verified live. F3 owns the mechanism (inputs, pin file,
  its own tests, `PLAN-foundation.md` 6.2); this stream's duties are the
  consumer side of 7.3 (step 0 fills `protect` from the drop-ins, the
  shadow units, the endpoints' `/proc/<MainPID>/exe` and the executables
  of running collector runs; step 7 moves `previous` only after step 6)
  and the S6 tests listed there. F3's own tests include the same case on
  its side: a protected version that is neither among the newest
  `keep_versions` nor pinned survives the prune (section 12).

Whatever F2 or F3 does not provide when S6/S7 start, S6 (F3 input) and S7
(F2 matrix) add to the foundation's files in agreement with the foundation
stream; this plan does not create a second release workflow or a second
install mechanism.

### 7.5 ops-control

- `inventories/prod/group_vars/all.yml`: `software_live_rust_version`,
  `software_live_rust_sha256` (variant map), so the four hosts share one pin.
- `inventories/prod/host_vars/<host>.yml`: `software_live_impl` and
  `software_live_rust_shadow` per host (staged canary and cutover; the
  inventory is the single place to flip, as for nyxmon and mailgun-relay).
- `playbooks/deploy-software-live.yml`: pre-task asserting the ops-library
  version that knows `software_live_impl` (existing pattern of
  `deploy-mailgun-relay.yml:17`); optional shadow endpoint check (8.1).
- `docs/SOFTWARE_LIVE.md`: shadow, cutover, verification, rollback runbook;
  CHANGELOG entry.

### 7.6 Rollback

- Normal: `software_live_impl: python` and `software_live_rust_shadow: false`
  in the host vars (the shadow is off after S10 anyway), then
  `just deploy-one software_live <host>` (under the deploy lock, in tmux).
  The role removes the drop-ins, reloads systemd, restarts the endpoint and
  the timer, and runs no Rust task, so it works even when the pinned release
  is broken (7.3 step 1); Python reads the Rust-written state and caches
  (3.3, P1).
- Emergency on the host (until S12):
  `rm /etc/systemd/system/software-live-{endpoint,collector}.service.d/impl.conf && systemctl daemon-reload && systemctl restart software-live-endpoint.service && systemctl start software-live-collector.service`,
  then flip the inventory before the next deploy.
- Rust to Rust: set the version and checksums that F3's `previous` pin of
  consumer `software-live` names (the version the production units ran
  before the current one); prune never removes it, so its directory is
  still installed (7.3 step 7).
- After S12: revert the S12 commit and redeploy (the Python file remains in
  the repository, 9 S12).

---

## 8. Rollout

### 8.1 Shadow (no production effect)

With `software_live_rust_shadow: true` the role installs, next to the
untouched Python units:

- `software-live-shadow-collector.service` (same sandbox as the collector,
  `ReadWritePaths=/var/lib/software-live/shadow`) running the Rust
  `collect --report-usage` with `--output /var/lib/software-live/shadow/state.json
  --cache /var/lib/software-live/shadow/upstream.json --group metrics`, then
  `-export-inventory` into `/var/lib/software-live/shadow/software-health.json`.
  Separate caches, so the shadow never touches the production caches; that
  costs one extra GitHub and endoflife.date request per host and day.
  `software-live-shadow-collector.timer` at `*:7/15` (between the
  production runs).
- `software-live-shadow-endpoint.service` as `metrics`, bound to
  `127.0.0.1:9119`, `IPAddressAllow=localhost` only, serving the
  **production** (Python-written) `state.json` through the Rust endpoint.
  In shadow mode the deploy playbook fetches both endpoints on the host
  (`ansible.builtin.uri`, `no_log: true`, as the existing verification) and
  asserts equal bodies except `meta.age_seconds`, and 401 without
  credentials on the shadow port.

`/var/lib/software-live/shadow/` is root:metrics 0750. Removing the flag
removes the shadow units and the directory.

### 8.2 Order and windows

1. staging (Debian 13 variant, canary): shadow ≥ 24 h.
2. macmini, fractal, production: shadow ≥ 24 h, concurrently with staging's
   cutover at the earliest.
3. Cutover order: staging → macmini → fractal → production, one host at a
   time, each verified before the next.

The ops coordination has announced possible work on production (Traefik
ACME move, window until 2026-10-30) and fractal (MinIO TLS and replication
users). Cutovers on fractal and production happen only after the
coordinator confirms that no such change is scheduled at the same time.
The echoport-command-guard cutover is scheduled last in the campaign and
never runs alongside other production or staging changes (section 12), so
no S9, S10 or S12 deploy of this stream overlaps it.

Every production or staging deploy of a role change (S9 with the S6 role,
S12 with its own change) needs the installed collection to contain it:
the coordinator makes the collection release commit (`galaxy.yml` bump
plus CHANGELOG heading) on ops-library `main` right before that deploy;
workers never bump `galaxy.yml` (section 12).
A Traefik restart during a collection makes the Traefik observation
`unknown` for one run (PID race); this is expected and is not a Rust
regression.

### 8.3 Verification per host after the cutover

- The playbook's own post-tasks (401 anonymous; schema 2; host; fresh;
  `os.observed`; `postgresql.observed`).
- Endpoint process: `readlink /proc/<pid>/exe` is the versioned binary,
  user `metrics`, listener only on `<tailscale-ip>:9110`.
- Two consecutive timer runs: `ExecMainStatus=0`, fresh `state.json`
  root:metrics 0640, `software-health.json` root:software-estate-publisher
  0640 with a new `observed_at_epoch`, caches root:root 0640.
- Nyxmon: the host's "Software health (HOST)" check result after the
  next hourly run has the same severity as before the cutover (read-only
  look at the Nyxmon database or dashboard).
- The next software-estate-publisher run on that host reports the
  `software_live` application without a coverage gap.
- Lean measurements (section 10).

### 8.4 Rollback drill (on staging, during S10)

Flip staging to `python` through the inventory and `deploy-one`, verify as
in 8.3 (Python process, Python reading Rust-written caches without extra
upstream requests and with `last_success` intact), flip back to `rust`,
verify again. Then the emergency path once (remove the drop-ins on the
host, verify Python, redeploy `rust`). Results go into the S10 report.

### 8.5 Soak and stop criteria

Stop and roll back the host if: the endpoint is not serving, a collection
fails (`ExecMainStatus != 0`), `observation_ok` turns false where Python
was true, a Nyxmon severity changes without a matching real change, the
projection is rejected by the software_estate reader, or memory exceeds
twice the budget of section 10. The soak before the Python retirement is
7 days on all four hosts without a rollback (owner decision, section 12).

---

## 9. Implementation slices

Every implementation slice ends with a review by gpt-6.1-sol at high
reasoning (`codex-review-loop`), then commit, push and, where the slice says
so, deploy. A slice gets at most three review rounds; the third round
reviews only the repair delta of round 2. If round 3 is not clean, the
worker stops and reports to the coordinator instead of merging (owner rule,
section 12). Slices touching production take the shared deploy lock (2).
Hours are for one worker.

| Id | Title | Depends on | Parallel | Touches production | Hours |
| --- | --- | --- | --- | --- | --- |
| S1 | Spike: `rust-apt` helper in `ubuntu:24.04` and `debian:13` containers vs python-apt on the same lists (memonly, origins and `trusted`, `version_compare`, candidate, holds, `name`/`fullname`); report appended to this plan | — | yes, from the start | no | 3 |
| S2 | Crate skeleton in the F1 workspace (append to `members`); CLI and exit codes; policy validation; python-compatible policy hash; report types, summary, freshness; `System` trait; `fixtures/generate.py` and the fixture check test; `TESTMAP.md` | F1 | no (critical path) | no | 4 |
| S3a | Upstream lookups and caches (GitHub, endoflife.date), cross-implementation cache compatibility, TLS via system store | S2 | yes (with S3b–S3e, S4) | no | 3 |
| S3b | Traefik observation: MainPID, `/proc` link checks, pinned-descriptor execution, identity checks, retry | S2 | yes | no | 3 |
| S3c | OS and PostgreSQL observation: os-release, lifecycle evaluation, `pg_lsclusters`, pinned postmaster probe | S2 | yes | no | 3 |
| S3d | `software-live-apt` helper (`rust-apt`, GPL-3.0-or-later, `LICENSE.GPL-3.0`, `cargo-deny` exception) and its invocation from `collect`; variant container CI job; the dependency-graph check that CI uses to reject `rust-apt` reachability from every member except `software-live-apt`, with its fixture tests (7.4) | S1, S2, F1, F2 (`release_checks.py`) | yes | no | 5 |
| S3e | `export-inventory`: safe source read, projection, atomic write with group; Python reader accepts Rust output | S2 | yes | no | 2 |
| S3f | `collect` orchestration: order, `generated_at_epoch`, atomic state write, `--report-usage` | S3a–S3e | no | no | 2 |
| S4 | `serve`: endpoint on hyper behind the `Endpoint` boundary (5.4), bind check, Basic auth with bcrypt, `htpasswd` fixtures, freshness | S2 | yes (with S3*) | no | 3 |
| S5 | Parity harness (6.2) incl. the container collect cases; fixes found by it | S3f, S4 | yes (with S6) | no | 4 |
| S6 | Role switch (7.3): impl selector, variant detection, install/pin/prune via the F3 role (plus the extra-members input, 7.4, if F3 lacks it), live-state `protect` list and `previous` rollback pin (7.3 steps 0 and 7) with the localhost sequence tests, candidate validation, drop-ins, verification, shadow units (8.1), `software_live_remove` update, README, CHANGELOG, tests | F3 (incl. `protect` and `previous`), S2 (CLI contract) | yes (from S2 on) | no | 4 |
| S7 | Release `software-live-v0.1.0`: F2 workflow extension for the variants and the tag prefix (7.4), release checks, tag | F2, S5 | no | no (GitHub release only) | 3 |
| S8 | ops-control (7.5): group/host vars with the pins and `impl: python`, shadow flag, version pre-task, runbook in `docs/SOFTWARE_LIVE.md`; the coordinator's collection release commit containing S6 (8.2) is a precondition for S9 | S6, S7 | no | no | 2 |
| S9 | Shadow on staging, then on macmini, fractal, production (deploy with `shadow: true`, impl python); ≥ 24 h; `shadow_compare.py` reports; lean measurements | S8, coordinator's collection release containing S6 (8.2) | yes (S11 in parallel) | yes (new shadow units only) | 2 + soak |
| S10 | Cutover staging → macmini → fractal → production with verification (8.3) and the rollback drill on staging (8.4); shadow off afterwards | S9, coordinator check (8.2) | no | yes | 3 |
| S11 | Manual CLI in ops-control: for hosts with impl `rust`, run the installed versioned `software-live collect --config-json` over SSH (path from the inventory pins) instead of streaming Python; keep the controller allowlist and timeouts; update ops-control `tests/test_software_live.py` and docs | S8 | yes (with S9/S10) | no | 2 |
| S12 | Python retirement, ≥ 7 days after S10 on all four hosts without a rollback (section 12): role default `rust`, base templates render the Rust commands (drop-ins removed), stop installing `software_live.py` and remove the deployed copy and `__pycache__` (keep `nyxmon_checks.py`), drop `python3-apt` from `software_live_packages` (no uninstall), keep `software_live.py` in the repository as the oracle for fixtures and parity, docs and CHANGELOG; merge, then the coordinator's collection release commit (8.2), then deploy to all four hosts | S10 + soak, S11 | no | yes | 3 |

Parallelism:

- From the start: S1 (spike), and as soon as F1 lands, S2. S6 needs F3,
  S7 needs F2; both foundation slices run in parallel with S2–S5.
- After S2: S3a, S3b, S3c, S3d (needs S1 and F2's `release_checks.py`;
  F2 runs in parallel with S2), S3e, S4 and S6 (needs F3) concurrently
  (up to seven workers; they touch separate modules or the role).
- After S3a–S3e: S3f; after S3f and S4: S5. S6 can finish meanwhile.
- After S8: S9 and S11 concurrently; S10 after S9.
- S12 waits for the soak.

Critical path: F1 → S2 → S3d (or the slowest S3*) → S3f → S5 → S7 (needs
F2) → S8 → collection release → S9 (24 h) → S10 → 7 days → S12.

Review gate per slice: the reviewer checks the slice against the sections
of this plan it names, the TESTMAP rows it changes, and the P3 list (no
undocumented divergence). A divergence found later is either fixed or
added to 4.2 in the same slice.

---

## 10. Lean goals (measured like nyxmon PLAN 4.4)

The budget is the memory the program allocates: the unit's cgroup memory
(`MemoryCurrent`, peak `MemoryPeak`) and anonymous RSS (`RssAnon`). Total
`ps` RSS also counts the file-backed binary mapping (shared page cache).

| Item | Python today | Budget |
| --- | --- | --- |
| Endpoint steady state, cgroup `MemoryCurrent` | 9.2–14.0 MiB | ≤ 4 MiB |
| Endpoint `RssAnon` | 8.9–13.7 MiB | ≤ 2 MiB |
| Endpoint `ps` RSS | 17.6–25.6 MiB | ≤ 8 MiB |
| Endpoint startup to listening | — | ≤ 100 ms |
| Collector peak (self + children `maxrss`, from `--report-usage`; on staging also the systemd "memory peak") | 80.7 MB cgroup peak on staging | ≤ 64 MiB (dominated by libapt-pkg's in-memory cache) |
| Collector CPU per run incl. export | 0.50–1.88 s | ≤ 1.0 s on macmini |
| `software-live` stripped binary | — | ≤ 6 MiB |
| `software-live-apt` stripped binary (without shared libs) | — | ≤ 2 MiB |

Measured during S9 (shadow) and S10 (after the cutover), recorded in the
S10 report. If glibc malloc arenas push the endpoint over budget,
`Environment=MALLOC_ARENA_MAX=2` goes into the drop-in before another
allocator is considered.

---

## 11. Risks

| Risk | Mitigation |
| --- | --- |
| libapt-pkg ABI per distribution; a future OS upgrade (e.g. Ubuntu 26.04) breaks the helper | helper isolated (5.2); fail-closed `apt.status: unknown`; OS-upgrade runbook gets the step "release the matching variant first"; Python remains the rollback until S12 |
| `rust-apt` API changes (pre-1.0, "breaking changes on minor") | exact version pin, `Cargo.lock`, container tests per variant |
| Re-exec / fd inheritance mistakes execute the wrong image | pinned-descriptor rule (3.3), dedicated Linux test with a real fake binary that re-execs |
| Python and Rust read/write the same caches during rollback | cache compatibility is P1 with cross-read tests (6.2) |
| Error texts differ and someone parses them | consumers read only status/issues/summary (1.5); P3 item 5 |
| GitHub API rate limit (60/h unauthenticated per IP) | daily cache per host; the shadow adds one request per host and day |
| endoflife.date schema change | same fail-closed handling as Python (`upstream_unknown`) |
| APT lists change between the Python and the shadow run | `shadow_compare.py` explains differences by time; repeated runs |
| Prune removes the version a Rust-to-Rust rollback needs, or one a unit still runs | F3 `previous` pin moved only after verification, `protect` list from the live drop-ins and processes, no prune on unknown live state, localhost sequence tests (7.3) |
| A member other than the helper pulls in `rust-apt` (GPL) | dependency-graph check in CI and in the release job (7.4, S3d) |
| Concurrent production work on fractal and production (8.2) | coordinator check before those cutovers |
| ops-control CI is red at `test-software-inventory` (unrelated eMudhra work) | S8/S11 run the targeted tests and record the pre-existing failure; this stream does not fix it |
| Graphyard Atlas step open | this stream changes neither `graphyard_vector` nor ingest tokens; the projection format is unchanged |

The owner questions of this plan (Q1, Q2) are decided; see section 12.

---

## 12. Owner decisions (2026-10-21)

The owner answered the planners' questions on 2026-10-21 (given in chat to
the campaign coordinator) and accepted every recommended answer.

For this stream:

- **Q1 APT binding and license: `rust-apt` in a separate helper.**
  `rust-apt` (GPL-3.0-or-later) is used only in the small helper binary
  `software-live-apt`, built per distribution variant (`ubuntu24.04` with
  `libapt-pkg.so.6.0`, `debian13` with `libapt-pkg.so.7.0`), with its own
  GPL license file (`rust/software-live-apt/LICENSE.GPL-3.0`, packed into
  the archive). The main `software-live` binary stays MIT and links no
  libapt-pkg (5.2, 7.2). The deb822 alternative is not built.
- **Q2 Python retirement: 7 days on all four hosts without a rollback.**
  S12 starts no earlier than 7 days after the last S10 cutover, and only if
  no host was rolled back in that time (8.5). `software_live.py` stays in
  the repository as the test oracle for fixtures and parity; it is no
  longer deployed after S12.

Campaign-wide decisions that bind this stream:

- **Foundation.** ops-library may get its first GitHub Actions workflows:
  `rust.yml` (CI for `rust/` only) and `rust-release.yml` with
  `contents: write` only in the publish job; binary releases are published
  on the public repository (F1, F2; 7.2, 7.4).
- **Collection releases.** The coordinator makes the collection release
  commit (`galaxy.yml` bump plus CHANGELOG heading) on ops-library `main`
  right before each production deploy that needs it; workers never bump
  `galaxy.yml` and write CHANGELOG entries under "Unreleased" (7.3, 8.2,
  S8, S12).
- **Scheduling.** The echoport-command-guard port is scheduled last in the
  campaign and never alongside other production or staging changes; this
  stream's production steps do not overlap it (8.2).
- **Review rounds.** A slice, and a plan, may get a third review round over
  the repair delta of round 2; if round 3 is not clean, the worker stops and
  reports (section 9). For this plan the owner allowed one fourth round
  over the repair delta of round 3 (2026-10-21); the slice rule of
  section 9 is unchanged.
- **Plan merged after round 4** (2026-10-21). Round 4 left one warning:
  step 0 of 7.3 protected the executables of the running endpoints but
  not of running collector runs. The owner decided to fix it and merge
  the plan without another plan review; the verification moves into the
  implementation slices. S6 (role switch) and the foundation slice F3
  (version protection) each get up to three gpt-6.1-sol high review
  rounds, and the running-collector case (7.3 step 0, the mandatory S6
  test, and the matching F3 prune test of 7.4) is a mandatory test in
  both.
- **Version protection** (2026-10-21, built into F3): prune never deletes
  a version in the consumer's `protect` list (filled from the live state)
  or the consumer's `previous` rollback pin (moved only after a new
  version is verified live). This stream fills both (7.3 steps 0 and 7,
  7.4) and tests the consumer side in S6.
