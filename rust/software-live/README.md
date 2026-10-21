# software-live (Rust port)

The Rust port of the `software_live` role's Python program
(`roles/software_live/files/software_live.py`): read-only Linux software
observations (Traefik, OS lifecycle, PostgreSQL, APT security updates), the
authenticated JSON endpoint that serves them, and their inventory projection.
[`PLAN.md`](PLAN.md) is the contract; [`TESTMAP.md`](TESTMAP.md) maps every
Python test to its Rust counterpart.

Nothing here is deployed yet: the role keeps running the Python program
until its switch slice (PLAN.md 7.3, slice S6) and a release (S7).

## Status

Slice S2 (crate skeleton):

- `software-live validate --config P | --config-json J` works as the Python
  program does (exit 0 valid; 1 invalid, unreadable or not JSON).
- The command line of every mode (PLAN.md 3.1) follows Python's `argparse`
  parser: options with every mode, in any order, `--opt=value`, unique
  prefixes, the last occurrence winning; usage errors exit 2.
  `--version` prints `software-live <version> (<commit>)`.
- `collect` works from S3f on (see below); `serve` stops with exit 1
  until S4.
- Slice S3d: `src/apt.rs` runs the APT helper `software-live-apt`
  (`../software-live-apt`, GPL-3.0-or-later, built per distribution
  variant) next to the executable and takes its JSON result, or reports the
  `unknown` object (PLAN.md 5.2); `collect` calls it (S3f).
- Library parts for the next slices: policy validation and
  `policy_sha256` (`src/policy.rs`), Python-compatible JSON
  (`src/pyjson.rs`), release numbers (`src/version.rs`), report types,
  summary and `with_freshness` (`src/report.rs`), and the `System` trait
  with the host implementation and the fixture world (`src/probe.rs`).

Slice S3b (Traefik observation, `src/traefik.rs`):

- `traefik::observe` is `observe_traefik`: `MainPID` from `systemctl`, the
  `/proc/<pid>/exe` link checks, the installed and the running binary
  hashed and probed, two attempts against a `MainPID` or link change, and
  the issues and status of PLAN.md 3.3.
- The running image is never executed through `/proc/<pid>/exe`: it is
  opened, the descriptor's own target must be the managed binary's real
  path, and the probe executes `/proc/self/fd/<fd>` with exactly that
  descriptor inherited (`System::run_inheriting`, no `unsafe`). The file
  identity must not change while it is hashed and probed.
- `collect` calls it (S3f).

Slice S3a (upstream lookups and caches):

- `upstream::upstream` and `upstream::lifecycle_upstream`: the latest
  stable Traefik release (GitHub) and the release cycles of an
  endoflife.date product, with the daily caches shared with the Python
  program: Rust reads the caches Python wrote and Python reads the ones Rust
  writes (`fixtures/rust-caches.json`, read by the Python test). A failed
  refresh is an `unknown` answer with the old cache as `last_success` and
  never rewrites the cache.
- HTTPS (`src/http.rs`): ureq over rustls, trust from the system store only
  (`rustls-native-certs`: `SSL_CERT_FILE`/`SSL_CERT_DIR`, else the
  distribution bundle), no proxy, no bundled roots.
- `atomic::write_json`: Python's `atomic_json` (mode 0640, optional group,
  `fsync`, rename; the old file stays on failure).
- `collect` calls them (S3f).

Slice S3c (OS and PostgreSQL observations, called by `collect` since S3f):

- `os::observe_os` with Python's os-release parser (`os::freedesktop_os_release`)
  and `postgresql::observe_postgresql` with `pg_lsclusters` parsing and the
  postmaster's version probe through a pinned descriptor, both keeping the
  fields observed before a failure.
- `lifecycle`: `lifecycle_ended` (on S3a's `upstream::lifecycle_date`), the
  cycle lookup and its evidence, the UTC date of the observation time.
- The PostgreSQL probe uses S3b's pinned-descriptor operations
  (`System::open`, `fstat`, `run_inheriting`). `System` gained `read_head`
  (the PID file), and every child now inherits no descriptor beyond its
  standard streams and the passed one (`subprocess`'s `close_fds`).

Slice S3e (inventory export, `src/export.rs`):

- `software-live export-inventory --config STATE --output O --group G`
  works as the Python program does: the export directory must be a
  root-owned directory writable by root alone; the state file is opened
  with `O_NOFOLLOW|O_NONBLOCK` and must be a regular, root-owned file with
  one link, writable by root alone, at most 1 MiB; the projection keeps the
  allowlisted fields only and is written with S3a's `atomic::write_json`
  (temporary file `.software-live-*` in the target directory, mode 0640,
  group `G` set through the descriptor, `fsync`, rename). Any failure prints
  `inventory export failed: <Class>`, exits 1 and leaves the previous
  projection as it was. It never reads `--config-json`, collects or
  connects.
- The projection is compact JSON with sorted keys (PLAN.md 4.2 item 3);
  the `software_estate` reader accepts it (`fixtures/rust-export.json`,
  read by the Python test, see below).

Slice S3f (`collect`, `src/collect.rs`, `src/usage.rs`):

- `software-live collect --config P | --config-json J [--cache C]
  [--output O [--group G]] [--report-usage]` works as the Python program
  does: the policy is validated (exit 1 if invalid), then the steps run in
  Python's order (the clock, the Traefik upstream if Traefik is expected,
  Traefik, the OS lifecycle upstream, the OS, the PostgreSQL lifecycle
  upstream if PostgreSQL is expected, PostgreSQL, APT through the helper)
  and `generated_at_epoch` is the clock read after the last observation.
  With `--output` the report is written atomically (mode 0640, group `G`
  through the descriptor when `G` is given and not empty; the group is
  looked up after the collection, an unknown group exits 1 and the previous
  state stays, as does any failed write); without it the report with its
  freshness is printed on stdout (the manual SSH mode). Exit 0 for every
  valid report, also when software needs attention; nothing on stdout with
  `--output`.
- `--cache` and `--output` are taken as Python's `pathlib.Path` spells them;
  a cache path without a name (`/`) stops `collect` with exit 1, as in
  Python.
- `--report-usage` (new, for the shadow units) adds one stderr line after
  the run, also after a failed one:
  `software-live: usage wall_s=… cpu_s=… maxrss_kib=… self_cpu_s=…
  self_maxrss_kib=… children_cpu_s=… children_maxrss_kib=…` (`getrusage`
  of the process and of its children; CPU is user plus system time; the
  total peak is the sum of both peaks, the bound of PLAN.md 10's collector
  peak). Other modes ignore the flag.
- Tests: `collect::tests` replay Python's `collect` with every step patched
  (`fixtures/report.json`, the order and the arguments of every step) and
  end to end in recorded worlds (`fixtures/collect.json`: the Traefik, OS
  and PostgreSQL worlds together, the upstream answers, the APT helper; the
  call log of every host access), and the state write on a real file
  system. `tests/cli.rs` runs no successful `collect`: it would read the
  host and ask GitHub and endoflife.date.

## Layout

```text
software-live/
  Cargo.toml  build.rs        build.rs embeds the commit for --version
  src/main.rs                 command line, exit codes
  src/lib.rs                  the modules below
  src/error.rs                PyError: Python exception class + message
  src/pyjson.rs               lossless json.loads, json.dumps(sort_keys=True), float repr
  src/policy.rs               validate_policy, policy_sha256
  src/version.rs              version(), numeric_version()
  src/report.rs               observations, summary, report, with_freshness
  src/lifecycle.rs            lifecycle dates, end states, cycle lookup, evidence
  src/os.rs                   os-release, observe_os
  src/postgresql.rs           pg_lsclusters, postmaster version probe, observe_postgresql
  src/probe.rs                trait System, HostSystem, the fixture world (tests)
  src/traefik.rs              observe_traefik, binary_info, main_pid
  src/http.rs                 the upstream HTTPS request (system trust store)
  src/upstream.rs             upstream, lifecycle_upstream, cache_variant, lifecycle_date
  src/atomic.rs               atomic_json
  src/apt.rs                  the APT observation through the helper software-live-apt
  src/export.rs               inventory_projection, export_inventory
  src/collect.rs              collect: the steps in Python's order, the state write, the manual output
  src/usage.rs                the --report-usage line (getrusage)
  tests/cli.rs                the binary against the Python program's exit codes
  tests/traefik_host.rs       Linux only: real processes and pinned descriptors
  fixtures/generate.py        writes fixtures/*.json from the Python program
  fixtures/*.json             generated; never edit by hand
  fixtures/rust-caches.json   caches as the Rust code writes them (see below)
  fixtures/rust-export.json   projections as the Rust code writes them (see below)
```

## Checks

From the repository root of a worktree (never in a shared checkout; they
write `rust/target/`):

```bash
just rs-software-live                    # cargo fmt --check, clippy -D warnings, tests of this crate
just rust-check                          # the whole workspace as the CI job runs it
just rs-software-live-fixtures           # regenerate the fixtures (Python 3.12), check them under 3.13
just test-software-live-rust-fixtures    # drift check: fixtures and TESTMAP vs the Python program
just rs-software-live-apt                # the APT helper in its ubuntu:24.04 and debian:13 containers (Docker)
```

After a change of `software_live.py`, regenerate the fixtures and update the
Rust code in the same change; `just test` fails until then.

`fixtures/rust-caches.json` is written by the Rust code, not by the
generator: after a change of the cache format,
`SOFTWARE_LIVE_BLESS=1 cargo test -p software-live rust_written` rewrites it,
then `just test-software-live-rust-fixtures` checks that the Python program
still reads it.

`fixtures/rust-export.json` is written by the Rust code, not by the
generator: `export::tests::rust_written_exports_are_committed` runs the real
export for every source the Python projection accepts and fails when the
committed file differs (`SOFTWARE_LIVE_BLESS=1 cargo test -p software-live
rust_written` rewrites it). `tests/test_software_live_rust_fixtures.py`
(`PythonReaderAcceptsRustExport`) then runs the `software_estate` reader on
each file and requires the value Python's own projection of the same source
gives.

`--version` takes the commit from `SOFTWARE_LIVE_GIT_COMMIT` (7 to 40
lowercase hex digits, set by the release workflow), else `git rev-parse
HEAD`, else `unknown`.
