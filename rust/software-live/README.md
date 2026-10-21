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
- `collect` validates its policy, then stops with exit 1 until S3f;
  `serve` stops with exit 1 until S4; `export-inventory` checks its
  arguments (`inventory export failed: ValueError`), then stops with exit 1
  until S3e.
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
- `collect` does not call it yet (S3f).

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
- Nothing calls these yet: `collect` comes with S3f.

Slice S3c (OS and PostgreSQL observations, library only until `collect`
is wired in S3f):

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

## Layout

```
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
  tests/cli.rs                the binary against the Python program's exit codes
  tests/traefik_host.rs       Linux only: real processes and pinned descriptors
  fixtures/generate.py        writes fixtures/*.json from the Python program
  fixtures/*.json             generated; never edit by hand
  fixtures/rust-caches.json   caches as the Rust code writes them (see below)
```

## Checks

From the repository root of a worktree (never in a shared checkout; they
write `rust/target/`):

```bash
just rs-software-live                    # cargo fmt --check, clippy -D warnings, tests of this crate
just rust-check                          # the whole workspace as the CI job runs it
just rs-software-live-fixtures           # regenerate the fixtures (Python 3.12), check them under 3.13
just test-software-live-rust-fixtures    # drift check: fixtures and TESTMAP vs the Python program
```

After a change of `software_live.py`, regenerate the fixtures and update the
Rust code in the same change; `just test` fails until then.

`fixtures/rust-caches.json` is written by the Rust code, not by the
generator: after a change of the cache format,
`SOFTWARE_LIVE_BLESS=1 cargo test -p software-live rust_written` rewrites it,
then `just test-software-live-rust-fixtures` checks that the Python program
still reads it.

`--version` takes the commit from `SOFTWARE_LIVE_GIT_COMMIT` (7 to 40
lowercase hex digits, set by the release workflow), else `git rev-parse
HEAD`, else `unknown`.
