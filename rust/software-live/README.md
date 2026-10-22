# software-live (Rust port)

The Rust port of the `software_live` role's Python program
(`roles/software_live/files/software_live.py`): read-only Linux software
observations (Traefik, OS lifecycle, PostgreSQL, APT security updates), the
authenticated JSON endpoint that serves them, and their inventory projection.
[`PLAN.md`](PLAN.md) is the contract; [`TESTMAP.md`](TESTMAP.md) maps every
Python test to its Rust counterpart.

Nothing here is deployed yet: the role can switch to a pinned release
(PLAN.md 7.3, slice S6), and the release `software-live-v0.1.0` (S7, see
"Release") exists, but no inventory pins it before S8, so every host keeps
running the Python program.

## Status

Slice S2 (crate skeleton):

- `software-live validate --config P | --config-json J` works as the Python
  program does (exit 0 valid; 1 invalid, unreadable or not JSON).
- The command line of every mode (PLAN.md 3.1) follows Python's `argparse`
  parser: options with every mode, in any order, `--opt=value`, unique
  prefixes, the last occurrence winning; usage errors exit 2.
  `--version` prints `software-live <version> (<commit>)`.
- `collect` works from S3f on and `serve` from S4 on (see below).
- Slice S3d: `src/apt.rs` runs the APT helper `software-live-apt`
  (`../software-live-apt`, GPL-3.0-or-later, built per distribution
  variant) next to the executable and takes its JSON result, or reports the
  `unknown` object (PLAN.md 5.2); `collect` calls it (S3f).
- Library parts for the next slices: policy validation and
  `policy_sha256` (`src/policy.rs`), Python-compatible JSON
  (`src/pyjson.rs`), release numbers (`src/version.rs`), report types,
  summary and `with_freshness` (`src/report.rs`), and the `System` trait
  with the host implementation and the fixture world (`src/probe.rs`).

Slice S4 (`serve`, the endpoint):

- `software-live serve --config /etc/software-live/endpoint.json` serves
  the state file as the Python endpoint does (PLAN.md 3.4): only `GET` of
  the exact configured path (`//` collapsed as in Python, a query string is
  404), 404 before authentication, Basic auth of the configured user against
  the role's `htpasswd` file (401 with `WWW-Authenticate`), the state re-read
  for every request through `with_freshness` (503 when missing or invalid,
  200 with `summary.fresh: false` when stale), sorted compact JSON with
  `Cache-Control: no-store`, no request logging.
- Startup (exit 1 on any failure): `bind` must be IPv4 loopback or
  `100.64.0.0/10`, `port` is read as Python's `int()` reads it, and the
  other keys must be strings (PLAN.md 4.2 item 14).
- `src/endpoint.rs` is the `Endpoint` boundary of PLAN.md 5.4 (bind check,
  Basic auth with a `Verifier`, hyper 1 on a current-thread tokio runtime
  with the handler on its blocking pool, one request per connection, the
  head within 5 s, the password check stopped after 5 s, at most 16
  connections at a time); `src/htpasswd.rs` is `htpasswd -vi` in process (PLAN.md 4.2 item 1),
  checked against the real `htpasswd` (`fixtures/htpasswd.json`).

Slice S5 (parity harness, PLAN.md 6.2):

- `parity/run_parity.py` runs the Python program and the Rust release
  binaries side by side on identical inputs and compares what they produce:
  `validate` for the whole policy matrix, the `serve` start-up matrix, every
  raw request of the endpoint fixture against both live servers (the real
  `htpasswd -vi` on the Python side), `export-inventory` with real root
  ownership, and `collect` on a real host — a fake Traefik and PostgreSQL
  (`parity/fakeproc.c`) running as processes, `systemctl` and
  `pg_lsclusters` shims, GitHub and endoflife.date served over HTTPS on
  127.0.0.1 through `/etc/hosts` with a throwaway CA in the system trust
  store (`parity/world.py`; neither program has a test-only override), APT
  on the image's real lists and the fake repositories of
  `software-live-apt/container/setup-world.sh` — including each program on
  the other's caches and state files and the software_estate reader on the
  Rust projections. `parity/compare.py` holds the P1/P2 rules.
- It runs as root in throwaway `ubuntu:24.04` and `debian:13` containers
  only: in CI as the last step of the `software-live-apt` job, locally
  with `just rs-software-live-parity` (Docker).
- Found and fixed: the endpoint takes at most 99 header lines (as Python's
  `http.client`) and refuses every request head over 64 KiB with 431
  however the bytes arrive (hyper alone let heads of up to about 128 KiB
  through when they came in one read); PLAN.md 4.2 item 2 now lists the
  head limits exactly.

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

## Release

The tag `software-live-v<version>` (the version of this crate and of
`software-live-apt`, which must be equal) makes `.github/workflows/rust-release.yml`
publish two archives (PLAN.md 7.1, 7.2; settings in
[`release.json`](release.json), the format in `../README.md` "Releases"):

```text
software-live-<version>-x86_64-unknown-linux-gnu-ubuntu24.04.tar.gz  (+ .sha256)
software-live-<version>-x86_64-unknown-linux-gnu-debian13.tar.gz     (+ .sha256)
```

each with exactly `software-live`, `software-live-apt`, `LICENSE` (MIT)
and `LICENSE.GPL-3.0`. `software-live` is one build on the `ubuntu-22.04`
runner (glibc ceiling 2.35), the same file in both archives (the variant
jobs check its sha256 before packing it); `software-live-apt` is built and
tested inside `ubuntu:24.04` (glibc ≤ 2.39, `libapt-pkg.so.6.0`) or
`debian:13` (glibc ≤ 2.41, `libapt-pkg.so.7.0`). Every binary's `--version`
must name the tag's version and commit; the helper also runs `observe` in
its image. The role pins a version and the sha256 of each variant's archive
(`software_live_rust_version`, `software_live_rust_sha256`, PLAN.md 7.3);
no release installs itself.

| Version | Tag | Release |
|---|---|---|
| 0.1.0 (S7) | `software-live-v0.1.0` | first release: `validate`, `collect`, `serve`, `export-inventory` |

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
  src/endpoint.rs             the Endpoint boundary: bind check, Basic auth, hyper server
  src/htpasswd.rs             htpasswd -vi in process (file and password rules, bcrypt)
  src/serve.rs                the software-live handler and endpoint.json
  tests/cli.rs                the binary against the Python program's exit codes
  tests/traefik_host.rs       Linux only: real processes and pinned descriptors
  fixtures/generate.py        writes fixtures/*.json from the Python program
  fixtures/*.json             generated; never edit by hand
  fixtures/rust-caches.json   caches as the Rust code writes them (see below)
  fixtures/rust-export.json   projections as the Rust code writes them (see below)
  fixtures/htpasswd.py        records fixtures/htpasswd.json with the real htpasswd (Docker)
  parity/run_parity.py        the parity harness (both programs side by side; container only)
  parity/world.py             its host: fake Traefik/PostgreSQL processes, shims, HTTPS upstream
  parity/compare.py           P1/P2 comparison of the two programs' JSON (test_compare.py)
  parity/fakeproc.c           the fake server binaries
  parity/container-run.sh     build both release binaries and run the harness in a variant image
  parity/docker-parity.sh     the same in Docker for both variants
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
just rs-software-live-parity             # the parity harness in both containers (Docker); `-- -v` lists every check
```

`just rs-software-live-parity ubuntu24.04 -- --section endpoint -v` runs one
variant and one section (`validate`, `config`, `endpoint`, `export`,
`collect`). The harness refuses to run outside a container: it changes
`/etc/hosts`, the trust store, `/usr` and the APT configuration.

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

`fixtures/htpasswd.json` is not written by `generate.py` either: bcrypt
salts are random and the verdicts come from the real `htpasswd -vi` of the
hosts' distributions. `python3 -I rust/software-live/fixtures/htpasswd.py`
(Docker, network for the images and `apache2-utils`) records it again in
`debian:13` and `ubuntu:24.04` containers and fails when the two disagree.

`--version` takes the commit from `SOFTWARE_LIVE_GIT_COMMIT` (7 to 40
lowercase hex digits, set by the release workflow), else `git rev-parse
HEAD`, else `unknown`.
