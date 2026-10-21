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
  src/probe.rs                trait System, HostSystem, the fixture world (tests)
  tests/cli.rs                the binary against the Python program's exit codes
  fixtures/generate.py        writes fixtures/*.json from the Python program
  fixtures/*.json             generated; never edit by hand
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

`--version` takes the commit from `SOFTWARE_LIVE_GIT_COMMIT` (7 to 40
lowercase hex digits, set by the release workflow), else `git rev-parse
HEAD`, else `unknown`.
