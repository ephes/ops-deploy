# Rust binaries

`rust/` is the Cargo workspace of the four Rust ports that replace Python
programs ops-deploy installs: `echoport-command-guard`, `metrics-httpd`,
`software-live` and its APT helper `software-live-apt`. It moved here from the
archived ops-library on 2026-11-18, with its history and its eight releases
([`rust/HISTORY.md`](https://github.com/ephes/ops-deploy/blob/main/rust/HISTORY.md)).
The workspace's own documentation is
[`rust/README.md`](https://github.com/ephes/ops-deploy/blob/main/rust/README.md);
this page is the short version for ops-deploy work.

## What it means for the rest of the repository

- The package never contains `rust/`: the wheel and the sdist hold only
  `src/ops_deploy` (`tests/test_rust_workspace.py` builds both and checks).
- `just check` needs no Rust toolchain. Ruff skips `rust/`.
- `tests/test_rust_workspace.py` keeps the frozen Python guard under
  `rust/oracle/` byte-identical to
  `src/ops_deploy/base/files/echoport_remote_command_guard.py.txt`, the guard
  ops-deploy installs. A change to that file fails `just check` until the
  oracle, the Rust guard's fixtures and the port follow.
- A Rust-only commit changes nothing the hosts install: they get a binary
  only through a release pinned in ops-control (version and sha256), and
  ops-control's pin of ops-deploy needs no bump for it.

## Checks

| Recipe | What it runs |
|---|---|
| `just rust-check` | fmt, clippy, tests, cargo-deny, the `rust-apt` isolation check, the `rust/scripts` tests, the fixture drift checks against the frozen oracles and the metrics-httpd parity harness |
| `just rust-check-apt [ubuntu24.04] [debian13]` | `software-live-apt` and the software-live parity harness in containers of both distributions (Docker) |

They need rustup's `cargo` first in `PATH` (the toolchain of
`rust/rust-toolchain.toml`), cargo-deny 0.20.2, uv with Pythons 3.12 to 3.14,
`htpasswd`, and Docker for `rust-check-apt`. A change under `rust/` runs them
before it is pushed; there is no CI job.

## Releases

Releases are built locally in `linux/amd64` containers (on a Mac: colima
with Rosetta) and published as GitHub releases of ops-deploy, tag
`<crate>-v<version>`:

```bash
just rust-release software-live           # build, publishes nothing
just rust-release-publish software-live   # tag, GitHub release, verify the uploads
```

`build` refuses a dirty checkout, a commit that is not on `origin/main` and a
version that is already released; `publish` never moves a tag or replaces an
asset. The install helper `ops_deploy.helpers.rust_release` downloads a
pinned release (still from ops-library's release URLs until the eight old
releases are published on ops-deploy) and checks the sha256 that ops-control
pins.
