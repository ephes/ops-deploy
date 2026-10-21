# Rust binaries of ops-library

A Cargo workspace for small Rust binaries that replace long-running Python
processes deployed by this collection. [`PLAN-foundation.md`](PLAN-foundation.md)
is the contract for the workspace, toolchain, dependency policy, CI, release
pipeline and the shared install helpers; each crate has its own plan:

| Crate (= binary = release tag prefix) | Plan | Status |
| --- | --- | --- |
| `metrics-httpd` | [`metrics-httpd/PLAN.md`](metrics-httpd/PLAN.md) | skeleton (F1): only `metrics-httpd --version` |
| `echoport-command-guard` | [`echoport-command-guard/PLAN.md`](echoport-command-guard/PLAN.md) | contract fixtures (S0); not yet a workspace member (its S1 adds the crate) |

Nothing in this directory is part of the Ansible collection: `galaxy.yml`
`build_ignore` excludes `rust` and `.github`, and
`tests/test_collection_build_ignore.py` (`just test-collection-build-ignore`,
part of `just test`) builds the collection and checks that no archive member
comes from either directory. No role installs a binary from here until its
crate's switch slice; merging Rust code changes nothing on any host.

## Layout

```
rust/
  Cargo.toml            virtual workspace: explicit members, shared lints and release profile
  Cargo.lock            committed; every build and test runs with --locked
  rust-toolchain.toml   pinned toolchain 1.99.1 (= MSRV, `rust-version`)
  deny.toml             cargo-deny policy for the whole workspace
  LICENSE               MIT, packed into every release archive
  scripts/              stdlib Python helpers for CI and releases, with tests
  metrics-httpd/        crate + binary `metrics-httpd`
  echoport-command-guard/  plan, Python oracle and fixtures; crate + binary from its S1
```

Rules (PLAN-foundation.md section 1):

- One crate per binary; directory name = package name = binary name = tag
  prefix (`metrics-httpd-v<version>`). Each crate has its **own** `version`,
  so the binaries release independently; `license`, `edition`,
  `rust-version`, `repository` and `publish = false` come from
  `[workspace.package]`, lints from `[workspace.lints]` (`[lints] workspace =
  true` in each crate).
- `members` in `Cargo.toml` is an explicit list (cargo rejects a glob that
  matches a plan-only directory). A stream appends its crate in its own first
  slice.
- On a rebase conflict in `Cargo.lock`, take `origin/main`'s lock, then let
  cargo add your crate and its new dependencies only
  (`cargo metadata --format-version 1 >/dev/null`), and commit. Never run a
  blanket `cargo update` in a feature slice; dependency upgrades are their own
  slice.
- `rust/target/` is ignored by git (`/rust/target/` in `.gitignore`).

## Build and check

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on the
first `cargo` call (a non-rustup cargo of the same version works too). From
the repository root of a worktree:

```bash
just rust-check     # everything the CI job runs (below)
just rust-test      # cargo test + the rust/scripts tests only
```

`just rust-check` runs, from `rust/`:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny --locked check          # cargo-deny 0.20.2, policy in deny.toml
python3 -I -m unittest discover -s scripts -p 'test_*.py'
```

Neither recipe is a dependency of `just test`, so the Ansible test suite keeps
working without a Rust toolchain. Run them in a worktree, not in a shared
checkout: they write `rust/target/`.

`metrics-httpd --version` prints `metrics-httpd <version> (<commit>)`. The
crate's `build.rs` embeds the commit: `METRICS_HTTPD_GIT_COMMIT` if set (the
release workflow sets the full SHA; it must be 7 to 40 lowercase hex digits,
anything else fails the build), else `git rev-parse HEAD`, else `unknown`.

### Members left out of the default job

A member that needs system build dependencies the CI runner image does not
have is listed in `rust/Cargo.toml`:

```toml
[workspace.metadata.ci]
exclude = ["<crate>"]
```

`scripts/ci_excludes.py` reads `cargo metadata --format-version 1 --no-deps`
and prints the matching `--exclude <crate>` arguments (empty today); it
rejects names that are not workspace members, duplicates, and a list that
would exclude every member. The CI job and `just rust-check`/`just rust-test`
pass them to `cargo clippy --workspace` and `cargo test --workspace`. The
crate's stream adds its own job that builds, lints and tests it in a suitable
container (PLAN-foundation.md sections 3 and 4).

## Dependency policy

- Target `x86_64-unknown-linux-gnu` (glibc, not musl); TLS, where a crate
  needs it, is rustls. Release builds target glibc 2.35 (built on
  `ubuntu-22.04`), which runs on every Linux host (lowest: Debian 12, glibc
  2.36).
- `deny.toml` (copied from mailgun-relay): RustSec advisories and yanked
  crates fail the check, only crates.io, licenses from an explicit allowlist
  (Apache-2.0, BSD-3-Clause, ISC, MIT, Unicode-3.0, Zlib). A new license
  needs its own line naming the crate that brings it. Copyleft licenses are
  not allowed workspace-wide. While a license on the list is not used by any
  crate, cargo-deny prints a `license-not-encountered` warning; that is not a
  failure.
- Maintained crates instead of re-implemented libraries or hand-rolled
  protocols; each crate plan lists its crates with a reason.

## CI

`.github/workflows/rust.yml` runs on pushes to `main` and on pull requests
that touch `rust/**` or `.github/workflows/rust*.yml`, and on
`workflow_dispatch`. One job on `ubuntu-22.04` (`permissions: contents:
read`, actions pinned by commit SHA): the pinned toolchain, a cargo cache
keyed on `rust-toolchain.toml` and `Cargo.lock`, the CI exclusions, then
`cargo fmt --check`, clippy with `-D warnings`, `cargo test`, cargo-deny
0.20.2 (the release tarball, sha256-checked, as mailgun-relay) with
`cargo deny --locked check`, and the `rust/scripts` tests with the runner's
`python3` (3.10; the scripts are stdlib-only).

If GitHub retires the `ubuntu-22.04` image, the same steps run in a
`ubuntu:22.04` container on `ubuntu-latest` (PLAN-foundation.md section 2).

## Releases

Not yet: the release workflow (`rust-release.yml`, per-binary tags
`<crate>-v<semver>`) and `scripts/release_checks.py` arrive with slice F2
(PLAN-foundation.md section 4).
