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
  scripts/              stdlib Python helpers for CI (ci_excludes.py) and releases
                        (release_checks.py), with tests and testdata/
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

`.github/workflows/rust-release.yml` builds and publishes one binary crate
per tag (PLAN-foundation.md section 4). Nothing installs a release on a host
by itself; the roles pin a version and its sha256 (section 6).

### Cutting a release

1. Bump `version` in `rust/<crate>/Cargo.toml` (each crate has its own),
   update `Cargo.lock` (`cargo metadata --format-version 1 >/dev/null`), merge
   to `main`.
2. Tag that commit `<crate>-v<version>` (e.g. `metrics-httpd-v0.1.0`) and
   push the tag. The workflow runs for the prefixes `metrics-httpd-v*`,
   `echoport-command-guard-v*` and `software-live-v*`; a crate that is not
   yet a workspace member fails in the first step.
3. The GitHub release `<crate> <version>` appears at
   `https://github.com/ephes/ops-library/releases/tag/<crate>-v<version>`
   with the archive(s) and `.sha256` files; the job summary prints each
   sha256 and the member sizes (the stripped binary). The release is never
   marked "latest" (`--latest=false`); a semver pre-release version
   (`0.2.0-rc.1`) becomes a GitHub pre-release.

A dry run without tag or release: *Actions → Rust release → Run workflow*
with a crate (or `gh workflow run rust-release.yml -f crate=metrics-httpd`);
the archives are uploaded as workflow artifacts. Collection tags, if the
collection ever gets any, are `v<semver>` or `<semver>` and never match a
binary prefix.

### What the workflow checks

- `prepare` (ubuntu-22.04): `scripts/release_checks.py tag` resolves the
  crate: the longest workspace member whose `<member>-v` prefixes the tag
  (`software-live-v1.0.0` is `software-live`, never `software-live-apt`),
  which must have a binary of its own name and exactly the tag's version
  (semver without build metadata). Then `release_checks.py matrix` (below),
  `cargo fmt --check`, clippy `-D warnings` and `cargo test` over the
  workspace without the `[workspace.metadata.ci] exclude` members (as
  `rust.yml`), and the `rust/scripts` tests. No cargo cache.
- `build`, one job per variant: `cargo build --release --locked --target
  x86_64-unknown-linux-gnu -p <member>...` with `<CRATE>_GIT_COMMIT` set to
  the full commit for every built member's `build.rs`; then
  `release_checks.py verify` runs for every binary of the variant the glibc
  check (`objdump -T`/`-p`: no `GLIBC_*` symbol version above the binary's
  ceiling, default 2.35, and no `NEEDED` library outside glibc, libgcc_s and
  the binary's `extra_needed`) and the smoke test (`<binary> --version` must
  print `<binary> <version> (<full commit>)`, then every `extra_smoke`
  command must exit 0 with an empty environment in an empty directory).
  `release_checks.py pack` writes the deterministic archive (exactly the
  declared regular files at the archive root, binaries 0755, other files
  0644, root-owned, the commit time as mtime, a gzip header without a name,
  so a re-run on the same commit and image gives the same bytes) and its
  `.sha256`; both are uploaded as a workflow artifact.
- `publish` (tags only, the only job with `contents: write`): downloads the
  artifacts, requires exactly the archives of the matrix, checks every
  sha256 and creates the release with `gh release create --verify-tag`.

### Archive names and `release.json`

Without `rust/<crate>/release.json` a crate has one unnamed variant built on
the `ubuntu-22.04` runner (glibc 2.35, runs on every Linux host):
`<crate>-<version>-x86_64-unknown-linux-gnu.tar.gz` with `<crate>` and
`LICENSE` (`rust/LICENSE`). A crate that needs more declares variants; each
one becomes its own build job and archive
`<crate>-<version>-x86_64-unknown-linux-gnu-<variant>.tar.gz`:

```json
{
  "variants": [
    {
      "name": "ubuntu24.04",
      "image": "ubuntu:24.04",
      "packages": ["libapt-pkg-dev", "g++"],
      "build": ["software-live", "software-live-apt"],
      "binaries": [
        {"name": "software-live"},
        {
          "name": "software-live-apt",
          "glibc_max": "2.39",
          "extra_needed": ["libapt-pkg.so.6.0", "libstdc++.so.6"],
          "extra_smoke": [["--help"]]
        }
      ],
      "files": [
        {"source": "rust/LICENSE", "name": "LICENSE"},
        {"source": "rust/software-live-apt/LICENSE", "name": "LICENSE.GPL-3.0"}
      ]
    }
  ]
}
```

| Key | Default | Meaning |
| --- | --- | --- |
| `name` | none (allowed only for a single variant) | archive suffix, `[a-z0-9][a-z0-9._-]*`, unique |
| `image` | the runner | container image (Debian/Ubuntu: the job installs `binutils ca-certificates curl gcc git libc6-dev python3`, rustup 1.29.1 sha256-checked, then the pinned toolchain) |
| `packages` | `[]` | extra apt packages; only with `image` |
| `build` | `[<crate>]` | workspace members to build (must include the crate); a CI-excluded member is allowed only with an `image` and is linted and tested inside it |
| `binaries` | `[{"name": <crate>}]` | archive binaries (mode 0755), each a binary of a `build` member; must include `<crate>` |
| `binaries[].glibc_max` | `"2.35"` | glibc ceiling of that binary |
| `binaries[].extra_needed` | `[]` | sonames allowed in addition to glibc and libgcc_s |
| `binaries[].extra_smoke` | `[]` | argument lists of extra smoke commands |
| `files` | `[{"source": "rust/LICENSE", "name": "LICENSE"}]` | other archive members (mode 0644); `source` relative to the repository root, a regular file |

Unknown keys, duplicate names and anything outside these rules fail the
`matrix` step before anything is built. `scripts/test_release_checks.py`
checks the defaults and a two-variant fixture
(`scripts/testdata/release-two-variants.json`) and asserts that every
releasable member of the committed workspace yields a valid matrix.

`release_checks.py glibc-floor [--max 2.35] [--allow <soname>] <binary>` and
`release_checks.py smoke --binary <path> --version <v> --commit <sha>
[--extra '["--arg"]']` run the same checks by hand on a Linux build.
