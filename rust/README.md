# Rust binaries of ops-deploy

A Cargo workspace for small Rust binaries that replace long-running Python
processes deployed by ops-deploy. It moved here from the archived ops-library
on 2026-11-18 with its history and its eight releases ([`HISTORY.md`](HISTORY.md)). [`PLAN-foundation.md`](PLAN-foundation.md)
is the contract for the workspace, toolchain, dependency policy, CI, release
pipeline and the shared install helpers; each crate has its own plan:

| Crate (= binary = release tag prefix) | Plan | Status |
| --- | --- | --- |
| `metrics-httpd` | [`metrics-httpd/PLAN.md`](metrics-httpd/PLAN.md) | core (S1): command line of all five modes, `--check-config`, server, auth, Python-compatible JSON; every mode answers the 501/404/401 gate; `json-file` mode for all eight variants (S2a), `script` mode (S2b), `apt-state` mode (S2c), `static` mode (S2e), `logyard-health` mode (S2d); process-level parity harness and shadow comparer (S3) ([`TESTMAP.md`](metrics-httpd/TESTMAP.md)) |
| `echoport-command-guard` | [`echoport-command-guard/PLAN.md`](echoport-command-guard/PLAN.md) | S1–S7: `--version`, `--check-policy`, every branch of the Python guard's `check()` (Layer-1 parity, filesystem layer), forced-command mode, `--decide` and `--shadow`; the parity gate (decision property tests, Layers 2 and 3 in containers, fuzzing); the role switch (S6); released as `echoport-command-guard-v0.1.0` (S7), a parity port that is never installed (its PLAN.md R12: the hardening slice H1 comes first) ([`TESTMAP.md`](echoport-command-guard/TESTMAP.md)) |
| `software-live` | [`software-live/PLAN.md`](software-live/PLAN.md) | crate skeleton (S2): `validate`, command line, policy hash, report types, fixtures from the Python program; the APT observation through its helper (S3d); see [`software-live/README.md`](software-live/README.md) |
| `software-live-apt` (no tag of its own; ships in the `software-live` archives) | [`software-live/PLAN.md`](software-live/PLAN.md) 5.2 | APT helper (S3d), GPL-3.0-or-later, built and tested per distribution variant in containers; see [`software-live-apt/README.md`](software-live-apt/README.md) |

Nothing in this directory is part of the ops-deploy package: the wheel and the
sdist hold only `src/ops_deploy`, and `tests/test_rust_workspace.py` (part of
`just check`) builds both and checks that no member comes from `rust/`. The
plans name ops-library's Ansible roles and `.github/workflows`; they are the
record of how the crates were built there. Today the Python originals the
harnesses compare against are the frozen copies under `oracle/`
([`HISTORY.md`](HISTORY.md)), and the checks and releases run locally (below).
Merging Rust code changes nothing on any host: a host runs a release only
after ops-control pins its version and sha256.

## Layout

```text
rust/
  Cargo.toml            virtual workspace: explicit members, shared lints and release profile
  Cargo.lock            committed; every build and test runs with --locked
  rust-toolchain.toml   pinned toolchain 1.99.1 (= MSRV, `rust-version`)
  deny.toml             cargo-deny policy for the whole workspace
  LICENSE               MIT, packed into every release archive
  HISTORY.md            the move from ops-library: history, commit ids, oracles
  releases.json         the eight releases built in ops-library (written once, never edited)
  oracle/               frozen ops-library files the harnesses compare against
  scripts/              stdlib Python: check exclusions (ci_excludes.py), release checks and release.py
                        (release_checks.py), with tests and testdata/
  metrics-httpd/        crate + binary `metrics-httpd`, plan, TESTMAP, Python-generated fixtures
  echoport-command-guard/  crate + binary `echoport-command-guard`, plan, Python oracle and fixtures,
                           container harnesses (parity/e2e/) and cargo-fuzz targets (fuzz/, not a member)
  software-live/        crate + binary `software-live` (Rust port of software_live.py)
  software-live-apt/    crate + binary `software-live-apt`, the APT helper of software-live
                        (rust-apt, GPL-3.0-or-later, LICENSE.GPL-3.0; container/ checks)
```

Rules (PLAN-foundation.md section 1):

- One crate per binary; directory name = package name = binary name = tag
  prefix (`metrics-httpd-v<version>`). Each crate has its **own** `version`,
  so the binaries release independently; `license`, `edition`,
  `rust-version`, `repository` and `publish = false` come from
  `[workspace.package]`, lints from `[workspace.lints]` (`[lints] workspace =
  true` in each crate). `software-live-apt` sets its own
  `license = "GPL-3.0-or-later"` (owner decision, PLAN-foundation.md section
  9) and carries the version of `software-live`. The one lint exception is
  `echoport-command-guard`: its `[lints]` copy the workspace lints with `unsafe_code = "deny"` instead of
  `forbid`, so that its `exec.rs` can allow the libc calls before the exec
  (its PLAN.md 5.3); keep that copy in step when the workspace lints change.
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
just rust-check       # the workspace checks (below)
just rust-check-apt   # software-live-apt and the software-live parity in containers
```

`just rust-check` runs, from `rust/`:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny --locked check          # cargo-deny 0.20.2, policy in deny.toml
python3 -I -m unittest discover -s scripts -p 'test_*.py'
```

Neither recipe is part of `just check`, so ops-deploy's gate keeps working
without a Rust toolchain; a change under `rust/` runs them before it is
pushed. `just rust-check` refuses a `cargo` that is not the pinned toolchain
(Homebrew's cargo ignores `rust-toolchain.toml`; put `~/.cargo/bin` first in
`PATH`). Run them in a worktree, not in a shared
checkout: they write `rust/target/`. The `cargo test` of
echoport-command-guard runs its Python oracle with `python3` (or
`$ECHOPORT_ORACLE_PYTHON`; `just rust-check` uses 3.12), so a Python 3 must be on `PATH`.

`metrics-httpd --version` prints `metrics-httpd <version> (<commit>)`. The
crate's `build.rs` embeds the commit: `METRICS_HTTPD_GIT_COMMIT` if set (the
release build sets the full SHA; it must be 7 to 40 lowercase hex digits,
anything else fails the build), else `git rev-parse HEAD`, else `unknown`.

### Members left out of the default job

A member that needs system build dependencies the default checks do not
have is listed in `rust/Cargo.toml`:

```toml
[workspace.metadata.ci]
exclude = ["<crate>"]
```

`scripts/ci_excludes.py` reads `cargo metadata --format-version 1 --no-deps`
and prints the matching `--exclude <crate>` arguments (today
`--exclude software-live-apt`); it
rejects names that are not workspace members, duplicates, and a list that
would exclude every member. `just rust-check` and the release's `prepare` job
pass them to `cargo clippy --workspace` and `cargo test --workspace`. The
crate's stream adds its own job that builds, lints and tests it in a suitable
container (PLAN-foundation.md sections 3 and 4): for `software-live-apt`
`just rust-check-apt` and the release's variant jobs (below).

## Dependency policy

- Target `x86_64-unknown-linux-gnu` (glibc, not musl); TLS, where a crate
  needs it, is rustls. Release builds target glibc 2.35 (built on
  `ubuntu-22.04`), which runs on every Linux host (lowest: Debian 12, glibc
  2.36).
- `deny.toml` (copied from mailgun-relay): RustSec advisories and yanked
  crates fail the check, only crates.io, licenses from an explicit allowlist
  (Apache-2.0, BSD-3-Clause, ISC, MIT, Unicode-3.0, Zlib). A new license
  needs its own line naming the crate that brings it. Copyleft licenses are
  not allowed workspace-wide; the one exception is `GPL-3.0-or-later` for
  `rust-apt` and `software-live-apt` (`[[licenses.exceptions]]`). Because
  that exception is scoped by crate, `scripts/release_checks.py
  apt-isolation` reads the full `cargo metadata --locked --all-features`
  graph and fails when any member other than `software-live-apt` can reach
  `rust-apt` (normal, build or dev edges, also through the helper);
  `just rust-check` and the release's `prepare` job run it. While a license on the list is not used by any
  crate, cargo-deny prints a `license-not-encountered` warning; that is not a
  failure.
- Maintained crates instead of re-implemented libraries or hand-rolled
  protocols; each crate plan lists its crates with a reason.

## Local checks

There is no GitHub Actions job (owner rule since 2026-11-15); ops-library's
`rust.yml` stayed behind in the archive. `just rust-check` runs what its
`rust` job ran, from `rust/`:

- `cargo fmt --check`, clippy with `-D warnings` and `cargo test` over the
  workspace without the `[workspace.metadata.ci] exclude` members, with
  `ECHOPORT_ORACLE_PYTHON` set to uv's Python 3.12 for the guard's oracle
  tests;
- `cargo deny --locked check` (cargo-deny 0.20.2) and the `rust-apt`
  isolation check;
- the `rust/scripts` tests (stdlib Python);
- the software-live parity comparator tests under Python 3.12;
- the fixture drift checks against the frozen oracles: the guard's
  `parity/gen_fixtures.py check` under 3.12 and 3.13, metrics-httpd's
  `fixtures/generate.py check` rendered under 3.14 (the Python of the
  ops-library venv that wrote them; the 3.12 stdlib renders other error
  pages) and `--stdlib-only` under 3.12 and 3.13, software-live's
  `fixtures/generate.py --check` under 3.14;
- `just rust-parity-metrics-httpd`: the rendered Python endpoint scripts
  under CPython 3.12 against the debug binary (needs `htpasswd`), then the
  tests of the shadow comparer.

The guard's `gen_fixtures.py record` step imported ops-library's
`tests/test_echoport_remote_command_guard.py`, which did not move: the
recorded corpus is frozen with the oracle and `record` says so.

`just rust-check-apt [ubuntu24.04] [debian13]` runs ops-library's
`software-live-apt` job: per variant a throwaway container of the image with
a copy of `rust/` (`software-live-apt/container/docker-check.sh`: clippy,
tests, release build with its GLIBC ceiling and `NEEDED` allowlist, the
python-apt comparison on a fake APT world), then the software-live parity
harness (`software-live/parity/docker-parity.sh`). The containers run on the
Docker engine's own platform (arm64 on a Mac);
`SOFTWARE_LIVE_APT_PLATFORM=linux/amd64` runs the x86_64 images.

## Releases

`scripts/release.py` builds and publishes one binary crate at a time, locally
(PLAN-foundation.md section 4 described ops-library's workflow, which it
replaces). Releases are GitHub releases of ops-deploy with tags
`<crate>-v<version>`; `import-old` publishes the eight releases built in
ops-library here again byte for byte ([`HISTORY.md`](HISTORY.md)). Nothing installs a
release on a host by itself; ops-control pins a version and its sha256.

### Cutting a release

1. Bump `version` in `rust/<crate>/Cargo.toml` (each crate has its own),
   update `Cargo.lock` (`cargo metadata --format-version 1 >/dev/null`), run
   `just rust-check` (and `just rust-check-apt` for software-live), get the
   change reviewed and push it to `main`.
2. In a clean checkout of that commit: `just rust-release <crate>`. It
   writes the archives, their `.sha256` files, `notes.md` and `build.json`
   to `rust/target/release-dist/<crate>-<version>/` and prints each sha256
   and the archive members. It publishes nothing.
3. `just rust-release-publish <crate>` tags the build commit, pushes the tag
   and creates the release `<crate> <version>` at
   `https://github.com/ephes/ops-deploy/releases/tag/<crate>-v<version>`
   (`gh release create --verify-tag --latest=false`; a semver pre-release
   becomes a GitHub pre-release), then downloads every asset and compares it
   with the local file. Nothing may resolve a binary through "latest".
4. Add the release row to the crate README's table and, in ops-control, the
   row of `tests/fixtures/ops_library_final/rust_releases.json` in the same
   change as the pin.

### Container engine

The build needs `linux/amd64` containers. On an Apple silicon Mac with
colima (`vmType: vz`, `rosetta: true`) the Rosetta binfmt handler must be
registered in the VM; `release.py` checks first that `docker run --platform
linux/amd64 ubuntu:22.04 uname -m` prints `x86_64` and stops otherwise. A
`colima restart` registers it; without a restart, register it in the VM by
hand:

```bash
colima ssh -- sudo sh -c 'printf "%s" ":rosetta:M::\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff:/mnt/lima-rosetta/rosetta:OCF" > /proc/sys/fs/binfmt_misc/register'
```

### What `build` does

1. Refuses a worktree with changes or untracked files, a commit that is not
   on `origin/main`, a non-empty output directory, and a *taken* version: its
   tag is on `origin` or it is listed in `releases.json`.
   `--compare-released` builds a taken version as a dry run (and refuses an
   untaken one); `build.json` records that, and `publish` refuses such a
   build.
2. Preflight of the `linux/amd64` engine (above).
3. Image phase, the only one with network: one builder image per image of
   the matrix, `ubuntu:22.04` for `prepare` and `shared` (and a variant
   without `image`; glibc 2.35 as the old runner) plus each variant image.
   Every image that builds, checks or packs a release binary is
   `linux/amd64`. `prepare` runs in an `ubuntu:22.04` image of the Docker
   engine's own platform (arm64 on a Mac): under Rosetta the emulator's own
   open file descriptors fail the guard's descriptor-inheritance tests, an
   artefact of the emulation, not of the code; the amd64 binaries are still
   checked and smoke-tested under amd64.
   Each starts from its base image pinned by the digest pulled at the start
   of the build, installs `binutils ca-certificates curl gcc git libc6-dev
   python3` and the variant's packages, rustup 1.29.1 (sha256-checked per
   platform), the
   source as `git archive` of the build commit (only `rust/`), the pinned
   toolchain and `cargo fetch --locked`. No code of the crates or their
   dependencies runs.
4. Build phase: every job is a container with `--network none`, no mount,
   and memory, process and time limits; files go in and come back with
   `docker cp`. `<CRATE>_GIT_COMMIT` is set to the full commit for every
   member's `build.rs`.
   - `prepare`: `cargo fmt --check`, clippy `-D warnings` and `cargo test`
     without the CI-excluded members, the `rust/scripts` tests and the
     `rust-apt` isolation check.
   - `shared` (only with a `shared` section in `release.json`): builds those
     members once, `release_checks.py verify` on their binaries, and hands
     them with their sha256 (`release_checks.py checksums`) to the variants.
   - one job per variant: clippy and tests of its CI-excluded members,
     `cargo build --release --locked --offline --target
     x86_64-unknown-linux-gnu -p <member>...` (skipped when the variant builds
     nothing itself), then `release_checks.py verify` for every binary (the
     shared ones again, inside the variant's image, after their sha256): the
     glibc check (`objdump -T`/`-p`: no `GLIBC_*` symbol version above the
     binary's ceiling, default 2.35, and no `NEEDED` library outside glibc,
     libgcc_s and the binary's `extra_needed`) and the smoke test
     (`<binary> --version` must print `<binary> <version> (<full commit>)`,
     then every `extra_smoke` command must exit 0 with an empty environment
     in an empty directory). `release_checks.py pack` writes the
     deterministic archive (exactly the declared regular files at the
     archive root, binaries 0755, other files 0644, root-owned, the commit
     time as mtime, a gzip header without a name) and its `.sha256`.
5. `notes.md` records the commit, each archive's sha256, the base image
   digests, the installed versions of the apt packages, the `rustc`
   version and the sha256 of `Cargo.lock` (the apt packages are not pinned
   by version, as in the workflow).

### What `publish` and `import-old` guarantee

`publish` works towards one end state and can be repeated: the tag on
`origin` points at the build commit, and the release holds exactly the
built archives and `.sha256` files, each equal to the local file. It never
moves or deletes a tag (a tag on another commit stops it), never replaces an
asset (`gh release upload` without `--clobber`), and stops on an asset with
other bytes or one it does not expect; such a case is settled by hand. If
the output directory is lost after the tag was pushed and before the
release is complete, the version is abandoned: the tag stays, an unfinished
release is deleted by hand, and the fix ships as the next patch version
(nothing can have installed it, because ops-control never recorded its
sha256).

`import-old [--tag <tag>]` publishes the releases of `releases.json` again:
it downloads each ops-library release, requires every asset's sha256 to equal
the record and each `.sha256` file to name its archive's checksum, tags the
recorded ops-deploy commit (it must be on `origin/main`; an existing tag
must point at it), creates the release and compares the downloaded assets
with the originals. It builds nothing and accepts no version outside the
file. `scripts/test_release.py` covers the job scripts and the refusals of
all three commands with a fake `docker` and `gh` and real git repositories.

### Archive names and `release.json`

Without `rust/<crate>/release.json` a crate has one unnamed variant built in
the `ubuntu:22.04` image (glibc 2.35, runs on every Linux host):
`<crate>-<version>-x86_64-unknown-linux-gnu.tar.gz` with `<crate>` and
`LICENSE` (`rust/LICENSE`). A crate that needs more declares variants; each
one becomes its own build job and archive
`<crate>-<version>-x86_64-unknown-linux-gnu-<variant>.tar.gz`. Binaries that
every variant shares go into `shared`: they are built once in `ubuntu:22.04` and
packed into every variant's archive. `software-live/release.json` (one
`software-live` build with the glibc floor 2.35 in both archives, the helper
per distribution; software-live PLAN.md 7.1, 7.2):

```json
{
  "shared": {
    "build": ["software-live"],
    "binaries": [{"name": "software-live"}]
  },
  "variants": [
    {
      "name": "ubuntu24.04",
      "image": "ubuntu:24.04",
      "packages": ["g++", "libapt-pkg-dev", "python3-apt"],
      "build": ["software-live-apt"],
      "binaries": [
        {
          "name": "software-live-apt",
          "glibc_max": "2.39",
          "extra_needed": ["libapt-pkg.so.6.0", "libstdc++.so.6"],
          "extra_smoke": [["observe", "--max-age", "172800", "--now", "4102444800"]]
        }
      ],
      "files": [
        {"source": "rust/LICENSE", "name": "LICENSE"},
        {"source": "rust/software-live-apt/LICENSE.GPL-3.0", "name": "LICENSE.GPL-3.0"}
      ]
    }
  ]
}
```

(abridged: the second variant `debian13` is the same with `debian:13`, the
ceiling 2.41 and `libapt-pkg.so.7.0`.)

| Key | Default | Meaning |
| --- | --- | --- |
| `shared` | none | `build` (members, not CI-excluded) and `binaries` (as below) built once on the runner and packed into every variant's archive; both keys required |
| `name` | none (allowed only for a single variant) | archive suffix, `[a-z0-9][a-z0-9._-]*`, unique |
| `image` | the runner | container image (Debian/Ubuntu: the job installs `binutils ca-certificates curl gcc git libc6-dev python3`, rustup 1.29.1 sha256-checked, then the pinned toolchain) |
| `packages` | `[]` | extra apt packages; only with `image` |
| `build` | `[<crate>]`, `[]` when `shared` builds the crate | workspace members to build (must include the crate unless `shared` builds it; never a `shared` member); a CI-excluded member is allowed only with an `image` and is linted and tested inside it |
| `binaries` | `[{"name": <crate>}]`, `[]` when `shared` builds the crate | archive binaries (mode 0755), each a binary of a `build` member; together with the `shared` binaries they must include `<crate>` |
| `binaries[].glibc_max` | `"2.35"` | glibc ceiling of that binary |
| `binaries[].extra_needed` | `[]` | sonames allowed in addition to glibc and libgcc_s |
| `binaries[].extra_smoke` | `[]` | argument lists of extra smoke commands |
| `files` | `[{"source": "rust/LICENSE", "name": "LICENSE"}]` | other archive members (mode 0644); `source` relative to the repository root, a regular file |

Unknown keys, duplicate names and anything outside these rules fail the
`matrix` step before anything is built. `scripts/test_release_checks.py`
checks the defaults, a two-variant fixture
(`scripts/testdata/release-two-variants.json`, each variant building its own
binaries), the `shared` rules and the committed
`software-live/release.json` against software-live PLAN.md 7.1/7.2, and
asserts that every releasable member of the committed workspace yields a
valid matrix.

`release_checks.py glibc-floor [--max 2.35] [--allow <soname>] <binary>` and
`release_checks.py smoke --binary <path> --version <v> --commit <sha>
[--extra '["--arg"]']` run the same checks by hand on a Linux build.

## Installing a release on a host

ops-deploy installs a pinned release with `ops_deploy.helpers.rust_release`
(its host script `helpers/templates/rust_release_host.py.txt`): the archive's
files go into `/opt/<crate>/<version>/` (checksum-verified, never modified in
place, downloaded only when that directory is missing), a pin records which
version each consumer runs and the version it ran before (the rollback
target), and pruning keeps every pinned and live version. ops-control's
inventory pins each version and sha256.
