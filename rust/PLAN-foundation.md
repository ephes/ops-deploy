# Rust in ops-library: shared foundation — plan

Status: F1 implemented (workspace, toolchain, cargo-deny policy, LICENSE,
`metrics-httpd` skeleton, `rust.yml` CI, `build_ignore` test, `just
rust-check`/`rust-test`; see `rust/README.md`); F2 implemented
(`rust-release.yml`, `rust/scripts/release_checks.py` with the
`release.json` format and tests; `rust/README.md` "Releases"); F3 implemented
(`roles/rust_release_binary` with the `protect` list and the `previous`
rollback pin, 6.2); F4 planned. Campaign
"Rust-Ports Runde 2" (umbrella item `rust-ports-campaign`), stream
`rust-metrics-httpd`, which also owns this foundation.

This document is the contract for the shared Rust foundation in ops-library:
the Cargo workspace under `rust/`, the toolchain and dependency policy, CI,
the release pipeline with per-binary tags, the collection packaging rules,
and the way roles (Ansible) and pyinfra services (ops-deploy) install a pinned
release binary. Three streams build on it in parallel:

| Crate (= binary = tag prefix) | Plan | Replaces |
| --- | --- | --- |
| `metrics-httpd` | `rust/metrics-httpd/PLAN.md` | the Python HTTP endpoint daemons of the `*_metrics_endpoint`, `metrics_endpoint`, `os_apt_maintenance`, `dns_deploy` (DDNS status), `openclaw_deploy`, `logyard_deploy`, `static_site_deploy` roles and ops-control's `torrent_vpn_metrics_endpoint` |
| `echoport-command-guard` | `rust/echoport-command-guard/PLAN.md` | `echoport_remote_command_guard` |
| `software-live` (+ helper `software-live-apt`, GPL, see 9) | `rust/software-live/PLAN.md` | `software_live` |

The precedents are mailgun-relay (`~/projects/mailgun-relay/rust/`,
`.github/workflows/rust-release.yml`, `scripts/release_checks.py`) and the
nyxmon agent (`~/projects/nyxmon/agent-rs/`, `.github/workflows/agent-rs-release.yml`,
PLAN.md sections 4.4 and 8). Where this plan says "as mailgun-relay", the
implementation copies that file and adapts names; it does not re-derive it.

Facts (read-only, 2026-10-21):

- ops-library is public (`github.com/ephes/ops-library`, default branch
  `main`), has **no GitHub Actions workflows and no git tags at all**; the
  collection version lives only in `galaxy.yml` (`2.63.5` at `6b505fa1`).
  ops-control installs the collection from a local checkout
  (`just install-local-library`, `OPS_LIBRARY_PATH` or `../ops-library`) and
  refuses deploys when the installed version differs from that checkout's
  `galaxy.yml` (`scripts/check-collection-version.py`).
- Linux target hosts (all `x86_64`):

  | Host | OS | glibc |
  | --- | --- | --- |
  | macmini | Ubuntu 24.04.5 | 2.39 |
  | fractal | Ubuntu 24.04.5 | 2.39 |
  | production (= edge) | Ubuntu 24.04.5 | 2.39 |
  | staging | Debian 13 (trixie) | 2.41 |
  | heis | Debian 13 (trixie) | 2.41 |
  | marina | Debian 12 (bookworm) | 2.36 |

  atlas and macstudio are macOS (arm64) and are not targets of any of the
  three crates as planned. The lowest glibc is **2.36 (marina)**.
- Local toolchain on the controller: cargo/rustc 1.99.1 (Homebrew).
- A Cargo virtual workspace with no members, or with a glob member that
  matches a directory without `Cargo.toml` (a plan-only crate directory), is
  rejected by cargo 1.99 ("the workspace has no members" / "failed to load
  manifest for workspace member"); tested in a scratch directory. Hence F1
  creates one real member and the members list is explicit.

---

## 1. Workspace layout

```
rust/
  Cargo.toml              # virtual workspace, explicit members, shared profile + lints
  Cargo.lock              # committed; every build and test runs --locked
  rust-toolchain.toml     # pinned toolchain (= MSRV)
  deny.toml               # cargo-deny policy for the whole workspace
  LICENSE                 # MIT (galaxy.yml says MIT; the repo has no LICENSE file), packed into every release archive
  README.md               # how to build/test/release; links the plans
  PLAN-foundation.md      # this file
  scripts/
    ci_excludes.py        # stdlib Python (F1): `[workspace.metadata.ci] exclude` → `--exclude <crate>` args
    test_ci_excludes.py
    release_checks.py     # stdlib Python (F2): tag/version, glibc floor, smoke, pack (from mailgun-relay)
    test_release_checks.py
  metrics-httpd/          # crate + binary `metrics-httpd`  (stream rust-metrics-httpd)
    Cargo.toml  build.rs  src/  tests/  fixtures/  parity/  PLAN.md  TESTMAP.md
  echoport-command-guard/ # crate + binary `echoport-command-guard` (its stream adds it)
  software-live/          # crate + binary `software-live` (its stream adds it)
  software-live-apt/      # crate + helper binary `software-live-apt`, GPL-3.0-or-later,
                          # own LICENSE file; released inside the software-live archives (9)
```

Rules:

- One crate per binary, directory name = package name = binary name = tag
  prefix. A stream may add internal library crates under its own directory
  (`rust/<crate>/crates/<lib>`) if it needs them; there is no shared library
  crate in F1 (nothing is shared yet; a later slice may extract one when two
  crates need the same code, e.g. `--version` with the commit).
- `rust/Cargo.toml` (F1):

  ```toml
  [workspace]
  resolver = "3"
  members = ["metrics-httpd"]          # each stream appends its crate in its own first slice

  [workspace.package]
  edition = "2024"
  rust-version = "1.99"
  license = "MIT"
  repository = "https://github.com/ephes/ops-library"
  publish = false

  [workspace.metadata.ci]
  exclude = []                          # section 3

  [workspace.lints.rust]
  unsafe_code = "forbid"
  [workspace.lints.clippy]
  dbg_macro = "warn"

  [profile.release]                     # as mailgun-relay (measured there: opt-level "s" smaller and leaner)
  opt-level = "s"
  lto = "thin"
  codegen-units = 1
  strip = true
  panic = "unwind"
  ```

  Each crate has its **own** `version` (not `workspace.package.version`), so
  the binaries release independently. A crate inherits `license` from the
  workspace (MIT) unless its plan and an owner decision say otherwise; the
  only such crate is `software-live-apt` (`license = "GPL-3.0-or-later"`,
  its own `rust/software-live-apt/LICENSE` with the GPL text; section 9).
- Merge conflicts: the three streams touch `members` and `Cargo.lock`. On a
  rebase conflict in `Cargo.lock`, take `origin/main`'s lock, re-add your
  crate (`cargo metadata --format-version 1 >/dev/null` updates the lock for
  new members/dependencies only), and commit; never run a blanket
  `cargo update` in a feature slice. Dependency upgrades are their own slice.
- `rust/target/` is ignored (`.gitignore` gets `/rust/target/`).

## 2. Toolchain and dependency policy

- `rust/rust-toolchain.toml`: `channel = "1.99.1"`, components `rustfmt`,
  `clippy`, `profile = "minimal"`. The pin is the MSRV (`rust-version`);
  both change together in a dedicated slice.
- Target triple `x86_64-unknown-linux-gnu`, **not musl**, for the same reason
  as nyxmon PLAN.md 8.1 (glibc `getaddrinfo`/`nsswitch.conf` semantics; the
  binaries resolve host names, e.g. Loki or MinIO URLs) and because all
  targets have glibc. TLS, where a crate needs it, is rustls (no OpenSSL), so
  the only dynamic dependencies are glibc and libgcc_s.
- glibc floor **2.35**: release builds run on `ubuntu-22.04` (glibc 2.35);
  `release_checks.py glibc-floor --max 2.35` fails the release if the binary
  references a newer `GLIBC_*` symbol version or needs a library other than
  glibc/libgcc (`objdump -T`/`-p`, as mailgun-relay). 2.35 ≤ 2.36 (marina),
  so one artifact runs on every Linux host above. If GitHub retires the
  `ubuntu-22.04` image, the fallback is the same job in a `ubuntu:22.04`
  container on `ubuntu-latest` (owner not needed; documented in
  `rust/README.md`).
- `rust/deny.toml`: copied from mailgun-relay (advisories with yanked =
  deny, licenses allowlist starting with Apache-2.0, MIT, BSD-3-Clause, ISC,
  Unicode-3.0, Zlib; `unknown-registry`/`unknown-git` = deny; only crates.io;
  `[graph] targets = ["x86_64-unknown-linux-gnu"]`). A new license needs an
  explicit line with the crate that brings it, as there. Copyleft licenses
  are not in the allowlist; the one exception (owner decision 2026-10-21,
  section 9) is a `[[licenses.exceptions]]` entry for `GPL-3.0-or-later`
  scoped to the crates `rust-apt` and `software-live-apt`, added by the
  software-live stream in the slice that adds the helper crate, never a
  workspace-wide allow. That slice also adds a CI check that no other
  workspace member depends on `rust-apt` (a `release_checks.py` subcommand
  over the `resolve` graph of `cargo metadata --format-version 1 --locked`:
  `rust-apt` may be reachable only from `software-live-apt`), so the MIT
  binaries stay free of GPL code.
- Crate choices follow the campaign rule: maintained crates instead of
  re-implemented libraries or hand-rolled protocols; each plan lists its
  crates with a reason.

## 3. CI (new: ops-library's first GitHub Actions workflow)

`.github/workflows/rust.yml` (F1):

- Triggers: `push` to `main` and `pull_request`, both with `paths:
  ["rust/**", ".github/workflows/rust*.yml"]`; `workflow_dispatch`.
- `permissions: contents: read`; actions pinned by commit SHA (the SHAs
  mailgun-relay's workflows use).
- Job `rust` on `ubuntu-22.04`, `working-directory: rust`, `shell: bash`:
  `rustup toolchain install` (reads the pin), `cargo fmt --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked`, `cargo deny --locked check`
  (cargo-deny 0.20.2 installed as in mailgun-relay's CI: the release
  tarball from GitHub, checked against a pinned sha256), and `python3 -I -m
  unittest discover -s scripts -p 'test_*.py'`. As mailgun-relay's CI job,
  it caches the cargo registry and `rust/target` keyed on
  `rust-toolchain.toml` and `Cargo.lock` (the release job of section 4 has
  no cache).
- Crates may add steps (e.g. `apt-get install apache2-utils` for the
  metrics-httpd parity harness) in later slices; they do not add jobs that run
  the Ansible/Python test suite — that suite stays local (`just test`) as
  today. A crate that needs system build dependencies the runner image
  does not have (`software-live-apt`: `libapt-pkg-dev` of a specific
  distro, a C++ compiler) is listed in the workspace's
  `[workspace.metadata.ci] exclude` and left out of the default job with
  `--workspace --exclude <crate>`; its stream adds a Rust-only job that
  builds, lints and tests it inside each variant's container image
  (section 4). `just rust-check` and `just rust-test` use the same
  exclusion. F1 implements the mechanism with an empty list:
  `rust/scripts/ci_excludes.py` turns the `cargo metadata --no-deps` JSON
  into the `--exclude` arguments and rejects non-members, duplicates and a
  list that excludes every member. `cargo fmt` and `cargo deny` still cover
  the whole workspace.
- `justfile` (F1) gets `rust-check` (the same commands, run from a worktree;
  never in `~/projects`) and `rust-test`. They are **not** dependencies of
  `just test`, so `just test` keeps working without a Rust toolchain.

## 4. Release pipeline with per-binary tags

`.github/workflows/rust-release.yml` (F2), adapted from mailgun-relay's
`rust-release.yml`:

- Triggers: `push` of tags `metrics-httpd-v*`, `echoport-command-guard-v*`,
  `software-live-v*` (all three from F2 on; a tag whose crate is not yet a
  workspace member fails in the tag step), and `workflow_dispatch` with an
  input `crate` (build + checks + workflow artifact, no release).
- Tag grammar: `<crate>-v<semver>`. `release_checks.py tag --tag <ref>
  --metadata <cargo metadata json>` resolves the crate by the longest
  matching workspace member name, requires the member to have a `[[bin]]` of
  the same name and the tag version to equal that crate's `version`, and
  prints `crate` and `version` for the next steps. Any other tag fails the
  job before building.
- Collection versioning does not clash: the collection has no tags today; if
  it ever gets tags they use `v<semver>` or bare `<semver>`, which never match
  the binary prefixes, and the release workflow ignores everything else.
  GitHub releases created by this workflow are named `<crate> <version>` and
  are created with `make_latest: false`, so the repository's "latest release"
  never points at a binary.
- Job (one per tag, `ubuntu-22.04`, no cargo cache, `permissions: contents:
  read`; only the publish job gets `contents: write`): fmt, clippy, the
  workspace tests — on the runner with the same `--workspace --exclude`
  list as CI (section 3), so a release of one crate never builds a
  CI-excluded crate on an unsupported image; a CI-excluded crate that the
  tagged crate's variants build (`software-live-apt` for `software-live`)
  is linted, tested and built only inside each variant's container —,
  `cargo build --release --locked -p <crate> --target
  x86_64-unknown-linux-gnu`, glibc floor check (2.35), smoke test
  (`<binary> --version` must print `<crate> <version> (<full commit sha>)`;
  the commit comes from the crate's `build.rs`: `<CRATE>_GIT_COMMIT` env,
  else `git rev-parse HEAD`, else `unknown`, as mailgun-relay), and a
  crate-specific extra smoke command if the crate's plan defines one
  (`release_checks.py smoke --extra ...`).
- Per-crate release settings (F2 defines the format and the defaults, a
  stream fills its own file): an optional `rust/<crate>/release.json`
  read by `release_checks.py`. Defaults, used when the file is absent:
  one variant without a name, built on the `ubuntu-22.04` runner itself,
  binaries `[<crate>]`, extra archive files `[LICENSE]` (the workspace
  MIT file), `NEEDED` allowlist glibc + libgcc_s, glibc floor 2.35. A
  crate may declare named variants, each with a container image, extra
  build packages, the workspace members to build, the archive members
  (each with its source path, e.g. `rust/software-live-apt/LICENSE` →
  `LICENSE.GPL-3.0`, the name of software-live PLAN 7.2), and a
  per-binary `NEEDED` allowlist and glibc ceiling. The release job becomes
  a matrix over the variants of the tagged crate. software-live uses this
  for `ubuntu24.04` (`ubuntu:24.04`, `libapt-pkg.so.6.0`) and `debian13`
  (`debian:13`, `libapt-pkg.so.7.0`); its plan (7.1, 7.4) owns the values.
  F2 ships the format with tests for the default and a two-variant fixture;
  it adds no real variant crate.
- As implemented in F2 (the keys and their defaults are in `rust/README.md`
  "Archive names and `release.json`"): `release.json` has one key
  `variants`; a variant has `name`, `image`, `packages`, `build`,
  `binaries` (`name`, `glibc_max`, `extra_needed` = sonames allowed in
  addition to glibc/libgcc_s, `extra_smoke` = argument lists) and `files`
  (`source` relative to the repository root, `name`). The `matrix` step
  validates it against `cargo metadata` before anything is built. Every
  binary of a variant is built inside that variant's image and smoke-tested
  with `<binary> --version` = `<binary> <version> (<commit>)`, each with its
  own ceiling and allowlist. software-live PLAN 7.2 wants the *same*
  `software-live` build (from the runner, glibc 2.35) in both variant
  archives; that needs a cross-job artifact the F2 matrix does not have yet
  — in F2 each variant builds its own `software-live` in its image, with
  the 2.35 ceiling still enforced on it. Adding the shared runner build is
  left to software-live S7 (its 7.4 last paragraph), in this workflow.
- Archive: `<crate>-<version>-x86_64-unknown-linux-gnu.tar.gz` (with
  variants: `<crate>-<version>-x86_64-unknown-linux-gnu-<variant>.tar.gz`;
  this name wins over any other spelling in a crate plan) holding
  exactly the regular files `<crate>` and `LICENSE` at its root (or the
  members the variant declares),
  deterministic (root-owned entries, commit time as mtime, gzip header
  without name), plus `<archive>.sha256`; both attached to the release
  `https://github.com/ephes/ops-library/releases/tag/<crate>-v<version>`.
  The job summary prints the sha256 and the stripped binary size.
- `rust/scripts/release_checks.py` is stdlib-only and unit-tested in
  `rust/scripts/test_release_checks.py` (tag parsing incl. prefixes that are
  prefixes of each other — `software-live` vs `software-live-apt` —,
  version mismatch, glibc floor parse fixtures, per-binary `NEEDED`
  allowlists, `release.json` defaults and a two-variant fixture,
  deterministic pack). Subcommands as implemented: `tag` (`--tag` or, for
  `workflow_dispatch`, `--crate`), `matrix`, `glibc-floor`, `smoke`,
  `verify` (glibc check + smoke for every binary of a matrix entry) and
  `pack`.

## 5. Collection packaging

- `galaxy.yml` `build_ignore` gains `rust` and `.github` (F1). `tests/` is
  already ignored. Without this, `ansible-galaxy collection build/install`
  from a developer checkout would pack `rust/target/` (hundreds of MB) into
  ops-control's `collections/`.
- F1 adds `tests/test_collection_build_ignore.py`: asserts both entries are
  present and, when `ansible-galaxy` is available, builds the collection into
  a temporary directory and asserts that no archive member starts with
  `rust/` or `.github/` and that `roles/` is still packed. Wired into `just
  test`.
- `galaxy.yml` `version` is never bumped by stream workers (campaign rule);
  CHANGELOG entries go under "Unreleased". A collection release (bump) is
  needed before a role change can be deployed, because ops-control checks
  the installed version. Owner decision 2026-10-21 (section 9): the
  coordinator makes that release commit (`galaxy.yml` bump + CHANGELOG
  heading) on ops-library `main` right before the production deploys that
  need it; each stream's plan names those slices.

## 6. Installing a pinned release binary

### 6.1 On-host layout (shared by every crate and both engines)

```
/opt/<crate>/<version>/<crate>       # root:root 0755, never modified in place
/opt/<crate>/<version>/LICENSE       # (and any other archive member, 6.2)
/opt/<crate>/<version>/.archive-sha256
/opt/<crate>/.pins/<consumer>        # root:root 0644, "<version>\n": the version this consumer runs, verified live
/opt/<crate>/.pins/<consumer>.previous  # root:root 0644, "<version>\n": the rollback pin (6.2)
/opt/<crate>/.staging-<version>/     # transient, removed on success and on failure
```

The `.pins` directory is new compared with mailgun-relay/nyxmon: several
independent consumers (for metrics-httpd up to nine roles/units on one host)
share one install root, so pruning may never remove a version another
consumer still runs. A consumer writes its pin only after it verified that its
unit (or other entry point) runs that version, and removes its pin when it
switches back to Python. Consumer names have no dot, so `<consumer>.previous`
never collides with another consumer's pin. A version (directory name, pin
content) is `MAJOR.MINOR.PATCH` with an optional pre-release and no build
metadata, the grammar of the tag `<crate>-v<version>`.

### 6.2 Ansible: internal helper role `rust_release_binary` (F3)

Implemented in F3: `roles/rust_release_binary/` (its README is the reference
for every input and fact), with the decisions (pin moves, prune plan, the
version and consumer grammar) as plain functions in
`plugins/filter/rust_release.py`, so F4 can make the same decisions on the
same files. Internal, like `webapp_deploy_internal`; used with `include_role`
+ `tasks_from` (without `tasks_from` it fails):

| tasks_from | Does | Inputs (`rust_release_binary_*`) |
| --- | --- | --- |
| `install` | the mailgun-relay `tasks/rust.yml` sequence, generalised: stat; refuse a different archive for an installed version; download with `get_url` + `checksum: sha256:` (or copy `local_archive` after checking its sha256 on the controller); list members and require exactly the regular files of `members` at the archive root, once each; unpack with `tar --no-same-owner` (not `unarchive`, which needs GNU tar on the controller side of the tests) into the staging dir; chown/chmod (`executables` 0755, other members 0644); record `.archive-sha256`; `mv --no-target-directory` into place; run `<binary> --version` as `validate_user` and assert the first line starts with `<name> <version> (`; `rescue` removes a fresh install of this include (never a directory that existed before) and fails (when `fail_hard`) or sets `rust_release_binary_failed` and warns via an ignored `fail` (mailgun-relay's pattern, so the Python rollback is never blocked; input validation is inside the guarded block for the same reason). Never moves a pin, never deletes another version | `name`, `version`, `sha256`, `members` (default `[<name>, LICENSE]`; software-live passes its helper and its GPL license file, its plan 7.4), `executables` (default `[<name>]`), `release_url` (default `https://github.com/ephes/ops-library/releases/download/{{ name }}-v{{ version }}/{{ name }}-{{ version }}-x86_64-unknown-linux-gnu.tar.gz`; a variant archive URL is passed here), `local_archive`, `install_root` (default `/opt/{{ name }}`), `validate_user` (default `nobody`), `fail_hard` (default `true`), `owner`/`group` (default root; only the tests change them) |
| `pin` | write or remove `.pins/<consumer>` and move the rollback pin `.pins/<consumer>.previous`: pinning `V` while the current pin names `C ≠ V` makes `C` the previous pin; pinning the current version again moves nothing; `state: absent` removes the current pin and keeps its version as the previous pin (unless `keep_previous: false`); an explicit `previous` replaces the automatic choice (for a consumer without a current pin that knows the live version). The previous pin is written before the current pin changes. `state: present` requires the version to be installed; a pin file that is not a regular file holding exactly one version fails the task and changes nothing | `name`, `install_root`, `consumer`, `version` or `state: absent`, `previous`, `keep_previous` (default `true`) |
| `prune` | keep the `keep_versions` (default 3) newest version directories by mtime (ties by name) **plus** every version named in any `.pins/*` (current and previous pins of every consumer) **plus** every version in `protect`; never touches symlinks, hidden entries or directories not named like a version. **Fails closed** (deletes nothing, warns with an ignored `fail`, never fails the play) when `live_state_unknown` is true, when an install of this crate failed earlier in the run, when a `protect` entry cannot be interpreted, when the root or `.pins` cannot be listed completely, or when a pin file is not a regular file holding exactly one version | `name`, `install_root`, `keep_versions`, `protect`, `live_state_unknown` (default `false`) |

Outputs (facts): `rust_release_binary_path` (`<root>/<version>/<name>`),
`rust_release_binary_failed`, `rust_release_binary_failed_names` (sticky for
the run), `rust_release_binary_pins` (`{current, previous}`),
`rust_release_binary_prune` (`{skipped, versions, keep, removed}`).

**Version protection (owner decision 2026-10-21, after the software-live and
echoport-guard plan reviews).** Prune never deletes

- (a) a version in the explicit `protect` list, which the consuming role fills
  from the **live state**: the version or the executable path that the live
  `authorized_keys` forced command, the unit's current `ExecStart`/drop-in or
  a running process names. Entries are versions or absolute executable paths
  as `readlink /proc/<pid>/exe` prints them (a trailing ` (deleted)` is
  accepted), so the list can carry the executables of **running oneshot
  processes**, e.g. a collector run that still executes vN after its unit
  moved on, and their helper children; `<root>/<version>/<file>` below the
  configured root or its resolved spelling (`realpath`) protects `<version>`,
  a path elsewhere (`/usr/bin/python3`) protects nothing, and a path that lies
  under the root but not as `<version>/<file>`, is not normalised, or names
  the binary outside both spellings of the root makes the live state unknown;
- (b) the separate `previous` rollback pin, which moves only when the
  consumer pins a new version, i.e. only after that version is verified live.

When the consumer marks its live state as unknown (`live_state_unknown:
true`: a drop-in, unit, cgroup or executable it needs could not be read),
prune deletes nothing. When to pin, what to protect and when the state is
unknown is the consumer's side (software-live plan 7.3, echoport-command-guard
plan 6.2); the mechanism and its tests are F3's.

Constraints the role keeps (and its tests assert):

- No secret is passed through `environment:` under `become_user`
  (`tests/test_become_environment_secrets.py`, ops-library ≥ 2.55.0); the
  helper handles no secrets at all and sets no `environment:`.
- `check_mode`: no download/unpack; an existing version is still validated
  (as mailgun-relay); pin and prune change nothing.
- Idempotent: a second run with the same version, pin and prune reports no
  change.
- Tests: `tests/test_rust_release_binary.py` (`just
  test-rust-release-binary`, wired into `just test`): static checks (task
  names, no `environment:`, no shell, only the version check becomes another
  user, verified download, archive member check before extraction, prune
  honours pins, `protect` and unknown state, previous pin written before the
  current one), unit tests of the filters, and `ansible-playbook` runs
  against localhost with locally built fake archives (a shell script named
  `<name>` that prints the version) in a temporary root, covering install,
  idempotent re-run, extra members, download with checksum,
  different-archive refusal, member refusals (extra, missing, duplicate,
  nested, symlink, directory, `..`), the warn-and-continue path (and prune
  blocked after it in the same run), check mode, pin moves, prune with the
  pins of two consumers and `protect`, the rollback sequence (install v2,
  roll back to v1, switch to v3 keeps v1 as the previous pin; v4 keeps v1
  only while it is protected), switch to Python keeping the last Rust
  version, repeated failed deploys with different targets that never prune
  the live version (failed verification, failed install, unknown live
  state, lost pins with the live executable protected), the executables of a
  still-running oneshot run under a symlinked root, and the fail-closed
  cases. The role targets GNU coreutils; on macOS the playbook runs use
  Homebrew's `gmv` as `mv`.

The existing `mailgun_relay_deploy` and `nyxmon_deploy` roles are **not**
migrated to the helper in this campaign (non-goal; they work and have their
own tests).

### 6.3 pyinfra: `ops_deploy.helpers.rust_release` (F4, ops-deploy repo)

Services that ops-control deploys with `engine: pyinfra` (for metrics-httpd:
`macmini_monitoring`, `logyard_core`/`logyard`, `benchmarks_static`) need the
same install semantics from ops-deploy (`github.com/ephes/ops-deploy`, pinned
by ops-control in `requirements-ops-deploy.txt`). F4 extracts the install/
verify/prune logic of `src/ops_deploy/services/nyxmon/agent.py` into
`src/ops_deploy/helpers/rust_release.py` with the on-host layout of 6.1
(including `.pins` with the `.previous` rollback pins), so Ansible and
pyinfra can take turns on a host without churn: same paths, same
`.archive-sha256`, same pin files and pin moves, same prune rule with the
same `protect` input and fail-closed cases (6.2).
nyxmon's agent keeps its own code in this campaign unless the extraction is a
pure refactor with its tests unchanged (the F4 worker decides; the review
checks it).

## 7. Slices

| Id | Repo | Scope | Depends on | Parallel | Est. |
| --- | --- | --- | --- | --- | --- |
| F1 | ops-library | `rust/` workspace (Cargo.toml, toolchain, deny.toml, LICENSE, README, `.gitignore`), `metrics-httpd` crate skeleton (`--version` with commit via `build.rs`, nothing else), `rust.yml` CI, `scripts/ci_excludes.py` (section 3), `galaxy.yml` build_ignore + `tests/test_collection_build_ignore.py`, `just rust-check`/`rust-test`, CHANGELOG (Unreleased) | — | first; nothing else needs to wait for more than F1 | 1–2 h |
| F2 | ops-library | `rust-release.yml`, `rust/scripts/release_checks.py` + tests (incl. the `release.json` format of 4 with defaults and a variant fixture), README release section; a `workflow_dispatch` dry run for `metrics-httpd` (artifact, no tag) proves the pipeline | F1 | with F3, F4 and all crate slices | 2–3 h |
| F3 | ops-library | `roles/rust_release_binary` (install/pin/prune with the `previous` rollback pin and the live-state `protect` list), `plugins/filter/rust_release.py`, README, tests, CHANGELOG | F1 (naming only) | with F2, F4 and all crate slices | 3–4 h |
| F4 | ops-deploy | `helpers/rust_release.py` with the 6.1 layout + tests; no service uses it yet | F3 (semantics frozen in its README) | with F2 and all crate slices | 2–3 h |

After F1 is merged the three streams start their own first slices; after F2
they can cut releases; after F3/F4 they can switch roles/services.

Acceptance (in addition to green `just test`, `just lint` and the new `rust`
CI job):

- **F1**: CI green on the PR/merge commit; `cargo test --workspace --locked`
  passes on a clean checkout; the built collection contains no `rust/` or
  `.github/` member (test); `metrics-httpd --version` prints
  `metrics-httpd 0.0.0 (<commit>)`.
- **F2**: the dry run produces an archive whose glibc check reports ≤ 2.35,
  the smoke test passes, the archive is byte-identical when the job is re-run
  on the same commit; tag parsing tests cover all three prefixes and the
  `software-live`/`software-live-apt` prefix pair; the variant fixture
  yields one archive name per variant.
- **F3**: the localhost playbook test passes all cases of 6.2, including a
  second consumer's pin protecting a version from prune, the previous pin
  keeping the rollback target through v1 → v2 → v1 → v3, protected live
  versions (also as running oneshot executables) surviving prune, repeated
  failed deploys never pruning the live version, and prune deleting nothing
  on unknown live state.
- **F4**: ops-deploy tests pass; a test asserts byte-identical pin/sha files
  (current and `.previous` pins) and the same prune decisions as F3 on the
  same fixture tree, including `protect` entries and the fail-closed cases
  (F3's `plugins/filter/rust_release.py` holds the reference decisions).

## 8. Review and delivery rules (all slices, all three streams)

- Each slice: own branch and worktree, review with the codex review loop
  (`gpt-6.1-sol`, high), fix, merge to `main`, push. At most three review
  rounds per slice (owner rule change 2026-10-21): round 1 over the whole
  slice, rounds 2 and 3 over the repair delta; if round 3 is not clean, the
  worker stops and reports to the coordinator instead of merging. The same
  limit applies to plan reviews.
- Merging Rust code is always safe: nothing deploys `rust/` (excluded from the
  collection) and no role installs a binary until its switch slice.
- Commit messages without tool/AI mentions; CHANGELOG under "Unreleased";
  never bump `galaxy.yml`.

## 9. Owner decisions (2026-10-21)

The owner answered the open questions of the campaign's plans on
2026-10-21 (given in chat to the coordinator) and accepted every
recommended answer. The ones that bind this foundation:

- **GitHub Actions in ops-library** (metrics-httpd Q1): yes. F1 adds
  `rust.yml` (CI for `rust/` only, `permissions: contents: read`), F2 adds
  `rust-release.yml` with `contents: write` only in the publish job; binary
  releases are published on the public `ephes/ops-library` repository.
- **Collection releases for deploys** (metrics-httpd Q2): the coordinator
  makes a collection release commit (`galaxy.yml` bump + CHANGELOG heading)
  on ops-library `main` right before the production deploys that need it.
  Workers never bump `galaxy.yml` (section 5).
- **software-live APT binding** (software-live plan, Q1): `rust-apt`
  (GPL-3.0-or-later) is allowed, but only in a separate small helper binary
  `software-live-apt`, built per distro variant (`ubuntu24.04` with
  `libapt-pkg.so.6.0`, `debian13` with `libapt-pkg.so.7.0`), with its own
  GPL license file. The main `software-live` binary stays MIT and free of
  libapt. For the foundation this means: the license override of section 1,
  the scoped cargo-deny exception and the no-`rust-apt` CI check of
  section 2, and the variant matrix and per-binary `NEEDED` allowlists of
  section 4 (F2 provides the mechanism; the software-live stream adds its
  crate, its `release.json`, the deny exception and the check). The
  release tag stays `software-live-v<semver>`; `software-live-apt` has no
  tags of its own.
- **echoport-command-guard** is ported, scheduled last in the campaign and
  never alongside other production/staging changes. The foundation slices
  are not affected (they change nothing in production); its tag prefix
  `echoport-command-guard-v*` is in F2's trigger list (section 4).
- **Review rounds**: a slice and a plan may get a third review round over
  the repair delta; if round 3 is not clean, stop and report (section 8).
