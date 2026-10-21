# Rust in ops-library: shared foundation — plan

Status: plan, not yet implemented. Campaign "Rust-Ports Runde 2"
(umbrella item `rust-ports-campaign`), stream `rust-metrics-httpd`, which also
owns this foundation.

This document is the contract for the shared Rust foundation in ops-library:
the Cargo workspace under `rust/`, the toolchain and dependency policy, CI,
the release pipeline with per-binary tags, the collection packaging rules,
and the way roles (Ansible) and pyinfra services (ops-deploy) install a pinned
release binary. Three streams build on it in parallel:

| Crate (= binary = tag prefix) | Plan | Replaces |
| --- | --- | --- |
| `metrics-httpd` | `rust/metrics-httpd/PLAN.md` | the Python HTTP endpoint daemons of the `*_metrics_endpoint`, `metrics_endpoint`, `os_apt_maintenance`, `dns_deploy` (DDNS status), `openclaw_deploy`, `logyard_deploy`, `static_site_deploy` roles and ops-control's `torrent_vpn_metrics_endpoint` |
| `echoport-command-guard` | `rust/echoport-command-guard/PLAN.md` | `echoport_remote_command_guard` |
| `software-live` | `rust/software-live/PLAN.md` | `software_live` |

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
    release_checks.py     # stdlib Python: tag/version, glibc floor, smoke, pack (from mailgun-relay)
    test_release_checks.py
  metrics-httpd/          # crate + binary `metrics-httpd`  (stream rust-metrics-httpd)
    Cargo.toml  build.rs  src/  tests/  fixtures/  parity/  PLAN.md  TESTMAP.md
  echoport-command-guard/ # crate + binary `echoport-command-guard` (its stream adds it)
  software-live/          # crate + binary `software-live` (its stream adds it)
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
  the binaries release independently.
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
  explicit line with the crate that brings it, as there.
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
  `cargo test --workspace --locked`, `cargo deny check` (cargo-deny
  installed with `cargo install --locked cargo-deny@<pinned version>` or the
  pinned `EmbarkStudios/cargo-deny-action` SHA, whichever mailgun-relay's CI
  uses), and `python3 -I -m unittest discover -s scripts -p 'test_*.py'`.
- Crates may add steps (e.g. `apt-get install apache2-utils` for the
  metrics-httpd parity harness) in later slices; they do not add jobs that run
  the Ansible/Python test suite — that suite stays local (`just test`) as
  today.
- `justfile` (F1) gets `rust-check` (the same commands, run from a worktree;
  never in `~/projects`) and `rust-test`. They are **not** dependencies of
  `just test`, so `just test` keeps working without a Rust toolchain.

## 4. Release pipeline with per-binary tags

`.github/workflows/rust-release.yml` (F2), adapted from mailgun-relay's
`rust-release.yml`:

- Triggers: `push` of tags `metrics-httpd-v*`, `echoport-command-guard-v*`,
  `software-live-v*` (a stream adds its prefix to this list in the slice that
  adds its crate), and `workflow_dispatch` with an input `crate` (build +
  checks + workflow artifact, no release).
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
  workspace tests, `cargo build --release --locked -p <crate> --target
  x86_64-unknown-linux-gnu`, glibc floor check (2.35), smoke test
  (`<binary> --version` must print `<crate> <version> (<full commit sha>)`;
  the commit comes from the crate's `build.rs`: `<CRATE>_GIT_COMMIT` env,
  else `git rev-parse HEAD`, else `unknown`, as mailgun-relay), and a
  crate-specific extra smoke command if the crate's plan defines one
  (`release_checks.py smoke --extra ...`).
- Archive: `<crate>-<version>-x86_64-unknown-linux-gnu.tar.gz` holding
  exactly the regular files `<crate>` and `LICENSE` at its root,
  deterministic (root-owned entries, commit time as mtime, gzip header
  without name), plus `<archive>.sha256`; both attached to the release
  `https://github.com/ephes/ops-library/releases/tag/<crate>-v<version>`.
  The job summary prints the sha256 and the stripped binary size.
- `rust/scripts/release_checks.py` is stdlib-only and unit-tested in
  `rust/scripts/test_release_checks.py` (tag parsing incl. prefixes that are
  prefixes of each other, version mismatch, glibc floor parse fixtures,
  deterministic pack).

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
  the installed version (owner question Q2 in the metrics-httpd plan).

## 6. Installing a pinned release binary

### 6.1 On-host layout (shared by every crate and both engines)

```
/opt/<crate>/<version>/<crate>       # root:root 0755, never modified in place
/opt/<crate>/<version>/LICENSE
/opt/<crate>/<version>/.archive-sha256
/opt/<crate>/.pins/<consumer>        # root:root 0644, one line: the version this consumer runs
/opt/<crate>/.staging-<version>/     # transient, removed on success and on failure
```

The `.pins` directory is new compared with mailgun-relay/nyxmon: several
independent consumers (for metrics-httpd up to nine roles/units on one host)
share one install root, so pruning may never remove a version another
consumer still runs. A consumer writes its pin only after it verified that its
unit (or other entry point) runs that version, and removes its pin when it
switches back to Python.

### 6.2 Ansible: internal helper role `rust_release_binary` (F3)

New role `roles/rust_release_binary/` (internal, like
`webapp_deploy_internal`), used with `include_role` + `tasks_from`:

| tasks_from | Does | Inputs (`rust_release_binary_*`) |
| --- | --- | --- |
| `install` | the mailgun-relay `tasks/rust.yml` sequence, generalised: stat; refuse a different archive for an installed version; download with `get_url` + `checksum: sha256:` (or copy `local_archive` after checking its sha256 on the controller); list members and require exactly the regular files `<name>` and `LICENSE`; unpack into the staging dir; chown/chmod; record `.archive-sha256`; `mv --no-target-directory` into place; run `<binary> --version` as `validate_user` and assert `<name> <version> (`; `rescue` removes a fresh install and fails (when `fail_hard`) or sets `rust_release_binary_failed` and warns via an ignored `fail` (mailgun-relay's pattern, so the Python rollback is never blocked) | `name`, `version`, `sha256`, `release_url` (default `https://github.com/ephes/ops-library/releases/download/{{ name }}-v{{ version }}/{{ name }}-{{ version }}-x86_64-unknown-linux-gnu.tar.gz`), `local_archive`, `install_root` (default `/opt/{{ name }}`), `validate_user`, `fail_hard` |
| `pin` | write or remove `.pins/<consumer>` | `name`, `install_root`, `consumer`, `version` or `state: absent` |
| `prune` | keep the `keep_versions` (default 3) newest version directories by mtime **plus** every version named in any `.pins/*`; never runs after a failure in the same play | `name`, `install_root`, `keep_versions` |

Outputs (facts): `rust_release_binary_path`
(`<root>/<version>/<name>`), `rust_release_binary_failed`.

Constraints the role must keep (and its tests assert):

- No secret is passed through `environment:` under `become_user`
  (`tests/test_become_environment_secrets.py`, ops-library ≥ 2.55.0); the
  helper handles no secrets at all.
- `check_mode`: no download/unpack; an existing version is still validated
  (as mailgun-relay).
- Idempotent: a second run with the same pin reports no change.
- Tests: `tests/test_rust_release_binary.py` (static: task names, no
  `environment:` with secrets, archive member check present, prune honours
  pins) plus an `ansible-playbook` run against localhost with a locally built
  fake archive (a shell script named `<name>` that prints the version),
  covering install, idempotent re-run, different-archive refusal, pin, prune
  with pins, and the warn-and-continue path. `just test-rust-release-binary`,
  wired into `just test`.

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
(including `.pins`), so Ansible and pyinfra can take turns on a host without
churn: same paths, same `.archive-sha256`, same pin files, same prune rule.
nyxmon's agent keeps its own code in this campaign unless the extraction is a
pure refactor with its tests unchanged (the F4 worker decides; the review
checks it).

## 7. Slices

| Id | Repo | Scope | Depends on | Parallel | Est. |
| --- | --- | --- | --- | --- | --- |
| F1 | ops-library | `rust/` workspace (Cargo.toml, toolchain, deny.toml, LICENSE, README, `.gitignore`), `metrics-httpd` crate skeleton (`--version` with commit via `build.rs`, nothing else), `rust.yml` CI, `galaxy.yml` build_ignore + `tests/test_collection_build_ignore.py`, `just rust-check`/`rust-test`, CHANGELOG (Unreleased) | — | first; nothing else needs to wait for more than F1 | 1–2 h |
| F2 | ops-library | `rust-release.yml`, `rust/scripts/release_checks.py` + tests, README release section; a `workflow_dispatch` dry run for `metrics-httpd` (artifact, no tag) proves the pipeline | F1 | with F3, F4 and all crate slices | 2–3 h |
| F3 | ops-library | `roles/rust_release_binary` (install/pin/prune), README, tests, CHANGELOG | F1 (naming only) | with F2, F4 and all crate slices | 3–4 h |
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
  on the same commit; tag parsing tests cover all three prefixes.
- **F3**: the localhost playbook test passes all cases of 6.2, including a
  second consumer's pin protecting a version from prune.
- **F4**: ops-deploy tests pass; a test asserts byte-identical pin/sha files
  and the same prune decisions as F3 on the same fixture tree.

## 8. Review and delivery rules (all slices, all three streams)

- Each slice: own branch and worktree, review with the codex review loop
  (`gpt-6.1-sol`, high), fix, merge to `main`, push.
- Merging Rust code is always safe: nothing deploys `rust/` (excluded from the
  collection) and no role installs a binary until its switch slice.
- Commit messages without tool/AI mentions; CHANGELOG under "Unreleased";
  never bump `galaxy.yml`.
