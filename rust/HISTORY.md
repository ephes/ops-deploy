# How rust/ came to ops-deploy

The Rust workspace was written in ops-library (`github.com/ephes/ops-library`)
from 2026-10-21 on. ops-library was archived on 2026-11-17 with its final
commit `46a674c2`; it held the only source of the four crates and the only
release pipeline (`.github/workflows/rust-release.yml`). On 2026-11-18 the
workspace moved here (owner decision, design
`rust-tools-home-20261117`, option a): the Rust ports now sit next to the
Python originals and the install helper they replace.

## The history

`git filter-repo` on a fresh clone of ops-library at `46a674c2` kept `rust/`
and the 26 files outside it that the harnesses read, and moved those from
`roles/` to `rust/oracle/roles/`:

```bash
git filter-repo --path rust/ --paths-from-file oracle-keep.txt \
  --path-rename roles/:rust/oracle/roles/
```

The result, 229 commits and 4,111 files, all under `rust/`, was merged into
ops-deploy with `git merge --allow-unrelated-histories`. `git log` and
`git blame` under `rust/` reach back to the first commit. The two GitHub
workflows (`rust.yml`, `rust-release.yml`) were dropped: the checks are
`just rust-check` and `just rust-check-apt`, releases are built by
`scripts/release.py` (README.md).

## Commit ids

filter-repo rewrote every commit. The released binaries print the ops-library
commit they were built from (`software-live 0.1.2 (e317ef13…)`), and
ops-control's frozen release table records those commits. In ops-deploy the
tags of the eight releases point at the rewritten commits with the same tree
under `rust/`:

| Tag | ops-library commit (printed by the binary) | ops-deploy commit |
|---|---|---|
| `echoport-command-guard-v0.1.0` | `5b734af536a7` | `81cb0616d932` |
| `echoport-command-guard-v0.2.0` | `966d178e1a0d` | `dc340e0109dd` |
| `echoport-command-guard-v0.3.0` | `49e67ffefba5` | `589a9f2f7e16` |
| `metrics-httpd-v0.1.0` | `20d566c46251` | `deb6f08ac4e3` |
| `metrics-httpd-v0.1.1` | `e317ef13855c` | `82bc78ec386c` |
| `software-live-v0.1.0` | `98c680019c6c` | `52f8c0669a24` |
| `software-live-v0.1.1` | `2f6091e98e64` | `75b0124cee05` |
| `software-live-v0.1.2` | `e317ef13855c` | `82bc78ec386c` |

`releases.json` holds the full ids together with every asset of those
releases (name, size, sha256). It was written once, from the ops-library
releases and checked against ops-control's
`tests/fixtures/ops_library_final/rust_releases.json` and filter-repo's
commit map; no tool edits it. On 2026-11-18 `scripts/release.py import-old`
published the eight releases again as releases of ops-deploy, byte for byte,
with their tags on the rewritten commits, and the install URLs moved to
ops-deploy: one URL scheme serves old and new releases, and nothing depends
on the archived repository. Old commits are never rebuilt: their harnesses point at paths the
rewritten history does not have.

## The oracles

`oracle/roles/` holds frozen copies of the ops-library files the harnesses
compare the ports against, at their final state:

- `echoport_remote_command_guard/files/echoport-remote-command-guard.py`, the
  Python guard. It still decides on production and marina, installed by
  ops-deploy from `src/ops_deploy/base/files/echoport_remote_command_guard.py.txt`.
  `tests/test_rust_workspace.py` (in `just check`) requires both files and
  the guard fixtures' `GUARD_SHA256` to be equal, so a change to the live
  guard fails the ordinary gate until the oracle, the fixtures
  (`echoport-command-guard/parity/gen_fixtures.py`) and the port follow. The
  guard's recorded corpus came from ops-library's test module, which did not
  move; `gen_fixtures.py record` refuses and the corpus stays frozen.
- The `defaults/main.yml` of the eleven roles behind the metrics-httpd
  endpoints (path, port and timeout of each). Until 2026-11-24 the ten
  endpoint templates, `os_apt_maintenance.py.j2` and
  `dns_deploy/files/ddns_status_httpd.py` were frozen here too, and the
  harness compared the port with them. ops-deploy's own scripts had moved on
  since the archive (bounded idle clients: every connection in its own
  thread; the metrics script's stderr no longer in the 502 answer), so the
  parity results described the archive, not the fleet. The harness now reads
  the scripts ops-deploy installs (`src/ops_deploy/...`,
  `metrics-httpd/fixtures/generate.py`), the frozen copies are gone, and the
  torrent-VPN script comes from ops-deploy as well instead of an ops-control
  checkout. A change to an installed endpoint that alters what the
  fixtures record fails `just rust-check` until the fixtures are
  regenerated, and then until the port agrees wherever the replay and the
  parity harness compare. The released 0.1.0 and 0.1.1 were qualified
  against the archive's scripts; their record is this repository's history.
- `software_live/files/software_live.py` and
  `software_estate/files/collect.py`. The Python collector is retired; its
  oracle stays frozen for good, and new behaviour of the Rust port (the
  Traefik cooldown of 0.1.3) knowingly differs from it.

The harnesses resolve these files under `rust/oracle/` instead of the
ops-library root.

## Changes made with the move

- The harness roots (`parity/oracle.py`, both `fixtures/generate.py`,
  `metrics-httpd/parity/static_site.py`, `software-live/parity/run_parity.py`
  and `shadow_compare.py`, the container and e2e scripts) pointed at
  `rust/oracle/` (metrics-httpd's two since 2026-11-24 at `src/ops_deploy`,
  see "The oracles").
- The container check scripts copy only `rust/` and run on an explicit
  platform with toolchain volumes per architecture.
- `Cargo.toml` names ops-deploy as the repository.
- `rustix` 1.1.5 → 1.1.6 for RUSTSEC-2026-0486, and `deny.toml` ignores
  RUSTSEC-2026-0543 (chrono unmaintained, no vulnerability); both advisories
  were published after the archive.
- The workflow tests of `scripts/test_release_checks.py` were replaced by
  `scripts/test_release.py`.
