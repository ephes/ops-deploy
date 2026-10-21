# software-live-apt (APT helper of software-live)

The APT observation of `software-live collect`
([`../software-live/PLAN.md`](../software-live/PLAN.md) 3.3 "APT" and 5.2) as
a separate executable. It links the distribution's `libapt-pkg` through
[`rust-apt`](https://gitlab.com/volian/rust-apt) and is therefore licensed
**GPL-3.0-or-later** ([`LICENSE.GPL-3.0`](LICENSE.GPL-3.0)), unlike the rest
of the workspace (MIT). The main binary `software-live` links neither
libapt-pkg nor this crate; it runs the helper as a child process
(`software-live/src/apt.rs`).

Nothing installs or runs it yet: the release (S7) packs it into the
`software-live` archives, the role switch (S6) installs it next to
`software-live`.

## Contract

```text
software-live-apt observe --max-age <seconds> --now <epoch>
software-live-apt --version          # software-live-apt <version> (<commit>)
```

`observe` prints the `apt` object of the report as one line of JSON and
exits 0, also when the observation is `unknown` (`"APT observation failed
(<Class>)"`: `CacheOpen`, or the OS error class of a security index whose
`stat` fails). A usage error exits 2. No stdin, no APT lock, nothing written
under `/var/cache/apt`:

- `Dir::Cache::pkgcache ""` as python-apt's `memonly=True`; when the
  directory of `srcpkgcache.bin` is writable (an unsandboxed root run) also
  `Dir::Cache::srcpkgcache ""`. Inside the collector unit
  (`ProtectSystem=strict`) the directory is read-only and libapt-pkg reads
  the warm `srcpkgcache.bin`.
- Holds come from the dpkg selection state of the cache (what `apt-mark
  showhold` prints), not from an `apt-mark` child.
- The dpkg status file counts as untrusted, as in python-apt.
- Versions are compared with NUL-terminated copies: libapt-pkg's
  `CmpFragment` reads past the end of a buffer that is not terminated, and
  rust-apt's `cmp_versions` passes Rust slices (PLAN.md 13.4).

The main binary accepts the result only with exactly `observe_apt`'s keys and
value types (`software-live/src/apt.rs`); anything else, a non-zero exit, a
timeout (60 s) or more than 4 MiB of output is `unknown` there.

## Build and checks

The crate is left out of the default CI job and `just rust-check`
(`[workspace.metadata.ci] exclude` in `../Cargo.toml`): it builds only where
`libapt-pkg-dev` and a C++ compiler are installed, and each variant links
its own libapt-pkg (`ubuntu24.04`: `libapt-pkg.so.6.0`, `debian13`:
`libapt-pkg.so.7.0`). The CI job `software-live-apt` and

```bash
just rs-software-live-apt               # both variants, in Docker
just rs-software-live-apt debian13      # one variant
```

run, inside a throwaway `ubuntu:24.04` or `debian:13` container,
`container/deps.sh` (packages, pinned rustup) and `container/run.sh`:

1. `cargo clippy -D warnings` and `cargo test` of this crate (the unit tests
   include version comparison against python-apt over the image's cache);
2. the release build, its GLIBC ceiling (2.39 / 2.41) and `NEEDED`
   allowlist (glibc, libgcc_s, the variant's libapt-pkg, libstdc++) with
   `scripts/release_checks.py glibc-floor`, and `--version`;
3. `container/setup-world.sh`: the fake APT world of PLAN.md 13.1 (fake
   packages and flat repositories for every branch of `security_origin`,
   held native and foreign-architecture packages, a pinned candidate, the
   same `.deb` in trusted and untrusted repositories; `docker-clean`
   removed as on the hosts);
4. `container/compare.py`: the helper against `observe_apt` of
   `roles/software_live/files/software_live.py` (python-apt) for fresh,
   stale and future index ages, identical JSON required; the expected
   result of every fake package; no file written under `/var/cache/apt` as
   root, and an unprivileged run (as in the unit) reading the warm cache
   without writing; a broken security index gives the same `unknown` result.

The scripts refuse to run outside a container (`/.dockerenv` or
`SOFTWARE_LIVE_APT_CONTAINER=yes`): `setup-world.sh` rewrites the APT
configuration.

## License

GPL-3.0-or-later, see [`LICENSE.GPL-3.0`](LICENSE.GPL-3.0). `rust/deny.toml`
allows this license for `rust-apt` and this crate only, and
`scripts/release_checks.py apt-isolation` (in CI and in the release job)
fails when any other workspace member can reach `rust-apt`.
