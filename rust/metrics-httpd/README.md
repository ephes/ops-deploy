# metrics-httpd (Rust port, in progress)

One Rust binary for the small authenticated HTTP endpoint daemons that the
`*_metrics_endpoint`, `metrics_endpoint`, `os_apt_maintenance`, `dns_deploy`
(DDNS status), `openclaw_deploy`, `logyard_deploy` and `static_site_deploy`
roles (and ops-control's `torrent_vpn_metrics_endpoint`) run as Python
scripts today. The contract is [PLAN.md](PLAN.md), the test map
[TESTMAP.md](TESTMAP.md). Version 0.1.0 is released (tag
`metrics-httpd-v0.1.0`, see "Release" below); nothing is deployed yet, the
hosts run the Python scripts.

Status: **S1** (core), **S2a** (`json-file` mode), **S2b** (`script`
mode), **S2c** (`apt-state` mode), **S2d** (`logyard-health` mode),
**S2e** (`static` mode), **S3** (parity harness, shadow
comparer) and **S4** (release 0.1.0). What exists:

- The command line of PLAN.md 4.9 for all five modes (`json-file`,
  `script`, `apt-state`, `logyard-health`, `static`), `--version`
  (`metrics-httpd <version> (<commit>)`) and `--check-config` (validates
  without binding, one summary line, exit 0 or 2).
- The server core: HTTP/1.1 on an IPv4 or IPv6 address with
  `SO_REUSEADDR`, header-read and keep-alive timeout (`--request-timeout`),
  at most 64 connections, graceful SIGTERM/SIGINT (exit 0), Python's access
  line on stderr (stdout for `static`, nothing for `logyard-health`), and
  the 501/404/401 answers of the Python scripts (PLAN.md 4.1).
- Basic auth against the htpasswd file with the rules of the `htpasswd`
  binary, in process (bcrypt `$2y$`/`$2a$` only, PLAN.md D-6).
- Python-compatible JSON (`json.dumps(json.loads(...), sort_keys=True)` byte
  for byte, including `float.__repr__`), the `meta` block helpers and an
  injectable clock.
- Mode `json-file` (PLAN.md 4.2): serves the JSON file with the `meta`
  block (`--meta replace`, or `merge` for dns), sorted as Python's
  `json.dumps`, with the 503/502 answers of the Python scripts; one binary
  for all eight variants (backup, storage, thermal, tailscale with
  `--path-match path-only`, dns, openclaw, ddns, torrent-vpn), selected by
  the flags of PLAN.md 7.3. Each 5xx answer writes one line with its cause
  to stderr. Which writers could produce JSON that Rust refuses (`NaN`,
  `Infinity`, lone surrogates): PLAN.md 5.3.
- `script` mode (S2b, `metrics_endpoint`): runs `--script` per request in
  its own process group and serves its stdout (200), a 502 page with the
  script's stderr or a 504 page after `--script-timeout`, which kills the
  whole process group (PLAN.md 4.4, D-8).
- `apt-state` mode (S2c, PLAN.md 4.5): serves the os_apt_maintenance
  state file with the computed `meta`, `summary` and reboot state (the
  reboot flag and `uname` are read per request), answers like the Python
  script for every fixture case, and answers with a JSON error where the
  script crashes (D-2).

- `static` mode (S2e, `static_site_deploy`): the site root served
  read-only by `tower-http`'s `ServeDir` (streamed files, `index.html`,
  `If-Modified-Since`, `Range`) with the answers of
  `static-site-httpd.py.j2` kept around it: GET/HEAD only, Python's 301
  for a directory without `/`, its 404 page, the four `end_headers`
  headers on every answer, the access line on stdout (PLAN.md 4.7, D-11).
- `logyard-health` mode (S2d, PLAN.md 4.6): configured from the
  `LOGYARD_*` environment of the unit; per request `GET /ready` and two
  `count_over_time` queries against Loki (http only, no redirects, D-13)
  and `systemctl show` per configured unit, served as the Python script's
  payload (status ok/warning/critical); no auth and no log line per
  request. `--check-config` also refuses a units list with rejected
  entries.

```bash
metrics-httpd json-file --bind 127.0.0.1 --port 9103 --path /.well-known/backup \
    --json-path /var/lib/backup-metrics/backup.json \
    --htpasswd-file /etc/backup-metrics-endpoint/htpasswd \
    --realm backup-metrics --server-name backup-metrics-httpd/0.1 --check-config
```

## Fixtures

`fixtures/generate.py` is the Python oracle (PLAN.md 8.2): it renders the
endpoint templates, runs their handlers on loopback with raw requests, calls
their `_check_auth` with the real `htpasswd`, and records CPython's
`json.dumps`, `float.__repr__`, `datetime` and `st_mtime` results.
`tests/fixtures.rs` replays every case (the `apt_state` family:
`tests/apt_state.rs`; `logyard_health`: `tests/logyard_health.rs`, with a
fake Loki in the test and the test-only `fixtures/fake-bin/systemctl`, which
the generator puts first on `PATH`). From the repository root:

```bash
just metrics-httpd-fixtures       # regenerate (venv; then 3.12 and 3.13 must agree)
just test-metrics-httpd-fixtures  # drift test, part of `just test`
```

The torrent-vpn json-file script lives in ops-control; the generator reads
it from `$METRICS_HTTPD_OPS_CONTROL`, a sibling `ops-control` checkout or
`~/projects/ops-control`, and keeps the committed torrent-vpn cases when
none is found.

`fixtures/script.json` (S2b) carries the fixture scripts themselves; the
replay writes them to a temporary directory and runs them.
`fixtures/static.json` (S2e) describes its sample site tree the same way.
`fixtures/static_real_site.json` is not generated: it records the deployed
benchmark site's files and types from the run below.

## Static-site parity

`parity/static_site.py` (stdlib) serves a site directory with the Rust
binary and compares every file (GET, HEAD, conditional GET) and directory
with the Python side: the rendered `static-site-httpd.py.j2` started on the
same directory, or a deployed server (`--reference-url`, read-only). For
the real benchmark site (S2e, 2026-10-21; no difference):

```bash
mkdir site && for f in index.html report.md snapshot.json; do
  curl -sSR -o "site/$f" "https://benchmarks.staging.django-cast.com/$f"; done
python3 -I rust/metrics-httpd/parity/static_site.py --site site \
    --binary rust/target/release/metrics-httpd \
    --reference-url https://benchmarks.staging.django-cast.com \
    --record rust/metrics-httpd/fixtures/static_real_site.json
```

`fixtures/htpasswd*` are committed test-only files (bcrypt cost 4; the
passwords are in `generate.py`), created once with `htpasswd -nbB -C 4`.

## Release

The binary is released by the tag `metrics-httpd-v<version>` through
`.github/workflows/rust-release.yml` (`rust/README.md` "Releases",
PLAN-foundation.md section 4). The crate has no `release.json`: one archive
`metrics-httpd-<version>-x86_64-unknown-linux-gnu.tar.gz` with
`metrics-httpd` and `LICENSE`, built on `ubuntu-22.04` (glibc floor 2.35),
plus its `.sha256`, attached to
`https://github.com/ephes/ops-library/releases/tag/metrics-httpd-v<version>`.
The roles pin a version and that sha256 (`metrics_httpd_rust_version`,
`metrics_httpd_rust_sha256`, PLAN.md 7.1); no release installs itself.

| Version | Tag (commit) | Archive sha256 | Stripped binary |
|---|---|---|---|
| 0.1.0 (S4, all five modes) | `metrics-httpd-v0.1.0` (`20d566c4`) | `7befbd0f4151d6eb11009d7a93a7e7defbd4559cb0c2086915fa598c6d85fc27` | 2,249,216 bytes (2.14 MiB), highest `GLIBC_2.34` |

## Build and test

From `rust/` in a worktree (never in a shared checkout; this writes
`rust/target/`), or with `just rust-check` from the repository root:

```bash
cargo test -p metrics-httpd --locked
```

## Parity harness and shadow comparer

`parity/run_parity.py` (PLAN.md 8.3) starts each rendered Python endpoint
script and the binary side by side on loopback, sends both the requests of
the fixture matrix (`http_common`, `json_file`, `script`, `apt_state`,
`logyard_health`, `static`) over
real sockets with the same file states, and compares the two live answers
by each case's `compare` mode; cases with an allowed difference (D item)
require Python's recorded answer and Rust's expectation. Then keep-alive,
concurrent requests, the slow-client D-1 difference, the SIGTERM exit codes
and `shadow_compare.py` against live pairs. From the repository root:

```bash
just rust-parity-metrics-httpd   # build, harness (CPython 3.12 endpoints), comparer tests
```

or by hand (the repo venv renders the templates; `htpasswd` must be on
`PATH`):

```bash
(cd rust && cargo build --locked -p metrics-httpd)
.venv/bin/python rust/metrics-httpd/parity/run_parity.py \
    --binary rust/target/debug/metrics-httpd --python "$(uv python find 3.12)" \
    [--family gate|json_file|script|apt_state|logyard_health|static|process|shadow ...] [-v]
```

The `rust` CI job runs the same step (with `apache2-utils`). Without an
ops-control checkout the torrent-vpn variant is reported as skipped. A
static `Content-Type` that differs is printed as a D-11 note, not a
failure: the Python side reads the host's `mime.types`.

`parity/shadow_compare.py` (PLAN.md 10.3, stdlib, copied to the hosts for
the S7 shadow run) compares the Python and Rust shadow units of one host:
`run --config <json>` appends one report line (counts, probe statuses and
differing keys, never a payload or the credential) and exits 1 on a
difference outside PLAN.md 5.2, `preflight --config <json>` checks that no
authenticated shadow answers 401, `summary --report <jsonl>...` totals the
reports. The configuration format and the comparison rules are in its
docstring; `parity/test_shadow_compare.py` tests it against fake pairs:

```bash
cd rust/metrics-httpd && python3 -I -m unittest discover -s parity -p 'test_*.py'
```
