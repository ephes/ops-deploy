# metrics-httpd (Rust port, in progress)

One Rust binary for the small authenticated HTTP endpoint daemons that the
`*_metrics_endpoint`, `metrics_endpoint`, `os_apt_maintenance`, `dns_deploy`
(DDNS status), `openclaw_deploy`, `logyard_deploy` and `static_site_deploy`
roles (and ops-control's `torrent_vpn_metrics_endpoint`) run as Python
scripts today. The contract is [PLAN.md](PLAN.md), the test map
[TESTMAP.md](TESTMAP.md). Nothing here is released or deployed yet; the
hosts run the Python scripts.

Status: **S1** (core) and **S2b** (`script` mode). What exists:

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
- `script` mode (S2b, `metrics_endpoint`): runs `--script` per request in
  its own process group and serves its stdout (200), a 502 page with the
  script's stderr or a 504 page after `--script-timeout`, which kills the
  whole process group (PLAN.md 4.4, D-8).
- In the other modes a request that passes the gate gets 500
  `internal_error` until the mode's slice (S2a, S2c–S2e) lands.

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
`tests/fixtures.rs` replays every case. From the repository root:

```bash
just metrics-httpd-fixtures       # regenerate (venv; then 3.12 and 3.13 must agree)
just test-metrics-httpd-fixtures  # drift test, part of `just test`
```

`fixtures/script.json` (S2b) carries the fixture scripts themselves; the
replay writes them to a temporary directory and runs them.

`fixtures/htpasswd*` are committed test-only files (bcrypt cost 4; the
passwords are in `generate.py`), created once with `htpasswd -nbB -C 4`.

## Build and test

From `rust/` in a worktree (never in a shared checkout; this writes
`rust/target/`), or with `just rust-check` from the repository root:

```bash
cargo test -p metrics-httpd --locked
```
