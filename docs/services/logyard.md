# logyard

Ports of the `logyard_deploy`, `logyard_ingress_deploy` and
`logyard_vector_deploy` Ansible roles together with the steps ops-control's
playbooks run around them. Logyard is Loki in Docker Compose (data under
`/var/lib/logyard/loki`), wired into the shared Graphyard Grafana, with a
private Traefik route for producers and a Vector journald producer per host.

```python
from ops_deploy.services.logyard import (
    LogyardConfig,
    LogyardIngressConfig,
    LogyardStackConfig,
    LogyardVectorConfig,
    NyxmonChecks,
    deploy_logyard,
)

cfg = LogyardStackConfig(
    core=LogyardConfig(
        source_path=Path("~/projects/logyard").expanduser(),
        secrets=SecretRef("secrets/prod/nyxmon.yml"),
        nyxmon=NyxmonChecks(
            suppression_url="http://macmini:9106/.well-known/os-apt-maintenance", suppression_reason="macmini"
        ),
    ),
    ingress=LogyardIngressConfig(host="logyard.example.com"),
    vector=LogyardVectorConfig(host_id="macmini"),
)
deploy_logyard(cfg, secrets)  # core, ingress, Vector: deploy-logyard.yml's order
```

Four entry points, as there are four playbooks: `deploy_logyard` (stack),
`deploy_logyard_core(cfg, secrets)`, `deploy_logyard_ingress(cfg)` and
`deploy_logyard_vector(cfg)`. The roles' dependencies are ported as
[`deploy_docker_install` and `deploy_vector_apt_install`](../infra.md).

All files are byte-identical to what the retired roles wrote (templates
shipped unchanged; `tests/test_logyard_golden.py` keeps them so, against
goldens in `tests/golden/logyard`), so the takeover rewrote and restarted
nothing.

## Secret

Only the core deploy needs one: `nyxmon_storage_metrics_password`, used as
the basic-auth password inside the Nyxmon checks' notification-suppression
block. It reaches the host on stdin only; the read-only probe compares
digests, never the stored password.

## Core (`LogyardConfig`)

| Field | Default | |
|---|---|---|
| `source_path` | required | Logyard checkout; needs `README.md`, `docs/operational-assumptions.md`, the home dashboard (the role's checks). The rsync method only; git follows after Phase 4 |
| `service_name`, `user`, `group` | `logyard` | |
| `home`, `site_path` | `/opt/apps/logyard`, `<home>/site` | compose file in `home`, config in `/etc/logyard` |
| `source_excludes` | the role's | `.git`, `.venv`, `__pycache__`, `*.pyc`, `.vault_password` |
| `docker_network_name` | `graphyard-monitoring` | shared with Grafana |
| `docker` | `DockerInstallConfig()` | |
| `loki` | `Loki()` | image `grafana/loki:3.5.11`, container, ports 3101/3100, data dir and its numeric owner `10001`, retention `336h`, schema, cache |
| `grafana` | `GrafanaWiring()` | `None` skips the wiring; container `graphyard-grafana`, datasource and dashboards paths in the Graphyard tree |
| `health` | `HealthEndpoint()` | `None` skips the endpoint; `127.0.0.1:9105/.well-known/logyard`, selector, freshness windows, `units` reported under `$.units.<id>`; `httpd_impl` (`python`), `httpd_rust_version`, `httpd_rust_sha256` select its HTTP server (the role's `logyard_health_impl` and the release pin, see [metrics-httpd switch](metrics_httpd.md)) |
| `ready_checks` | `ReadyChecks()` | 18 tries, 5 s; `None` skips |
| `nyxmon` | required | `NyxmonChecks`: database path/user, service name, health URL, interval, suppression URL and reason |

### What the core deploy does

1. Docker Engine and Compose (`docker_install`).
2. Group and nologin user `logyard`, `home` and `site_path`, `/etc/logyard`,
   Loki's data directory (`10001:10001 0755`; compared by numeric id, since
   `stat` prints `UNKNOWN` for ids without a name). Existing data is untouched.
3. `rsync` and the source sync (`--checksum`, `--delete`, owned by `logyard`).
4. Docker network (created if missing), Loki config, compose file, unit; the
   unit is enabled and started, and restarted only when one of the three
   changed (and not right after being started).
5. Grafana wiring: requires the container to exist (fails otherwise), joins
   it to the network, writes the datasource provisioning file and the
   dashboards below `<dashboards_root>/logyard` (`root:root`, `0755`/`0644`;
   files other than the dashboards keep their content and get the same
   owner and mode), starts the container if stopped. The datasource
   directory and the dashboards root are Graphyard's: they are created when
   missing, their owner and mode are left alone (see the ownership rule on
   the [graphyard](graphyard.md) page). The container restarts
   once, at the end, only if something above changed. The role copies the
   dashboards on the host after the sync; here they are put from the
   controller's checkout (the same bytes), so a change is known while
   planning.
6. Health endpoint script and unit, and the HTTP server switch's select
   step ([metrics-httpd switch](metrics_httpd.md); `metrics-httpd
   logyard-health --check-config` runs as `logyard` with exactly the unit's
   `Environment=` lines); restarted when the script, the unit or the drop-in
   changed. Then the switch's verify step: the unit runs the selected server
   and answers 200 with a JSON `status`; then the pin and the prune.
7. Read-only: Loki `/ready`, and the endpoint reporting `loki.ready`.
8. The playbook's post task: the three json-metrics checks in Nyxmon's SQLite
   database (skipped when `/home/nyxmon/site/db.sqlite3` is missing, as
   there). A read-only probe compares digests of what the database holds with
   what would be written; the upsert (the playbook's script, run as `nyxmon`)
   happens only when they differ, so a hand-edited check is repaired and a
   converged run writes nothing.

The playbook's Nyxmon checks read `$.units.vector.*`, so `health.units` should
name the `vector` unit on a host that runs the producer (the ops-control
registration does for macmini); the defaults, like the role's, report none.

Differences from the role: the apt `rsync` package is installed (the role
assumes it); `/var/lib/logyard` is created `root:root` by `mkdir -p` where
Ansible's `file` gives intermediate directories the leaf's owner; services
restart in the order of their steps instead of all at the end; the shared
Grafana directories keep Graphyard's owner (the role sets them to
`root:root`).

## Ingress (`LogyardIngressConfig`)

`host` (required, not the example), `backend_url`, `traefik_cert_resolver`,
`root_redirect_enabled`/`root_redirect_url`, `middlewares`, `allowed_paths`
(default: `POST /loki/api/v1/push`, `GET|HEAD /ready`; Loki has no auth, so
nothing else is routed), `internal_ip_ranges`. Writes
`/etc/traefik/dynamic/logyard.yml`; Traefik is not restarted (file provider).

## Vector (`LogyardVectorConfig`)

When the global and producer fragments already match the rendered content,
`root:vector` ownership and `0640` mode, validate the existing live directory
without staging files. This observational check preserves the existing
health-check policy. Any content or metadata drift uses staged validation
before replacing either live fragment. Staging creates and removes temporary
files and is counted as a mutating operation; a fully converged repeat uses
only the live-directory check.

`host_id` (required), `ingest_endpoint`, `environment`, unit and match
filters, `current_boot_only`, `min_levels`, `journald`, `files`, `darwin`,
`vector_user`, sink tuning. Installs Vector from apt, writes the
shared `00-global.yaml` (`data_dir`; a different `data_dir` already on the host
stops the deploy) and the Logyard fragment, points `/etc/default/vector` at the
config directory, removes the legacy `/etc/vector/vector.yaml`, validates the
staged directory with `vector validate --skip-healthchecks` before replacing
either file (before the defaults file or the legacy config are touched), and restarts Vector when a file changed (also on the install
run: the package may have started it with the stock config).

### What the producer ships

The remap turns each journald entry into one Loki line with the labels
`host`, `source_type`, `environment`, `service` and `level`:

- `service` is the systemd unit without its suffix (`SYSLOG_IDENTIFIER` when
  there is no unit). Login sessions (`session-<n>`, `session-c<n>`) become
  `session` and systemd's generated transient units (`run-u<n>`,
  `run-r<32 hex digits>`, `run-p<n>-i<n>`) become `run`; other `run-*` units keep their
  name, and the full unit name stays in the line's `unit` field. Entries
  Docker's journald log driver writes under `docker.service` take the
  container name (`CONTAINER_NAME`) verbatim, so Loki's own container is
  `service="logyard-loki"`.
- `level` is the application's own level when the message carries one, and
  journald's `PRIORITY` otherwise. Read in this order, first match wins:
  OpenThread's `[C]`/`[W]`/`[N]`/`[I]`/`[D]` prefix (`otbr-agent` only),
  gunicorn's `[ERROR]`-style tag, a JSON body's `level` (pino's numbers 10-60
  too; other numbers do not count) or else its `severity`, and for lines
  that start like logfmt (`key=`), the top-level `level=` or `lvl=` field
  (words inside a quoted value do not count). Words outside the known level
  names are ignored. Programs that log everything to stderr (PRIORITY 3)
  therefore no longer show up as errors, and errors written to stdout no
  longer show up as info.
- `min_levels` maps a `service` value to the least severe level that is still
  shipped (default `DEFAULT_MIN_LEVELS`: `logyard-loki` from `warning`,
  `otbr-agent` from `notice`). Loki's own query logs would otherwise come
  back into Loki as errors with every query, and OTBR writes about 200,000
  `[I]` lines a day of mesh chatter. A configured map replaces the defaults:
  to add a floor and keep them, pass
  `{**vector.DEFAULT_MIN_LEVELS, "<service>": "<level>"}`. The journal on the
  host keeps what journald's rate limit lets through. Loki itself runs with
  `server.log_level: warn` (`loki-config.yml.j2`): at `info` it wrote lines
  for every query, and during obs-daily-pack's 06:30 run journald suppressed
  4,000-11,000 docker.service messages a day, other containers' lines
  included.

`tests/test_logyard_vector_remap.py` runs the rendered remap through
`vector test` with journald-shaped events (skipped without a local `vector`).

Every shipped message (journald and files, and the Traefik user agent and
path) is redacted, best effort: a defence in depth for the common shapes,
not a guarantee for arbitrary text. In order: a URL's user information,
everything from `://` to the last `@` before the next `/`, space, quote or
angle bracket (`https://REDACTED@host`, `postgresql://REDACTED@db`; clients
accept almost any character in a password, so the rule does not parse it);
a URL query string as a whole, fragment included (`?REDACTED`); the value
of every `&name=value` or `#name=value` pair (form bodies, OAuth fragments);
bearer tokens and Basic credentials (`Bearer REDACTED`, `Basic REDACTED`,
also inside JSON). logfmt fields such as `code=200` (after a space) stay as
they are. Not caught: secrets in other shapes, e.g. a bare-word token, a
password holding a space, quote or `/`, an `@` inside a query that follows
the host without a `/`. A service that logs such text is not a candidate
for shipping without its own filter. What is guaranteed: Traefik's query
values and referer are never shipped (parsed fields only), and PostgreSQL
lines are scrubbed as described under `postgres`.

### Log files (`files`)

`files` adds log files beside journald. Each `FileSource` has its own
`service` label (unique per producer; the Vector component id and with it
the file checkpoints derive from it, so reordering `files` keeps them) and
goes to Loki through a second sink
with `source_type="file"` (labels `host`, `source_type`, `environment`,
`service`, `level`); the line carries the `file` it came from. A first start
reads from the end of each file (no history is backfilled); afterwards
Vector's checkpoints in `data_dir` resume where it stopped. Files not
written for `file_ignore_older_secs` (7 days) are not watched. File sources
need `allow_unconfined_label_templates` (the default): without it the sink
could not set `service` and `level`, and the config is refused. Fields:

| Field | Meaning |
|-------|---------|
| `service` | the `service` label |
| `paths` | absolute paths, globs (`*`, `?`) in the file name; no spaces, quotes or `..` |
| `kind` | the line parser, below (`plain` by default) |
| `drop` | RE2 patterns; a matching line is not shipped (no `'`) |
| `min_level` | floor like `min_levels` |
| `fingerprint` | `checksum` (default, of the first line) follows rename-and-create (logrotate `create`) and copy-and-truncate rotation (`darwin_log_trim`, logrotate `copytruncate`). `inode` misreads copy-and-truncate as a continuation of the old file, and after rename-and-create the new file can get a freed inode back (logrotate's `delaycompress` frees the `.1` file's inode right before it creates the new log): Vector then matches the stale checkpoint of that older file, resumes at its offset and ships nothing until the new file has grown past it (rspamd on macmini, 2026-11-21). Use `inode` only for files whose first line repeats across rotations |
| `acl` | Linux only: `dir` grants the Vector user (`vector_user`) `r-x` on the parent directory (files already world-readable in a closed directory), `files` also `r--` on the matching files there now and, as the directory's default ACL, on files created there later. A directory's first default ACL is explicit and tight (`d:u::rwx,d:g::---,d:o::---,d:m::r--` plus Vector's read): Linux ignores the creator's umask once a default ACL exists, so files created there later are readable by their owner and Vector only, whatever their mode asks for group and others. Vector's read still needs group read in the creation mode (the mode's group bits cap the mask), so a rotated log must be created like logrotate's `create 0640`, not `0600`. The directories must be literal (globs in file names only); `setfacl`/`getfacl` must be installed |
| `sample_rate`, `slow_ms` | `traefik` only, below |

The kinds:

- `traefik`: Traefik's access log, JSON (`format = "json"`) or the common
  log format. A line that matches neither (a header value with a quote, a
  garbled request) ships only as `unparsed access log line (<n> bytes)`.
  The line becomes `<status> <method> <host><path> <ms>ms
  router=<router>` with the fields `http_method`, `http_host`, `http_path`,
  `http_query_keys`, `http_status`, `duration_ms`, `router`, `client`,
  `client_user` (and `user_agent` from the common log format). Query values
  and the referer are never shipped, only the parameter names. Each path
  segment is checked percent-decoded but shipped as logged (an encoded `/`
  does not move a boundary); it becomes `REDACTED` when, decoded, it holds
  `?`, `=` or `&` (an embedded query), a `:` before an `@` (credentials of
  an embedded URL) or a run of 20 or more letters and
  digits that mixes both (tokens, hashes, signed ids, share slugs). A path
  that decodes to a Home Assistant webhook route (`/api/webhook`) becomes
  `/api/webhook/REDACTED` as a whole. Server errors, requests without a response
  (status 0), 401/403/407/429, other client errors on a routed host, and
  requests at least `slow_ms` (1000) slow are always shipped. Everything
  else (2xx and 3xx, client aborts 499 such as long polls, the 404s of
  requests no router matched) is sampled one in `sample_rate` (1 ships
  all); Vector marks those lines with `sample_rate`. `level`: `error` for
  5xx and status 0, `warning` for other 4xx except 499, else `info`.
- `postgres`: PostgreSQL's stderr log (`<time> <zone> [<pid>] [user@db
  ]SEVERITY:  text`). Continuation lines and `DETAIL`, `STATEMENT`,
  `QUERY`, `CONTEXT`, `HINT` and `LOCATION` lines (which can carry row
  values and statements) are not shipped, nor checkpoint and autovacuum
  `LOG` lines. In the lines that are shipped, everything after a
  `statement`, `execute`, `parse`, `bind` or `utility command` keyword (with
  or without `duration:`) becomes `[omitted]`, and so does the rest of the
  line from the first single quote, and from the first double quote that
  does not open the identifier after `user`, `database`, `role`, `relation`,
  `table`, `column`, `constraint` and the other object words (PostgreSQL
  inserts input values verbatim, so an embedded quote cannot end them). `FATAL` is `critical`, `PANIC` `emerg`.
- `fail2ban`: bans, unbans and jail events with the level fail2ban writes;
  the per-attempt `Found` lines (the attempts are in the journal's `sshd`
  entries) and `already banned` are not shipped. The jail is in `jail`.
- `echoport`: Echoport's cron logs (`LEVEL <date> <time> <logger> text` or
  plain lines). `DEBUG` lines and the idle scheduler ticks (`Checking <n>
  scheduled targets...`, `Complete: 0 triggered, <n> skipped`) are not shipped.
- `plain`: a level word at the start of the line, after an optional
  timestamp or in brackets (`INFO:`, `2026-11-19 16:58:46,374 WARNING`,
  `[ERROR]`; the words of the level table, `EMERG`/`PANIC`/`ALERT`/`CRIT`/
  `FATAL`/`ERR`/`WARN`/`NOTICE`/`TRACE` included), else `info`.

The `acl` grants run as root through `files/logyard_vector_acl.py`: a
read-only `check` while planning (a converged host shows no change), then
`apply` after validation and before the restart. Every directory and file is
opened one path component at a time without following a symbolic link
(`O_NOFOLLOW`) and changed through `/proc/self/fd/<n>`, so a link anywhere
in the path, or planted by a service in its own log directory, never moves a
grant onto another file; links and non-regular files among the matches are
skipped. Access is evaluated as Linux does (owner, named entry, one
matching group entry covering the whole request, `other`, within the mask).
Access the Vector user already has is left alone, and an existing named
entry is extended, keeping its rights. The mask is never recalculated
(`setfacl -n`). The deploy stops before changing anything when the grant
would not take effect or would change other rights: the mask, or for a file
without ACL its group bits, is too narrow (a `0600` file; an existing
default ACL whose mask, or group entry without a mask, excludes reading); Vector
owns the file without the bits; or Vector already has some rights through a
group or `other` that a named entry would replace. A configured directory
that does not exist stops the deploy too.

Trust boundary: Vector's file source follows symbolic links. On Linux it
reads as `vector` (groups `adm`, `systemd-journal`), so a link in a log
directory can at most point it at another file that account may read
anyway, which then ships under the source's `service`. On macOS Vector runs
as root: list only files in directories that root or the machine's
administrator account writes (the launchd agents' `~/Library/Logs`, root's
`/private/var/log`); a link planted there by that account would ship a
root-only file to Logyard, whose readers are the same administrator.

`tests/test_logyard_vector_files.py` runs the file pipelines through
`vector test`.

### macOS (`darwin`)

With `darwin` set (and `journald: false`), the producer is the Homebrew
Vector that Graphyard's Darwin deploy runs as root under launchd
(`launchd_label`, default `de.wersdoerfer.graphyard.vector`; `binary_path`,
default `/opt/homebrew/bin/vector`). The deploy installs nothing: it stops
unless that binary and the shared `00-global.yaml` exist (deploy
`graphyard_vector` first) and the `data_dir` matches, validates the staged
directory with that binary, writes the fragment `root:<config_group>`
(`wheel`) `0640`, and restarts the job with `launchctl kickstart -k` when the
fragment changed. A successful `kickstart` records the fragment's hash in
`<data_dir>/logyard-fragment.applied`; a current fragment without that
record (the restart failed), or with the job not running, is restarted
again on the next run. Only the
Logyard fragment decides; `00-global.yaml` is Graphyard's, and the staged
validation keeps the live one. Graphyard's own Darwin deploy validates the directory with
this fragment in it. The fragment has no journald source, transform or sink.

The template-confinement opt-out is chosen from `vector --version` while
planning. On a host without Vector the configured default
(`supports_template_confinement`, `True`) applies; validation stops a wrong
guess before it reaches the running service, and the next run corrects it.

## Tests

`tests/test_logyard_golden.py`, `tests/test_logyard.py`,
`tests/test_logyard_vector_remap.py`, `tests/test_logyard_vector_files.py`,
`tests/test_logyard_vector_acl.py`,
`tests/test_logyard_ingress_vector.py` and `tests/test_infra_docker_vector.py`
(fake connector: first runs, converged no-ops, each kind of change and what it
restarts, secret handling, config validation). The Ansible/pyinfra coexistence
smoke lives in ops-control (`just smoke-logyard-coexistence`).

## Per-container replacement CA store

`loki.ca_store_root` optionally names an absolute host directory containing prepared
`<container-name>/bundle.pem` and `<container-name>/empty` stores. The
container retains its pinned application image and receives a read-only mount
at `/run/managed-ca`, with `SSL_CERT_FILE` and `SSL_CERT_DIR` pointing there.
Prepare from each image’s own trust material before deployment, verify the
specific runtime honors the overrides, and refresh preparation after image or
custom CA changes. The default is unset and preserves existing image behavior.
This option replaces default native trust paths; explicit application CA
overrides still require a separate audit.

Refreshing store files alone does not trigger compose change detection. Explicitly
restart/recreate affected containers to discard loaded trust contexts, then repeat
negative and positive TLS probes. The preparation role owns root:root 0755 for
the managed store root; LiveKit declares the same metadata for bind validation.

When replacement trust is enabled, preconditions require the prepared bundle, empty directory and manifest before any service changes. A missing store fails deployment; prepare the target image first rather than allowing Compose to create a missing source.
