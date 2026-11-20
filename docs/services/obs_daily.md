# obs_daily

The observability routine on the host that runs Loki, InfluxDB and Nyxmon.
Its daily job looks for problems **nobody knows about yet**; known problems
are fixed through their own work items, so the module holds no list of
known problems. Three parts:

1. **Evidence pack** (`obs-daily-pack.timer`, deterministic, no LLM): every
   morning a JSON pack that maps the last 24 hours for an open-ended LLM
   review: an inventory of hosts, services and volumes, a raw sample of what
   every service logged (any level), and what changed against each host's
   or series' own past. It helps the reader navigate; it filters nothing.
2. **Hand-over point** (`obs_ctl.py`, run by root over SSH): an LLM triage on
   another machine fetches the pack, drills down with read-only Loki and
   InfluxDB queries (`query`), decides what is new, and hands back one
   digest, which goes out as a Telegram message through Nyxmon's notifier.
   The triage itself is not part of this module (the estate runs it on the
   Studio with Codex).
3. **Status endpoint** (`obs-daily-status.service`): a loopback JSON endpoint
   for Nyxmon checks (pack and triage freshness, systemd restart loops,
   launchd crash loops reported from a Mac).

```python
from ops_deploy.services.obs_daily import ObsDailyConfig, deploy_obs_daily

deploy_obs_daily(ObsDailyConfig(sleeping_hosts=["atlas"]))
```

## What runs on the host

| Path | Content |
|------|---------|
| `/usr/local/lib/obs-daily/obs_pack.py` | the pack builder (Python stdlib only) |
| `/usr/local/lib/obs-daily/obs_status.py` | the status endpoint (imports `obs_pack.py` from its directory) |
| `/usr/local/lib/obs-daily/obs_ctl.py` | the hand-over point |
| `/usr/local/lib/obs-daily/obs_daily_send.py` | the sender: Nyxmon's `AsyncTelegramNotifier` |
| `/etc/obs-daily/config.json` | the shared rendered config (directory `root:nyxmon 0750`) |
| `/etc/obs-daily/influx-token` | read-only InfluxDB token and its authorization ID (`root:nyxmon 0640`) |
| `/var/lib/obs-daily/` | `packs/<date>.json` and `packs/latest.json`, `signatures.json`, `status.json`, `triage/<date>-<ns>-<pid>.json`, `triage.json`, `launchd.json`, `timemachine.json` (`nyxmon:adm 2750`, files `0640`) |
| `obs-daily-pack.service` / `.timer` | oneshot as the Nyxmon user at `on_calendar` (default `*-*-* 06:30:00`, `Persistent=true`), `ProtectSystem=strict`, only `site_path` writable, up to an hour (the first run fills the baseline) |
| `obs-daily-status.service` | the endpoint as the Nyxmon user on `status_listen` (default `127.0.0.1:9123`), read-only system |

The pack runs as the Nyxmon user because it reads Nyxmon's database
(read-only, `mode=ro`) for the checks that are not ok and the HTTPS hosts
Nyxmon probes. The group `adm` (`state_group`) lets operators read packs and
status without root.

## The evidence pack

Every section runs on its own; a failing query is recorded under `errors`
and the pack is still written. All log scans drop Loki's own container logs
(`loki_exclude_lines`, default `"syslog_identifier":"logyard-loki"`): they
reach journald as stderr and come back into Loki as errors.

| Section | Source | Content |
|---------|--------|---------|
| (log hosts) | Loki's host labels of eight days plus the configured `log_hosts` | no host at all is a pack error: the configured hosts are listed as silent, the other log sections are skipped and no day enters the baseline |
| `logs.volume` | for today and each of the 7 days before, per host: `sum by (unit)` over lines whose parsed JSON has a unit (trusted), and `sum by (service)` over the other lines (caller-named, shown as `ident:<name>`) | services whose lines changed by a factor of 3 (or fell to a fifth) with at least 500 lines, services that appeared (none on the 7 days before, at least 20 today) or vanished (at least 5 of 7 days with a median of 50 or more, none today), totals per host, hosts without a line in the last hour (`sleeping_hosts` excepted). Login sessions and transient `run-u*` units are left out (thousands of streams would break Loki's series limit) |
| `logs.samples` | per host and `service` label (login sessions and transient `run-u*` units left out), the newest `sample_lines_per_window` (100) lines of each 6-hour window of the last day, at any level, four at a time | per service: lines in 24 h, lines sampled, template groups, and per group (the 6 most frequent and up to 3 that occurred once) `time n=<count in sample> <level> <raw message>` (400 characters); the detail shrinks in steps (down to one group of 120 characters) until the section fits `sample_budget_bytes` (500,000). A service whose query fails is marked and is a pack error |
| `logs.signatures` | problem-like lines (error, fail, fatal, panic, exception, traceback, denied, refused, timeout, segfault, oom, killed, corrupt, unable to, cannot, invalid, critical, abort, crash, warn, unreachable, unhealthy, degraded) per host in four 6-hour windows; a window that hits the 2,000-line limit is halved up to five times (about 11 minutes); one still at the limit is sampled, and its day stays out of the baseline | templates per source with up to two raw `examples` (400 characters): `new` (never seen in the baseline, at least `new_signature_min` lines) and `surging` (known, at least 50 lines and ten times the daily average) |
| `logs.unit_restarts` | PID 1's `Scheduled restart job`, `Start request repeated too quickly`, `Failed with result` per host and unit (transient `run-*`, `session-*`, `user@*` units ignored) | counts per unit |
| `metrics` | InfluxDB `graphyard_metrics`, 15 days up to the pack's own clock (`ctx.now`, not InfluxDB's `now()`); the daily baselines are 24-hour windows ending at the pack's time of day; no series at all, or none updated within 2 hours, is a pack error | `deviations` (gauge series, not `*_total`, whose last-24-hour mean or maximum has a robust z-score of at least `deviation_z` and a relative change of at least `deviation_relative` against their own daily values), `silent` (series quiet for over 2 hours, 2 days for `sleeping_hosts` and Home Assistant sensors, grouped by host and subject), `appeared` (first point in the last day), `filesystems` (at least 85 % used or full within 30 days at the least-squares trend; the sealed macOS system snapshot mounted at `/` is skipped, it mirrors its Data volume) |
| `tls` | every enabled Nyxmon check with an `https://` URL (its `url` and, for JSON metrics checks, the `data.url` it really fetches), plus `tls_hosts`, all of them (eight at a time) | certificates expiring within 21 days, and hosts whose handshake fails |
| `nyxmon_not_ok` | Nyxmon's database | checks whose last result is not ok (what already alerts) |

Darwin mount noise (Time Machine snapshots, `/private/tmp`, simulator
runtimes, `/dev`, the recovery volume), inode detail series and short-lived
network interfaces (`veth*`, `br-*`, `docker*`, `utun*` and the like) are
skipped.

### Templates and raw lines

A template groups variants of one message: a JSON line is flattened to
`key=value`, and values of keys that vary per event (ids, paths, URLs,
times, sizes, addresses, users, counts) become `<v>`, as do the same keys in
logfmt lines; then URLs, times, UUIDs, e-mail addresses, IP addresses,
values of secret-named keys (token, password, secret, key, auth, cookie,
session, credential; masked first, escape-aware), the word after
`user`/`for`/`from`/`login` and similar, absolute paths, long hex or base64
runs, quoted text and numbers are masked. Templates only group; next to
each group the pack carries raw lines (`logs.samples`, `examples` of
`logs.signatures`) with real host, service and unit names. Lone surrogates
anywhere in the pack become visible escapes before it is published.
`logs.samples` is measured as published (indented, nested in the pack)
against `sample_budget_bytes`; if it
does not fit even at the least detail, the lines of the last services and
then the last entries are left out (a pack note says how many). Each message is
masked from at most its first 1,000 characters and kept to 4,000, so long
lines cannot stall the pack; lone surrogates from escaped JSON become
visible `\udXXX` escapes, so a pack always encodes. A Loki answer above 64
MiB narrows its window like the line limit does, and so does a connection
Loki closes without an answer: Loki's query frontend splits a query into
1-hour pieces whose answers pass inside Loki over gRPC with a 4 MiB limit, and
a piece above it is dropped silently. The signature pass's 2,000-line limit
keeps a piece below that for lines of up to about 2 KB (on 2026-11-19, 5,000
RustFS lines of about 1.2 KB on fractal made the whole signature section
fail); a window that is still not answered at about 11 minutes is skipped with
a note, like one too large. After 40 unanswered windows in one pack the
signature section fails instead (a Loki that answers nothing is an outage, not
an oversized piece); the earlier days it had read completely and the host activity are saved first, pruned to the retention window as on a normal run. The unit-restart query and the "unit_loops" status keep
their 5,000-line limit: systemd's restart lines are short.

The source is the stream's `service` label, which Vector derives from
journald's trusted `_SYSTEMD_UNIT`. Only a line whose JSON, parsed by Loki
(`| json unit="unit"`), carries a non-empty `unit` counts as trusted (lines
the parser rejects count as caller-named, with the error labels dropped);
for any other line Vector may have used the caller-supplied
`SYSLOG_IDENTIFIER`, and the pack shows such sources as `ident:<name>`
(`logs.volume` counts the two kinds of lines separately). Trusted volume and
signature sources use the full parsed unit name (Vector strips suffixes
from the `service` label).

Trust boundary: Loki's labels and the JSON fields Vector writes (`unit`,
`pid`) come from Logyard's producers, which are the estate's own hosts
(Logyard accepts pushes only from its network allowlist). The routine
trusts them for provenance (PID 1 lines, unit-derived sources); a producer
that is itself compromised could fake restart events or label names. Log
text is data for the triage, never instructions; the triage model runs
without tools or network (see agent-stuff `tools/obs-triage`).

### Raw logs go to the triage (owner-accepted residual risk)

Owner decision 2026-11-19: the triage must read raw log lines and drill
down itself, because a filtered or anonymised view cannot show problems
nobody knows about yet. The pack and the `query` answers therefore carry
log text unchanged (hosts, services, users, paths, addresses, and any
secret a program wrongly logged) to the triage machine and from there to
the model provider (Codex, `gpt-6.2-sol`). There is no word list, no
anonymisation of names and no scrubbing pass. Secrets that show up in logs
are a finding to fix at the source (the triage reports them with a
fingerprint marker: the length and at most four first characters, never
more than a quarter of the value). What each destination receives:

- **Telegram** (outside the estate): no model text at all. The digest names
  items by slugs the triage tool assigns (`obs-<date>-<n>`), their severity
  and fixed notices; the tool checks every line against that grammar again
  before delivery.
- **The ledger** (the owner's self-hosted work app): the model's title,
  summary, next action and evidence, and its `project` (trimmed,
  `ops-control` when blank, then 1 to 41 characters of `[a-z0-9_.-]`
  starting with a letter or digit, without a credential word or token
  shape; otherwise the finding is dropped), as a best effort: a whole text
  field is
  withheld (replaced by a pointer to the local run report on the Studio)
  when it names a credential outside a marker (longer stems such as passw,
  token, secret, cookie or authoriz anywhere, even inside words; short ones
  such as key, auth or session as whole words), holds a character outside
  a closed list (printable ASCII, tabs and line breaks, which become spaces,
  äöü and a few accented letters, common typographic signs; so `Straße` or
  an emoji withholds a field too) or a token-like run (long mixed letters
  and digits, base64, hex); mail addresses are masked. Accepted residual
  risk: a copied secret without a credential word nearby that does not look
  like a token (short, letters only) can reach the ledger.
- **macmini's triage archive** (`/var/lib/obs-daily/triage/`, Nyxmon user
  and `adm` group): every valid result that got the delivery lock and could
  read the previous status, archived before the send is tried; the send
  happens only once the archive write succeeded (so a failed send or a
  retry leaves a record; a lock timeout or an unreadable status sends
  nothing and leaves none, and a failed archive write sends nothing, though
  a record may already be in place): `date`, `status`, `ran_at`, the digest text, `detail` (300
  characters) and the first 20 created items' slugs and titles (200
  characters each). Titles produced by the current
  triage filter are filtered as in the ledger; the same residual applies.
- **The Studio run report** (owner-only files): the model's full answer.

Accepted residual risk: a secret logged by mistake reaches the model
provider before it is found and rotated.

Templates are counted per host: a failure that is routine on one host is
still new when it first appears on another. The pack groups the same
template of several hosts into one entry with `hosts`. The baseline keeps
counts only, no raw lines.

The baseline `signatures.json` keeps one count per host, template and day for
`signature_retention_days` (30). "New" and "surging" compare today only with
the retained days strictly before today, so a rerun on the same day reports the same.
On the first run, and after a gap, it is filled from up to `backfill_days`
(7) earlier days before today is compared. A host's surge average counts
the covered days on which it is known to have shipped a log line or on
which the template occurred
(`host_active`, confirmed from all its lines, sessions and transient units
included, over the last eight days of each run), so a newly shipping host
is not measured against days before it existed. A day with a window that had to
be skipped (too large or not answered even after splitting) never enters the baseline and is
a pack error; the next run tries it again. A pack larger than
`pack_max_bytes` (1,200,000; at most 2,000,000, half of what `obs_ctl.py
pack` hands over; the model reads it in one go) has its longest lists halved until it
fits, which is a pack error too; one that still does not fit is replaced by
a small error pack.

## The hand-over point

```bash
ssh root@<host> /usr/bin/python3 -I /usr/local/lib/obs-daily/obs_ctl.py --config /etc/obs-daily/config.json pack
ssh root@<host> /usr/bin/python3 -I /usr/local/lib/obs-daily/obs_ctl.py --config /etc/obs-daily/config.json deliver < result.json
ssh root@<host> /usr/bin/python3 -I /usr/local/lib/obs-daily/obs_ctl.py --config /etc/obs-daily/config.json launchd < report.json
ssh root@<host> /usr/bin/python3 -I /usr/local/lib/obs-daily/obs_ctl.py --config /etc/obs-daily/config.json timemachine < report.json
ssh root@<host> /usr/bin/python3 -I /usr/local/lib/obs-daily/obs_ctl.py --config /etc/obs-daily/config.json query < queries.json
```

(`ObsDailyConfig.ctl_command(action)` renders the command.)

`lib_dir` and `config_dir` must not overlap `site_path` or the Nyxmon
site (config validation), and the deploy checks, before its first
privileged write and again after them, that the scripts, the config and the
token file root uses, and every existing directory above them and above
`site_path`, belong to root and are not group- or world-writable, and that
`site_path` is no link. It reads its config as root and does every file access in `site_path` as
the Nyxmon user, who owns it: root never opens a path there, so a link
planted in the directory cannot reach a privileged file. Files are written
through a fresh temporary file and renamed. Only the sender starts while
still root, through `systemd-run` as the Nyxmon user.

- `pack` prints `packs/latest.json` (at most 4 MiB, a regular file reached
  without following any link below `site_path`); exit 3 when there is none.
- `deliver` reads `{"date", "status": "ok"|"skipped"|"failed", "detail",
  "message", "new_items", "ran_at"}`, keeps it as
  `triage/<date>-<ns>-<pid>.json` (one record per received result, so a
  rerun never overwrites an earlier one; if that write fails, nothing is
  sent, the call exits 1, and a record may already be in place), then sends a non-empty `message` (at
  most 3,800 characters; one without visible text is refused) through
  `systemd-run` as the Nyxmon user with Nyxmon's Python, and writes
  `triage.json`. The sender reads Nyxmon's environment file itself
  (`--env-file`), as the Nyxmon user; systemd's `EnvironmentFile=` would open
  that Nyxmon-writable path as root. There is no queue on this host: it
  prints `obs-ctl: delivered` only once Telegram acknowledged the message
  (or there was nothing to send), and the caller keeps the result and sends
  it again until the call exits 0 with that line, whole, on standard output
  (an SSH failure or timeout after the line counts as unconfirmed; the Studio keeps such results in its
  outbox, the newest 30: an outage of more than about a month loses the
  oldest). A lost confirmation means a repeated message. Diagnostics go to
  standard error; standard output carries only that receipt line.
  One delivery at a time (`/run/obs-daily-ctl.lock`, outside the state
  directory; after a minute of waiting it sends nothing and exits 3). File
  reads and writes happen in children that dropped to the Nyxmon user (a
  `triage.json` that exists but is empty, larger than 1 MiB or cannot be
  read as a regular JSON file within 20 seconds, or a write that does not
  finish within 20 seconds, stops the delivery; exit 1), and each write is
  synced (file and directory). A `ran_at` more than five minutes in the
  future is refused. `epoch` moves when a result reached the owner (or had
  nothing to send); `ok_epoch` (behind `triage.age_seconds`, which Nyxmon
  checks) only for a delivered result with status `ok`, and to the time
  that triage ran (`ran_at`, finite epoch seconds, required for `ok`), so a
  replayed old result never makes the triage look fresh. Exit 0 delivered
  or nothing to send, 1 the send failed, 2 unusable input, 3 lock busy.
- `query` runs the triage's drill-down: `{"queries": [{"kind", "query",
  "start", "end", "limit", "step", "fn"}]}` (1 to 10 queries, each at most
  4,000 characters), as the Nyxmon user (it drops privileges before reading
  its input; that user can read the read-only InfluxDB token). `start`/`end`
  are `now`, `-24h`/`now-90m` (s, m, h, d), RFC 3339 or epoch seconds
  (default the last hour, `end` never in the future), quantized once to whole
  microseconds, a range of at most 31 days for every kind; what is checked
  is exactly what is sent.
  - `loki` runs LogQL through `query_range` (log lines or metric series):
    `limit` 1 to 500 lines (default 200), `step` whole seconds (raised so a
    range yields at most about 1,000 points). A log line comes back as
    `time host/service level message | {other fields of the record}` (unit,
    pid, boot id, ...; 1,000 characters, in time order); a series that does
    not fit keeps its newest points (`points_cut` counts the others).
  - `influx` and `influx_series` take a tag selector instead of Flux:
    space-separated `key=value`, `key!=value` or `key=~regex` terms (1 to 12;
    values only of letters, digits and `_.,:/@%+-`, so a Flux string literal
    can neither interpolate `${...}` nor escape; regexes without `/`, `"` and
    whitespace and without backslashes other than `\.`, `\d`, `\w`, checked in
    one pass), e.g.
    `metric=host.load5 subject_id=fractal`. The script builds the Flux
    itself (bucket, measurement `graphyard_metrics`, field `value`, the exact
    range with microseconds, the selector as string literals), so no free Flux reaches
    InfluxDB: no other server, no writes, no imports. `influx` aggregates each
    matching series with `fn` (`mean`, `max`, `min`, `last`, `count`, `sum`)
    in windows of `step` seconds, widened to at most 500 points per series;
    `influx_series` returns the newest point of every matching series (with
    all its tags), for discovery. Rows come back as JSON.

  Each query runs in its own thread with a 60-second socket timeout and is
  abandoned after 65 seconds of wall-clock time (an answer that keeps
  trickling cannot hold the batch), and reads at most 8 MiB; no query starts
  after 480 seconds. Each result is cut at 24 KiB (`cut` counts what was left out). A
  refused or failing query is an `error` in its result; the others still
  run. Raw records go out unchanged (see above); lone surrogates become
  visible `\udXXX` escapes. Exit 0, or 2 on unusable input.
- `launchd` reads `{"host", "checked", "errors", "loops": [...]}` from a Mac
  (one report at a time, `/run/obs-daily-launchd.lock`)
  and keeps it as `launchd.json` with its arrival time; a report that
  sampled no job (`checked` 0), has non-integer counts or a loop without a
  label is refused. The merge runs in a child that is stopped after 20
  seconds, so a stalled report never keeps the lock. Every loop is counted;
  each keeps its own last sighting (at most 500 kept, newest first, and the
  file kept below half a MiB; counts are integers below 10^9), and the
  endpoint lists at most 20. A `launchd.json` that exists but cannot be read
  (too large, not a regular JSON file) makes the report fail (exit 1)
  instead of being overwritten, so held loops are never erased unseen. Each job's loop stays reported for 30 minutes
  after its own last sighting (`last_seen`), so Nyxmon's polling sees a short
  burst; the endpoint applies the same expiry when it answers. State files are read only when they are regular files, by a child
  with a 20-second limit.
- `timemachine` reads one Time Machine probe report from a Mac (agent-stuff
  `tools/tm-guard`, every 5 minutes on the Studio; ops-control
  `runbooks/time-machine-client-stall.md`): `host`, `tmutil` (`ok`,
  `timeout`, `hung` for a `tmutil` the probe killed that still has not
  exited, `error`), `running`, `stopping`, `phase`, `percent`, `bytes`,
  `files`, `total_bytes`, `total_files`, `auto_backup`, `stalled_seconds`
  (seconds a running backup went without any progress), `band_check` (`ok`,
  `failed`, `skipped`) with `band_newest_epoch` (the newest write into the
  bundle's `bands/` and `mapped/` on the backup server), `cross_check_ok`
  and `probe_epoch`. Every field is type- and range-checked before it is used
  (texts must be strings and are cut to printable ASCII, 200 characters;
  numbers are range-checked before any conversion); a report whose `tmutil`
  answered needs `running`. It replaces `timemachine.json` (one report at a
  time, `/run/obs-daily-timemachine.lock`, written as the Nyxmon user by a
  child that is killed after 20 seconds and, if it still does not exit,
  left behind 5 seconds later, so a writer stuck in I/O never holds the
  lock; a child that may be left behind first closes every inherited
  descriptor, the lock and the SSH streams included) with its arrival time.
  The endpoint reads the times from it only as plain integers: an unusable
  arrival `epoch` reads as no report, an unusable `stalled_seconds` as
  `999999999` (its rules fail), an unusable `band_newest_epoch` as a null
  `band_age_seconds`; the other fields pass only as strings, booleans or
  finite numbers (anything else becomes null). Exit 0 kept, 1 not
  written, 2 unusable input, 3 another report held the lock.

## The status endpoint

`GET http://127.0.0.1:9123/.well-known/obs-daily`:

```json
{
  "pack": {"date": "2026-11-18", "errors": 0, "age_seconds": 3600},
  "triage": {"date": "2026-11-18", "status": "ok", "delivered": true, "age_seconds": 60, "delivery_age_seconds": 60},
  "unit_loops": {"ok": true, "error": null, "window_seconds": 3600, "count": 0, "loops": []},
  "launchd": {"host": "studio", "checked": 22, "count": 0, "loops": [], "age_seconds": 120},
  "timemachine": {"host": "studio", "state": "disabled", "tmutil": "ok", "tmutil_ok": true, "running": false,
                  "auto_backup": false, "stalled_seconds": 0, "cross_check_ok": true, "band_check": "ok",
                  "band_age_seconds": 7200, "age_seconds": 90, "...": "phase, percent, bytes, files, totals, details"}
}
```

`timemachine` is the last probe report: `tmutil_ok` is true only when
`tmutil status` answered in time, `stalled_seconds` is the probe's count of
seconds a running backup went without progress (0 when none runs),
`cross_check_ok` is false when a backup runs and the band read on the backup
server failed, and `state` (`no report`, `tmutil <timeout|hung|error|unknown>`,
`running <phase>`, `disabled`, `idle`) is for the reader only: `disabled`
(automatic backups off, none running) is a normal state, not a failure.
Without a report `age_seconds` is `999999999` and the other rules' fields
are missing.

`triage.age_seconds` is the age of the last triage that ran (status `ok`)
and reached the owner; a day that was `skipped` or `failed` is delivered as
a notice (`delivery_age_seconds`) but lets `age_seconds` grow, so a triage
that never runs shows up. The endpoint reads state files only when they are small regular files (a
link or FIFO reads as missing). A missing file reads as age `999999999`, so a
threshold check fails instead of passing on a missing value; `pack.errors` counts pack sections whose
source failed. `unit_loops` comes from a background thread that queries Loki
every `cache_seconds` (60, at least 30) for the last `loop_window_seconds`
(3,600), one query per host, so a request never waits for Loki and a burst
on one host cannot crowd out another (`truncated_hosts` names a host with
more matching lines than one query returns, and the result is then not
`ok`). Only PID 1's own lines count: journald's trusted `_PID` is 1 and
`_SYSTEMD_UNIT` is `init.scope`, filtered in Loki (`service="init"`, then
`| json pid, unit | pid="1" | unit="init.scope"`) together with the transient
units before the line limit applies; user managers
(`systemd --user`) are not covered. A unit is in a loop
with at least `loop_events` (5) restart jobs or failures, or once systemd
gave up on it ("Start request repeated too quickly"). Unit names are
reported as logged. `ok` is false while
nothing was checked yet, after a failed query, when the last result is
older than three refresh rounds, when a host's query failed
(`failed_hosts`; the other hosts' loops are still reported), when no host
logged in the window, when
a host shipped no PID 1 line (`service="init"` with `pid` 1 and unit
`init.scope`) in a day (`no_pid1_hosts`:
its loops would go unseen), or
when a host of `log_hosts`, or one that logged in the last day, did not
(`missing_hosts`: it stopped shipping logs or is down; a configured host
stays missing until it is removed from `log_hosts`; `sleeping_hosts`
excepted). Activity
comes from a bounded `count_over_time` query, not Loki's label metadata.

## The read-only InfluxDB token

The deploy runs `files/influx_read_token.py` (as a `python3 -I -c`
argument, backslash-free for a fish root shell). `check` tries a query with
the token in `/etc/obs-daily/influx-token`; when that fails, `ensure`
checks again (a probe can fail on a passing hiccup) and keeps a working
token. Otherwise it creates one with `influx auth create --read-bucket
<bucket id>` inside `influx_container` (whose CLI holds the operator login),
checks it from a temporary file, installs it, and only then deletes the
older authorizations of this deployment (described `obs-daily read-only
<token file>`), all under a lock next to the token file. The token
file holds the token and, on its second line, the active authorization's
ID (one rename installs the pair); authorizations are told
apart by ID for cleanup. A kept token must be that authorization's token
(compared with the authorization list in memory, never printed), the
authorization active and allowed only to read the bucket. Where InfluxDB
hashes tokens and lists none, the binding cannot be shown: `ensure` refuses
before creating anything (a limitation of this module); a new token that
fails its checks is revoked again and its temporary file removed; the token must also be refused when it asks for the authorizations
list (so no operator token is ever kept). A working token
gets the same cleanup, and `check` reports `stale` while another
authorization of this deployment exists, so the deploy runs `ensure` and a
rotation interrupted after the install is finished by the next deploy. It refuses a token file whose directories are not
root-only and never follows a link at the token file itself. `check`
reports `stale` when the file is root's but its group or mode differ from
`root:<group> 0640`, and `ensure` repairs that. A token file that is not
root's, or is group- or world-writable, already fails the trusted-path check
while planning, before `ensure` runs: remove it (`rm
/etc/obs-daily/influx-token`) and deploy again, which creates a new token
and revokes the old authorizations of this deployment. The trusted-path check also runs while planning, before pyinfra reads
anything about the target files. The token is never printed and never on a command line. The
deploy then checks it again, checks with `systemd-run` as the Nyxmon user
that the sender loads Nyxmon's notifier with credentials (`--check`; it sends
nothing), and that the endpoint answers with its sections. It never builds a
pack or sends a message itself.

## Rollout

The Nyxmon checks that read the endpoint belong to the caller (ops-control
adds each one once its inputs exist: the endpoint, a pack and a recorded
triage result, a launchd report). A first rollout is: deploy; start `obs-daily-pack.service`
once; run the triage and the launchd report once from the triage machine;
deploy again; check that the three checks exist in Nyxmon; make sure the
triage machine's scheduled jobs (daily triage, launchd report, weekly
review) are installed and loaded, since the manual runs above do not prove
that; read the
endpoint (`pack.errors` 0, `unit_loops.ok` true, `launchd.age_seconds`
small) and the checks' first results in Nyxmon. A quiet triage day sends no
message (and still moves `triage.delivery_age_seconds`), so Telegram delivery
is proven only by an observed digest or notice: one that arrived in Telegram,
or `triage.json` showing `delivery: delivered` for a non-empty message.

## Running it by hand

```bash
systemctl start obs-daily-pack.service       # build today's pack (no message)
journalctl -u obs-daily-pack.service -n 20
curl -s http://127.0.0.1:9123/.well-known/obs-daily
```

The pack builder's exit status: 0 pack written, 2 unusable configuration.
