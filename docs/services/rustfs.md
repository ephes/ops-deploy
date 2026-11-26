# RustFS deployment

`ops_deploy.services.rustfs` installs one pinned RustFS server (single node,
single disk) as a successor candidate for MinIO. It is a fresh service with its
own user, data root and port; it never reads, converts or shares MinIO's data
directory and adds no migration. Bucket replication to a second RustFS, its
noncurrent-version expiry and a replication monitor are optional declarations
([Replication](#replication)).

## Pinned release

RustFS **1.0.6** (GitHub release of 2026-11-15, tag commit `de9009d88264`),
the latest stable release when pinned, with no published advisory affecting
it. 1.0.6 replaced 1.0.4 (pinned 2026-11-03); the 1.0.5/1.0.6 scanner fixes
(usage convergence, partial-cycle progress, skipped empty tier recovery
scans) address the replica's idle load measured on 1.0.4.
The deploy picks the artifact for the host's `uname -m`:

| Arch | Release archive | Archive sha256 | `rustfs` sha256 |
|---|---|---|---|
| x86_64 | `rustfs-linux-x86_64-musl-v1.0.6.zip` | `a4d109a0…398f` | `9bb7de39…f0f1` |
| aarch64 | `rustfs-linux-aarch64-musl-v1.0.6.zip` | `dcbe86db…5855` | `21e3f324…13fb` |

Full digests live in `config.py` (`RUSTFS_ARTIFACTS`); the archive digests are
the release's `SHA256SUMS` and provenance subjects. A matching installed
executable is preserved. Otherwise the archive is downloaded into a private
temporary directory, checked, its single member extracted with Python's
`zipfile`, checked again and renamed into place. `local_binary` installs a
controller copy instead, which must match the pinned binary digest of the
host's architecture; it is uploaded beside the executable and renamed over it,
so a running server never has its executable overwritten.

## What runs

- System user/group `rustfs`, home `/var/lib/rustfs` (0750).
- Data root `data_dir` (default `/mnt/cryptdata/rustfs/data`, 0750) below
  `required_mount` (default `/mnt/cryptdata`). Before any change a read-only
  probe refuses unless `required_mount` is a mount point and the data root (or
  its nearest existing ancestor) is on it; any mount at or below an existing
  data root refuses (from `/proc/self/mountinfo`, so same-device bind mounts
  count), a symlink in the data root's existing path refuses, and the data root is walked for the first foreign-owned descendant,
  without following symlinks, reading objects or repairing anything. The unit adds `AssertPathIsMountPoint` and
  `RequiresMountsFor`, so a missing volume also stops a restart.
- `/etc/default/rustfs` (root 0600) and `rustfs.service` with
  `ProtectSystem=strict` and write access only to the data root and home.
- The S3 API listens on `127.0.0.1:9020` only by default (MinIO's 9001/9002
  are refused as values). `bind_host` may instead name one IPv4 address of the
  host, for a replica that its source reaches over a private network. The console, FTP/FTPS/SFTP/WebDAV listeners, the update check and
  the OTLP exporter are switched off explicitly; RustFS enables the console and
  the update check by default.
- `scanner_cycle_seconds` (default unset) writes `RUSTFS_SCANNER_CYCLE`, the
  pause in seconds between the end of one background scanner cycle and the
  start of the next (60 to 604800; RustFS adds ±10 % jitter).
  Unset, RustFS uses its speed preset: 60 s at the default speed. On a large
  replica (the macmini: 124,000 objects in `backups`, a usage cache of about
  90 MB rewritten every 10-20 s) every cycle ran into the 1800 s cycle runtime
  budget, ended partial and the next one started about a minute later, so the
  scanner never rested. A longer pause delays only scanner work:
  noncurrent-version expiry, usage counts and the scanner's heal checks.
  An explicit value is the normal inter-cycle cadence; dirty-usage
  notifications do not bypass it, but after a deferred cycle RustFS 1.0.6 may
  schedule a short retry (seconds) and reports that as the effective
  interval. RustFS skips the pause while it still
  rebuilds a usage snapshot it did not find at startup (admin `GET
  /rustfs/admin/v3/scanner/status`,
  `cycle_schedule.usage_bootstrap_rebuild_pending`). Since 1.0.5 the first
  cycle after a restart with a warm usage cache starts after
  `min(cycle, 60 s)` (±10 %), not after the whole interval; a cold cache or
  active replication can start it at once. Expect one scan right after every
  restart, then the configured pause; a deferred scan (the first one too) can
  be followed by a retry within seconds before that pause applies. After a change check
  `runtime_config.cycle_interval_seconds` (source `env`); that is the
  configured value. `cycle_schedule.effective_interval_seconds` may show a
  short retry after a deferred cycle and is not a check of the setting.
  Changing it rewrites the environment file and restarts RustFS.
- `tier_free_version_recovery` (default true) set to false writes
  `RUSTFS_TIER_FREE_VERSION_RECOVERY_ENABLED="false"`. RustFS 1.0.4 walked every
  bucket up to every 10 minutes for tier free versions even when no remote tier
  exists (upstream issue #8758, fixed in 1.0.5 by skipping empty tier recovery
  scans; 1.0.6 still reads the opt-out). This role configures no tiers, but it does not inspect tiers
  configured outside it: disable the sweep only on a server whose data root has
  no tier configuration (no `.rustfs.sys/config/tier-config.bin` or
  `tier-config.json`; `mc ilm tier ls <alias>` answers successfully with no
  tiers). With a tier, a disabled sweep
  leaves free versions of transitioned objects unreclaimed until it is enabled
  again. Changing it rewrites the environment file and restarts RustFS.
- A port preflight refuses when anything but `rustfs.service` holds the port.
  After rollout the deploy waits for the port and for `GET /health/ready`.
- With `expose_via_traefik`, `/etc/traefik/dynamic/rustfs.yml` routes
  `traefik_api_host` to the API for `internal_ip_ranges` only (no router for any
  other client, no basic auth, no compression middleware, HTTPS redirect).
  Traefik watches the file; it is not restarted. Its backend is this server
  (`bind_host:api_port`), or with `traefik_upstream` (`host:port`) a RustFS on
  another host, so the route can stay on the host that runs Traefik when the
  primary moves elsewhere. `traefik_api_aliases` adds further names to the
  same two routers (rule `(Host(api) || Host(alias) …) && (ClientIP …)`), so
  a neutral API name and an implementation-specific one reach the same
  backend under the same restriction; aliases must differ from the API host
  and from each other.

## Buckets and IAM as code

`buckets`, `policies` and `identities` are declarative. A standard-library
host helper reads them (with all credentials) on stdin, signs SigV4 requests to
the loopback S3 API and the native admin API (`/rustfs/admin/v3`, plain JSON;
the MinIO-compatible `/minio/admin` path needs encrypted bodies and is not
used), and prints only a pending count or a constant refusal.

- Buckets are created when absent; `versioning=True` (default) enables
  versioning, `False` leaves the state alone and never suspends it.
- Policies are created or updated when their document differs after canonicalizing
  statement order, the set-valued Action/Resource fields and Condition string
  values. Condition string-list order is ignored, and a scalar string equals a
  one-element list for every operator and key. Different Condition values still
  differ. The server's single-value spellings do not cause drift.
- Every identity is exact: its attached policies are set to the declared list,
  and group membership refuses. A disabled user refuses (the deploy never
  enables it). A recognized `SignatureDoesNotMatch`/`InvalidAccessKeyId` on a
  signed proof request (`proof`: a bucket for `GetBucketLocation`, or an absent
  key under the identity's prefix for a one-byte ranged `GetObject`) rotates
  the secret; `AccessDenied`/`NoSuchKey` prove it matches. Anything else
  refuses.
- Undeclared users, policies and buckets are left alone.

Other deploys that manage RustFS accounts reuse this helper's SigV4 client and
admin calls instead of carrying their own: `iam_client_command(program, *args)`
(`deploy.py`) runs `program` on the host with `files/iam_host.py` loaded first
(its `main` does not run). Echoport's `rustfs_admin` account provisioner uses
it ([Echoport](echoport.md#other-s3-stores)).

While planning, the helper inspects the running server; if this run installs,
rewrites the environment (root rotation) or the unit, or starts or restarts a
stopped service, the inspection waits until execution, after the restart. A healthy repeat changes nothing.

## Replication

A source server replicates declared buckets to a replica server, both
deployed by this module; the replica's deploy runs first, because the source's
target write checks the remote bucket.

- **Replica:** `bind_host` on the private address the source reaches, the
  replicated buckets (versioned, `noncurrent_expiry_days`), a replicator
  identity whose policy allows the replication actions on those buckets
  (`s3:ReplicateObject`, `s3:ReplicateDelete`, `s3:ReplicateTags`, `s3:PutObject`,
  `s3:DeleteObject`, `s3:DeleteObjectVersion`, the bucket reads `s3:GetBucketVersioning`,
  `s3:GetReplicationConfiguration`, `s3:ListBucket`, ...) and a monitor identity
  that may only list those buckets and read the heartbeat objects.
  `s3:DeleteObjectVersion` is required: RustFS authorizes a replicated DELETE
  that carries a source version ID (delete markers since 1.0.5, and version
  purges such as noncurrent expiry) as `s3:DeleteObjectVersion`; without it the
  replica answers `AccessDenied` and the deleted object stays visible there.
- **Source:** the same buckets and one `RustfsReplication` per bucket
  (`endpoint` is the replica's `host:port`). The helper creates one remote
  target per bucket (`set-remote-target`, which RustFS validates against the
  remote bucket with `RustfsCredentials.replication`) and one rule
  `rule_id` with priority 1, an empty prefix and delete, delete-marker,
  existing-object and replica-modification replication. A target whose
  stored access key differs is updated in place (`update=true&creds=true`);
  RustFS never returns a target's secret, so rotate the replicator by
  changing its access key too. Another rule or role in the bucket's
  replication document, or a lifecycle rule other than
  `replicated-noncurrent-expiry`, refuses; nothing is replaced silently.
- RustFS accepts private and Tailnet (100.64.0.0/10) target addresses and host
  names; loopback targets need `RUSTFS_REPLICATION_ALLOW_LOOPBACK_TARGET`,
  which only the local test sets.
- `noncurrent_expiry_days` writes the one-rule lifecycle document
  `replicated-noncurrent-expiry` (noncurrent versions expire after that many
  days, delete markers without versions are removed), on source and replica.

### Monitor

`monitor=RustfsReplicationMonitor(role=..., jobs=...)` installs
`/usr/local/bin/rustfs-replication-monitor` (with this module's SigV4 helper
as its library in `/usr/local/lib/rustfs-replication-monitor`), the jobs file
`/etc/rustfs-replication-monitor.json`, the monitor identity in
`/etc/default/rustfs-replication-monitor` (root 0600) and a timer (every
300 s by default). The deploy enables the timer and never runs the job.

- `source` (`rustfs-replication-heartbeat.timer`): per job the replication
  queue (`/rustfs/admin/v3/replicationmetrics`), the current object count and
  size of the bucket on both sides (paginated `ListObjectsV2`; the replica
  with the monitor identity at `replica_endpoint`, plain `http://host:port`),
  and the heartbeat object
  `heartbeat_key` written into the bucket. A job with `heartbeat=False`
  writes it into `heartbeat_status_bucket`, another job's bucket, so an
  application bucket that is synced verbatim stays free of foreign objects.
  It reads root from `/etc/default/rustfs`. A source job watches only a bucket
  replicated under its own name (`target_bucket` equal to `bucket`). An empty
  source with a nonempty replica counts as a 100 % size mismatch.
- `replica` (`rustfs-replication-lag-check.timer`): per job it reads the
  replicated heartbeat object with the monitor identity and writes
  `<state_root>/<job>/status.json` (same fields as the MinIO replica probe),
  sets `lag.marker` to the object's modification time and touches
  `parity.marker` whenever parity holds (created on the first run, so a new
  job starts its parity grace). Levels follow the MinIO probe: warning and
  critical by lag hours. A parity breach (a non-empty replication queue, or
  an object or size delta over the job's tolerances) is graded by how long
  parity has been missing, measured from `parity.marker`: `ok` below the
  job's `queue_warning_minutes` (default 30), `warning` from there,
  `critical` from `parity_critical_hours` (default 1 h, where the marker
  turns stale anyway). The heartbeat lists the source before the replica, so
  during the nightly backup burst one heartbeat can show a delta with an
  empty queue (2026-11-25/26 at 03:00 CET: `backups` 1.2 GB over its 1 GiB
  tolerance, gone with the next heartbeat 15 min later); a real gap persists
  and turns critical after the hour. A breach without a named cause, or from
  a heartbeat that lacks a parity field, is critical at once.
  `status.json` lists the deciding reasons in `critical_reasons`, the
  tolerated causes (`replication_queue_nonzero`,
  `object_delta_exceeds_tolerance`, `size_delta_exceeds_tolerance`) in
  `warning_reasons`, and the breach age in
  `parity_breach_seconds`; the journal gets one line per job that is not ok
  or has a warning reason. The service exits 2 when a required job is
  critical. File-age checks on the markers are the operator's alerting hook.
  With `status_port` (below) the unit sets `RUSTFS_MONITOR_CRITICAL_EXIT=0`
  and a run that wrote every status file exits 0 with a critical job: the
  endpoint reports it, and a unit failing on every critical run read as a
  restart loop to the journal checks (obs_daily `unit_loops`, 2026-11-20).
  Without the endpoint a critical run still fails the unit; a crash, a
  failed readiness check or an unwritable state root fails it either way.
- `replica` with `status_port`: `rustfs-replication-status.service` serves
  `GET /.well-known/rustfs-replication` on `127.0.0.1:<status_port>` for a
  Nyxmon json-metrics check on the same host. It computes per request, from
  the state root only, each job's `level`, `reasons`, status and marker ages,
  and the totals `ok` (false while a required job is critical: status file
  missing, unreadable or older than three monitor runs, probe level critical,
  `lag.marker` at `critical_hours` or `parity.marker` at
  `parity_critical_hours`), `warning` and `critical_jobs`. It runs as a
  dynamic user with the state root read-only, no credentials and loopback
  only; a preflight refuses when anything else holds the port.

The monitor deploy removes the other role's units
(`rustfs-replication-heartbeat.*` on a replica, `rustfs-replication-lag-check.*`
on a source) and an undeclared status endpoint unit: it stops and disables each, deletes
the unit files and reloads systemd. Scripts, environment, jobs file and state
stay (both roles share them).

Both monitor timers use `OnBootSec` and `OnActiveSec` (`timer_on_boot_sec`),
`OnUnitActiveSec` (`timer_interval_sec`), an `OnCalendar` backstop
(`timer_on_calendar`, default `*:0/5`) and `Persistent=true`, so a reboot or
late timer restart cannot leave them at `NEXT n/a`.

`Persistent=true` fires the job right after boot, so both services wait
first: `After=`/`Wants=` `systemd-time-wait-sync.service` (the first NTP sync;
a clock that is still off gets `RequestTimeTooSkewed` and a wrong lag) and an
`ExecStartPre=` curl on `<endpoint>/health/ready` with retries for up to 180 s
(RustFS and its Tailscale bind address still starting). A reboot therefore
leaves no failed check behind; if NTP never syncs, the job waits and its
status file goes stale instead.

Errors in the status file and journal carry only the helper's constant
diagnostics and HTTP status codes, never a credential, a server error code or
a response body.

## Proof

`tests/integration/rustfs/run-container.sh RUSTFS_BINARY EVIDENCE_DIR` runs
real pyinfra deploys in a throwaway Ubuntu 24.04 systemd container with an
owned volume at `/mnt/cryptdata`: absent-mount refusal, first deploy, strict
zero-change repeats, listener and IAM checks, identity and root rotation,
attachment drift repair, stopped-service recovery, and disabled-user,
same-device bind mount, symlinked-ancestor and foreign-data refusals. It ran on
arm64 Docker (aarch64 artifact); the x86_64 artifact is pinned by digest but
was not executed there.

`just test-rustfs-replication RUSTFS_BINARY` starts a source and a replica
from the pinned release executable as the current user on free loopback
ports (no Docker), runs the helper on both, then the heartbeat writer and the
probe: existing, overwritten and deleted objects reach the replica, more than
one listing page is counted, both jobs report `ok`, the monitor identity
cannot write, a replicator rotation updates the targets, a foreign lifecycle
rule refuses, and no credential appears in any output. It ran with the
x86_64 artifact on Linux.

## Example

```python
from pydantic import SecretStr
from ops_deploy.services.rustfs import (
    RustfsBucket,
    RustfsConfig,
    RustfsCredentials,
    RustfsIdentity,
    RustfsPolicy,
    RustfsUserCredentials,
    deploy_rustfs,
)

policy = RustfsPolicy(
    name="app-rw",
    document={
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": ["arn:aws:s3:::app/*"]}
        ],
    },
)
cfg = RustfsConfig(
    buckets=(RustfsBucket(name="app"),),
    policies=(policy,),
    identities=(RustfsIdentity(name="app", policies=("app-rw",), proof="app"),),
)
credentials = RustfsCredentials(
    root=RustfsUserCredentials(access=SecretStr("..."), secret=SecretStr("...")),
    identities={"app": RustfsUserCredentials(access=SecretStr("..."), secret=SecretStr("..."))},
)
deploy_rustfs(cfg=cfg, credentials=credentials)
```
