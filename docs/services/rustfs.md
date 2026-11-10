# RustFS deployment

`ops_deploy.services.rustfs` installs one pinned RustFS server (single node,
single disk) as a successor candidate for MinIO. It is a fresh service with its
own user, data root and port; it never reads, converts or shares MinIO's data
directory and adds no migration. Bucket replication to a second RustFS, its
noncurrent-version expiry and a replication monitor are optional declarations
([Replication](#replication)).

## Pinned release

RustFS **1.0.4** (GitHub release of 2026-10-25, commit `46337942d55f`), the
latest stable release when pinned, with no published advisory affecting it.
The deploy picks the artifact for the host's `uname -m`:

| Arch | Release archive | Archive sha256 | `rustfs` sha256 |
|---|---|---|---|
| x86_64 | `rustfs-linux-x86_64-musl-v1.0.4.zip` | `4924ad4b…c534b` | `96eab436…d5ecc` |
| aarch64 | `rustfs-linux-aarch64-musl-v1.0.4.zip` | `81414fd0…187a` | `d3a23915…544f` |

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
- A port preflight refuses when anything but `rustfs.service` holds the port.
  After rollout the deploy waits for the port and for `GET /health/ready`.
- With `expose_via_traefik`, `/etc/traefik/dynamic/rustfs.yml` routes
  `traefik_api_host` to the API for `internal_ip_ranges` only (no router for any
  other client, no basic auth, no compression middleware, HTTPS redirect).
  Traefik watches the file; it is not restarted.

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
  `s3:DeleteObject`, the bucket reads `s3:GetBucketVersioning`,
  `s3:GetReplicationConfiguration`, `s3:ListBucket`, ...) and a monitor identity
  that may only list those buckets and read the heartbeat objects.
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
  job starts its parity grace). Levels and reasons follow the MinIO probe:
  warning/critical by lag hours, critical when parity breaks (queue, object
  delta or size delta beyond the job's tolerances). The service exits 2 when
  a required job is critical. File-age checks on the markers are the
  operator's alerting hook.

Both monitor timers use `OnBootSec` and `OnActiveSec` (`timer_on_boot_sec`),
`OnUnitActiveSec` (`timer_interval_sec`), an `OnCalendar` backstop
(`timer_on_calendar`, default `*:0/5`) and `Persistent=true`, so a reboot or
late timer restart cannot leave them at `NEXT n/a`.

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
