# RustFS deployment

`ops_deploy.services.rustfs` installs one pinned RustFS server (single node,
single disk) as a successor candidate for MinIO. It is a fresh service with its
own user, data root and port; it never reads, converts or shares MinIO's data
directory, and it adds no migration, replication or lifecycle rules.

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
  count), and the data root is walked for the first foreign-owned descendant,
  without following symlinks, reading objects or repairing anything. The unit adds `AssertPathIsMountPoint` and
  `RequiresMountsFor`, so a missing volume also stops a restart.
- `/etc/default/rustfs` (root 0600) and `rustfs.service` with
  `ProtectSystem=strict` and write access only to the data root and home.
- The S3 API listens on `127.0.0.1:9020` only (MinIO's 9001/9002 are refused
  as values). The console, FTP/FTPS/SFTP/WebDAV listeners, the update check and
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
- Policies are created or updated when their document differs after ignoring
  statement order and single-value spellings (the server stores a one-element
  list as a string).
- Every identity is exact: its attached policies are set to the declared list,
  and group membership refuses. A disabled user refuses (the deploy never
  enables it). A recognized `SignatureDoesNotMatch`/`InvalidAccessKeyId` on a
  signed proof request (`proof`: a bucket for `GetBucketLocation`, or an absent
  key under the identity's prefix for a one-byte ranged `GetObject`) rotates
  the secret; `AccessDenied`/`NoSuchKey` prove it matches. Anything else
  refuses.
- Undeclared users, policies and buckets are left alone.

While planning, the helper inspects the running server; if this run installs,
rewrites the environment (root rotation) or the unit, or starts or restarts a
stopped service, the inspection waits until execution, after the restart. A healthy repeat changes nothing.

## Proof

`tests/integration/rustfs/run-container.sh RUSTFS_BINARY EVIDENCE_DIR` runs
real pyinfra deploys in a throwaway Ubuntu 24.04 systemd container with an
owned volume at `/mnt/cryptdata`: absent-mount refusal, first deploy, strict
zero-change repeats, listener and IAM checks, identity and root rotation,
attachment drift repair, stopped-service recovery, and disabled-user,
same-device bind mount and foreign-data refusals. It ran on
arm64 Docker (aarch64 artifact); the x86_64 artifact is pinned by digest but
was not executed there.

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
