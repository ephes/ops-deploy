# Fractal monitoring

`infra.mail_relay_client`, `infra.smartd` and `infra.zed` expose typed alerting
roles. `services.fractal_monitoring` combines those roles with the original
storage exporter, cached storage and backup HTTP endpoints, and MinIO lag job.
Its separate `deploy_fractal_monitoring_checks` stage validates both cached
HTTP endpoints and upserts Fractal's two original Nyxmon checks. The private
caller supplies inventory, thresholds, endpoint credentials and fixed host order.

This deployment changes no thermal/fan service, SMART schedule, APM/spindown
policy, ZFS dataset policy, backup endpoint, retention rule or collector program.
Applying a changed smartd configuration can restart its daemon and perform its
normal hardware queries. A ZED deployment enables existing scrub timers; it does
not start a scrub or invoke its post-scrub spindown hook. Physical drive behavior
requires separate inventory qualification.

## Alerting APIs

```python
from ops_deploy.infra import (
    MailRelayClientConfig,
    SmartdConfig,
    SmartdDevice,
    ZedConfig,
    deploy_mail_relay_client,
    deploy_smartd,
    deploy_zed,
)

deploy_mail_relay_client(
    cfg=MailRelayClientConfig(
        relayhost="100.64.0.2",
        myhostname="storage",
        myorigin="example.invalid",
        use_tls=True,
    )
)
deploy_smartd(
    cfg=SmartdConfig(
        devices=(SmartdDevice(name="owned-drive", device="/dev/disk/by-id/EXPLICIT-DEVICE", type="sat"),),
        mail_to="root",
        opts="--interval=7200",
    )
)
deploy_zed(cfg=ZedConfig(email_to="root", scrub_pools=("pool",)))
```

The relay edits only declared Postfix settings, compares semantic `postconf`
values and preserves distribution/unowned settings. `use_tls=False` leaves an
existing TLS setting alone. Hostname/origin defaults resolve the target's FQDN.
A genuine fresh install requires all three initial conditions: no installed
Postfix package, no `postconf`, and no main.cf. After the package creates its
account/master configuration, the helper creates only an absent main.cf from
`/usr/share/postfix/main.cf.debian`, without overwriting a concurrent file. Every
declared setting and `postfix check` must pass before the daemon starts. An
already installed missing/damaged configuration requires explicit operator
recovery; it is never mistaken for a fresh install. Interrupted initial package
bootstrap can therefore require explicit recovery rather than regeneration.

SMART defaults retain the original `-a -o on -S on`, temperature thresholds
4/40/45, short/long schedules and per-device no-spinup/schedule overrides.
`manage_service=False` skips unconditional enable/start; the original config
handler still restarts on an actual configuration change. ZED preserves unowned
RC lines and settings, scrub calendar/jitter/Persistent semantics and optional
existing post-scrub helper. No helper is invented or installed for that policy.
Small component-specific restart debt preserves failed rollouts for a retry.

## Cached monitoring

`FractalMonitoringConfig` holds `relay`, `smartd`, `zed`, `exporter`, `storage`,
`backup`, `replication`, declared Tailscale identities and explicit schema rules.
`StorageExporterConfig`, `StorageEndpointConfig`, `BackupEndpointConfig` and
`ReplicationLagConfig` retain the original templates/programs and defaults.
Collector paths, endpoints, data-directory permissions, no-login accounts without
home creation, timer policies and source version/SHA are typed inputs. Existing
endpoint account group/shell policy is enforced without creating its home.

The deployment checks cached JSON, credential validity, known files and unit
metadata. It never invokes a collector or a hardware query while planning.
Unchanged resources with a fresh schema-compatible cache cause no managed
collection. Changed collector scripts/units/jobs, or missing, stale or
incompatible reports, cause one managed refresh before schema validation and
Nyxmon updates. A recent compatible failure report remains a failure report; it
is not repeatedly refreshed until it becomes healthy. These refreshes can query
SMART/ZFS metadata and scan the explicitly configured backup/bundle directories.
They are real managed side effects, including quiet-hour cache/spindown behavior
inside the unchanged original collectors.

Endpoint rollout debt records only known pending reload/restart/timer/refresh
actions, so interrupted writes do not silently adopt an old fresh report. Native
`htpasswd` verifies on-host with password stdin. Current credentials keep their
existing bcrypt bytes; native tool/file-format/access failures refuse replacement.
Passwords and generated verifiers are never process arguments, environment values
or controller output. Endpoint Unix account provisioning uses in-host UID/GID/shell
metadata and native account tools; it does not fetch the standard broad Users
fact or return credential records. Unit prevalidation uses temporary `/run` files: this is
transient filesystem activity, not a global zero-I/O claim.

The original Python/Rust metrics-httpd implementation switch is reused. Python
remains selected when configured; an inactive pinned Rust release remains pinned
and can still undergo the original ahead-of-switch checks. No new Rust version
or switch policy is introduced.

Before any endpoint writes, path admission checks every declared file/directory
and ancestor, unit/debt/lock paths and JSON scratch path. Linked paths, wrong
file/directory types, shared scratch inodes, or a missing unmanaged external
exporter refuse as functional path-integrity errors. Only the explicit legacy
lag shell symlink may be removed. Missing owned directories can be created;
there is no engine/owner acknowledgement or adoption marker. An independently
enabled exporter is installed even with the storage endpoint disabled, and its
original root:root0755 pool-cache directory policy is enforced.

## MinIO source and failure policy

The default mc asset is the official [GitHub release asset](https://github.com/minio/mc/releases/tag/RELEASE.2025-08-13T08-35-41Z)
for `RELEASE.2025-08-13T08-35-41Z`, SHA256
`01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891`.
It replaces an unavailable legacy default download URL, with identical bytes and
version. Only the original pinned version/digest is accepted; explicit custom source URLs
remain supported for those same bytes. An existing exact binary
is not fetched or replaced; downloads stage privately and require the exact
checksum before replacement. This default executable is Linux AMD64.

The original lag program still receives MinIO credentials through its existing
host EnvironmentFile and short-lived child environment, never deployment argv
or logs. Jobs, heartbeat/parity markers, grace periods and timer policy are
retained. Recent critical/error reports are compatible cache states. A refresh
keeps the original tolerated nonzero probe policy; it does not turn a monitored
failure into an artificial healthy result. Missing/stale state can therefore
require another managed refresh on the next deployment. Periodic timers and the
explicit legacy force path continue to provide operator reassertion.

## Nyxmon and qualification scope

`FractalMonitoringChecksConfig` owns exactly Fractal Storage and Fractal Backup,
service `fractal`, interval300. Private data supplies the original59+13 rules,
notification suppression and schema paths. Credentials are added only to stdin,
including suppression auth. Both cache-only HTTP schemas/freshness checks must
pass before either SQL update. The SQL retains global retirement of the original
legacy check name, numeric ordering normalization and exact create/update rules.
A current row preserves its running status, processing marker and next schedule;
a changed/disabled row is enabled and reset exactly as in the original script.
SQLite connections are short-lived; no keeper process or exported credential
digest is used.

Owned native evidence covers real Ubuntu24 ARM Postfix bootstrap/refusal/repeat,
Python HTTP/auth/realm/cache behavior and real ZFS2.2 file-vdev metadata. SMART
lifecycle proof uses an explicitly emulated scsi_debug device, with fixture-only
virtualization-condition and SMART-capability setup; it proves no physical
NVMe/SATA efficacy. Original failed prototypes are retained. A separate owned
AMD64 KVM guest ran the exact pinned mc and MinIO with the unmodified lag program:
healthy first/repeat and status-only heartbeat passed, missing required objects
returned critical/exit2, optional critical returned exit0, parity breach retained
the grace marker, and recovery passed. Those probes wrote their declared synthetic
status/marker files; this is component evidence, not a typed composite no-op.
Inventory preflight/live qualification remains pending. No migration completion,
owner/lifecycle acceptance or hardware attestation is claimed by these APIs.
