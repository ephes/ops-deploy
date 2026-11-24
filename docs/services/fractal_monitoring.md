# Fractal monitoring

`infra.mail_relay_client`, `infra.smartd` and `infra.zed` expose typed alerting
roles. `services.fractal_monitoring` combines those roles with the original
storage exporter and cached storage and backup HTTP endpoints (the MinIO
replication lag job is removed with MinIO).
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
`SmartdDevice.temp_diff`, `temp_info` and `temp_crit` (non-negative integers,
`None` by default) override the role-wide `-W DIFF,INFO,CRIT` for one device,
mirroring the ops-library role's per-device `smartd_temp_*` keys. smartd logs at
INFO and mails once at CRIT, so give spinning disks and NVMe SSDs thresholds that
fit their specification; devices without overrides render unchanged.
`manage_service=False` skips unconditional enable/start; the original config
handler still restarts on an actual configuration change. ZED preserves unowned
RC lines and settings, scrub calendar/jitter/Persistent semantics and optional
existing post-scrub helper. No helper is invented or installed for that policy.
Small component-specific restart debt preserves failed rollouts for a retry.

## Cached monitoring

`FractalMonitoringConfig` holds `relay`, `smartd`, `zed`, `exporter`, `storage`,
`backup`, declared Tailscale identities and explicit schema rules.
`StorageExporterConfig`, `StorageEndpointConfig` and `BackupEndpointConfig`
retain the original templates/programs and defaults.
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
exporter refuse as functional path-integrity errors. Missing owned directories can be created;
there is no engine/owner acknowledgement or adoption marker. An independently
enabled exporter is installed even with the storage endpoint disabled, and its
original root:root0755 pool-cache directory policy is enforced.

`retired_mc_absent` (default `False`) removes the MinIO client that the
replication lag monitor installed at `/usr/local/bin/mc` until its removal
(RELEASE.2025-08-13T08-35-41Z, sha256 `01f866e9…`; nothing has installed it on
the monitoring host since). Only a regular file with exactly that sha256 is
removed; a symlink, another file type or another binary at the path refuses the
deployment before any change, an absent file is a no-op. The Echoport deploys
and runner registrations install the same release at the same path, so never
set it on a host that runs Echoport.

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
NVMe/SATA efficacy. Original failed prototypes are retained.
Inventory preflight/live qualification remains pending. No migration completion,
owner/lifecycle acceptance or hardware attestation is claimed by these APIs.
