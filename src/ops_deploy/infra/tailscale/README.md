# Tailscale core, cached endpoint and identity lifecycle

`deploy_tailscale(TailscaleConfig(...), secrets)` keeps the original Debian/Ubuntu
repository, package-present and service policy. `package_version="latest"`
means present, not an upgrade of an existing package. Ordinary deployment
refreshes the configured upstream public key, validates it with native GnuPG
without a temporary home/keyring, and compares before replacement. Fetch or
validation failure preserves the existing key and fails visibly. Native GnuPG
is an explicit install-missing prerequisite alongside the original python3-debian.

Running nodes keep their identity and are never rejoined. Only actual selected
`CorpDNS`/`RouteAll` preference drift invokes `tailscale set`. The target-local
reader uses sanitized LocalAPI preferences and sends just those two booleans,
backend state and native version to the controller. An absent native socket
and genuinely unreachable daemon are an explicit unavailable dependency, never
inferred preference values; service start precedes preference/join decisions,
and final verification requires the daemon to be readable. It never exports raw status,
preferences, peer/user profiles or state files. The native qualification is bound
to Tailscale1.104.2; an unsupported selected schema fails rather than inventing
false defaults. Non-manual joins use the original `tailscale_auth_key` secret
through redacted stdin and a private0600 target-local one-use file. Credential
values never appear in argv, environment or native failure output. Manual-up
keeps the original operator-managed join behavior.

`deploy_tailscale_metrics` retains all five original Python/unit templates,
the optional pinned Rust switch, original service sandbox and IPAddressAllow,
periodic calendar/monotonic backstops and effective ingress/egress BPF validation.
A healthy compatible fresh cache does not trigger collection. Managed input
change, missing/stale/schema-incompatible cache or pending rollout work invokes
the original collector as a managed action. Fresh false/error health results
stay visible; they do not trigger a refresh merely to erase an alert. Dry plans
never collect, query hardware or execute repair. Partial resource/reload/refresh
work uses the existing shared endpoint rollout journal, cleared after convergence;
it is recovery debt, not an adoption or hardware-attestation marker.

`deploy_tailscale_nyxmon` implements the dedicated original SQL upsert, with
credentials bound exactly to prepared endpoint targets. It updates only type,
URL, interval and check data. Existing disabled/status/processing/schedule
columns remain untouched even when configuration changes. It never retires
other checks or re-enables a disabled check. A missing optional database skips;
permission, schema and I/O failures refuse writes. Check uses SQLite read-only
mode and emits no row, credential or verifier contents.

`deploy_tailscale_backup` preserves the original timestamped state/config/dropin
layout, gzip archive, latest links, shallow archive permission repair and optional
controller fetch. Backup is intentionally managed and reads identity material.
The declared operator destination defaults to `~/backups/tailscale`; there is no
workspace restriction. Controller directory0700/archive0600 and a unique remote
0700 directory/0600 login-user handoff avoid pyinfra3.10's sudo download `chmod +r`
copy. Transfer cleanup runs after failure as well as success; uncertain cleanup
must retain the writer slot. The backup preserves the original hot-rsync
consistency limit; it does not claim an application-atomic identity snapshot.

The original ordinary backup default is `prefix="manual"`, while restore
requires an inventory-host filename prefix. Keep that limitation explicit:
`just backup tailscale macmini macmini` creates a host-prefixed archive for
`just restore-tailscale-manual latest macmini`. A differently-prefixed newest
archive makes the original `latest` policy refuse, rather than silently choosing
another snapshot. Explicit wrong-host archives always refuse. Host-bound latest
selection and aligning legacy defaults remain a separate bounded follow-up.

`deploy_tailscale_manual_restore` is explicitly for a manual LAN/out-of-band
connection. Ordinary restore remains excluded from metadata dispatch because
stopping tailscaled over Tailnet would sever the connection. Validate host prefix,
archive integrity, native rsync availability and member/path safety before
stopping the daemon. Staging admission requires trusted root-owned ancestors;
creation walks directory descriptors with no-follow opens and fd metadata
updates, refusing a precreated unprivileged `/tmp` entry before any change. Extract in
private staging, then stop, restore original paths without deleting unrelated
state, and apply the requested original start/restart and optional private-file
up policy. Failure after stop preserves partial state and fails; there is no
automatic repair/replay. Never treat a successful synthetic copy/service-control
test as production identity or physical-network qualification.

`deploy_tailscale_remove` requires the original explicit removal confirmation.
It preserves original stop/disable then best-effort logout ordering and the
separate skip_logout flag. Logout after stop can fail, so online authorization
revocation is not attested. The actual1.104.2 vendor postrm deletes state on dpkg
purge: default `purge_state=False` therefore removes the package without purge;
true explicitly purges. This corrects the source role's unconditional purge,
which contradicted its state-preservation flag. Repository resources are removed;
state/sysconfig/dropins are explicitly removed only on requested purge. Existing
metrics consumers follow the original lifecycle contract and are not silently
redefined as part of package removal.

Owned fixture capability/component proofs, source provenance, installed-artifact
proof and inventory qualification are distinct. These APIs alone do not attest
real inventory, physical interfaces, hardware, all lifecycle routes or owner
acceptance. No backup/restore/removal demonstration on inventory is implied.

At the API level, create the backup with `TailscaleBackupConfig(prefix=<inventory_name>)`
so the strict restore host prefix matches `TailscaleManualRestoreConfig(inventory_name=...)`.
The `just backup` and `just restore-tailscale-manual` examples above are recipes in
the external **ops-control** consumer, not this package’s justfile.
