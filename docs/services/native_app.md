# Native applications

`ops_deploy.services.native_app` provides a small release/TOML/custom-unit
runtime and a route-only runtime. `NativeAppConfig` is frozen, rejects unknown
fields and validates on the controller. It reuses compose_app's validated
parts and route access modes directly; existing compose and Django APIs are
unchanged. No capped helper/core/ops code is added.

This first subset supports one exact-version tar.gz release, one regular-file
archive member, one custom systemd service, non-secret TOML files with scalar
values and one-level tables, directories and a system account. The release URL
and per-architecture SHA256 digests come from private configuration. Downloads
are checked before installation; only the named regular member is streamed to
a same-directory temporary file and atomically renamed. Archive paths,
symlinks and devices are never extracted. HTTP needs an explicit reason.

A matching existing version is adopted without downloading or replacing the
binary. The root-only applied state then records its content digest and source
identity. Later tracked content drift triggers a verified reinstall, including a corrupt
binary that cannot report its version. An unrecognized unmanaged binary or
unsafe ownership or group/world-write permissions refuse before any version execution. A recognizable newer installed
version refuses a downgrade. Adoption trusts the existing binary's reported
version: compare the deployed binary/version with the approved release before
a real conversion. Existing data is never synced or recursively chowned.
The subset checks required executables instead of installing packages.

Release preflight uses the following trust and classification order. Every
existing binary must be a regular non-symlink owned by root:root, without group
or world write permission, before its content or reported version is trusted.
Safe noncanonical modes such as 0750 still undergo the downgrade check before
canonical mode 0755 is restored.

| Existing binary | Version handling | Result |
|---|---|---|
| Unsafe owner or group/world writable | Never execute | Refuse for operator review |
| Safe, content unchanged from root-only applied state | Reuse the previously verified version | Check downgrade, then source identity and canonical mode |
| Safe, changed content with recognizable version | Bounded version probe | Refuse newer versions; otherwise reconcile the approved pin |
| Safe, changed content with missing, failed or undecodable version output | Treat as unrecognized | Reinstall only when the previous source identity matches the approved pin and its tracked content changed |
| Safe, unmanaged binary with unrecognized output | Bounded version probe | Refuse for operator review |

Both stdout and stderr decoding failures follow the unrecognized-version path.
A downloaded candidate must still report the approved version before publication.

`source`, `account`, `configs`, `unit`, `binary_link` and health/listener checks
are runtime parts. A route-only config omits all of them; `user` and `site_path`
remain BaseServiceConfig metadata and cause no service user or site creation.
A remote route backend needs `remote_reason`. The route model requires
`public_reason` for public access and secret references for basic auth. Unknown
source kinds, including apt and PyPI, fail validation.

## Configuration

The private controller passes data to `NativeAppConfig.model_validate` and
calls `deploy_native_app(cfg, secrets)`. Runtime config includes:

| Field | Meaning |
|---|---|
| `account` | name, primary group, home, shell; existing account settings are preserved |
| `source` | exact numeric version, URL with optional `{arch}`, `checksums` keyed by `x86_64`/`aarch64`, regular `member`, absolute `dest`, version argv |
| `configs` | absolute path, mode and non-secret TOML `data` |
| `unit` | name, user/group, working directory, argv, environment, After dependencies and NOFILE |
| `mounts_required`, `paths_required` | read-only refusal before any write |
| `listen_port` | loopback TCP port; refuse foreign unit ownership or unexpected bind address |
| `health_url`, `health_statuses` | loopback HTTP check after rollout |
| `route` | existing access modes, stable names, frame policy, internal ranges; optional remote backend reason |

Example route-only data, using invented identifiers:

```python
from ops_deploy.core.secrets import SecretRef
from ops_deploy.services.native_app import NativeAppConfig

config = NativeAppConfig.model_validate(
    {
        "service_name": "proxy_fixture",
        "title": "Proxy fixture",
        "user": "root",
        "site_path": "/var/lib/proxy-fixture",
        "secrets": SecretRef("secrets/fixture/proxy.yml"),
        "route": {
            "name": "proxy-fixture",
            "host": "proxy.example.invalid",
            "port": 18001,
            "backend_host": "backend.example.invalid",
            "remote_reason": "Existing separately managed backend",
            "access": "internal_or_basic_auth",
            "basic_auth_user": "fixture",
            "basic_auth_password": {"secret": "password"},
        },
    }
)
```

## Restarts and recovery

Planning only reads: Linux/systemd, mounts, external paths, dependencies,
listener ownership, release version/content, unit reload state and markers.
The post-start listener check waits up to 20 seconds for binding; a foreign
listener or unexpected address fails immediately. The state directory is `/var/lib/ops-deploy/<service>/`, root-only 0700; symlink,
foreign-owner and writable state directories refuse. Before writes, `pending`
is written. Before runtime-input writes, `restart` is written. A new service
starts once; a running service restarts once after changed input files.
A unit file left changed by an interrupted run is reloaded on resume. A
restart marker survives failures, even when the files now match, and causes
one restart on retry. A pending-only retry checks health and records state
without a restart. Applied state and marker cleanup happen after checks.

Traefik uses its watched file provider: this deploy never restarts Traefik.
Its existing password hash is reused if it still verifies; secret rotation is
an updated secret plus this deploy. Private entry-point and rotation guards
must prevent an old deployment engine from rewriting canonical files.

## Canonical conversion and proof

| Origin shape | Canonical shape | Expected effect |
|---|---|---|
| role TOML with duplicated unit environment settings | deterministic TOML and explicit argv/environment data | one planned app restart; private parity test checks effective settings |
| role `After=network.target` | `After=network-online.target`, plus required mounts | explicit ordering; same bind address, user, paths and data |
| per-run salted route hash and proxy restart | stable verified hash, file-provider watch | no Traefik restart |
| already installed matching release | adopted installed binary plus root state | no version change or reinstall |

Run `tests/smoke/test_native_app_smoke.py` on an isolated Linux smoke target
(`SMOKE_VM` must be unique). It covers first install, canonical conversion,
zero-change reruns, data retention, config drift, failure between input writes
and rollout, resumed restart, route-only convergence, missing-mount refusal
and stable Traefik PID. The private repo additionally rehearses conversion
from the actual origin role with fixture credentials.

Removal and backup/restore are deliberately separate lifecycle ports. Apt/deb,
policy-rc.d claims and descriptor preservation, PyPI, Git/Node builds, vendor
units, multi-unit rollout and typed provisioning steps are absent. The first
apt consumer must implement and prove the reviewed descriptor/crash contract;
that future prerequisite does not block this tarball-only subset.
