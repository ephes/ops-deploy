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


## Read-only venv inventory prerequisite

`native_app.inventory` exposes a separate metadata probe for preparing a future
PyPI source. It adds no source kind, installer, adoption marker or deployment
operation. `NativeAppConfig` still rejects `pypi_uv`. A result never authorizes
executing, reinstalling, deleting or adopting an existing environment.

```python
from ops_deploy.services.native_app.inventory import (
    VenvInventoryRequest,
    probe_venv_inventory,
)

# Inside a pyinfra deploy context; example values are fixture metadata, not app pins.
request = VenvInventoryRequest(
    venv="/opt/fixture/.venv",
    owner_uid=1001,
    python_version="3.12.13",
    distributions={"fixture-package": "1.2.3"},
)
result = probe_venv_inventory(request)
print(result.status, result.reason)
```

The expected distribution mapping must describe the complete intended inventory,
including transitive packages. Names use normalized case and `-_.` aliases;
duplicate aliases refuse. Versions accept bounded release, epoch, pre/post/dev
and local forms, without URLs or floating labels. A matching candidate requires
literal version equality, not an inferred compatible range. Recognition of a
newer version compares plain numeric releases only; a changed version that
cannot be ordered by that limited rule stays unknown, even when another package
has a recognizable newer numeric declaration. This is not a full
package resolver or a choice of fresh-install lock/hash policy.

The independently trusted system prerequisite `/usr/bin/python3` runs with
`-I -S -B`: isolated imports, no site hooks, no bytecode writes. The probe never
runs the venv interpreter, activation script, uv, pip, package or entrypoint.
It reads only bounded known paths and metadata fields. It does not load
`direct_url.json`, echo raw metadata/URLs or expose package output. The result
contains a reason, bounded count, declared Python version and a SHA256 identity
of sorted normalized names and literal versions. That identity is **metadata
only**, not installed-file integrity or reproducible-install proof.

| Observation | Result | Meaning |
|---|---|---|
| Venv root absent beneath trusted ancestors | `absent` | No install action follows |
| Foreign owner, group/world write or unsafe metadata/root symlink | `refused_untrusted` | Refuse before metadata/version trust |
| Matching declared Python and exact complete standard metadata set | `matching_candidate` | Metadata matches; actual interpreter, content and usability remain unverified |
| Numeric installed declaration newer than requested | `recognizable_newer` | Not a downgrade/reinstall instruction |
| Older/different numeric declaration, extra or missing distribution | `different_inventory` | Report drift, never repair it here |
| Malformed/undecodable/unreadable/changing/oversized/unsupported state | `unknown` | Stop for a separately scoped decision |

Every ancestor and opened metadata component must be owned by root or the
explicit expected UID, with no group/world-write permission. Directory-relative
no-follow descriptors keep reads anchored after opening. A standard
`bin/python` symlink is observed **without following its target**; a regular
entry is also never executed. Neither form is proof of executable trust. A
missing internal file is an unknown existing venv, not permission to replace it.
World-writable ancestors, including a sticky `/tmp`, are deliberately refused.

This first probe supports `lib/pythonX.Y/site-packages/*.dist-info/METADATA`,
with an explicit three-component `3.X.Y` declaration in `version` or uv's
`version_info` in `pyvenv.cfg`, and excludes inherited
system site packages. A minor-only uv declaration such as `version_info = 3.12` stays unknown;
the probe never infers its patch version. Any `.pth`, `.egg-info`, `.egg-link`, `sitecustomize` or
`usercustomize` startup-hook form makes the layout unknown even when its direct
distribution inventory is readable. Hook detection includes source, bytecode,
extension and package forms without importing them. This includes
uv's common `_virtualenv.pth`: do not remove an existing hook to force a match.
All internal metadata trust and layout checks precede Python/version drift
classification. Unsupported hooks and ambiguous changed distributions stay
unknown before any numeric-newer result. Audited hook/path handling is a future
prerequisite. Results can be partial when
classification refuses and must never be used as a persistent authorization.

Bounds: 64 KiB serialized request, 4096 path characters, 8192 site directory
entries, 4096 distributions, 256 KiB per metadata file, 32 MiB total metadata,
16 KiB `pyvenv.cfg`, and a 4096-character result. UTF-8 and parse failures are
controlled classifications. Failed or malformed fact output raises a bounded
controller error rather than becoming a candidate.

Before any adoption/consumer: separately prove actual interpreter and executable
trust before execution, package-content identity, point-of-use revalidation,
liveness and interrupted publication/resume. Venv relocation/shebangs, safe
installer provenance, EnvFile/EnvironmentFile, preserve/data/key handling and
full recovery remain separate slices. No apt/PyPI consumer follows from this
read-only API alone.

### Isolated Docker proof

`tests/test_native_venv_inventory_docker.py` exercises the real public caller and
pyinfra Docker connector against an explicitly supplied **already running owned
container**. Default tests skip it. It creates only synthetic venv metadata in
`/opt/native-venv-inventory-fixture`, verifies all before/after file metadata and
content (excluding atime), refusal cases, no generated operations and untouched
execution sentinels. The candidate assertions exercise the real fact command,
which invokes only the independent system interpreter with `-I -S -B`; source
and command tests verify that no venv interpreter or package runner is called.
The noexec mount means an untouched executable sentinel alone cannot prove that
execution was never attempted. The `.pth` hook instead writes into the writable
fixture root if it is imported. Its connector transport permits only inspect and
exec, preventing image/container fallback creation or commit. Admission checks
both declared and effective mounts before fixture cleanup: no binds, volumes,
`--mount` or resolved mounts are accepted. It also checks effective privilege,
no-new-privileges, private namespaces, devices and exact tmpfs safety flags.

The fixture uses the native architecture's pinned official Python 3.12.13 image,
with a tiny derived `/usr/bin/python3` symlink to the image's trusted interpreter.
It requires a read-only root, network none, no ports or host binds/volumes/socket,
one CPU, 256 MiB memory/swap limit, 32 PIDs, only CHOWN capability, no new
privileges, user `65534:65534` and a 32 MiB noexec/nosuid/nodev tmpfs at that
fixture path owned by UID/GID65534. Labels must include
`ops-deploy.fixture=native-venv-inventory` and a unique `ops-deploy.run`; the
container name starts `native-p0a-`. CHOWN is used only to set/revert a synthetic
foreign-owner case through an explicit root exec. No production path or secret
enters the fixture.

Set `NATIVE_VENV_DOCKER_CONTAINER` to its full inspected ID,
`NATIVE_VENV_IMAGE_ID` to its exact image ID, `NATIVE_VENV_RUN_ID` to the label,
and, for a remote fixture, scope `DOCKER_HOST`/SSH agent to the test subprocess.
Run only this test under a bounded timeout, retain complete evidence, then remove
only the exact owned container and derived image. Do not prune shared images or
change daemon configuration. The proof creates no real app and does not replace
a later installer/adoption failure rehearsal or authorized inventory-host proof.
