# MinIO deployment (in preparation)

The port of `minio_deploy` preserves the pinned server/client, service, environment and Traefik route. The private adapter composes encrypted-volume preparation first and accepts only its declared host. It does not own replication, lifecycle jobs, backup identities, unrelated aliases or object contents. This implementation is not yet qualified or selected by inventory metadata.

## Deliberate convergence changes

The client checks before writing. It compares the declared shared alias locally without returning credentials, and imports it through stdin only when different. IAM inspection and signed requests use a private temporary client config; credentials never appear in command arguments or probe output. Existing enabled users are rotated only after a recognized signature mismatch. A disabled managed user stops the run. Transport errors, malformed output and unrecognized server errors are failures, never evidence that a user or policy is absent.

Each declared policy is compared after canonicalizing only statement order and the set-valued Action/Resource fields. Mutable policy drift is updated in place. The versioned weeknotes source policy is immutable: drift requires a new reviewed policy name. Its rollback branch remains with the legacy play; the pyinfra adapter refuses the disabled setting with that pointer. Superseded policy detachment/removal happens only when present, after proving the replacement attachment. Superseded retirement requires an additive identity; the configuration rejects retirement on an exact identity. Exact-policy identities also require no group membership; additive identities retain their original weaker attachment contract.

Bucket creation, anonymous access and versioning are inspected first. `versioning=false` means leave the existing versioning state alone, not disable it. Data directory ownership/mode applies only to each top-level directory. A read-only foreign-owner search stops on the first descendant mismatch; it never chmods/chowns stored objects recursively. On a healthy store this admission walks every descendant metadata entry, so its cost grows with the object tree. It has no separate probe timeout and reads no object bodies.

## Artifact and proof limits

The pinned upstream download URLs returned HTTP410 during research. An existing matching binary needs no download. Fresh installation requires the same verified artifact, not an invented replacement release. Owned fixtures may use read-only copies of those exact executables.

Local ARM/QEMU checks of the copied amd64 binaries established CLI/IAM mechanics only. They are explicitly emulated and do not qualify native systemd behavior, inventory adoption, object preservation or healthy repeat convergence. Native fixture, review and coordinated live receipts are still pending.

Direct legacy Ansible deployment retains its old recursive directory handling, alias/identity upserts and unconditional bootstrap commands. After eventual adoption, use the metadata-aware deployment entry point. No new engine-refusal or rollback-acknowledgement guard is introduced.

## Public API and defaults

```python
import os
from pydantic import SecretStr
from ops_deploy.services.minio import MinioBucket, MinioConfig, MinioCredentials, deploy_minio

cfg = MinioConfig(
    bootstrap_with_mc=True,
    buckets=(MinioBucket(name="example-artifacts"),),
)
credentials = MinioCredentials(
    root_user=SecretStr(os.environ["MINIO_ROOT_USER"]),
    root_password=SecretStr(os.environ["MINIO_ROOT_PASSWORD"]),
)
deploy_minio(cfg=cfg, credentials=credentials)
```

`MinioConfig` follows the active role defaults: system user/group `minio`,
home `/home/minio`, data `/var/lib/minio/data`, root-owned environment
`/etc/default/minio` mode0600, unit `/etc/systemd/system/minio.service`, loopback
API9001 and console9002. The server and client are fixed to the checksummed
versions in the role. Paths must be canonical; API/console ports must differ.
A truly fresh deployment has no unit/environment and empty or absent data roots;
existing data requires successful read-only descendant-ownership admission.

Healthy existing servers inspect every owned IAM contract with current root
credentials read only inside the host helper from the root-owned0600 environment.
The parser accepts the declared literal fields, rejects duplicate/unknown or
ambiguous lines, and never evaluates shell content or returns credential material.
A desired root rotation writes the protected environment, performs the normal
change-gated restart, then rechecks desired credentials before alias/IAM changes.

A missing or mismatched pinned client is installed as a managed prerequisite.
A known inactive/failed unit is started with its existing valid configuration
before desired configuration changes. Recovery requires the declared root-owned
unit, pinned executable, unchanged non-root environment, no drop-ins or pending
daemon reload, and an unambiguous systemd state. Full IAM admission then runs
before other configuration or IAM writes. If that admission refuses, the actual
client installation or service start remains an explicitly reported partial
recovery; it is never called a zero-change refusal. Unknown/foreign service or
credential state still stops. No extra acknowledgement or manual repair is needed
for these normal known-owned recovery paths. Qualification of these new paths is
pending an inspected native fixture receipt.

The original Ansible role installs the client and starts the unit before bootstrap.
It writes desired root credentials but defers its restart handler until later;
there is no explicit flush before bootstrap uses the new credentials. Its real
root-rotation result must therefore be observed separately, not assumed successful.

The original private play's loopback API/console port checks run before managed
operations and accept only listeners owned by `minio.service`.

Traefik exposure defaults off. When enabled, configure `traefik_host` and
`traefik_api_host`; the unchanged dual-console/API route lives at the fixed
`/etc/traefik/dynamic/minio.yml`. Console basic authentication defaults on and
requires `console_basic_auth_password`; an existing matching bcrypt hash is
reused. `internal_ip_ranges`, `traefik_cert_resolver`, service restart/resource
limits, paths and optional TLS/SSE settings retain the role's defaults. TLS
uses `tls_cert_content` mode0644 and `tls_key_content` mode0600; SSE takes
`sse_master_key`. Secret values are separate `SecretStr` inputs, never config
fields or command arguments. Root environment values reject line breaks,
quotes and backslashes that would alter the role's quoted environment syntax.

The deployment's additional declarative inputs are:

| Input | Meaning / default |
| --- | --- |
| `buckets` | `MinioBucket(name, versioning=False, policy="private")`; empty by default |
| `policies` | `MinioPolicy(name, document, immutable=False, content=None)`; optional `content` preserves exact JSON file spelling and must encode the same document |
| `identities` | `MinioIdentity(name, policies, proof, exact=False)`; `proof` is a bucket or non-existent key under the permitted prefix |
| `credentials.identities` | Exactly those identity names mapped to `MinioUserCredentials(access, secret)`; keys must be distinct and cannot be root |
| `superseded` | `MinioSupersededPolicy(name, identity)`; remove only after the identity's declared replacements are attached and no other user/group holds the old policy |
| `mc_config_dir` | Shared client config `/root/.mc`; only `host_alias` (default `local`) is owned |
| `policy_dir` | Root-owned `/etc/minio/policies`, mode0750; declared policy files mode0640 |
| `local_minio_binary`, `local_mc_binary` | Optional explicit controller artifacts, always checked against the fixed SHA256 before planning writes |

The legacy role's service-account bootstrap, backup-account entry point, config
export, custom bucket/lifecycle policy and removal workflows are not invoked.
The private adapter supplies its existing declared policies and four identities;
this public API does not discover or adopt unrelated users automatically.

## Validation status

Current local evidence includes actual Ansible renders of all three templates
for default, TLS/SSE/custom limits and console-auth-off cases against library
`d88c3286` (MinIO runtime source unchanged from `cf3a0c74`). Actual pyinfra
operation tests cover zero managed changes/uploads for a matching host,
IAM-only changes without service restart, refusal before any operation, policy
file-only drift and bcrypt reuse. A real owned-file negative test proves a bad
download cannot replace the existing executable. The installer verifies its
private temporary download before atomic replacement.

The owned native harness is under `tests/integration/minio`: it will use exact
binaries in a fresh x86 Ubuntu24 systemd guest on a GitHub-owned VM, with a shared
kernel, synthetic objects/credentials and no private inventory mounts. The
private download token is scoped to the runner download step and excluded from
the guest. Installed-resource/direct_url proof and raw phase receipts are
required. No native success or inventory switch is claimed yet.

The prepared pyinfra client's fixed source is the official GitHub release asset
`https://github.com/minio/mc/releases/download/RELEASE.2025-08-13T08-35-41Z/mc.linux-amd64.RELEASE.2025-08-13T08-35-41Z`.
An anonymous download was verified at30535864bytes with the unchanged SHA256
`01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891`.
This explicitly replaces the unavailable legacy dl.min.io client URL; it does not
change the version or binary. An already matching client makes no download.
Legacy Ansible/operator custom URLs are unchanged. The MinIO **server** source
still returns410; no alternate server version or source is silently selected.

An alternate offline native KVM transport is prepared under
`tests/integration/minio/kvm/README.md`; execution and qualification remain pending.
