# MinIO deployment

The port of `minio_deploy` preserves the pinned server/client, service, environment and Traefik route. The private adapter composes encrypted-volume preparation first and accepts only its declared host. It does not own replication, lifecycle jobs, backup identities, unrelated aliases or object contents. The public runtime has completed owned native qualification and the private metadata-selected deployment has completed its normal first/repeat inventory qualification.

## Deliberate convergence changes

The client checks before writing. It compares the declared shared alias locally without returning credentials, and imports it through stdin only when different. IAM inspection and signed requests use a private temporary client config; credentials never appear in command arguments or probe output. Existing enabled users are rotated only after a recognized signature mismatch. A disabled managed user stops the run. Transport errors, malformed output and unrecognized server errors are failures, never evidence that a user or policy is absent.

Each declared policy is compared after canonicalizing only statement order and the set-valued Action/Resource fields. Mutable policy drift is updated in place. The versioned weeknotes source policy is immutable: drift requires a new reviewed policy name. Its separate maintenance rollback now has an owned native-qualified typed operation; private routing remains tracked conversion work. The current deployed adapter still refuses the disabled setting with a legacy-play pointer until that private equivalent is adopted. This is not a permanent Ansible exception. Superseded policy detachment/removal happens only when present, after proving the replacement attachment. Superseded retirement requires an additive identity; the configuration rejects retirement on an exact identity. Exact-policy identities also require no group membership; additive identities retain their original weaker attachment contract.

Bucket creation, anonymous access and versioning are inspected first. `versioning=false` means leave the existing versioning state alone, not disable it. Data directory ownership/mode applies only to each top-level directory. A read-only foreign-owner search stops on the first descendant mismatch; it never chmods/chowns stored objects recursively. On a healthy store this admission walks every descendant metadata entry, so its cost grows with the object tree. It has no separate probe timeout and reads no object bodies.

## Artifact and proof limits

The original server download URL still returns HTTP410; the client now uses an exact verified official GitHub asset (below). An existing matching binary needs no download. Fresh server installation requires the same verified artifact, not an invented replacement release. Owned fixtures used read-only copies of those exact executables.

Local ARM/QEMU checks of the copied amd64 binaries established CLI/IAM mechanics only. They are explicitly emulated and do not qualify native systemd behavior, inventory adoption, object preservation or healthy repeat convergence. Those earlier checks are distinct from the completed native fixture and separate inventory qualification below.

Direct legacy Ansible deployment retains its old recursive directory handling, alias/identity upserts and unconditional bootstrap commands. Use the metadata-aware deployment entry point for the adopted default. No new engine-refusal or rollback-acknowledgement guard is introduced.

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
for these normal known-owned recovery paths. These paths completed the owned native matrix described below.

The original Ansible role installs the client and starts the unit before bootstrap.
It writes desired root credentials but defers its restart handler until later;
there is no explicit flush before bootstrap uses the new credentials. The native original-role root rotation actually failed with exit 2 after changing
the environment and before its deferred restart. That untouched half-applied
state was then safely refused by pyinfra before any write: the new environment
did not prove the active process credentials. The fixture recorded this result
before an explicit synthetic environment reset/restart. This is an honest refusal
limit, not a claim that every historical half-applied state automatically recovers.

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

The completed offline KVM run used public artifact
`1249bd010929a6e2d70796838d0f4b32807fa7fa`, with all 684 actually installed
noneditable package resources equal to Git. QMP reported KVM present/enabled;
the fresh x86 Ubuntu24 guest used its independent Linux 6.8 kernel and loopback
only. All 28 MinIO phases completed, including 13 healthy repeats with zero managed
operations/uploads and strict scoped before/after equality. Every pyinfra and
original-role phase separately proved the unrelated alias unchanged without
recording credential values. Missing-client recovery installed one artifact;
stopped-unit recovery performed one managed start; root rotation performed
three managed operations and no upload. Disabled-IAM refusals after a managed
recovery prerequisite retain that actual partial change rather than claiming
zero mutation. Immutable/extra-policy/disabled refusals, versioning retention,
identity rotation and superseded cleanup were exercised on synthetic data.

The original Ansible normal/missing-client/stopped-service cases succeeded with
real writes; its root-rotation failure is retained as described above. Earlier
failed build/QMP/bootstrap/fixture attempts remain separate evidence. In
particular, attempt5 reached the matrix but failed a mutated fixture alias
expectation; it was not relabeled successful. The final run retained full raw
phase evidence, exited 0, and removed its exact owned containers/images before
releasing the shared writer lock. No production IAM, object or service request
was part of this owned qualification, and it makes no global-I/O claim.

A separate, checksum-bound original S4 lag-probe component also completed six
synthetic cases after the MinIO summary. Its expected marker/status writes are
not zero-change, typed S4 deployment, composite, hardware or inventory proof.

The pyinfra client's fixed source is the official GitHub release asset
`https://github.com/minio/mc/releases/download/RELEASE.2025-08-13T08-35-41Z/mc.linux-amd64.RELEASE.2025-08-13T08-35-41Z`.
An anonymous download was verified at30535864bytes with the unchanged SHA256
`01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891`.
This explicitly replaces the unavailable legacy dl.min.io client URL; it does not
change the version or binary. An already matching client makes no download.
Legacy Ansible/operator custom URLs are unchanged. The MinIO **server** source
still returns410; no alternate server version or source is silently selected.

The executed offline native KVM transport and all retained attempt limits are
documented under `tests/integration/minio/kvm/README.md`. Inventory qualification is separately recorded below.


## Inventory deployment qualification

On2026-10-28 the private metadata-selected chain completed a normal plan, default
first deploy and explicit-host repeat using immutable public1249bd0. Each actual
call ran6 encrypted-volume and29 MinIO operations:70 successful operations total,
zero managed changes and zero uploads. Every actual CLI child proved all684
installed resource bytes/noneditable direct_url. Protected file/config/unit/PID,
mount, package, listener and explicit-directory metadata remained exact, as did
health and memory-only secret-content comparisons. No restart, root rotation,
manual IAM repair, remount or binary/package upgrade occurred.

An earlier plan stopped before apply on two real conditional rollout rows. The
final recorder retained those raw rows and proved only the exact installed
callbacks false from identical earlier state/host operation operands with literal
planned-change False; unknown/changed callbacks remain refusals. Both actual
calls independently confirmed zero managed changes. The original stop, bounded
final snapshot and its ephemeral-comparison discontinuity are retained; the fresh
successful window had continuous comparisons and verified lock release.

This is normal deployment qualification, not blanket workflow conversion or a
global physical-I/O claim. The observer did not enumerate object names/bodies or
export IAM. The qualified normal descendant ownership admission still has the
metadata-only whole-root latency limit above. Loopback route/status checks are
not certificate validation. Explicit maintenance rollback and other lifecycle
workflows remain separately tracked; the Ansible role is unchanged.

### Native-qualified policy rollback component

The normal deployment remains unchanged. A separate host-local helper is available for the original tag-scoped `daybook_weeknotes_source_policy_enabled=false`
maintenance path: inspect the explicitly named policy, attempt detachment of the
declared identity, independently prove that identity absent, remove the policy,
and require the precise missing-policy response. An ignored detach error is not
success until independent verification proves detachment. Failed removal can
follow a real partial detach; it is not zero mutation.

The original rollback does not require an exact document comparison or a new
replacement policy, so this path adds neither gate. Other holders retain the
server's actual removal behavior. The `policy_rollback` module exposes a separate typed operation; it is
not wired into the private CLI. It uses protected stdin and a disposable private
client alias, retains independent final absence verification before the named
local document removal, and never invokes full normal IAM reconciliation.
The exact pinned server and client completed the separate offline x86 KVM
maintenance matrix at `990523fbdd4f5c73b150375f6b73870245fba35a`:24 typed phases,
including10 successful whole-snapshot repeats with zero managed operations and
uploads, plus five expected failures. All907 installed resources matched Git and
noneditable provenance; KVM enabled/present, independent guest kernel and exact
cleanup were recorded. The original nine-task foreign-holder comparison exited2
at server removal after detaching the declared identity; typed behavior matched.
Unrelated policy/identity, alias, known synthetic object, binary and process
projections stayed exact. Failed operations can already detach or remove server
state even when pyinfra's managed list is empty; those raw effects remain explicit.
Private maintenance routing is still pending. No production policy revocation
was performed or is needed merely to qualify this implementation.
