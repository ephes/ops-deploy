# Prepared owned Home Assistant application fixture

Source preparation only: no HA application run, inventory adoption or hardware
qualification has happened yet. The root deployment API remains prepared until
the actual matrix and complete receipts pass. Backup/restore/remove are separate.

## Isolation and exact sources

The workflow reuses the qualified Paperless disposable public GitHub Ubuntu24 VM
and privileged systemd-userspace container boundary:2CPU/6GiB/2048PIDs,
no explicit host binds, forwarded ports, socket or credential environment,
owned labels only,15-minute build and100-minute guest plus130-minute outer job.
The container shares that disposable VM kernel; it is not KVM. Actual machine/OS,
noneditable distribution/direct_url and full Git resource-set/every-byte identity
are recorded before application work. Only anonymous exact public source enters.
No production inventory, real device, model-provider or Thread data is read.

Current/upgrade cases can be selected separately to retain completed evidence
when a later fixture repair needs a bounded retry. Collection and cleanup retain
separate exits and exact owned resources. Interrupted effects remain unknown when
no after-snapshot exists. No stale resource removal or automatic fixture repair.

## Explicit baseline and actual application

`prerequisites.py` seeds the exact official UV0.13.5 archive/checksum, a synthetic
existing service account/minimal unmanaged configuration, and the udev daemon.
The unchanged original role requires UV to exist before its own later installer.
These are labelled existing-host prerequisites, never pristine original bootstrap.
The public library is pinned to9d88 (unchanged cf3 runtime). The current leg uses
HA2026.10.2; upgrade begins with2026.10.1 then requests2026.10.2. Both retain
Python3.14.8 and actual Matter8.1.2. `application-provenance.json` records declared
public release artifacts, not a claim that each dependency download was hashed.
Actual installed versions/distributions are recorded in every snapshot.

`api.py` uses HA's own interpreter/aiohttp and real onboarding user creation,
authorization-code exchange and WebSocket long-lived-token command. Credentials
stay in guest process memory or the0700 guest fixture area excluded from evidence.
Only the user/token onboarding path is completed: core onboarding would start
unrelated external integrations. No raw auth storage is rewritten to fake login.

The model server implements real OpenAI models/completions/SSE with a fixed
synthetic response; no prompt is forwarded or logged. Wyoming exposes only
Describe/Info, not speech inference. OTBR serves one public synthetic existing
MeshCoP dataset and refuses writes; this is API-flow proof, not commissioning or
radio proof. All synthetic peers bind127.0.0.1 inside the guest. HA itself binds guest
interfaces so the original default-IPv4 rewrite works; only loopback and the
actual guest source IPv4 are trusted proxies, and Docker publishes no host port.
The original and typed internal_url both remain the explicit loopback URL. The separate
`protocol_control.py` uses exact upstream clients(openai3.10.0, wyoming1.10.2,
python-otbr-api3.0.0) against ephemeral loopback ports; that control alone is not
HA/native qualification. Run it with those three `uv run --with` dependencies.

## Matrix and evidence

The original role bootstrap/current-selected/repeat is retained alongside actual
installed typed planning/first/repeat/fish and original-after-typed comparison.
Upgrade uses the declared prior HA version rather than replaying current setup.
Actual selected builtin conversation canaries, Matter/Wyoming/OTBR flows and
Assist registry selections run through HA. Model calls must advance on a healthy
selected repeat and remain unchanged during planning. Raw planned unconditional,
conditional and unresolved flags remain explicit; no callback is invoked to
manufacture a zero-change plan.

The matrix includes stopped service, wrong API token, empty canary, preserved
operator configuration, missing version record, missing entire environment,
explicit force reinstall, foreign trust drop-in refusal, wrong constraints,
invalid configuration, selected/unrelated areas, standalone voice/missing STT,
custom1.6.1 install/repeat/stamp/archive recovery/disable/recreate and actual legacy
custom/LiteLLM retirement back to builtin. Each synthetic fault/reset is labelled;
no production restart, data restore, radio operation or IAM mutation is implied.
Existing component-level file-template/ownership/overwrite controls remain
separate evidence; this matrix's live config starts unmanaged and synthetic.

Normal repeat deliberately preserves genuine original apt refresh, solver,
service-state daemon reload and active canary work. It is **not** a zero-managed
claim. Selected program/file metadata, private config bytes, units/PIDs and actual
package versions are compared strictly on healthy repeats. The custom component
walk is bounded to2048 public program entries. DB/registry/root metadata is
observed separately; background recorder/token/storage changes are not blanket
physical-immutability claims. Selected synthetic registry projections exclude
config-entry data/options and credentials. No actual user body is exported.

Each phase saves a start receipt, bounded sanitized operation progress/CLI log,
complete selected before/after snapshots, actual classifications/uploads/failures
and comparison flags before assertions. Private bodies and raw command output
remain in the disposable guest; durable evidence is redacted. The collector
allows only bounded flat regular files and hashes every exported file. A failure
retains its raw phase result; missing after-state or failed cleanup cannot become
a successful or zero-effect receipt.

## Remaining qualification cases

This first matrix is not the complete research-plan matrix. Wrong Python,
missing pip/unit, install failure, additional foreign/duplicate API entries,
credential/model/prompt rotations and managed configuration overwrite remain
explicit followups. Component-level source/owned controls do not substitute for
those application cases. Backup/restore/remove and trust-only maintenance also
remain separate; a successful first matrix does not close these paths.
