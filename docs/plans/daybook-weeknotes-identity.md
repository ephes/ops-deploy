# Weeknotes identity operator conversion plan

## Scope

Port the existing explicit prepare, dry-run, apply, verify and status rail.
Do not install/update application code, activate a timer, rotate authentication,
run reconciliation or introduce an additional owner acknowledgement. Preserve
the existing apply phrase exactly. Epoch/enable/rollback/rotation wrappers are
later composition work; no permanent Ansible exemption is introduced.

The current independent `identity_host.py` is a bound installation verifier,
not an operator CLI. Keep it unchanged. Reuse the existing public Sessions
`render_template` function to compute the exact installed helper and launcher
bytes from their existing immutable templates. Build an explicit values mapping
containing only the declared operator path/user/UV/PATH fields, including
`daybook_weeknotes_reconcile_state_path`; call `render_template` directly, never
`role_values` or the full Sessions resource renderer (which require storage
credentials). Do not duplicate app code or
require unrelated Sessions storage credentials merely to run an operator.

## Public declaration and execution

Add a small Darwin-only identity operator config with an explicit non-root GUI
owner, original fixed home/checkout/runtime/config/helper/launcher/env/checksum,
seed/plan/attestation/root-proof and reconcile state paths, UV executable, PATH, forty-hex required
revision, one of five actions, existing apply confirmation and a hidden private
move sequence. Validate original production path relationships and strict data
types, including the original `state_path == runtime_dir + "/state.json"`
relationship. Model errors must hide private input; seed/config expectations use
protected stdin and remain out of command arguments, environment assignments,
repr and diagnostics. Use the original positive identities/ordered intent,
without adding private deployment values to public source.

Controller preparation resolves normal Main once, without modifying the owner's
checkout, and loads only the original private intent fields. It validates the
request before SSH. On target, preserve original root connection and explicit
owner login execution context. All SDK facts/operations clear the seven
inherited privilege fields. No root fallback, interactive password or TCC step.

The deploy schedules the already-qualified exact Weeknotes system disable
sequence before a managed identity operation. The identity host helper:

1. Admits original root connection and resolves the original owner UID; seed group remains original `staff`.
2. Runs owner-context Git HEAD/root/all-untracked cleanliness checks and requires
   the controller's exact revision. It neither changes source nor synchronizes
   a Python environment as a deployment prerequisite.
3. Checks original checkout and .git ownership/shape; exact root 0755 regular,
   single-link helper/launcher bytes; owner 0600 environment and root 0644
   checksum metadata. Expected code is rendered from existing templates.
4. For non-status actions requires nonempty exact content-free private intent.
   Prepare creates the owner 0600 seed only if absent, using atomic no-replace
   descriptor publication. Existing seed must be a single regular owner 0600
   file whose parsed body equals exact intent in remote memory. Never overwrite
   a seed, plan, state, lock, auth file or attestation for convergence.
   The existing Sessions helper syncs the file, not the directory; interruption
   after linking may leave a second hard link, which fails closed for operator
   inspection. No automatic link recovery or crash-durability claim is added.
5. Runs only the original installed launcher/action under original service-user
   login context. The launcher retains its environment checksum, isolated frozen
   UV invocation and existing application/locking behavior. No new outer app
   deadline or invented recovery/lock deletion. Private command output is
   captured in remote RAM; no raw stderr or private payload reaches diagnostics.
6. Apply additionally runs original verify, validates its closed successful
   schema and requires the apply and verify plan hashes to match, then atomically writes only the original root 0600
   activation proof with schema, epoch, hash and required revision. That hash
   remains private in the target proof and is not a deployment fact or log.

All five launcher calls are managed application work, including dry-run,
verification and status. Never invoke them inside a fact or claim a zero-op
repeat. Status retains the app's existing closed content-free status report;
prepare/apply reports are limited to original documented content-free fields.
Unknown output fails without disclosing it. Document controller preflight order:
invalid local Main/intent refuses before SSH; on an admitted target quiescence
precedes all target operator work.

## Private routing

Use an explicit fixed-Studio operator entry point with action choices and the
existing business phrase. Reuse normal inventory, Studio alias/transport key,
secret store and once-per-run Daybook source context. Read only original private
blog identities, not unrelated app secrets. Use existing playbook declaration as
oracle for the ordered seed. Convert the five convenience recipes while keeping
their original disabled Sessions-install prerequisites, exact apply prompt and
explicit original fallback during metadata-selected migration. No metadata/live
count credit until real qualification and Root's serialized adoption.

Subsequent epoch/enable/rollback/rotation composition must preserve the retired
timer guard and original multi-step ordering; none is activated by this phase.

## Qualification

Pair helper/launcher rendering (including the exact reconcile state path), defaults and declaration mappings with the actual
owned collection. Test strict production scope, privilege clearing, fixed caller
routing and no app secrets/source work before selected execution. Mechanism
fixtures use synthetic private intent/plan/state, inert fake app/UV executables
and unique owned paths/labels. Validate original models before disclosed
unvalidated model_copy fixture substitutions. Native proof exercises actual
immutable Git package over owned root and owner SSH, first/repeat, wrong intent,
unsafe linked/irregular seed/helper/env, dirty or wrong-revision checkout,
failed apply/postverify, proof-only-after-verify and cleanup. No inventory app,
post/content/data operation, credential rotation, restoration or removal is
allowed for proof. Retain unrelated keeper and protected synthetic file metadata.

Run all meaningfully affected tests and canonical full test/type/lint/docs/size
checks; use a fresh different-family implementation review after this plan gate.
Freeze exact resource map and actual noneditable Git/controller/guest evidence,
complete CI logs and failure provenance. Root independently verifies and
serializes any Main/private pin/inventory/live execution. This plan adds no
permission flow to existing operator usage.
