# Prepared owned Home Assistant application fixture

The first owned run failed during original Ansible bootstrap before any typed
phase. The revised existing-host run41017001167 passed bootstrap in both cases,
then current failed the original Matter port wait and upgrade refused a unit
change during its read-only plan. Matter was already auto-restarting before
both phases; its startup cause was not captured. No successful native, inventory
or hardware qualification is claimed. The root deployment API remains prepared until
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
It also seeds the selected HA/Python environment with pip, then calls that exact
HA version's original loader/RequirementsManager for Matter's complete declared
dependency and after-dependency closure. The loader and manifests are SHA-bound;
its actual `matter.config_flow` import must pass before the original role starts.
The original pip/legacy-package probes also run against the seeded environment,
and its original decision must retain the environment/application. Missing pip
or an accidentally installed legacy `python-matter-server` aborts before the role.
The interpreter, pip-seeded virtualenv and selected HA package are all
pre-provisioned existing-host state. Phase00 therefore does not exercise the
original interpreter installation, virtualenv creation or HA package installation
paths, nor their changed results/restart notifications. Later typed replacement
phases are separate coverage, not original pristine-bootstrap proof.
No HA application or integration is started by this prerequisite. Public package
and loader diagnostics are retained, including failures. A failure aborts before
any role/matrix phase; it never skips the original postcheck.

This corrects failed run40972365656: the original postcheck imported Matter before
the original role's fresh environment had optional `aiohasupervisor` installed.
Both original failed artifacts and cleanup receipts remain evidence; installing
only that one package or bypassing the import is not the baseline. Exact original
requirements-loader/import oracles pass both selected versions on the owned Mac
controller, which is not Linux/systemd qualification. A separately authorized new
run is still required; no automatic failure replay.
The unchanged original role requires UV to exist before its own later installer.
These are labelled existing-host prerequisites, never pristine original bootstrap.
The public library is pinned to9d88 (unchanged cf3 runtime). The current leg uses
HA2026.10.2; upgrade begins with2026.10.1 then requests2026.10.2. Both retain
Python3.14.8 and actual Matter 8.1.2. `application-provenance.json` records declared
public release artifacts, not a claim that each dependency download was hashed.
Actual installed versions/distributions are recorded in every snapshot.

## Frozen current/upgrade matrix entry

This branch's `run-guest.sh` invokes the original `harness` current/upgrade matrix.
Dispatch only `fixture_cases=["current","upgrade"]` with its reviewed immutable
source SHA and separate coordinator authorization. Each leg performs admission,
its declared existing-host seed, unchanged original bootstrap, actual original
native-library load proof, then Matter readiness before onboarding or any
selected-original/typed phase. The original phase scope and strict comparisons
remain unchanged. A failed native oracle captures bounded startup diagnostics
and aborts before any selected/typed phase; it never repairs the guest.

The prior single diagnostic run41134898722 remains a failure with verified
collection/cleanup. Its `diagnose_matter` helper remains current-only source but
is no longer the guest entry. This matrix preparation does not constitute a
successful corrected native run or authorize automatic failure replay.

Readiness requires the loopback5580 port and a loaded, active/running Matter unit
with a positive PID and unchanged PID/restart count for20seconds within90seconds.
It only observes; it never restarts or repairs the service. Strict phase
before/after comparators are unchanged. The readiness receipt includes fixed
systemd Result, ExecMainCode, ExecMainStatus and NRestarts fields. Both success and
failure capture at most200 Matter journal lines (1MiB output ceiling,10seconds)
and the final1MiB of the owned regular Matter logfile. Unit observations have a
5second command deadline; owned command groups are killed/reaped on limits.
Missing/nonregular logs and collection failures remain explicit. The existing
outer guest100minute/build15minute/job130minute bounds and cleanup remain intact.
Only this disposable synthetic Matter service's diagnostics are exported: no HA
journal, auth registry, model/audio/user body or host data is collected. Existing
synthetic-value redaction is retained. This replaces the prior evidence gap with
bounded startup evidence.

Run 41134898722 established the prerequisite failure: original Matter 8.1.2 with
CHIP 2025.7.0 failed `ctypes.CDLL` because `libnl-route-3.so.200` was absent. Both
netlink packages were absent from the captured dpkg inventory. The unchanged
original role declares neither, and no owned private inventory source overrides
its additional-package list. This does not establish how any live host acquired
the dependency. The fixture image now preinstalls Ubuntu `libnl-route-3-200`
(which depends on `libnl-3-200`) as explicit existing-host OS state. Neither the
original role nor any of the 971 production resource changes; pristine installation
coverage still excludes this preinstalled dependency.

The official [CHIP 2025.7.0 wheel](https://pypi.org/project/home-assistant-chip-core/2025.7.0/)
`home_assistant_chip_core-2025.7.0-cp37-abi3-manylinux_2_31_x86_64.whl`
SHA256 is `afde5db4bdaf3065eef4c641041de94530353fbd6ab8aa40fa2fd09c8ac1bbec`.
Its ELF `DT_NEEDED` includes both netlink libraries; Python package metadata
contains Python dependencies only. Ubuntu's [Noble package file list](https://packages.ubuntu.com/noble/amd64/libnl-route-3-200/filelist)
identifies the missing SONAME's provider. The diagnostic records installed Debian
versions, `readelf --dynamic`, and actual service-account `ctypes.CDLL` using the
original CHIP resolver, with the installed native binary, direct CHIP imports and metadata hashes
checked against that wheel. Each command has a 15-second/1 MiB bound, using the
existing owned-process cleanup. This does not initialize a second CHIP stack or
restart the service. Any failure is retained and stops before readiness; success
still requires the unchanged 90-second/20-second stable unit/port oracle. Corrected
native loading/readiness remains pending a separately authorized run; the failed
run and cleanup are retained, never relabelled successful.

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


The guest exports `OPS_LIBRARY_PATH` as the exact owned absolute original
collection checkout from process start and unsets `OPS_DEPLOY_PATH`. Before the
harness runs, it verifies that checkout at
`9d88de8f9d04498bbb6d71174792534e87db4a88`. The first matrix exercises the installed
public deployment API; private CLI binding remains a separate qualification.


## Frozen cafbe interpreter diagnostic after c701

Run41139171439 proved the corrected Matter native load and stable readiness in
both guests. Upgrade planning passed; the first typed mutation then failed in the
Python lookup after two managed operations and one upload. Current selection
failed separately in the original STT entity resolution. Preserve those partial
results; neither case qualifies the application matrix.

This feature's guest entry is a single **current interpreter-only diagnostic**.
Dispatch this revision only with the explicit workflow input
`fixture_cases='["current"]'`; the unchanged published workflow's default
current+upgrade input is not the diagnostic scope. Root authorizes the exact
immutable source and this input before dispatch. An upgrade input deliberately
fails admission and must not be used as a diagnostic retry.

It shares the exact checksum-pinned UV0.13.5/account seed, creates only the owned
Python3.14.8 environment, and runs no original role, HA/Matter package, service,
provider or application matrix. Direct fixed `runuser -- env HOME=...` lookups
retain inherited environment; a separately labelled control removes only the
observed UV/XDG/VIRTUAL_ENV keys. Evidence includes command output, cwd, uid/gid
and those environment names, never environment values. The actual SDK query and
original install operation run through real State/LocalConnector contexts in a
bounded child (900seconds, 1MiB combined process output; each recorded stream is
limited to16KiB with explicit truncation). The install operation first finds the seeded interpreter. If that lookup
succeeds, it completes without executing an install command; that result does
not exercise or qualify the post-install lookup/failure path. Only a failed
initial lookup reaches the install command and its fresh post-install find.
The install may mutate only this owned interpreter. UV seed is bounded to600seconds; direct finds to60seconds. Both parent
and child require owned hosted-guest identity before effects.

The fixture oracle `reviewed_transport.py` is byte-identical to public feature
1295d7d75a299d09fa98e1460c75b2e9b0fcc6bc's protected transport. Comparing it with
the frozen production lookup is diagnostic, not adoption or an attribution of
cause. All971 production resources are unchanged. The diagnostic records actual
SDK failed-host and operation-completion state, including the existing escaped
generator error. Completion of diagnostic collection does not imply a successful
lookup or application deployment. Source controls use fixed synthetic commands
through the real SDK; actual Linux/UV behavior still requires a separately
approved immutable guest run.

The full matrix entry now delegates to the canonical harness module, so phases
recorded by the matrix's imported typed caller appear in its summary even when a
later phase fails. Strict per-phase comparisons remain unchanged. Full current
and upgrade execution, remaining faults/lifecycles, original STT diagnosis and
ordinary private controller binding remain open.


## Interpreter repair controls after cafbe

The current guest entry retains the same single-current, interpreter-only scope.
No application matrix is dispatched by this source. Native execution of the
repair requires a separately frozen source/provenance packet and Root GO.

The cafbe native result established the failure: service-user UV discovery
inspected the unrelated controller `.venv/bin/python`, whose interpreter target
was inaccessible. Clearing candidate environment keys and using the protected
transport did not change that result. Installation succeeded, its post-find
failed, and the generator error left SDK metadata incomplete with no failed host.

The prepared production correction enters the configured service home inside
`runuser` for find/install and yields a fixed failure callback after a failed
post-find. This is intentionally different cwd behavior. Actual original
Ansible.command/become stays in a readable controller, falls back to distinct
module temporary directories for an inaccessible playbook directory, and stays
in an accessible service home; the original role does not specify `chdir`.

The repaired fixture records original core2.21.5/full801 identity and command
results in those three contexts, then compares the hash-guarded exact cafbe
interpreter with the repaired implementation. Direct UV and actual SDK controls
cover readable and private controller directories, neutral home, existing-Python
no-op, cold owned-Python uninstall/install, repeat no-op, an owned inaccessible
home `.venv` post-find fault with one SDK retry, and a clean follow-up after fault
removal. The private-controller mode and synthetic symlink are restored in
`finally`; owned guest cleanup remains unchanged. No real account or application
interpreter is removed. Deferred planning can report a possible install while
execution discovers the existing interpreter and reports no change. Failed
operations complete and enter `failed_hosts`; `executed=True` does not mean they
succeeded. SDK change results remain the restart-notification input.

Original command processes are limited to 120 seconds each; each direct UV repair
command is limited to 120 seconds; the SDK child has a 900-second outer bound,
command/query timeouts, and bounded public output. Original and typed native
repair results remain pending until the exact authorized run completes. This is
not full Home Assistant, private workflow, inventory or hardware qualification.


The normal wrapper accepts `PYINFRA_FLAGS` including pyinfra `--retry`; default
retry count is zero. SDK 3.10 otherwise drops earlier-attempt commands from its
final change result. The interpreter operation therefore carries a per-invocation
set of actual hosts whose install command succeeded during execution. A retry
that freshly finds Python yields a fixed bookkeeping callback for that earlier
change, preserving HA and selected Matter notifications without another install.
Planning, a failed install, an initially present interpreter and a separate
invocation do not set or inherit that progress. This does not alter SDK internals.
