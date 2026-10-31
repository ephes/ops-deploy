# Home Assistant implementation in preparation

The Home Assistant port is being implemented against the original public
`homeassistant_deploy`, backup, restore, remove and trust-maintenance contracts.
There is no deployment API, private engine switch or native qualification yet.
The selected application, Python and Matter versions are not being upgraded.

## Configuration ownership foundation

`services.homeassistant.configuration` models the original task ordering using
synthetic, in-memory inputs. It does not connect to a target, parse arbitrary user
YAML, write files or invoke Ansible. Later host integration must keep configuration
and credential bodies protected and retain actual backup and notification behavior.

- Management flags default off. Existing `configuration.yaml` and include files,
  including empty files, are preserved unless overwrite is enabled.
- Secrets management is independent of the overwrite flag. A changed managed
  secrets file still requires the original protected backup and mode0600.
- Only the exact old role-generated MET, system-monitor and discovery blocks
  are removed. MET removal has its original separate flag; other bytes remain
  untouched. Cleanup uses whether the file existed before the template task.
- The ordered edit records preserve separate original template/replacement
  tasks, backup requirements and replacement-only restart notifications. They
  are desired edits, not evidence that a file or service has changed. Bodies
  are hidden from repr and must never enter controller receipts.

The bound unmodified original task file and tests cover flag combinations,
new/existing/empty files, near-match preservation, task order and exact repeats.
This is source-level behavior proof only. Native application/API, real canaries,
venv recovery, backup/restore and removal qualification remain outstanding.

## Physical runtime input foundation

`HomeAssistantRuntimeConfig` follows original user/home/site/path derivations,
including independent explicit config/data/log/venv/unit overrides. Home Assistant
and Matter unit templates are unmodified original source, rendered with the
original whitespace behavior. Optional Matter dependencies, logging and original
Python/package guards are covered by source tests. The original default package
spec remains unpinned; actual selected private versions will be mapped explicitly.

The prepared components below implement UV, trust and Python environment/package
steps, but the full entry point, private include-variable mapping, service
rollout, application flows and lifecycle paths remain implementation work.
No physical no-op or application acceptance follows from template/input tests.

The prepared UV component uses the original Home Assistant 0.13.5 version and
complete checksum defaults, leaving the shared installer's 0.13.4 defaults
unchanged. Its nested `uv` settings represent the resolved original include:
HA version/path/update/force settings are distinct from generic checksum/owner/
group settings. The original `homeassistant_uv_install_user` is inert in the
dependency role and gains no new ownership authority. Deprecated symlinks remain
disabled. `manage_uv=false` skips this entire component; an explicit `uv_path`
for later application commands remains independent of the install directory.
When enabled, it uses the existing checksum-verified installer and retains the
original final version/help checks, classified as read-only commands. Fake-host
tests cover current, outdated, update-disabled, forced, symlink and explicit
path/owner cases. Its original role gate runs before the shared installer:
with updates disabled, a broken existing UV is not silently replaced and must
fail its final functionality check; a missing UVX alone is not an original
replacement trigger. The shared installer's broader recovery behavior remains
unchanged for other callers. Real install,
ownership, interruption and healthy-repeat proof remains part of the forthcoming
native matrix, not a consequence of these synthetic command checks.

## Python replacement decisions in preparation

The prepared `python_state` module evaluates the original Home Assistant and
Matter replacement/install decisions without executing probes or changing a host.
Home Assistant replacement includes force, llama.cpp rebuild, missing or mismatched
Python, broken pip and legacy Matter contamination. Matter uses its separate
environment, pip and chip dependency checks. Unpinned application specifications
retain the original behavior: an existing binary does not implicitly upgrade.

Replacement preserves the original ordering: stop an existing Matter unit before
an existing Home Assistant unit when replacing the old Home Assistant environment,
even when Matter management is now disabled. Missing environments do not invent
existing-unit stop actions. A malformed interpreter response remains an error.
Tests evaluate the bound original task expressions over all combinations of these
predicates. This is source parity, not an executed virtualenv or recovery proof;
prepared host probes, UV/security and environment/package composition are
described below. Service rollout and actual native recovery remain unfinished.

Prepared observation wiring runs the bounded original interpreter/package probes
as the declared service user, with bytecode disabled and status-only results.
It separates interpreter/pip/legacy-package inspection from application version
and Matter chip imports: an environment selected for replacement never runs the
old application's version/import commands first. Tests execute the actual encoded
helper using owned synthetic executables and a local identity stub. They prove
command sequencing and response validation, not actual Home Assistant or Matter
behavior, service-user privilege separation, or physical no-op on a target.
Existence follows the original `stat` behavior without following symlinks. A
dangling Python link therefore fails version inspection before replacement;
a failed application command retains the original empty-version/install
decision, including the lack of an implicit upgrade for an unpinned spec.

The prepared unit-trust adapter sends the unchanged original systemd/proc
inspection program and exact managed drop-in bytes. It preserves the original
unknown-drop-in, manager/environment trust, reload and running-process guards,
including the explicit missing-unit preflight option. Owned synthetic systemctl
and proc fixtures exercise its actual encoded command and verify that private
environment values never enter its status output. The separate prepared writer
creates the original root-owned 0755 drop-in directory and exact 0644 file,
returning only the file change for handler notification. Disabled management
leaves an existing drop-in untouched. Post-handler verification runs only for
managed certificates with desired state `started`; planning does not execute it,
and a failed running-process report fails without repair or fallback. Verification
uses a fresh direct command with suppressed output, rather than the planning
probe path; command/schema failures remain failed host operations. Synthetic
SDK controls prove ordering and notification selection, not real systemd trust
or completion of the separate UV system-certificate maintenance workflow.

The prepared account/layout component retains the original append-only dialout
membership, home/shell settings and ordered0755 directory ownership. It returns
the exact static udev-rule dependency for the original deferred handler boundary;
reload-rules and tty trigger run only when that rule changed. Synthetic connector
checks cover current-rule suppression and unrelated group preservation. This is
not a public deploy entry point or a native udev/radio/system-account proof; full
validation, trust and package prerequisites must precede its eventual caller.


## Trust-floor component in preparation

The prepared `security` component copies the original `python_security_floor`
inspectors and controller policy. Nested `security` inputs carry the original
package floors, Requires-Python constraints, distrusted fingerprints, optional
managed-base binding and explicit policy overrides. The original HA/Matter
list of environments remains independently overridable. Missing interpreters
are skipped only during preflight; a dangling link counts as an existing path
and its failed inspection is not silently treated as absent.

Preflight inspects existing environments and, when enabled, the system CA
store before deployment writes. Constraint files limit package resolution and
do not install packages. The post-install read-only operation obtains fresh
reports at execution time and applies the same policy; it does not reuse a
planning report. Inspector programs import certifi/pip only, never Home Assistant,
and retain isolated Python execution with added bytecode suppression. These
checks cannot prove global zero I/O or physical-device behavior. Original policy
failures are not silently remediated, and explicit existing trust overrides are
not rewritten. The Python sequence is now composed below; outer caller sequencing and native
qualification remain unfinished. This component is not a deployment API.


The prepared interpreter component preserves `uv python find VERSION` followed
by installation only on a nonzero find result. The managed operation performs
fresh queries at execution and verifies availability after installation. Its
actual change result is intended for the original deferred HA/optional Matter
restart notifications. Later virtualenv observations must occur after this step:
installing a Python patch can retarget UV's minor-version link and make an
existing virtualenv current without rebuilding it. Cold-plan deferral is limited
to declared earlier user/UV creation prerequisites. Synthetic SDK tests establish
operation ordering and failure behavior, not real UV download or symlink changes.

The interpreter correction explicitly enters the configured service home inside
`runuser` before both UV lookup and installation. This intentionally prevents an
unrelated controller project's `.venv` from affecting discovery. It is a behavior
correction, not literal original working-directory parity: actual original
Ansible command/become probes kept a readable controller directory, used distinct
module temporary directories when the playbook directory was inaccessible, and
kept an accessible service home. The original role declares no `chdir`.

Lookup uses the reviewed protected connector/context transport. A successful UV
install followed by an unavailable interpreter yields a fixed failure callback,
so pyinfra completes the operation and marks the host failed. Failed operations
can have `executed=True`; this is not a zero-execution claim. Operation-local
progress preserves an earlier successful installation across an inherited SDK
retry, so HA and selected Matter still receive its restart notification. The
retry bookkeeping callback represents that earlier change, not another install;
planning and independent invocations do not share progress. Native repair proof
is still pending. The bounded current-only interpreter fixture retains the exact
cafbe negative implementation, original core801 identity, real UV and SDK
present/cold/repeat/failure/retry controls, without application phases. Final
Home Assistant qualification still requires both full application cases, remaining
fault/lifecycle contracts, and ordinary private source-context binding.


The prepared recursive environment-ownership component checks descendant
metadata, because the SDK directory operation only recurses when the root's
owner/group differs. It preserves the original role's `follow=true` behavior:
symlinks and existing targets participate, including linked directory contents
and intermediate links. Thus the scope includes UV interpreter targets reached
from the declared virtualenv; it is not confined to lexical descendants. No file
bodies or path listings are returned. Existing modes and modification times stay
unchanged, and already-correct ownership never invokes chown. Missing ancestors
are created with the original ownership/umask behavior. Only a root link is
resolved first; a missing root beneath a dangling ancestor retains the original
failure instead of creating that ancestor link's target. A link cycle or a root
resolving to `/` fails before repair; this is an early guard, not a claim that the
original module had identical partial-failure effects.

Owned local Colima ARM/Linux primitive tests exercise real descendant ownership
repair, hardlinks, dangling links, existing external targets, link chains and
strict full-metadata repeats. The test container has no network or host mounts,
a read-only root filesystem and a bounded temporary filesystem; its owned image
and container are removed afterward. These are typed filesystem primitive tests,
not execution of the complete original Ansible role or native Home Assistant,
Matter, radio or inventory qualification. Full deployment sequencing and native application/lifecycle proof remain
unfinished.

### Prepared virtualenv replacement

The unexported environment component resolves the selected interpreter and reads
Python/pip/legacy-package state again at execution, after the requested Python
installation. It preserves Matter-before-HA stopping for an existing HA
environment, including an old Matter unit when Matter management is disabled.
The missing-Python case preserves the original no-stop path. Removal handles
files, links and directories; creation uses the original service user, HOME,
site working directory, implicit HA `.venv` and explicit Matter destination.
Cold plans with a known pending creation prerequisite expose an unresolved
creation row; execution always performs the real observation. A failed creation
after stopping/removal remains failed with those partial effects, with no
automatic restart or invented rollback. SDK sequencing tests use synthetic
facts; real HA/Matter replacement and recovery remain in the future native
matrix. Prepared package and record/link/ownership composition is described
below; the complete deployment entry point remains unfinished.

The caller passes the actual preceding `install_python` operation as
`python_install` to `prepare_environment`. A planned Python installation thus
makes environment planning explicitly unresolved even when user and UV already
exist; it is not misclassified as an unavailable prerequisite. Execution still
fails before any stop/removal if the requested interpreter remains unavailable.

### Prepared application installation

The separate unexported application component observes application presence and
version after environment preparation. It binds the preceding environment
operation during planning so a soon-to-be-replaced HA/chip environment is not
imported. Execution queries fresh post-rebuild state. Original force, legacy HA
rebuild, missing binary, explicit `==` drift and Matter chip-import repair
predicates are shared with the source-bound policy oracle. Existing unpinned
applications are not implicitly upgraded. The command preserves original
service-user/HOME/site, shell-style package-spec argv parsing without a shell,
and security constraints; invalid quoting fails before registering effects.
No application-specific command timeout is added: the original package install
tasks have none, while the owned qualification runner has its separate finite
job deadline. Install failure remains failure, with no service restart/rollback
from this component. Extras and record/ownership composition are described
below; outer service-handler wiring remains unfinished. These SDK tests do not
qualify real HA/Matter application installation or recovery.

### Prepared extra-package resolution and notification

The original nonempty extra-package list runs `uv pip install` on every normal
invocation. The typed component preserves that command as **declared managed
execution**, including when UV only audits already-current packages. It is not
marked read-only and is not counted as a zero-managed SDK repeat. This avoids a
hidden `uv --check` planning query: owned UV research observed initial lock and
interpreter-cache metadata writes from check mode. The component invokes no UV
command during planning; the actual command and any cache/lock effects are part
of execution. It preserves each spec as one argv argument, original constraints
before specs, service user/HOME/site and no added application-specific timeout.

Deferred HA restart notification uses the original successful-output expression
`Installed|Updated|Uninstalled|Prepared|Built`, not merely the SDK managed-row
flag. A current audit therefore executes without requesting a restart. Failure
remains failed with any actual partial effects; premature notification access
is rejected by OperationMeta. SDK tests and the bound original Jinja expression
cover this distinction. Exact native UV/application/cache behavior and full
deployment/handler composition remain pending. Do not advertise this component
as global physical no-I/O or completed HA deployment qualification.

### Prepared Python-runtime composition

The unexported composition now orders requested-Python installation, HA
replacement, convenience link, version record, recursive ownership, main
application and extra-package resolution before optional separate Matter
storage/log/chip directories, environment, record, ownership and application.
Matter's second pre-install ownership check runs only when its application
actually needs installation, after its chip/version observation. That embedded
recursive check retains the original task's lack of a timeout, unlike the
separate 300-second ownership rows. It shares the application operation: a failed
or hung check is reported under application installation, and prior ownership
effects are not rolled back. Known earlier
operation dependencies defer cold planning probes; real execution rechecks each
state. This component still requires the outer original validation, trust,
account/UV/constraint prerequisites and final configuration/security/service
flush logic; it is not the completed deployment entry point.

Returned notification callbacks use completed operations: original Python,
ownership and application changes notify HA (and managed Matter); HA extras
use only their original successful-output expression. Version record or
convenience-link changes alone do not invent a restart notification. No service
restart happens inside this component. SDK cold/current, selected/unselected
Matter, record-only repair, changed/audit-only extras and failed-install tests
prove sequencing with synthetic responses and real SDK file operations. Native
application/venv/filesystem behavior and hardware remain unqualified.

### Prepared service units and handler boundaries

The unit component writes the byte-bound original HA and optional Matter
templates as root-owned 0644 files. It returns actual change dependencies and
does not reload or restart immediately. The separate desired-state component
keeps HA-before-Matter ordering, explicit started/stopped/restarted/reloaded
states and enablement. As in the original `service.yml`, every selected service
requests a daemon reload even when already current. This is declared managed
execution, not a zero-managed repeat.

The handler component retains reload-before-HA-before-Matter order, each original
restart-on-change switch and the original handler's `enabled: true` (even when
the desired-state setting disables that service). Its caller must supply only
notifications pending at that particular original flush boundary; reusing old
true callbacks would incorrectly repeat a restart. Config flows and final
Matter/trust verification still need the outer deployment's multiple boundaries.
No full deployment API is exported yet. Actual SDK tests cover current/missing
units, explicit states, flags and a failed unit metadata install with its prior
upload preserved; these synthetic connector tests are not native service proof.

## Prepared configuration rendering

The configuration renderer copies the original configuration, secrets and six
stock include templates byte for byte, retaining whitespace, comments, ordering
and the original interpolation rules. Configuration values retain role defaults;
the default SQLite URL follows the declared config path, independently of the
data path. Explicit database URLs and already-resolved UniFi/optional example
credentials use protected values. Every rendered body is returned as `SecretStr`,
including configuration and includes; consumers must keep unwrapped bytes in
protected stdin or host-local memory, never a durable controller receipt.

This component does not resolve the host's UniFi credential, parse or normalize
user YAML, write files, create backups, or notify a handler. Physical template
versus replace symlink behavior and named backup semantics are handled by the
separate host-local primitive below. Source/template tests are not native application proof.

### Prepared physical configuration primitive

The host-local file primitive accepts one protected template or replacement
task at a time. Templates replace a leaf symlink, retain its target, repair
declared ownership/mode, and make the original PID/time-named backup on content
changes or link replacement. Replacement tasks follow the leaf link, retain
its identity, preserve target metadata with the original atomic-move EPERM
tolerance, and back up beside the original path
only when the exact expression changes the body. Missing parents are not made;
missing replacement files fail. A matching regular file is not rewritten.

Only fixed status/effect flags and exception class names leave this helper.
`effects_started` distinguishes an attempted apply from a completed backup,
body write or metadata change: failures can leave a partial backup or newly
written body, so a failed operation is not evidence of zero effects. Ordinary
retry converges remaining metadata/content work. Current/rendered bytes, their
digests and backup filenames are not emitted. No global filesystem-I/O claim
is made; reading a file may update access time.

This primitive has local synthetic filesystem/original-Ansible controls only.
The configuration task composition below wires these primitives and UniFi
resolution. Full deployment and native Ubuntu/application/inventory qualification
remain pending.

The temporary-file attribute copy keeps the original ordering and EPERM-only
best effort behavior. A replacement has no explicit owner/mode arguments, so
it does not add a mandatory repair after that tolerated error. Other metadata
errors remain failures. The paired injected-error oracle uses actual Ansible
`atomic_move`; it is not proof of a real unprivileged foreign-owner scenario.

### Prepared host-local UniFi secret resolution

The managed secrets task now has a host-local source path: a nonempty explicit
value wins unchanged; otherwise only the selected file or variable source is
used. File reads tolerate the original read failure and trim decoded content.
Explicit and variable values retain whitespace. A missing value fails only the
managed secrets operation; there is no automatic fallback to another source.

The controller prepares two protected template halves around a unique temporary
marker, removes that marker, and sends the halves with protected source inputs.
The effective file-sourced credential is inserted only on the host. It is never
returned, hashed into a receipt, or placed in a process argument. Original
quoting and optional commented-example interpolation remain unchanged. Probe
mode may read the declared source file but does not write the destination.
The configuration composition below skips the unmanaged-secrets branch entirely.
Full deployment ordering remains pending outer composition; this is not native
or inventory credential qualification.

An owned original-Ansible control also confirmed surrogate-escaped non-UTF-8
file bytes survive the original slurp/template path. The protected host helper
keeps that byte behavior instead of silently replacing or rejecting those bytes.
This is a compatibility observation, not a claim that the result is valid YAML.

### Prepared configuration task composition

`configure_files` orders the managed secrets task, initial configuration stat,
guarded template, exact legacy/obsolete replacements, then initial include stats
and the six stock includes. Original pre-template existence controls replacement
eligibility; overwrite does not cause a newly created file to be treated as
preexisting. Existing includes are left alone when overwrite is false, including
a broken leaf link, matching the original stat guard. Only actual replacement
changes request the later Home Assistant restart; template writes do not.

The actual SDK regenerates each operation for execution. When a known pending
prerequisite or predecessor makes current contents obsolete for planning, the
plan reports a pending write and execution re-inspects the resulting file. It
does not call execution callbacks while planning or claim the pending row is
read-only. Metadata baseline operations are explicitly read-only. Unmanaged
configuration, includes and secrets cause no body or credential probes.

Owned local SDK tests cover fresh creation, whole-metadata repeat equality
(excluding access time), overwrite/replacement ordering and notifications,
read-only planning, initial broken links and cold prerequisite deferral. A
preexisting invalid replacement path fails during planning before writes. A
separate fault introduced after planning proves an earlier secrets write remains
when execution later fails; there is no automatic rollback or zero-effect claim.
These are controller-local filesystem/SDK controls, not Linux application proof.
The final deploy API and non-stock template aliases remain part of outer source
completion; no inventory engine is switched by this prepared component.

## Prepared ingress component

The shipped Traefik template retains the original router names, TLS empty-map
versus certResolver behavior, header values, ordered middleware/entrypoint lists
and local-address fallback. The backend defaults to the original application
port `10020`, matching the application configuration renderer. A missing IPv4 fact uses `192.168.178.50`; an explicit
empty value is not silently replaced. The original future `traefik_mode` field
still has no implementation effect.

The writer creates the root-owned 0755 dynamic directory and exact 0644
`homeassistant.yml`, returning only the file result for the original notification.
The default handler is informational because Traefik watches its configuration;
no restart or reload is invented. Disabled ingress does not read or change the
existing route. An exact protected rendered body can be supplied for an alternate
template; resolving that operator template and any selected external handler
remains the outer caller's responsibility. This is not yet a complete private
override binding. Source-bound render/default and SDK write controls are not
native routing, certificate or application readiness qualification.

## Prepared Matter, OTBR and Wyoming flow component

The three simple config flows inspect only the configured
`.storage/core.config_entries` file on the target. Original first-domain URL
selection and exact Wyoming host/port matching are retained; unrelated registry
fields and entries are not exported. A current entry needs no API request.
Planning only inspects the registry; execution rechecks it before the managed
flow. Missing configuration is represented as pending work, not a new admission
barrier. Malformed/unreadable storage fails with a fixed diagnostic.

Needed flows preserve readiness GET, forwarded headers, timeout/retry settings,
optional Matter port wait, start/submit requests and `already_configured` handling.
Readiness is shared in RAM within one host/role invocation; the outer deploy must
reset it after the original Custom Conversation handler flush. Original URI safe
GET redirects, separate per-request cookie jars, gzip/JSON handling, user agent
and URL/default-NETRC authentication precedence are retained. Credentials and
responses stay in host memory; input travels through protected stdin, and only
fixed phase/status/request-attempt counts return. Counts describe explicit
readiness/start/submit attempts, not internal redirect or auth-challenge hops.
No result file is written. The configured security `system_python` runs both
inspection and execution. A process-local wall-clock deadline covers the whole
helper, including redirects, auth retries and response reads; it stops with a
fixed phase/attempt report before the controller's additional grace expires.
Socket timeout is not misrepresented as a whole-request deadline. External
termination or transport loss can still leave effects unobserved and must not
be reported as zero changes.

An observed original Ansible defect is distinguished from intended flow handling:
a first `already_configured` result skips submission but leaves a registered
skipped result, causing the final guard/message to fail. The prepared component
accepts that explicit result as intended by the original skip branch. It still
fails HTTP 200 without a parsed flow ID or explicit `already_configured` result;
a submitted flow must finish with `create_entry` or `already_configured`.
Failed configuration request
attempts can have remote effects: receipts must retain the attempted count and
phase, never claim atomic rollback or zero effects from a failed response.

Controller-local synthetic HTTP/registry and actual SDK controls exercise
planning without API calls, shared readiness, first/repeat behavior and fault
classification. They do not qualify real HA onboarding/config flows, TLS, radios
or native deployment. Area/pipeline/bridge management and active canaries remain
separate work; this component does not replace or disable them.

## Prepared area-registry protocol component

The area helper preserves original ID-first selection (no name fallback when an
ID is supplied), last duplicate lookup, alias normalization and only the declared
alias/temperature/humidity fields. Unlisted areas and fields are left alone.
Repeated desired entries retain the original snapshot comparison order; a later
unresolvable entry can fail after an earlier update. Failure reports keep the
attempted and acknowledged update counts rather than implying rollback.

The original service virtualenv/interpreter and user are selected. API URL
rewriting retains the original localhost-substring/default-IPv4 rule with the
explicit application port. WebSocket TLS uses aiohttp defaults independently of
HTTP readiness settings. Tokens, area bodies/IDs and responses stay in host RAM;
protected stdin carries configuration and fixed status/counts return without a
result file. Inspection sends authentication and a list request, never an area
update. Application re-reads the list before applying declared changes. The
configured API timeout bounds the whole exchange, including unmatched messages
and stalled peers; an expired or failed update may already have remote effects.

This is a protocol component, not a complete deployment API. The outer deploy
still must compose original HTTP readiness, selected enable flags, service-user
prerequisites and execution-only managed updates. Owned loopback tests run both
the captured original script and the new helper against synthetic registries,
including partial failures, and exercise real WebSocket transport. The dev-only
aiohttp 3.14.5 dependency matches the selected HA release; it does not install or
upgrade any inventory application. Actual HA API, service-user execution and
native deployment qualification remain pending.

## Prepared pipeline protocol component

The pipeline helper handles already-resolved desired definitions through the
original list/create/update/set-preferred WebSocket calls. Unlike area selection,
a missing pipeline ID falls back to the first matching name. Creates append the
returned record to the comparison snapshot; updates retain the original cached
record, including the original behavior for duplicate desired declarations.
Unlisted pipelines are preserved. Omitted wake-word and local-intent fields
inherit existing values, and updates preserve existing acknowledgement media.
Without a preferred declaration, the current preferred pipeline is left unchanged.

Inspection only authenticates and lists. It reports the first needed mutation,
not a complete operation count or simulated ID for a future create. Application
re-reads the list, applies in order and retains attempted/acknowledged mutation
counts through create/update/preferred failures. Tokens and pipeline bodies/IDs
remain in host memory; no result file is created. The configured API timeout
bounds the whole exchange. Failed sends or responses may already have effects.

This host protocol component still needs the original registry auto-detection,
desired-definition preparation, validation, readiness and managed controller
composition. The separate existing-pipeline STT/TTS path is not replaced by the
list/create interface. Owned real WebSocket/original-inline-script comparisons
exercise these protocol semantics, not complete role prerequisites, live HA
application behavior or native deployment.

The separate voice protocol now has its own `get`/conditional `update` path. It
re-reads one declared pipeline and changes only enabled STT/TTS engine, language
and voice selections. Conversation, name/language, wake-word, local-intent,
acknowledgement and preferred selection stay intact; this path never creates a
pipeline. Owned original-inline comparisons cover both flags, current state and
failed-after-effect updates. The original storage-based target/engine resolution
and STT entity wait (TTS explicitly skips that wait) are still required outer
work; these protocol tests do not stand in for those prerequisites.

The prepared host-local state reader now selects desired definitions and the
standalone voice target from only the three named storage files. It preserves
first exact Wyoming host/port and entity selection, undefined-versus-empty engine
semantics, boolean conversion, preferred-target/language fallbacks and original
entity-file existence requirements. Explicit built-in conversation selection
still requires its active canary outside check mode. The root-context reader
returns only selected operational fields over suppressed output into a masked
controller value; complete registry bodies remain on the host. It performs no
API requests or storage writes. Original HTTP readiness, enabled outer stages,
STT wait and service-user protocol composition are still unfinished. These
owned storage/expression controls are not native or inventory qualification.

## Prepared built-in conversation execution

The original `llama_cpp_provision.py` is packaged byte-for-byte. Its managed-entry
ownership checks, local-intent fallback before retirement/key rotation, no-tools
configuration and real active response canary remain intact. The controller
installs the same service-owned helper and supplies its original configuration
through protected stdin as the service user. No token, registry body, prompt or
canary response is logged. Only a masked entity ID and completion/change flags
remain in invocation memory for later pipeline wiring.

Selected execution is explicitly managed, including a healthy unchanged canary.
The helper's `changed:false` is a separate application report, not a claim of zero
API activity or zero managed operations. Dry registration never invokes the
helper. Failures preserve the original helper's sanitized operator diagnostic, clear
previous canary success and report possible partial effects;
they do not invent a zero-effect result. The finite controller deadline can stop
waiting without proving remote quiescence, so timeout is a failed, uncertain run.

Owned controls include all 17 original synthetic transport-boundary tests,
real loopback HTTP/WebSocket healthy/auth/error canaries, and actual pyinfra
plan/execution controls with a synthetic helper. They do not exercise a real HA
model/provider or qualify native deployment. Original legacy-component discovery,
one-time clean-environment migration, readiness/handler resets and full outer
selection still need composition; this helper is not the full deployment API.


### Shared API readiness boundaries (prepared)

The original authenticated `/api/` status GET can run independently of a config
flow. It retains initial-plus-retry behavior, proxy/TLS/redirect handling and the
invocation-local ready cache; it opens no registry and sends no configuration
POST. Readiness executes only in the operation phase, with protected payloads and
fixed status output. It is classified read-only for managed configuration; HTTP
logging and background service activity are not claimed physically immutable.
The SDK still records executed callback operations as changed, separate from
this read-only classification.

After each original handler flush, `reset_api_readiness` must be registered at
that exact execution boundary. Resetting the Python field while registering the
whole deployment is too early: the earlier readiness operation can set it true
again before the later request. Actual local-connector controls reproduce that
wrong ordering (one GET) and the corrected boundary (two GETs), with no requests
in either dry-plan variant. The outer deployment still supplies original flags
and the handler flush; this component is not whole-service/native qualification.


### Legacy conversation migration (prepared)

Before the built-in conversation path upgrades Python, the original preparation
observes the named `custom_components/custom_conversation` entry with `lstat`,
searches only the configured virtualenv's `lib` metadata for real directory
names matching `litellm*.dist-info`, and selects the `custom_conversation` domain
from the named `core.config_entries` registry. The new host-local component
returns only presence/rebuild/retirement booleans and a skipped-metadata count;
no entry ID, registry body, package name or error path leaves the helper. The
controller command has a finite 90-second timeout. No package import or API call
is made by this observation. Reading metadata/registry bytes can update atime.

The search preserves original `find` behavior: descendant directory links are
not followed, hidden candidates are skipped but hidden parents are traversed,
and inaccessible/non-directory library metadata is skipped with a count rather
than invented complete-observation certainty or a new refusal. Actual original
Ansible seven-task controls match eight owned cases, including a dangling
component, package-directory symlink and non-directory `lib`.

The outer role must retain the initial rebuild flag, call the real original
retirement helper when selected, then remove the exact component path before
Python replacement. The removal handles a file, directory or dangling link,
without following its root link; actual local-connector first/repeat controls
preserve the unrelated link target. These components do not yet compose the full
retirement/upgrade sequence or prove native application and inventory behavior.


### Custom Conversation protocol (prepared)

The optional Custom Conversation component preserves the original 1.6.1 config
flow, owned credential/model comparison, options normalization and real
conversation canary. Ten protocol functions remain AST-identical to the captured
original helper. A reconfigure flow uses the domain handler plus `entry_id`;
options repair preserves the operator's agents, ignored intents and Langfuse
values. Empty instructions restore the exact version-bound component default.
Multiple entries are rejected before any API mutation even when disabling, as
in the original outer task; disabling one entry makes the original DELETE.

All runtime settings, credentials and canary text travel in protected stdin,
not task environment or command arguments. The host reads only the named
`core.config_entries`; registry/model response bodies and credentials are not
exported. The selected entity is returned to protected controller process RAM
for later pipeline composition. There is no target result file. Error reports
retain source-owned step/status/hints and exception classes, suppress upstream
response details and count attempted mutations. The controller retains phase,
attempt count and partial-effect status in its invocation result and exposes
those fixed fields with a sanitized failure diagnostic. Failure or timeout can leave
partial effects; the controller timeout does not prove remote quiescence.

REST/WebSocket timeouts use the shared `HomeAssistantApiConfig.timeout`, matching
original `homeassistant_api_timeout`. The separate controller deadline defaults
to 3,600 seconds and is configurable. This is a deliberate finite supervision
limit on the originally unbounded command: a sufficiently slow sequence of
otherwise permitted retries can hit it. It is not claimed to encompass every
retry combination or unsolicited WebSocket stream; that outcome fails with
uncertain remote activity rather than inventing quiescence or an automatic retry.

The API URL's scheme, port and path prefix, forwarded headers and original
aiohttp certificate verification are preserved. This helper does not adopt a
`validate_certs:false` override from another integration. A successful unchanged
configuration still performs the real `conversation/process` canary and is a
managed operation; helper `changed:false` is not zero API activity. Registration
and dry planning do not run it. The outer role still needs to supply the original
enabled-or-existing selection, readiness, component installation and handler
flush ordering before this is a complete deployment path.

Owned controls exercise real loopback HTTP/WebSocket creation, reconfiguration,
options, removal, healthy and failed canaries, duplicates and malformed input;
actual pyinfra local-connector controls cover plan/execution, invalid reports
and timeout uncertainty. These synthetic controls do not qualify a real HA
model/provider, native application deployment or inventory adoption.


### Optional Custom Conversation installation (prepared)

The installation component retains the original pinned 1.6.1 release/checksum,
operator URL override, parent ownership/modes and version-plus-checksum stamp.
An already matching archive makes no network request; owner/mode drift alone is
reconciled. A transfer is staged and checksum-verified before atomic replacement,
so bad HTTP or checksum results retain the old archive. The declared original
get_url transport defaults include proxy environment, verified TLS, gzip,
challenge-based URL Basic/Digest credentials and host-local netrc; URLs and
credentials stay in protected stdin/remote RAM. No Ansible runtime is invoked.

Only a missing/unreadable/mismatched trimmed stamp selects component reinstall.
The exact component root is removed without following a root symlink, then GNU
tar extracts the original named subtree with strip-components=2 and declared
owner/group arguments. GNU tar ignores ownership flags during extraction, so the
component then follows the original per-listed-member/top-folder `lchown` pass;
it does not recursively walk unrelated paths or follow member symlinks. Ordinary
archive modes and timestamps retain the original post-ownership semantics. The final 0644
stamp contains version and SHA plus a newline. Matching stamps deliberately
skip content verification, as the original role does. Only successful extraction
or stamp changes notify a later HA handler; downloading an archive or fixing
parent metadata alone does not. For an existing archive symlink, ownership applies
to the link itself. On Linux, the typed metadata step omits Ansible's temporary
chmod-and-restore of the link target, preserving its final mode without that
unnecessary target write; symlink permissions are not settable there.

Removal/extraction remains non-atomic to match the original task sequence. An
extraction failure can remove the old component despite a failed operation
report; temporary download staging also causes filesystem activity even when
verification fails. No rollback or zero-effect result is invented. Observation
reads the named archive/stamp, with possible atime updates; it does not walk user
data. Helper requests retain the original ten-second socket timeout, while the
controller adds a configurable 900-second command limit. A controller timeout is
not proof of remote process quiescence.

Owned Linux userspace controls exercise real GNU tar root-file/directory/link
cases, archive metadata and strict content/inode/mtime/ctime repeats. Synthetic
HTTP controls prove checksum failure preservation, metadata-only/current cases,
gzip and original auth behavior. These are filesystem/protocol component
proofs, not native HA/model/radio or live inventory qualification; full outer
optional selection/readiness/handler composition remains pending.


### Area execution composition (prepared)

The selected area task group now registers the original cached HTTP readiness
before an execution-time WebSocket inspection. Planning makes no API call, even
before the application virtualenv exists, and keeps an unresolved managed row;
it does not pretend that row is proven unchanged. Execution applies only actual
owned-field drift. A converged repeat still reads API state but sends no area
update. The original enablement and service-start/handler ordering belong to the
full deployment composition, which remains pending.

Only fixed success/change/attempt counters leave the helper. Unknown or malformed
apply results clear prior inspection success and retain partial-effects/remote-
activity uncertainty; no area names, registry bodies or response errors appear in
controller diagnostics. Inspection failures are emitted through an SDK command
callback so pyinfra completes failure accounting for that host and permits other
hosts in the batch to finish; they do not escape the command generator. Owned
real loopback API and LocalConnector controls prove
plan silence, readiness ordering, first update, zero-managed repeat and actual
write-before-error retention. These are component tests, not live HA or device
qualification.


### Pipeline execution composition (prepared)

List and standalone voice selection now run in a separate read-only operation
before protocol work. Only the named storage files are read in the original root
context; selected operational fields remain protected controller/host process
memory. Current invocation canary results supply automatic conversation IDs.
The custom-conversation fallback retains its original warning; an enabled
built-in automatic agent still requires its successful active canary. No
registry or API call occurs while planning, and unresolved operation rows are
not reported as proven unchanged.

A list then performs original cached readiness and service-user API inspection,
applying only pending changes. Standalone voice first compares its stored target
and enabled fields; a matching target skips readiness and WebSocket calls.
Needed standalone changes retain the original service-user STT registry wait
(initial attempt plus retries), while TTS provider IDs do not need an entity-
registry wait. Preparation and service-user readability are distinct. The wait
reads only the selected registry, does not import HA, and returns fixed status
and attempt counts rather than entity IDs or bodies. Its finite controller
ceiling covers configured delays plus a grace period; timeout does not prove
remote quiescence.

API inspection/apply preserves fixed counter validation and host-specific SDK
failure accounting. Unknown failures clear prior success; an acknowledged error
after a configuration request may retain real partial changes. No automatic
rollback, restart or response-body export is added. Owned synthetic named files,
loopback HTTP/WebSocket and real LocalConnector tests exercise list/create/
preferred and voice first/repeat, no-API converged voice, missing STT, auth and
partial response faults. Full outer role selection, native application and
inventory adoption remain pending.

Pipeline result, readiness and conversation objects belong to one host invocation.
Create them inside each host's deploy function; reusing a pipeline result on a
different host fails during registration, before target inspection or execution.
Inspect transport loss is reported through a failed SDK callback, so the failed
host is accounted for and unrelated hosts can continue. Owned controls cover
separate-host selections and successful service-user STT wait before updates.

### Normal deployment composition (prepared)

`HomeAssistantDeployConfig` and `deploy_homeassistant`, exported from
`ops_deploy.services.homeassistant`, now compose the original normal role's components.
This source is awaiting full owned application qualification and is not yet
selected by private service metadata. It does not qualify hardware, Thread/radio
state, model services or backup/restore/remove.

The configuration combines `runtime`, file ownership `configuration`, rendered
`values`, `unifi`, `secret_examples`, `ingress` and `api` with the original selected
area/integration/conversation/pipeline branches. Declared pipeline and area JSON
are `SecretStr` values; selected runtime IDs remain in invocation memory.
`values.app_port` supplies omitted API/ingress defaults, and the configured Matter
port supplies the omitted integration URL. An omitted default IPv4 in API or ingress derives from the other component,
matching the original single default-route fact; explicit overrides remain unchanged.
Explicit endpoints remain unchanged.
The default package remains the original unpinned `homeassistant`; an actual
inventory pin is not silently supplied by this public API. Built-in conversation
retains the original pinned Core >=2026.10.2 requirement and active canary.

The deployment preserves environment/unit/system trust admission, the existing
UV prerequisite, packages/account/layout/UV/constraints, legacy retirement before
Python replacement, security verification, configuration, units/ingress/service
state, areas and three simple flows. Custom component installation and built-in
conversation each retain their original handler flush/readiness-reset boundary.
Only notifications pending at a boundary can restart services; later flushes do
not reuse earlier callbacks. Matter import checks and running trust verification
remain after the final applicable handlers. Application checks execute as the
service user and retain raw output only transiently, reporting fixed failure
messages. Their controller ceiling is 3600 seconds; timeout does not prove remote
quiescence or zero effects.

Planning reads the original named metadata prerequisites/selection, without
calling an application API or a conversation model. The legacy metadata search
remains scoped to the configured virtualenv/lib; custom selection returns only
the named registry's domain count. No unrelated registry body or entry ID is
exported. New installation prerequisites defer dependent Python/configuration
inspection until execution; raw plan rows can therefore remain unresolved.

Normal repeat is deliberately **not** described as zero managed work: the original
apt refresh, extra-package resolution, desired-state daemon reload and selected
conversation canary remain actual operations. Read-only status marking describes
managed configuration ownership, not global I/O or background service effects.

## Prepared owned application matrix

The [owned native fixture](https://github.com/ephes/ops-deploy/tree/pyinfra-homeassistant-20261028/tests/integration/homeassistant)
uses a disposable public GitHub Ubuntu24 systemd container, sharing its VM kernel.
It is prepared source, not yet an application or inventory qualification. The
matrix compares the unchanged original role with real installed typed HA2026.10.2,
a declared2026.10.1 upgrade, Python3.14.8 and Matter8.1.2. Synthetic loopback model,
Wyoming and OTBR peers exercise actual application APIs without hardware or a
real model-provider request. Existing-host prerequisites and every fault/reset
remain explicit; ordinary refresh/reload/canary operations are not called zero
managed work. See the fixture README for privacy, resource and cleanup boundaries.

The revised owned run passed original bootstrap but exposed an auto-restarting
Matter prerequisite. The single owned diagnostic identified a missing
`libnl-route-3.so.200`; the fixture image now declares Ubuntu `libnl-route-3-200`
as pre-existing OS state. Original role and production resources are unchanged;
this does not establish any live host's package provenance. A bounded original
CHIP resolver/CDLL oracle records installed dependency identity before readiness.
The frozen entry now returns to the original current/upgrade matrix, requiring
this native-load proof and bounded Matter readiness/startup evidence before any
selected or typed phase. The matrix requires stable Matter PID/restart
count and port readiness before selected phases, retaining all strict snapshot
comparisons. Neither the diagnostic source nor local tests constitute native
application or inventory qualification.
