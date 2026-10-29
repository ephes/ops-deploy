# Daybook operations runtime

This implementation slice defines the protected schema-five profile, original
runtime resource rendering and distinct metadata/managed health boundaries. Host install,
stop/update transitions and normal routing are being qualified separately; this
slice does not switch an inventory engine or authorize a live source update.

`DaybookRuntimeConfig`, `RuntimeKind` and `RuntimeWorkers` preserve the original
`daybook_operations_runtime_deploy` role's profile, worker reserve, deadline/lease,
owner and capability-host interfaces. Fresh installation renders disabled;
`cutover` is the only action that renders enabled. Existing transition
confirmation and action/start restrictions remain. The three packaged templates
are byte-for-byte copies of ops-library cf3a0c74.

The normal default decision uses the current Main revision resolved once for the
whole run. An enabled installation with exact declared source/lock/runtime and
resource equality selects verification on unchanged resources. A change selects the original
guarded stop → importer install → replace → cutover/start → verify update flow,
once all dependent APIs are qualified. Fresh or disabled installations stay
disabled. The installed old commit must never replace desired Main to manufacture
a no-op. Original CLI health is managed work on both empty and nonempty stores,
separate from source/resource drift: a current halted or stopped keeper fails verification
without selecting a mutating update. An existing disabled profile does not require
a running GUI job or store during observation; normal disabled installation
converges those prerequisites without activation. Revision text alone is not proof of source/resource equality.

The limited pure metadata/monitor contract uses `GET /v1/status` with a separate existing
**monitor-purpose** credential through the existing redacted `SecretValues`
container, under its `monitor_token` key. The executor credential is denied by that route.
There is no retry, redirect or fallback to executor `operations status --binding`,
which can expire server authority and opens a local Journal. Existing guarded
update effects remain separate and must be counted as managed effects.

The HTTPS client retains exactly `binding`, `enabled`, `active_state`,
`expiry_pending`, `unapplied_receipts` and `needs_operator` for explicitly declared
sources. It discards the rest of the response and emits fixed failure categories;
no raw response/error body, principal, IDs, arbitrary blocker text or token enters
its results. It verifies TLS normally, limits the body to 256 KiB, uses a 30-second
socket timeout and performs one request. A failed monitor call remains a failure.

The reviewed deployed handler and reachable helper source have a dedicated
aggregate read path before expiry/contact/write transactions; no local Journal
constructor is used. Actual endpoint use requires that same source boundary and
the existing monitor credential purpose, without permission or policy changes.

Run the paired resource oracle explicitly with the actual original role:

```sh
OPS_LIBRARY_PATH=../ops-library uv run --locked --with ansible-core \
  pytest tests/test_daybook_runtime_contract.py tests/test_daybook_runtime_status_tls.py
```

The owned local HTTPS fixture checks certificate denial, exact route, monitor vs
executor purpose, repeated reads, redirect denial and oversized-response failure.
It has synthetic operational metadata and no personal data or inventory access.

The next local verification slice reads code/package bytes, the declared profile,
resource equality and delivery-store directory metadata. Credential bytes are
compared in memory; no credential digest is placed in command arguments or proof
metadata. Directory entries are counted without opening delivery or halt records.
It probes the exact loaded command, the supervisor session and pinned interpreter
without importing Daybook. The pyinfra fact receives a closed-after-use in-memory
stream: raw string fact stdin is deliberately avoided because verbose pyinfra
completion logging prints that argument. A real verbose local CLI fixture checks
the supported stream path without any inventory or real credential.

Transition predicates retain the original same-day run windows (including their
lead), recheck-before-stop requirement, already-stopped recovery, quiet store and
source guards, profile identity and kind/store continuity, and replacement drain
proof. They do not perform a transition by themselves. Original executor-status
expiry effects remain managed application effects, separate from pure monitoring.

The guarded stop API (`stop_daybook_runtime`) retains the original hosted-mode
stop sequence: Aqua/keeper/host/store checks, run-window guard, bounded quiet
waits and per-source original executor status, a fresh local check and second
window guard, keeper bootout, graceful supervisor SIGTERM, exit/session/drain
proof. Failure inside the stop sequence attempts to recover only the keeper on
unchanged code before failing. As in the original role's rescue, this also applies
to a serving-only recovery whose keeper label was already unloaded: it can load
the existing keeper again, so this is a managed recovery effect, not a claim that
all initial launchd state is preserved. It never kills the capability host or uses SIGKILL.

This stop stage is **managed**, including executor/Journal effects when a prior
failure already stopped the supervisor. It is not used by unchanged-resource
verification or presented as a read-only check. The original CLI's own bounds
are retained without adding an outer executor-status deadline. Its managed status
command retains the original login context; an inner subprocess captures only
the CLI stdout and frames it separately from login-profile output. Both raw
streams remain in memory and are discarded; a failing CLI still fails the stage. Local metadata
commands remain bounded. `RuntimeStopPolicy` carries the original window inputs;
the role's empty-window/zero-lead defaults are separate from the private update
wrapper's existing 20-minute lead and two Europe/Berlin windows.

The stop API is under qualification. It has not been invoked on an inventory
host; guarded replace/cutover and source fanout still follow before normal
routing and any engine switch. Existing stop confirmation semantics are kept;
this adds no new owner acknowledgment or activation path.

The owned `daybook-runtime-native.yml` harness uses a disposable ARM Darwin
runner, an immutable noneditable Git installation, a unique GUI keeper and tmux
capability host, synthetic Daybook code, an owned loopback SSH transport and
unusable fixture credentials. It enumerates the actual installed package set
(excluding interpreter bytecode), compares all resource bytes to Git and checks
the distribution's exact Git direct URL. Existing Mac application fixtures are
not replayed by this workflow.

The fixture exercises pure SSH verification repeats, window/halt/busy/unanswered
refusals preserving the keeper PID, a graceful stop and already-stopped managed
recovery, and an actual TERM timeout that must restore the keeper on unchanged
code. Selected source/resource/store metadata and the capability host are
protected throughout; deliberate fixture fault setup is recorded separately.
The monitor rows and application are synthetic, so this does not qualify a real
Daybook source transition, default service or inventory host. Exact owned cleanup
may terminate its own remaining fixture processes; production stop uses TERM
only. A real local CLI negative test proves the harness refuses non-hosted use
before any host resource or package verification is attempted.

The fixture starts the tmux server in foreground mode without a command and
creates its host session through a separate client, following the
[tmux manual](https://github.com/tmux/tmux/blob/master/tmux.1). This retains the
server and descendants under exact owned cleanup. Its uv interpreter and caches
are explicitly confined to the owned root; workflow controller/action caches
remain disposable-VM setup and are recorded as outside fixture cleanup.

The hosted workflow installs a missing tmux formula as the ordinary runner user
with Homebrew auto-update disabled. This is disposable fixture setup; it does not
install or upgrade software on an inventory host. The
[first attempt](https://github.com/ephes/ops-deploy/actions/runs/40636933117)
failed at setup because tmux was missing, before any app/GUI/SSH case ran;
its hosted artifacts have a seven-day retention period.

The owned fixture records a diagnostic only after a failed normal verification,
then still fails on that original result. It compares protected metadata and
keeper PID before/after the diagnostic, which cannot pre-warm or replace the
first normal observation. It uses the exact observer over the same SSH connector and retains
only observer metadata, fixed failure categories and per-probe return codes with
fixed stderr classifications. A failed uv check also retains matching fixed
error/plan tags, without package names, paths or raw messages. Child stderr, argv, environment and input bodies
stay out of the receipt. This adds no retry, bypass or change to normal verifier
success criteria; failed attempts remain failed evidence.

Delegated metadata probes pass their explicit command environment after sudo,
so `TMUX_TMPDIR` and Git selectors reach the target user despite sudo's normal
environment reset. They execute directly with `/` as cwd and the target user's `HOME`, avoiding
login-profile output and side effects. All probe paths are absolute; the SSH
login user does not need traversal access to the target user's home. This is the new pure metadata contract;
original Ansible's module wrapper isolated command stdout even when it used a
login shell. Same-user probes also use the explicit public cwd. This changes
no sudoers, authentication, SSH or timeout policy. Managed executor status keeps
its separate original contract; it is not this pure metadata path. The owned
fixture requests only managed Python and records its version and exact owned
managed-prefix metadata before testing the runtime.


Fixture ownership is established before editable synchronization. Later setup
assigns only newly created config/store resources; recursively chowning the
synchronized code and environment changes their metadata and causes a real uv
outdated-environment result. The failed native attempts are retained; the
production locked-environment guard is unchanged.


`stage_daybook_runtime` implements the original disabled-first `install` and
quiescent `replace` configuration stages after a separate guarded code install.
It requires exact declared code/lock/interpreter state before writing. An enabled
profile refuses `install`; replacement requires the label and serving process
absent and all old store evidence drained, preserving API identity, kinds and
store continuity. It writes only the disabled policy, private store/credential
and staged plist. It never installs the live LaunchAgent, updates source or starts
anything. Cutover, source fanout and normal dispatcher wiring remain separate.

Staging status compares metadata/resources without application imports. Its
verification design also retains original installed `Config.load` validation,
including on current repeats after a rejected first, so a matching file cannot
hide a client rejection. The constructor-only verification boundary is being
qualified separately from executor status/Journal behavior; no inventory use of
this new staging API is qualified or authorized by its source implementation.

The proposed constructor-only repeat verification executes `Config.load` through
the direct metadata account/environment/cwd path with `-I -B`, without login
profiles, the application CLI, `Client.call` or Journal construction. The changed
staging operation retains the original login-context validation separately; both
suppress bytecode writes. This is an explicit new verification contract, pending
whole-slice source/owned proof review before inventory use. TLS context setup can
read native trust resources; no whole-host zero-I/O claim is made.

Staging writes use descriptor-relative traversal, exclusive temporary files and
atomic replacement without following directory links. Missing ancestors of the
declared private store/credential directories are explicit private preparation;
existing ancestors remain unchanged. Other resource parents must exist before
any mutation. Legacy pre-schema-three delivery slots are read only during managed
replacement to prove their original idle phase, never by a dry-run/status fact;
ordinary current-schema verification counts directory entries without opening
record bodies.


The pure runtime observer retains the original interpreter ownership split.
User-owned checkouts use their existing GUI user's uv-managed tree. The
protected Inbox's root-owned checkout uses the original sibling
`/Library/Application Support/Daybook/python` tree, root `HOME=/var/root` and
`UV_PYTHON_INSTALL_DIR` for uv find and offline lock checking. The tree derives
from the original Inbox install root; there is no new selector flag. Before a
root copy is executed as the GUI user for the isolated stdlib version probe,
its root ownership, regular single-link, 0755 mode, exact pinned source bytes and
`pyvenv.cfg` home must match the root-managed source interpreter. No digest is
logged. A failed check remains noncurrent; observation never repairs it.

The separate owned root Python fixture exercises that original root layout
with disposable synthetic source and Python3.14.7. Installation, lock/sync and
binary materialization are explicit managed fixture setup. No app is imported,
no launchd job is started and no inventory source, profile, TCC authorization or
interpreter is changed by that proof. User-owned Sessions and resource proofs
remain separate; root qualification cannot be inferred from their user uv paths.

The root pre-execution check also verifies root ownership and non-writable-by-
others metadata for the protected code/environment and pinned Python tree,
including directory ancestry, package/startup files and the regular single-link
`pyvenv.cfg`. It reads no package/config bodies in that metadata walk. A
root-owned sticky temporary ancestor outside the protected roots permits the
disposable fixture's isolated root; the protected objects themselves remain
strict. Root uv is never invoked against a tree that failed this check. Binary
hashes compare only the declared package executables in memory. Unsafe files or
local metadata/read failures remain noncurrent, with no repair or execution.

The metadata check recognizes only uv's two original bookkeeping lock leaves:
`.venv/.lock` and the managed Python install directory's `.lock`. uv0.13.6
creates these inert flock files mode0666. The pinned [Unix lock implementation](https://github.com/astral-sh/uv/blob/329bf9448afd9f9088d14a4d57fbc61eb454f117/crates/uv-fs/src/locked_file.rs) opens/locks these files and does not execute their contents. They may retain that mode only as
root-owned regular single-link nonexecuting files under the same strict
ancestry; their bodies are never read or hashed by the observer. No chmod or
new lock policy is applied. Other writable objects, including another `.lock`
name, code/startup files and `pyvenv.cfg`, still refuse before root uv execution.
The separate native proof records the actual uv version and both exact metadata
rows; an older whole-tree assumption that rejected these normal locks is retained
as failed qualification evidence.


The root parity component was qualified at immutable `f45583b`: native
[40711152759](https://github.com/ephes/ops-deploy/actions/runs/40711152759)
verified all762 installed package resources and fifteen genuine pre-execution
fault cases, with successful cleanup. It exercised the installed observer's
direct probes in controller Python3.13 plus actual GUI Python3.14.7 and root
uv0.13.6. Two initial and one final direct-probe repeats preserved the selected
source/interpreter metadata. Native cache/temporary I/O remains outside that
comparison. This is neither a normal pyinfra deployment/zero-operation proof nor
inventory/default qualification; full Inbox adoption remains separate.

Canonical [40711152756](https://github.com/ephes/ops-deploy/actions/runs/40711152756)
passed8207 tests with514 known skips on both Python versions. Earlier failed
native runs remain part of the qualification history: the first fixture expected
a later refusal phase, and subsequent diagnostics exposed the ordinary uv lock
mode compatibility issue. The final scoped review retained its execution limits
and repaired the hard-link regression's masked negative case; it did not relabel
those failures or claim a whole-family live review.

## Attended cutover and rollback component

`transition_daybook_runtime` retains the original confirmed `cutover` and
`rollback` actions and optional start. It checks the exact source, existing
profile identity/store/kinds, closeout marker, loaded keeper and detached
supervisor before mutation. Original executor `operations status` and `idle`
commands remain managed application work: they can open the application Journal
and expire authority. Their raw output stays in memory; only four aggregate
status fields are interpreted. This is distinct from pure monitor verification.

The transition stages credentials and the candidate, disables only the declared
label, preserves the original idle wait, proves it unloaded, and checks all
rollback-store entries before selecting a command. The first original command
is saved once, including binary plist bytes. Closeout prevents recreating the
backup. The selected policy is parsed through the original managed client
constructor. Starting still requires reconciled server state before enabling
and bootstrapping the exact label. A failed intermediate step retains its real
partial effects; the component does not automatically restart or roll back.

The original GUI account login context is retained for managed commands.
Read-only metadata probes continue to use their separate direct context.
This component does not install code, select a new source, quiesce a running
keeper, or expand the runtime update's Inbox-only dependency into Sessions or
Photos. Private normal routing, complete update composition and inventory
qualification are separate work.

The original `binding` selects one source for transition `status`/`idle`;
`status_sources` selects the full monitoring/stop set. They retain separate
original purposes, so the typed model adds no new membership restriction.
Live and saved command metadata are checked before mutation and rechecked
after unloading before replacement.

## Owned transition/report qualification

Immutable runtime `8065a2998d0cba326ef2a677a7844940807c15ca` completed
[native run40781491228](https://github.com/ephes/ops-deploy/actions/runs/40781491228)
with all behavioral assertions and cleanup successful. The actual noneditable
installation enumerated exactly817 package resources, every byte matching Git,
with the exact Git direct URL. The fixture used an inert owned application,
synthetic server/ledger and unusable credentials. It exercised cutover/start,
original-command preservation, rollback and explicit rollback repeat, plus
three exact-category refusals protecting resources/PIDs. Explicit rollback
repeat still performs one managed application/transition operation; this is
not a zero-effect repeat claim. The optional report actually returned the
validated count3 through the real GUI/SSH/SDK path.

The raw native receipt retained its initial `status: failed` label because this
new fixture omitted its final success assignment. The raw artifact is retained:
GH exit0, completed assertions, final ledger-equality field and cleanup evidence
were independently adjudicated. The fixture now asserts final ledger equality
and sets passed only after its assertions; `OwnedMac.finish` still resets any
real failure to failed. No identical runtime proof was replayed for this metadata
correction. Scoped review ended Suggestion-only with documented execution
limits; it is not represented as a full CLEAN reviewer execution.

The initial canonical run40781491157 failed only the scanner treating an encoded
Python resource as raw shell source. Test-only `5f4145e` checks the actual composed
transition through real bash and fish, preserving protected stdin and sanitized
errors. [Canonical40783227181](https://github.com/ephes/ops-deploy/actions/runs/40783227181)
passed8600 tests with518 known skips on each Python version; all817 runtime
resources remained byte/mode exact8065. These component proofs add no inventory
default and authorize no real source/profile/keeper transition. Normal routing and inventory adoption of managed original CLI health and
lifecycle actions remain separate work.

## Original managed health, update check and closeout

`verify_daybook_runtime_health` retains the original role's exact health
predicate: genuine CLI exit0, the local profile enabled and local status other
than `unreadable`. It runs the original GUI-account `operations status` once for
every declared source on both empty and nonempty stores. This application work
can read its own Journal and expire server authority. It is always a managed
operation, including ordinary repeats on unchanged configuration/code. Only
verified/count metadata leaves the host; raw record, status and error bodies
stay in memory. A failed CLI or unreadable local record remains a genuine failure.

Remote source `enabled`, `needs_operator` and `expiry_pending` are reported
metadata, not original refusal predicates or reasons to activate a source.
The separate monitor credential does not establish the executor credential's
binding-GET success. Pure local-resource/monitor observations are useful for
planning and comparison; normal full verification also invokes original managed
CLI health. No empty-store shortcut or blanket active-work barrier is added.

`check_daybook_runtime_update` preserves the existing update-check workflow: the
original confirmed hosted-stop declaration, GUI/capability/store/window checks
and one original executor status per source, without quiet retries, bootout,
signals or source replacement. Its old read-only label was inaccurate; typed
update-check counts this as managed application work. Existing metadata
observation is sufficient for safe planning, so no extra preflight product flow
or migration acknowledgement is required ahead of normal update.

`closeout_daybook_runtime` preserves the original confirmed closeout action. It
deletes only the saved original command and publishes the original marker,
leaving the running keeper, source, profile and credentials alone. Repeated
closeout verifies the current marker and missing backup without a managed
change. Static marker validation precedes backup removal; partial filesystem
failures remain failures. Closeout ends rollback, so actual destructive lifecycle
execution is separate from owned mechanism qualification.

[Owned native40791011004](https://github.com/ephes/ops-deploy/actions/runs/40791011004)
passed on immutable `1147256`: the actual noneditable installed set contained
exactly873 package resources, all bytes matching Git and its direct URL. Synthetic
root/GUI/SSH cases proved empty health first/repeat and readable nonempty health,
each one managed operation with two actual CLI calls; intentionally disabled
remote sources and attention flags remained accepted. Managed update-check
first/repeat likewise called both declared sources without stopping the keeper.
Unreadable, CLI-nonzero and busy-source cases genuinely failed after respectively
one, one and two actual CLI calls; failed operation `changed:false` does not mean
no application work happened. Closeout changed only its backup/marker resources,
its repeat had no managed change, and the keeper PID stayed fixed. Cleanup passed.

The initial native40790627690 failed during tmux setup before health ran; its raw
receipt/log and successful cleanup remain retained. The bounded fixture repair
shortened its socket basename inside the unique owned directory. A separate local
same-context control records a105-byte socket-path failure and short-path success,
including the terminating byte budget. The old native setup did not retain tmux
stderr, so this does not establish its exclusive original cause.

[Canonical40791010910](https://github.com/ephes/ops-deploy/actions/runs/40791010910)
passed8867 tests with521 known skips on both Python versions. The scoped review
ended with one diagnostic Suggestion and no Critical/Warning findings; sandbox
execution limits and the initial INVALID review are retained. The comment now
acknowledges that exit1 may include a denied sudo context: bounded nonreadiness
still fails if persistent and is never treated as success. This is owned synthetic
component proof, not actual private-adapter or inventory qualification. Private
normal routing, complete update composition, live transitions and defaults remain
pending.

Managed health preserves the original `verify_retries` / `poll_delay` metadata
startup budget before its once-per-source CLI calls. Each original keeper,
process and session stage gets its initial attempt plus the declared retries:
13 attempts and12 waits for the default12, following Ansible2.21 task execution.
Only these metadata observations retry; executor CLI calls do not. Unknown probe
failures remain genuine failures.

## User-owned code prerequisite

`ops_deploy.services.daybook_operations_runtime.code.install_daybook_runtime_code`
prepares the original user-owned target's source and locked environment. The
connecting identity must be that existing GUI user. Studio's root-owned source
remains the separate Inbox dependency. This component neither starts the runtime
nor changes its profile, credentials, journal or launchd jobs.

The code predicate checks the exact once-resolved Main revision and declared
tracked code, a clean checkout, frozen dependencies and the original exact
managed-Python home/version. Current code can remain in use. Replacing code or
changing the environment requires the original keeper label unloaded and no
`operations serve` running for that user. Unknown process/tool failures remain
unavailable; they do not establish quiescence. These checks belong to this
runtime code prerequisite, not to unrelated legacy Sessions checkouts.

Planning uses metadata/code/lock predicates only. A queued read-only guard also
runs before managed preparation or transfer. A genuine change creates a private
per-run upload directory, uses ordinary connecting-identity SFTP, verifies the
bundle descriptor and commit, and cleans the exact temporary directory on success
or failure. The temporary handoff replaces the old persistent deployment-bundle
cache; the application does not consume that cache. Existing old cache files are
left alone. No credential file or durable credential verifier is created.

As in the original role, a readable different revision removes only the declared
checkout before Git initialization, bundle-ref fetching and detached checkout.
The code refuses a dirty checkout that remains on the same declared revision.
A missing exact Python patch is installed with the original `--no-bin` selector;
installation respects an inherited user download policy. Synchronization retains
frozen/no-dev/managed-Python semantics and cannot download another interpreter.
A failed build, lock check or interpreter-home postcondition stays failed.
UV predicates and managed work inherit the same user location/config context
(including XDG/UV directories), with the same explicit UV overrides. Interpreter
selection and home drift are checked before the lock predicate. Managed
source/build work uses the original user context; application imports,
CLI status, constructor validation and model calls are absent from this component.

The [owned native proof](https://github.com/ephes/ops-deploy/actions/runs/40801523101)
at `e4bb6c0` passed with actual user-SSH/SFTP, UV0.13.5 and Python3.14.7:
first4 managed operations/1actualSFTP, strict repeat0/0, current enabled keeper
PID/resources preserved, changed source refused before transfer while in use,
quiescent replacement3/1, and replacement repeat0/0. All907 installed package
resources matched immutable Git, with exact installed-set/direct-URL and
noneditable provenance. Temporary resources were cleaned up. The genuine all7
unsafe inherited SDK field positive control was blocked before any privileged
command; actual component handoffs disabled every escalation field.

The fixture used a disposable loopback-only user sshd and owned UV install/cache
directories, not real inventory identities or Atlas availability. Selected
managed metadata equality does not claim global zero I/O. Synthetic Git/SDK
regressions and [canonical CI](https://github.com/ephes/ops-deploy/actions/runs/40801523031)
are separate evidence: both Python versions passed9334 tests/522 skipped.
Private normal routing and real inventory/source transitions remain separate
qualification work under the original maintenance-window contract.
