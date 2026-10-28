# Daybook operations runtime

This implementation slice defines the protected schema-five profile, original
runtime resource rendering and monitor-only verification boundary. Host install,
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
resource equality selects pure verification. A change selects the original
guarded stop → importer install → replace → cutover/start → verify update flow,
once all dependent APIs are qualified. Fresh or disabled installations stay
disabled. The installed old commit must never replace desired Main to manufacture
a no-op. Health is checked by pure verification, separately from source/resource
drift: a current halted or stopped keeper fails verification for operator attention
without selecting a mutating update. An existing disabled profile does not require
a running GUI job or store during observation; normal disabled installation
converges those prerequisites without activation. Revision text alone is not proof of source/resource equality.

The new pure verification contract uses `GET /v1/status` with a separate existing
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
expiry effects remain managed update effects, separate from pure monitoring.

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
failure already stopped the supervisor. It is not used by pure default
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
