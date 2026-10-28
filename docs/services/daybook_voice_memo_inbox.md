# Voice Memo Inbox components

The typed Inbox installer ports the original
`daybook_voice_memo_inbox_deploy` declaration. The component is source-reviewed
and qualified on a disposable Darwin VM. It does not change inventory engines
or qualify a default deployment; normal update and lifecycle adoption are separate.

`DaybookInboxConfig` retains the original defaults and fixed protected root
checkout, shared root Python tree, GUI account layout, two launchd labels,
policy and separate owner-only credential resource. Credentials are separate
`SecretContent` expectations sent over stdin. Inspection compares only declared
resource bodies in memory and code/package metadata; it does not publish
credential hashes or open recordings, importer ledger, activation markers or a
Journal. The original optional `voice-memos status --summary-only` command reads
an importer ledger despite its name; it is not a read-only deployment fact in
this port and has not been invoked on an inventory host.

`install_daybook_inbox(config, secrets, source_tree, bundle, ...)` is the explicit
disabled-first installer substage. It never activates or baselines an Inbox.
The existing activation, first-scan proof and credential-rotation workflows are
separate lifecycle work still requiring typed conversion; no permanent Ansible
fallback is introduced here. Normal runtime updates retain their original
stop/window → Inbox-only install → replacement → cutover → verify sequence.
Sessions and Photos source convergence do not become new update dependencies.

When the declared source, locked Python and final resources are already current,
installation queues pure verification and preserves an enabled operations keeper.
The keeper's declared live plist is the final resource projection; the installer
still writes only its original disabled-first plist. After managed installation,
`verify-installed` requires the original disabled/quiescent install set. It does
not compare that intermediate handoff against the later keeper plist or change
the existing profile's enabled bit. Ordinary already-current verification keeps
using the final keeper projection. Drift under a live keeper
requires the existing runtime update sequence before this installer can mutate
anything. This is the original running-code guard, not a new acknowledgement.

Managed installation disables both original lanes before bootout. It preserves
the original twelve-observation, five-second launchd termination window and
refuses unavailable/domain/permission errors rather than interpreting them as
absence. It then prepares the original directories and logs, stages one exact
Main bundle using the existing SSH identity in a per-run private directory,
checks descriptor metadata and bytes before root publication, verifies the
bundle before replacing a drifted checkout, and installs the original pinned
root Python with frozen dependencies and a regular protected interpreter copy.
The original service-user import and CLI-help smoke is managed application work
following Python convergence; it never runs inside a fact. Resource writes are
atomic; logs retain their contents, inode and timestamps. Transfer failures remain
failures and trigger cleanup of only the owned temporary transfer.

Desired Main is resolved once by the normal controller source workflow. No
installed-old-ref pin, new activation marker, bypass flag or engine confirmation
is added. A source transition for an active keeper needs its existing functional
window and a concrete source/lock/effect review before inventory execution.

Paired declaration/resource checks use the actual collection:

```sh
OPS_LIBRARY_PATH=../ops-library uv run --locked --with ansible-core pytest \
  tests/test_daybook_inbox_declaration.py tests/test_daybook_inbox_controls.py
```

Owned fixtures use inert code and unusable credentials. They do not read real
Voice Memos, call private app status, activate an Inbox or change TCC/auth policy.
Mechanism and source proofs are recorded separately from actual inventory
qualification.

The installer explicitly disables inherited CLI sudo/doas/dzdo/su for connecting-identity
metadata and private SFTP staging. Literal empty user overrides accompany that
same no-escalation call. This prevents pyinfra from copying an upload through shared
plaintext temporary staging; it never enables privilege or selects another user.
Root publication remains the separately guarded operation using protected stdin
and descriptor checks. Internal raw expected texts follow Sessions' established
rendering pattern; public resource objects remain `SecretContent`, and only the
secret operation unwraps them.

## Component qualification

Immutable implementation `79e0191d9342c7ff49b1fd8f3cbecc3c12379242` passed
[canonical CI](https://github.com/ephes/ops-deploy/actions/runs/40772667951)
(8,527 tests on each Python version) and the
[owned native fixture](https://github.com/ephes/ops-deploy/actions/runs/40772667957).
The actual noneditable package contained exactly the 813 expected resource files,
with every byte matching that Git revision. Fixed original declarations and
four template resources are independently paired against the collection oracle;
owned fixture paths and labels are explicitly substituted.

The native component first completed eight managed operations and one real SFTP
upload. Repeat and already-current enabled-keeper verification performed zero
managed operations/uploads and preserved scoped metadata and the keeper PID.
Resource drift under that keeper refused before operations. The stopped-but-enabled
handoff performed one resource operation and verified the disabled-first set
without changing the existing profile's enabled bit. Separate healthy/fault handoffs
inherited every SDK privilege field and proved none executed at the real transport
boundary. Copy-digest, writable-code and genuine SFTP-setup failures remained
failures; owned resources and private transfer directories were cleaned up.

Initial policy-test failures, the earlier native proof and all review rounds are
retained as provenance; they are not relabelled successful full qualification.
Review execution had sandbox limits, distinct from the passing caller/CI/native
checks. These are component/mechanism proofs with inert app code and fake auth,
not real importer activation, data processing or an inventory rollout. Temporary
UV/cache I/O and unique enabled launchd override rows are outside any claim of
whole-machine I/O or state immutability.

## Optional update interruption report

`report_daybook_inbox_interruption` preserves the original optional best-effort
pre-update summary. Metadata-only availability checks do not run the application.
When an explicit managed install/update requests the report, the original GUI
account context runs `voice-memos status --summary-only`. That command can read
the application's ledger and is counted as managed application work. Only a
validated nonnegative `long_in_flight_count` is logged as an operator summary; raw output and errors
stay in memory. Missing or failed application summaries remain optional and do not introduce
an acknowledgement or refusal. The ordinary current keeper verification path
does not run this report. Genuine SDK/transport failures retain their failed
operation result. Owned synthetic ledgers must qualify this behavior
before any actual update requests it.
