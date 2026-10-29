# Daybook Photos offload

`DaybookPhotosOffloadConfig` and `install_daybook_photos_offload` preserve the
original `daybook_photos_offload_deploy` declaration and its two templates. This
component has disposable macOS mechanism proof; no inventory target, default
engine, Photos activation or lifecycle is qualified by that owned evidence.

The original checkout is root-owned under
`/Library/Application Support/Daybook/photos-offload/daybook`. Existing installs
must retain the protected `managed-v1` attestation. The local `source.bundle`,
checkout and `.git` remain root-owned and ACL-free. Git configuration, index
flags, tracked and ignored content, link counts and ancestry are checked before
source mutation. Normal Main updates use the original local-bundle clone/fetch
and detached checkout, preserving `.git` and the checkout-local `.venv`. Git commands disable implicit
background pack maintenance for that invocation, so the following protected-tree
check observes a completed mutation. Root Git mutations retain the original
absence of a whole-command deadline; pure metadata probes keep their bounds.

The `.venv` belongs to the declared GUI user with mode 0700. Root prepares or
recreates only this state-free directory when its interpreter is wrong or
cannot start. Privileged tree checks exclude its descendants. Interpreter and
UV dependency observations run as the GUI user without a login profile;
managed UV sync retains the original `-H -i` transition and
`--frozen --no-config --no-dev --no-install-project --python 3.14.7`. Only UV's
dry `--check` predicate uses offline/no-download/no-cache settings. Missing
managed Python may be installed by the original managed sync; no root execution
of the user-writable environment or incidental version upgrade is introduced.

Source uploads use the existing connecting identity and a unique mode 0700
per-run temporary directory. Explicit preparation and checked root publication
are managed operations. Upload/chmod/cleanup disable all inherited SDK
escalation fields; normal root installation and original GUI-user operations
remain separate. Publication checks the uploaded descriptor, byte count, hash,
mode, owner and single-link type before replacing the protected local bundle.
Failure cleanup removes only the exact per-run bundle and directory.

Only the configured Photos GUI label is quiesced. No unrelated operations
keeper, Sessions checkout or Inbox runtime guard is consulted. Root source and
Python stages require disabled/unloaded Photos state; GUI-user directory/log
and launcher/plist stages require the same. Existing log bodies, inode and
timestamps are preserved. Configuration writes occur as the original GUI user,
with ACL clearing, canonical paths and plist validation. The configured Photos
library is checked only as a canonical directory: no library entry, media,
ledger or log body is read, and no application is run by installation/status.

Defaults select disabled launchd state. The optional original enabled declaration
may load the agent after convergence; activation failures attempt both exact
label disable and bootout and require a genuine disabled/unloaded rescue.
The calendar remains 08:10 and 20:10, Aqua-only, RunAtLoad false. A current install
queues only pure component verification. No TCC, authentication or policy
change is implied. The launcher itself performs original managed summary-only
Photos reconciliation when scheduled or explicitly operated; that application
work is not claimed read-only merely because its output is a summary.

The normal controller Main/fast-forward resolver remains the sole revision
authority. Use `photos_main_bundle(source_bundle, revision, private_run_root)`
to derive a local `refs/heads/main` bundle from its single bound
`refs/remotes/origin/main`, then pass that exact path in
`daybook_photos_offload_repo_bundle_src` and to the installer. Retain this context
through actual pyinfra operation execution. No owner checkout or shared mirror
is modified; no installed-ref pin or user ref override bypasses normal Main.

Focused tests include actual owned Git clone/fetch/update/attestation refusals,
private transfer IO/fault cleanup, GUI resource files and environment replacement
with controlled probes, exact original template/default oracles, launchd state
machine faults and the real controller entrypoint. Root/ACL/UV identity is
simulated in some local tests and is separate from native proof.

The disposable macOS run on immutable `f42d8ce78a839c647e4ea22d7ee96173a340bac8`
verified the complete 925-resource noneditable installed set and direct Git
provenance. Actual root-to-GUI environment/resource work and SSH/SFTP completed:
first 7 managed operations/1 upload, strict repeat 0/0, environment-only rebuild
1/0, existing Main update 5/1 preserving Git/environment identities and logs,
and final repeat 0/0. Missing attestation refused before operations; an injected
upload-setup failure and a genuine digest-publication failure retained their
partial effects and exact temporary cleanup. All seven inherited SDK privilege
fields were disabled/cleared in actual handoffs. The unrelated GUI keeper PID
and plist stayed unchanged; owned cleanup completed. This proves disabled
installation mechanisms, while optional enabled activation retains separate
paired/state-machine coverage. The fixture used an empty owned library and an
inert import sentinel; entry reads and process-wide app calls were not counted,
and no whole-host zero-I/O claim is made.
