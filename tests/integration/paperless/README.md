# Owned Paperless native fixture

The current and upgrade matrices completed successfully in runs40777068134 and
40788020395 respectively. Earlier partial/failed evidence remains retained below.
Runtime and harness source review and exact feature publication precede each dispatch.
It uses public `ephes/ops-deploy` GitHub Actions on a disposable Ubuntu24 x86 VM,
with a fresh Ubuntu24 systemd Docker userspace. The guest shares that VM's
kernel. This is not KVM, physical scanner or inventory qualification.

`run-owned.sh` requires actual GitHub-hosted/public-repository provenance,
immutable40hex source, no checkout authentication configuration, a pinned uv,
and at least12GiB free on both checkout and Docker filesystems, recording actual
capacity before building. [GitHub documents14GB standard runner storage](https://docs.github.com/en/actions/reference/runners/github-hosted-runners);
the earlier40GiB free-space requirement was not viable.12GiB is an admission
floor, not measured peak use: original dependency installation may still exhaust
space, which remains a failed qualification without package omissions or unrelated
runner cleanup. Its unique container/image labels include
run ID and attempt. It permits privileged systemd only on that disposable VM,
with2CPU/6GiB RAM/no additional swap/2048PIDs and one20MiB local log. There are
no host source/data/credential/socket bind mounts or published ports. Disk use
is bounded by the finite disposable runner filesystem and runtime deadline;
Docker overlay storage has no additional per-container disk quota here.
Build has a15-minute limit; current execution has70 minutes and upgrade100
minutes, beneath the130-minute workflow cap. Dispatch can select either leg or
both; a completed current matrix need not be replayed for an upgrade-only retry.
No unrelated runner resources are removed to make room.

The guest receives an explicit non-secret environment allowlist and anonymously
checks out the exact public source. It compares its bootstrap to that Git body,
installs the package noneditable at the exact Git ref, and verifies the full
actual installed resource set and every byte, direct_url, interpreter prefix,
Ubuntu version and fresh owned machine identity. Original role source is fixed
atd88c3286b2fb58a8799663d6c1f3a9d6061af37b; no inventory or secret repository is
checked out. All document/account/password data is generated synthetic input.
No inference/model request is part of the fixture.

Two fresh VM legs start with the original role at3.2.1 and3.0.4 respectively;
the latter upgrades through the typed3.2.1 deployment. No downgrade is used
as fixture setup. Each uses actual1GiB tmpfs for synthetic data. Its path-shaped
source label lets genuine Ansible14.5 mount facts report it; no facts are injected.
This is neither encryption nor a block-device proof. A new systemd machine ID
is generated at guest boot, rather than inherited from the built image.

The matrix covers original role behavior; Paperless first/repeat with
real PostgreSQL17, Redis, four units and application health; synthetic SFTP/OCR
and authenticated search; SQL/soft-delete/schema/language/count parity; index
failure/resume/retry; legacy/current release and Python/package/static recovery;
real yescrypt and recursive ACL/bind mount behavior; SSH candidate refusal and
shared Redis mismatch and declared database password repair. Missing-venv and
unexecutable-interpreter cases run in the current leg; wrong-Python and missing
support-package cases run in the upgrade leg. The invalid interpreter remains
an original trust-preflight refusal, not an invented recovery bypass. Deliberate
fault setup/restoration is explicit and retained separately from deploy effects.
The exact old OCR fragment and ownership repair also run through actual helpers
on a separate synthetic program tree; that is distinguished from installed
OCR source, which may no longer contain the old fragment.
The two completed matrices below qualify these owned cases within the stated scope.
Original Ansible rewrites and actual partial failures must remain visible.

Healthy repeats require every actual operation successful, zero managed changes
and uploads, and whole captured state equality. Raw before/after program metadata
is retained in compressed files; atime and Python bytecode caches are excluded.
The before snapshot and started marker are durable before each managed phase;
an interrupted phase never gains a fabricated after/completion receipt.
The immutable started marker names its `completion_receipt`; completion is
shown only by that valid final JSON receipt with both snapshots. The marker
alone never declares either success or interruption. Baseline capture precedes
creation of the synthetic secret playbook, which is removed even if writing fails.
DB evidence is limited to synthetic live-document count, migration aggregate and
declared administrator flags, with two bounded index metadata files. Password,
shadow and environment bodies are compared in memory only; no credential body
or durable verifier digest is written. Raw CLI output is temporarily private,
bounded to20MiB and sanitized before evidence publication, including values split
across write calls. A sanitized prefix is also flushed during each typed phase,
with a possible incomplete secret prefix withheld; termination does not fabricate
the missing tail. Per-phase progress records bounded UTC/elapsed time and fixed
operation names only, never command argv/stdin/responses. This is not a global
physical-I/O or document-freshness claim.

Runner cleanup preserves evidence before removing exactly its container and
image, then verifies their absence and records execution/cleanup exits
separately. Collection accepts only512 flat regular files, at most40MiB each and
1GiB total; it hashes every accepted body before copying. A collection failure
remains separate from run and cleanup exits. Failure never starts an automatic retry. No production deployment,
document inspection, lifecycle action or version upgrade is authorized by this
fixture.

Initial run40731203287 built both owned Ubuntu images, then stopped before
container creation because the runner also tried to inspect a local
`ubuntu:24.04` tag. BuildKit had resolved the base by digest without creating that
tag. Both legs retained the full build logs and nine partial runner artifacts:
run exit1, collection exit1 (no container), cleanup exit0 (owned image absent).
No guest or application phase ran. The runner now inspects only its actual owned
image; the resolved upstream base digest is evidence in the retained full
BuildKit log, not inferred from a possibly absent or unrelated local base tag.

Run40732257237 booted both real systemd guests and verified all793 noneditable
installed package files against exact31c8. Original Ansible then changed14 tasks
and failed installing PostgreSQL17: the new PGDG repository had been written,
but its cache refresh reported no change and the package was unavailable. Its
3600-second cache TTL can suppress refresh after preceding dependency updates;
the causal effect of a fresh index is tested separately, not assumed. Both raw
before/after snapshots show package/file/unit and private-content changes.
Run exit1, collection0 and cleanup0 are retained; no Paperless pyinfra phase ran.

Only that exact original missing-package failure admits a labelled owned-fixture
recovery: capture the fixed public PGDG source, bounded apt-list metadata and
package policy; perform one fatal-on-error apt cache refresh; preserve its result
and rerun the original role. An auth, network, repository or other failure stops.
This is explicit fixture recovery, not a successful original fresh bootstrap or
permission to repair inventory apt state. The first failure remains separate.
The cache-refresh attempt is recorded before execution; timeout and bounded
partial output retain a separate result, and output overflow retains its actual
exit and a marked20MiB prefix. Neither case permits the original-role retry.

Run40734868340 confirmed the cache issue: the same public PGDG source initially
had no downloaded lists or package candidate; the explicit refresh returned0,
added lists and exposed PostgreSQL17, which the original retry installed. Both
retries then stopped at `sshd -t` because `/run/sshd` was absent (76ok/21changed/
1failed). Ubuntu's socket activation had not started SSH in the fresh container.
All initial/retry failures, physical deltas, cache diagnostics and exits remain;
run1/collection0/cleanup0, no Paperless pyinfra phase.

The fixture now starts the actual owned `ssh.service` before the original-role
baseline, recording its prior/actual state, PID and runtime-directory metadata.
This models the running SSH prerequisite of the existing host and enables the
already planned synthetic SFTP test. It does not manually create `/run/sshd`,
change host authentication/settings, or publish ports. This prepared guest
baseline and the separate cache recovery are not pristine original bootstrap
success claims.


Run40737132706 completed the SSH prerequisite and the labelled PGDG cache
recovery in both guests. The original retry then reached123ok/49changed/1failed:
upstream3.2.1 and3.0.4 `wipe_index()` iterated the absent `data/index` directory.
Both run1/collection0/cleanup0 receipts, original failures and44 collected guest
files remain; no Paperless pyinfra phase ran. This also exposed a real gap in the
typed reindex helper, which invoked the same command without creating the leaf.

Only the exact original missing-index error admits one explicitly labelled owned
service-user `mkdir` prerequisite and a fresh original-role retry; it does not
skip reindex or become a pristine-bootstrap success claim. The typed helper now
creates only an absent configured index leaf with no-follow directory-descriptor
traversal, as the service user after stopping units. Existing directories and
parents receive no metadata repair; symlinks/non-directories/missing parents
refuse, preserving ordinary failure/resume behavior.

A distinct owned case stops the synthetic units and removes the whole index.
It then executes the exact SHA-bound old7522 helper against the actual app,
retaining its expected failure and raw before/after snapshots. No directory is
preseeded before the normal new typed deployment. Recovery must create the index
with the actual service UID, start the previously stopped configured units, and
pass a strict0managed/0upload repeat. The old-helper control is not a full old
package deployment or a zero-managed-operation claim. The native result of this
runtime repair is still outstanding; no inventory mkdir/reindex is authorized.

Run40741436081 retained both original cache/index failures and completed the
explicitly prepared original retry (122ok/12changed/0failed). Both typed first
phases then reached their final readiness operation and failed: `/api/` returned
302, but the shared HTTP helper deliberately does not follow redirects. Current
adoption recorded4 managed operations and upgrade14, with103 of104 operations
successful in each; these are partial managed effects, not healthy or zero-write
qualification. Both run1/collection0/cleanup0 receipts,70 collected guest files
and90 downloaded files are retained. Actual full823 resource sets/direct_url
match the executed source. No later repeat, OCR/SFTP or missing-index fault case
was reached.

The exact3.2.1 URL source redirects to `schema/view/`, confirmed separately with
the release's RedirectView expression under locked Django5.2.16. The failed run
did not retain the actual Location header. The next guest records that header,
the allowed same-origin destination and actual final200 before typed adoption;
no response body is collected. The new Paperless-specific readiness check
rejects external/unexpected redirects and unsuccessful final responses.

The same attempt exposed a uv dependency mismatch: the original role installed
0.13.5, while the shared typed default requested0.13.4. Paperless now supplies
the original0.13.5 dependency defaults and caller settings without changing any
other service's shared defaults. Native snapshots explicitly include both uv
binary identities/content and actual version; first adoption/upgrade must retain
them exactly. Package-operation classifications remain honest: the first run
reported package operations even though full package-version snapshots matched.


The sixth attempt reached both successful first deployments and 102-operation
repeats with zero managed changes/uploads, then failed strict snapshot equality:
only mtime/ctime of data, media, consume and the consume bind alias changed.
The original failure remains evidence, not a physical no-op result. Exact upstream
Paperless path checks create/delete write-test files. A local causal experiment
with the observed Django5.2.18 reproduced those writes; this alone does not prove
native command attribution. Only the migration status probe now adds
`--skip-checks`; managed migrations retain full system checks.

The next owned run executes the old status command and fixed status command
separately after adoption. It retains both complete selected root metadata
snapshots, requires the old command's exact mtime/ctime delta and the fixed
command's exact equality, then runs the unchanged strict healthy/fish repeats
and full fault matrix. The old control intentionally writes synthetic roots;
no timestamp exemption, production probe or claim of global zero I/O is added.

Run40758213091’s current and upgrade legs passed the real old/fixed migration-status controls
and ordinary/fish healthy repeats with exact complete snapshots and zero managed
changes/uploads. Both then failed the zero-change expectation after an original
Ansible repeat: typed static collection ran once, changing only the static tree.
The typed implementation incorrectly required0755 on every frontend file.
Ansible2.21.5 recursive `remote_src` copy applies the declared mode to the root,
preserves equal children and uses source modes for changed/missing files; its
actual frontend files were0644/0664. The isolated original-module regression
confirms that distinction. The typed overlay now preserves matching children,
copies changed/missing file modes and missing subtree metadata, and inspects
content without imposing a recursive mode the original did not manage.
The next matrix retains exact source/destination public-program hashes and modes
around both writers. Earlier raw snapshots establish the mode mismatch, but
cannot retroactively prove equality of every program body. Both runners recorded
run exit1, collection exit0 and cleanup exit0. All824 installed resources and
58 collected guest files per leg were independently verified. Strict complete
snapshot equality on healthy repeats remains required; no mode exemption is
introduced in those comparisons. Full application/recovery qualification is
still pending, and every original failure remains retained.

The eighth current-version leg passed all102 operations in adoption and each
ordinary/fish/after-original repeat. All three repeats had zero managed changes,
zero uploads and equal complete snapshots. All three static observations found
2817 public program files (2631 frontend), matching source/destination bodies,
no path errors and no pending collection. It then failed the first synthetic SFTP
upload before recording its detailed output. That lost output cannot be recovered
or replaced by inference; current runner1/collection0/cleanup0 remains retained.
The upgrade leg reached the same SFTP failure after its12-managed-operation
upgrade and three strict0managed/0upload repeats. Both runner1/collection0/cleanup0
receipts and all61 collected guest files per leg are retained; all825 installed
resources/direct_url match the executed source.

The actual current snapshots show that the original failed run created the
scanner SSH drop-in but never reached its deferred SSH handler. The prepared
SSH PID and start time remained unchanged through the original retry and typed
repeats. A separate owned ARM64 Ubuntu OpenSSH experiment reproduced the mechanism:
password authentication succeeds but SFTP closes with the old loaded config;
reloading the unchanged on-disk config activates internal-sftp and succeeds.
This is mechanism evidence, not retrospective proof of the discarded AMD64 error.

The next fixture always retains complete sanitized SFTP stdout/stderr/status,
including timeout output, before asserting. Its pre-adoption `pwd` probe writes
no synthetic document. Only the exact closed-connection result plus retained
original missing-index failure, newly created drop-in, unchanged prepared PID,
unchanged current file metadata/body and no handler execution permits explicit
completion of the original `restart ssh` handler. The fixture loads that exact
library task (`state: restarted`, `enabled: true`), records its outcome and new
PID/enablement, requires all other selected state and private content unchanged,
and requires the same-config SFTP probe to succeed. Other auth/network/chroot
errors stop. This is a labelled owned bootstrap recovery, not an original pristine
bootstrap or a forced restart added to the typed runtime. The guest still has
no host ports/data mounts; SFTP uses only its internal loopback connection.


Run40771823685's current and upgrade legs exercised that exact pending-handler recovery:
SFTP closed with exit255 before the original restart+enable task, then passed
with the same configuration and a new SSH PID; only the selected SSH unit changed.
Actual synthetic SFTP upload, OCR and authenticated search subsequently passed.
The ordinary, fish and after-original repeats each ran102 successful operations
with zero managed changes/uploads and exact entire snapshots.

The next fault control failed an overly strict assertion before reaching typed
missing-index recovery: the old7522 managed reindex helper failed as expected
with the entire index still absent, but its original Django system checks changed
mtime/ctime on the four writable roots. All other selected state and private
content matched. Both full raw failures and runner1/collection0/cleanup0 are retained.
This execution helper is intentionally managed, unlike the corrected read-only
migration-status probe. Its fault oracle now records those eight observed timestamp
writes, requires every other field exact, and rejects extra changes or unchanged/
backwards expected timestamps. It does not add skip-checks to managed reindex,
change application code, or exempt metadata from any healthy-repeat assertion.
Run40777068134 completed the current matrix:50 phases,26 healthy strict repeats
with102 successful operations each, zero managed changes/uploads and entire
captured public/private equality. Real missing-entire-index recovery, ordinary
retry after an injected failure with prior service-state resumption, Python/
release recovery, SFTP/OCR/search and the remaining current cases passed. The
two declared synthetic scanner-password rotation/restoration phases intentionally
changed private content; they are not no-op phases. All329 collected file hashes
and the actual825 noneditable package resources matched9ac; run/collection/
cleanup exits were0. The guest shares the owned VM kernel; no physical-device or
inventory qualification follows.

The same run's upgrade leg reached38 completed typed phases, including the real
3.0.4→3.2.1 upgrade with12 managed operations and20 strict zero-change repeats,
then exhausted the outer70-minute deadline during `incomplete-release-recovery`.
Its before snapshot is retained, but no after/completion receipt or final summary
exists; interrupted effects and the underlying in-flight operation are unknown.
All260 collected hashes and825 package resources match9ac; run124/collection0/
cleanup0 remain a failed, incomplete matrix. This motivates the finite100-minute
upgrade allowance and durable sanitized progress, not a claim of a runtime bug
or a successful interrupted phase. No completed assertion is weakened.


Upgrade-only run40788020395 at02d completed all50 typed phases (48 healthy,
2 expected faults). Its actual3.0.4-to-3.2.1 first apply performed12 managed
operations and zero uploads. All26 healthy zero-managed repeats had102 successful
operations, zero uploads and entire public/private captured-state equality. The
separate old missing-index helper still failed as expected with only its declared
system-check root timestamp changes. Synthetic scanner password change/restore
intentionally changed private state; neither is a no-op claim. Incomplete release,
legacy current-directory, wrong Python, missing supporting package and all index/
scanner recovery cases reached their strict successful repeat.

Actual SFTP upload/OCR/authenticated search passed on generated data, as did the
observed302 `schema/view/` to same-origin `/api/schema/view/` final200 path and
installed virtual package provider. The original lost SSH handler was completed
only by its source-bound labelled fixture recovery. All374 collected file sizes/
hashes and all849 actual installed noneditable package resources matched02d;
run/collection/cleanup were0/0/0. The1064-line full job log had no error markers.
This completes the owned current+upgrade matrix together with the already passed
current run, without replaying it. It preserves the earlier upgrade timeout124
and unknown interrupted operation as a failed historical attempt. Production
adoption, physical hardware and separate lifecycle actions remain unqualified.
