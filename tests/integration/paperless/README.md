# Owned Paperless native fixture (under preparation)

The matrix source is implemented; it has not run. Runtime and harness source
review and exact feature publication precede dispatch.
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
Build and execution have15/70-minute limits, beneath the90-minute workflow cap.
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
the latter upgrades through the prepared3.2.1 deployment. No downgrade is used
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
Those cases are not claimed qualified until actual receipts are accepted.
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
across write calls. This is not a global physical-I/O or document-freshness claim.

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
