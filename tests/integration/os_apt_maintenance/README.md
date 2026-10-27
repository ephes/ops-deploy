# Owned OS apt maintenance qualification

The GitHub workflow installs the exact Git artifact non-editably and checks every installed
resource name and byte against that commit. It uses a disposable Ubuntu 24 VM for Python
and an isolated Debian 13 systemd Docker guest for the real pinned metrics-httpd 0.1.0
binary. Debian has its own filesystem/userspace/systemd and shares the Ubuntu runner kernel;
this is not a full Debian-kernel qualification. The guest receives public source by copy,
with no inventory, host data, credentials, or Docker socket mounts. Image IDs/digests,
platform details, installed resource hashes, each phase and failure evidence are retained.

The real deploy creates accounts, files, systemd units/timers, state, credentials, HTTP
listeners and SQLite rows. Fixture timers point to 2099 with persistence off so they cannot
fire during qualification. Separate weekly/custom fixtures contain actual Ansible-rendered
bytes from library cf3a0c74; native coexistence runs that exact full role and dependencies.
The deploy's runner gets synthetic apt-get/systemctl executable paths. The first-deploy
job exercises its real command construction and durable-state path, while recording the
four apt action arguments instead of upgrading packages or rebooting. This is synthetic
job-branch evidence, not real upgrade/reboot qualification. Fixture bootstrap installs its
own prerequisites, including Ansible’s sudo and python3-apt dependencies, before
the deployment snapshots. The actual `/opt/metrics-httpd` release/pin tree is
part of strict endpoint snapshots. No inventory host is contacted.

Phases cover fresh state/first job, authenticated and anonymous HTTP, exact repeated managed
files/PID/state/packages/apt policy/timer state, fish transport, full Ansible coexistence,
timer-only change, fixture credential rotation/recovery, normal refresh disable/repeat,
and missing-state initialization without a job. The loaded-but-unlinked timer fault is
separate: the actual cf3 role runs against it first, then the fixture restores the units
and injects it again for pyinfra. Raw original-role return code/logs/before-after state are
retained for explicit comparison. The role fault oracle is unadjudicated: its
return code and refresh-timer outcome are recorded without a success or zero-change
assertion, while all other protected resources remain strict. A green native job does
not by itself establish fault parity. Pyinfra must stop the timer. Systemd 255 reports the exact known combined
stop/disable operation’s ignored missing-unit error; systemd 257 completes that
operation successfully. The fixture asserts each observed outcome explicitly. This is classified as a
partial systemd fault, never a healthy zero-change repeat: pyinfra can report zero managed
operations although the preceding stop physically happened. The fixture restores the
original configuration and then requires a healthy strict repeat. No daemon reload or
state cleanup is injected merely to make a repeat pass.
Nyxmon phases use a synthetic database: create four rows, repeat, preserve current disabled
rows, change an owned interval while preserving status/schedule/processing, keep an unrelated
row, repeat via fish, and skip an absent database. SQLite main-file content/metadata and all
rows remain strict for repeats; WAL/SHM files are observed separately because SQLite readers
may change bookkeeping. No global zero-I/O claim and no production connection keeper.

Run only via `OS apt maintenance integration`. Main publication and inventory cutover remain
coordinator-gated after the workflow evidence has been read. The harness refuses non-GitHub,
non-root, non-systemd, unsupported OS/architecture and pre-existing fixture state.

The Ubuntu run of the original-role fault oracle returned 0 with only refresh-timer
metadata changing: active/enabled became failed with an empty UnitFileState after
Ansible’s unconditional reload. The pyinfra fault stopped activity but left inactive
with cached enabled metadata and the exact ignored disable error. These are not identical
systemd outcomes; both require classification as an externally damaged-unit fault.
Restoring the original declared configuration and repeating succeeded in each case.
Release-tree immutability is only established by runs that snapshot `/opt/metrics-httpd`;
the first two runs used an incorrect absent path and do not prove that part.

The Debian 13 systemd 257 run stopped and disabled the unlinked unit successfully
(1 reported managed operation, no ignored failure, inactive/empty UnitFileState).
It is classified separately as a successful fault stop, not a healthy zero-change
repeat. This differs from the Ubuntu systemd 255 partial operation described above.
Both platforms keep every non-refresh-timer resource strict during this fault.
