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
own prerequisites before the deployment snapshots. No inventory host is contacted.

Phases cover fresh state/first job, authenticated and anonymous HTTP, exact repeated managed
files/PID/state/packages/apt policy/timer state, fish transport, full Ansible coexistence,
timer-only change, fixture credential rotation/recovery, normal refresh disable/repeat,
and missing-state initialization without a job. The loaded-but-unlinked timer fault is
separate: the actual cf3 role runs against it first, then the fixture restores the units
and injects it again for pyinfra. Raw original-role return code/logs/before-after state are
retained for explicit comparison. The role fault oracle is unadjudicated: its
return code and refresh-timer outcome are recorded without a success or zero-change
assertion, while all other protected resources remain strict. A green native job does
not by itself establish fault parity. Pyinfra must stop the timer; exactly its known combined
stop/disable operation may report the ignored missing-unit error. This is classified as a
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
