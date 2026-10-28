# software_live

`SoftwareLiveConfig` and `deploy_software_live` deploy the existing read-only software
observation program, its authenticated HTTP endpoint and collection timer. Python and
released Rust implementations use the original operational policy, state format,
units and implementation drop-ins. The Python program, shared `nyxmon_checks.py`,
filter and eight templates are copied from ops-library `cf3a0c74` without modification.
No software upgrade, package refresh or reboot job is introduced.

```python
from ops_deploy.services.software_live import SoftwareLiveConfig, deploy_software_live

config = SoftwareLiveConfig(
    secrets="secrets/software-live.yml",
    auth_user="monitor",
    bind="tailscale",
    policy={
        "host": "example",
        "os": {"expected_id": "ubuntu", "desired_cycle": "24.04", "product": "ubuntu"},
        "postgresql": {"expected": False},
        "traefik": {
            "expected": False,
            "unit": "traefik.service",
            "binary_path": "/usr/local/bin/traefik",
            "desired_version": None,
        },
    },
)
# secrets supplies endpoint_password; keep it out of inventory and command arguments.
deploy_software_live(cfg=config, secrets=secrets)
```

## Collection and verification

The accepted convergence change is deliberate: collection runs when a managed program,
unit, drop-in, policy, endpoint configuration or implementation changes, or when
`state.json` is missing or its `generated_at_epoch` is outside the 30-minute freshness
window. A current fresh deploy verifies the selected running implementation and performs
anonymous/authenticated HTTP checks without requesting another collection. When collection
is needed, it waits for an existing collector to finish, starts the real collector and
requires the state mtime to advance. A failed inspection does not guess that state is missing.

The Ansible role still requests a collection on every invocation, although it reports that
operation as unchanged. Alternating tools therefore rewrites observation state on the
Ansible turn. That is an explicit behavioral difference, not a physical no-op claim.
The existing timers retain their original schedules. Timer activity can naturally update
observations independently of deployment; qualify strict repeats in an idle observation
window and distinguish naturally changing state from deployment actions.

Defaults retain `/etc/software-live`, `/var/lib/software-live`,
`/usr/local/lib/software-live`, user/group `metrics`, port 9110, collection schedule
`*:0/15`, and Python implementation. Directory paths must name dedicated software-live
directories. Existing private orchestration forces its host policy, Tailscale bind,
credentials and optional publisher export. The endpoint health contract retains the original
private playbook's literal port 9110 even if the role endpoint port is overridden.

## Rust selection, rollback and shadow

Set `impl="rust"`, `rust_version` and `rust_sha256` keyed by `ubuntu24.04` and/or
`debian13`. The released archive contains `software-live`, `software-live-apt`, `LICENSE`
and `LICENSE.GPL-3.0`. A controller-local archive is also supported. Release installation,
validation, pinning and pruning reuse the existing Rust release helper. Production
ownership remains root; the Ansible role's unprivileged owner/group fixture knobs are
not exposed as production configuration.

Selecting Python removes both Rust production drop-ins and reloads/restarts the original
units before attempting an optional Rust shadow installation. Invalid or unreadable shadow
release input therefore fails after rollback, rather than canceling rollback during planning.
No pin moves and no release is pruned before implementation verification. Current and
previous production pins, shadow pins, loaded unit commands, process executables and
cgroup children protect live releases. An unknown live state skips pruning.

`rust_shadow=True` retains the original Rust shadow collector/timer and loopback endpoint
on port 9119 (`*:7/15`). The shadow endpoint serves production state; shadow collection
writes its own state. `compare_software_live_shadow` is a separate final stage so an
optional comparison failure cannot hold back verified production checks. Turning shadow
off removes only its units, configuration and shadow state before unpinning it.

## Check registration and removal

`SoftwareLiveNyxmonConfig` takes an explicit list of verified host IDs/URLs.
`deploy_software_live_nyxmon` reads only those named rows, then invokes the existing
installed `nyxmon_checks.py` only if their owned fields or disabled state differ.
A new check is idle. An update re-enables it and resets `next_check_time` to zero while
preserving status and processing metadata. A current row is left unchanged. These are
software-live's original semantics, distinct from the OS apt check helper.
SQLite readers can still affect WAL/SHM bookkeeping; read-only SQL is not a global zero-I/O
claim. Actual inventory evidence must stay limited to declared operational rows and database
metadata rather than reading unrelated rows or hashing a real database body.

`remove_software_live(SoftwareLiveRemoveConfig())` stops/removes the six units, production
drop-ins, configuration, programs/releases and shadow state. It retains production state
unless `remove_data=True`. Orchestration disables the corresponding Nyxmon check on its
monitoring host before stopping the endpoint. Removal uses the same dedicated path validation.
Daemon reload is conditional on actual unit/resource removal.

## Qualification status

Inventory engine selection has not changed. Tests include actual operations, owned SQLite
semantics, source hashes and independently rendered Ansible files from exact `cf3a0c74`.
The [owned native run](https://github.com/ephes/ops-deploy/actions/runs/40609646598) passed
both Ubuntu 24 Python and Debian 13 Rust 0.1.1 legs at implementation `5799bc457d66`.
Each leg exercised 33 phases, including 16 healthy repeats with zero managed operations,
zero uploads and exact protected snapshots. All 640 installed source resources matched
that Git commit, with a noneditable installation. Both legs exercised implementation
switching, authenticated shadow comparison, credential rotation, stale/missing-state
collection, owned Nyxmon create/reenable/disable and data-preserving/explicit-data removal.

The deliberate invalid-shadow fault performed five real Python rollback operations before
rejecting the optional shadow release: two drop-ins were removed, systemd reloaded and the
endpoint/timer restarted. Pins stayed unchanged. This fault is not a zero-change phase.
The original Ansible role succeeded in the same fixture and rewrote observation state as
expected; its collection behavior is distinct from the new freshness gate.

Debian uses an isolated systemd userspace guest and shares the Ubuntu runner kernel.
All fixture data and credentials were synthetic; no inventory data, credentials or sockets
were mounted. No upgrade or reboot job was run. Owned SQLite rows and main-database bytes
were strict, with sidecar bookkeeping observed separately. The [full CI matrix](https://github.com/ephes/ops-deploy/actions/runs/40609646540)
also passed at the same implementation. Inventory qualification subsequently passed with the same software runtime in
the composed immutable `5caf929` controller. Normal default first/repeat each
completed 39 operations with zero managed changes/uploads. The four-host fleet
first completed 156 operations with only a declared policy write and its
observation collector (two managed operations, one upload); the fleet repeat
completed 156 operations with zero managed changes/uploads. The policy update
matched an already installed application version; binaries, application PIDs,
packages and other protected configuration stayed unchanged. Existing warning
baselines were retained.

The policy-triggered collector was a declared managed execution. Separate
background or unattributed observation changes and real monitoring database
metadata were recorded without reading database bodies or unrelated rows. The
real database main-file mtime changed between phases, while each observer's own
before/after metadata matched and sidecars were absent. Causal attribution is
unproven; this qualification does not claim global zero I/O or a fully updated
fleet.
