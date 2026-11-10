# software_estate_publisher

`SoftwareEstatePublisherConfig` and `deploy_software_estate_publisher` install the
local software inventory publisher of ops-library's `software_estate_publisher`
(macOS user LaunchAgent) and `software_estate_publisher_linux` (systemd timer)
roles: the five programs of the `software_estate` role, a configuration with the
controller's host policy, the writer credential, a manual entry point and the
schedule. The publisher collects only its own host and sends to the inventory
endpoint over HTTPS; nothing connects to it.

```python
from ops_deploy.services.software_estate_publisher import (
    SoftwareEstatePublisherConfig,
    deploy_software_estate_publisher,
)

config = SoftwareEstatePublisherConfig(
    platform="linux",
    hostnames=("example",),
    endpoint="https://receiver.example.org/v1/inventory",
    policy={"host": "example", "applications": [], "application_roots": []},
    minute=23,
    python="/usr/bin/python3",
)
deploy_software_estate_publisher(cfg=config, secrets=secrets)  # secrets["writer"]
```

## Release and files

The programs are vendored unchanged from `roles/software_estate/files/` (stored
as `files/<name>.py.txt`, installed as `<name>.py`), the
templates from both roles' `templates/` (`tests/test_ops_library_drift.py`). The
release directory is the roles' content address: the sha256 of the five program
texts, each with trailing whitespace stripped, joined in the order `publish.py`,
`collect.py`, `emit.py`, `outbox.py`, `send.py` (Ansible's `lookup('file')`).
An unchanged program set keeps the directory; older release directories are
never removed. `config.json` is `to_nice_json` (indent 4, sorted keys) plus a
newline.

## Linux (`platform="linux"`)

A root connection, in the role's order: the role's path checks (no symlinks,
root-owned, not group or world writable; the private paths owned by the
publisher account with mode 0600/0700), group and system user
`software-estate-publisher` (home `/nonexistent`, shell `/usr/sbin/nologin`, no
supplementary groups), `/etc/software-estate-publisher` and
`/var/lib/software-estate-publisher{,/outbox}` (0700), the release under
`/usr/local/lib/software-estate-publisher/<sha256>` (root, 0755/0644), the
writer (installed on every run, `secret_file`), `config.json`, a validation with
`publish.py --check` as the publisher account (exit 75, the busy lock, is retried
every 5 s up to 60 times; read-only), `/usr/local/bin/software-estate-publisher`,
the service and timer units. A unit change reloads systemd, restarts the timer
and starts one run (`--no-block`).

`state="absent"` reads each unit's `LoadState` and `ActiveState` from
`systemctl show`, independent of its file: systemd keeps a unit loaded, and a
timer scheduled, after the file is deleted. It stops the timer and service
while they are active, disables those whose unit file exists, removes the
timer's `timers.target.wants` link directly when its file is already gone,
deletes the two unit files and reloads systemd when a file or link was removed
or a unit is loaded without its file. A read-only check then fails the
deploy if either unit is still loaded or active (`failed` counts as stopped).
The account, programs, configuration, writer, state and outbox stay.

## macOS (`platform="darwin"`)

`files/darwin_host.py` runs on the host with the request on stdin (the writer
only in the apply request). The connection is the owner (as on Atlas) or root
(as on Studio): then the file part runs in a child process as the owner, and
launchctl runs as root against the owner's `gui/<uid>` domain. A status fact
decides whether the apply runs; the verification afterwards is read-only.

The apply follows the role: path checks (below the owner's home, no symlink,
owned by the owner, private, single link), private directories, programs
(0600), a missing writer only when one is supplied (an existing one is never
replaced), `config.json`, the `publish.py --check` validation, `run` (0700),
`~/Library/LaunchAgents` (0755) and the plist (0600, `plutil -lint`). A changed
program set, configuration or plist, or an unloaded job, disables, boots out,
enables and bootstraps the job; `launchctl enable` runs on every apply.

The credential must be usable whether or not this deploy supplies a writer
(Studio supplies none; its credential is
`~/.config/software-estate/graphyard-studio.writer`). Status and verification
check it as `publish.py --check` reads it: a regular file of the owner, no
group or world bits, a single link, at most 4096 bytes, readable by the owner
(it is opened and read, so a mode-000 file is not usable), in a directory of
the owner without group or world bits. An existing credential or parent with
group or world bits, another owner, a symlink or a hard link fails the role's
path check, so status, apply and verification refuse it. A missing, unreadable
or oversized credential, or a missing parent, makes the status `pending`, so the apply
runs; unless it provisions a missing credential from a supplied writer, the
apply then refuses before the job is touched, and the verification fails and
names the credential.

`state="absent"` disables and boots out the job and deletes the plist only.
Programs, configuration, `run`, state, outbox and credentials stay.

## Nyxmon checks of the receiver

`ops_deploy.services.software_live.deploy_nyxmon_checks` upserts checks a
caller supplies (the role's `tasks_from: nyxmon` format) with the helper
`software_live` deploys (`/usr/local/lib/software-live/nyxmon_checks.py`), after
the same digest probe the software-live checks use, so a current database gets
no write and the credentials in the checks travel only on stdin.
