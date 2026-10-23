# Traefik

`ops_deploy.infra` also ports the base Traefik roles of ops-library:
`traefik_deploy` (full deploy and the health probes), `traefik_backup`,
`traefik_restore` and `traefik_remove`. Like the other infra deploys each is a frozen, strict config
plus a `@deploy` function outside the size-capped helpers/ops/core layer. None
of them takes a secret. Per-service routes stay with
[`traefik_route`](concepts/helpers.md).

```python
from ops_deploy.infra import (
    FileCertificate,
    TraefikDeployConfig,
    TraefikRemoveConfig,
    deploy_traefik,
    deploy_traefik_backup,
    deploy_traefik_remove,
    deploy_traefik_restore,
)

deploy_traefik(
    TraefikDeployConfig(
        version="3.7.14",
        checksum="sha256:d08641f5...",
        letsencrypt_email="ops@example.org",
        file_certificates=(
            FileCertificate(
                cert_file="/etc/letsencrypt/live/x/fullchain.pem", key_file="/etc/letsencrypt/live/x/privkey.pem"
            ),
        ),
    )
)
deploy_traefik_remove(TraefikRemoveConfig(confirm=True))
```

## Transaction-managed hosts are refused

Hosts enrolled in the guarded Traefik transaction workflow
(`roles/traefik_deploy/TRANSACTIONS.md` in ops-library) take binary and
static-config changes only through that workflow. The role's `guard.yml`
refuses full deploy, restore and removal there, and so do these deploys:
with `transaction_required` set, or when `/var/lib/traefik-transactions`
exists on the host, `deploy_traefik`, `deploy_traefik_restore` and
`deploy_traefik_remove` stop while planning, before any change. Backup only
reads and is allowed everywhere. The role's transaction engine is ported (next
section) with a transport that runs it detached on the host, but no deploy runs
it yet, and its prepare entries are not ported. Its health-probe entries are
ported (see [Health probes](#health-probes)) and are allowed on these hosts.

## Transaction engine

`ops_deploy.infra.traefik_tx.engine` is the host side of that workflow: a port
of ops-library's `roles/traefik_deploy/files/traefik_transaction.py` at
`3110a0f1` for the actions `inspect`, `binary` and `resume`, plus a
`rebaseline` action of its own. It is one program,
standard library only (under 1,500 lines), that runs as root under
`/usr/bin/python3` 3.11 or newer:

```sh
python3 engine.py --request request.json
```

[Detached transactions](#detached-transactions) below upload it and run it on
the host, out of reach of the session that started it. Nothing calls that
transport yet: binary updates still go through ops-library's Ansible
transaction entry, which runs the reference engine.

| Action | What it does |
|---|---|
| `inspect` | read-only: the live identity and the host record |
| `binary` | replaces only the executable with a checksum-pinned release, restarts and verifies; any failure puts the original back |
| `resume` | reviewed reconciliation: a new `clear` record for the live identity once the baseline probe passes |
| `rebaseline` | route-only reconciliation without a review: a new `clear` record when only the dynamic tree changed and the baseline probe passes (below); ops-deploy only |
| `enroll`, `alias`, `metrics_bind`, `acme_storage` | refused before anything is read or written; they stay with the Ansible entry |

**Same state, same records.** State directory `/var/lib/traefik-transactions`
(`state.json`, one directory per transaction and, after a `rebaseline`,
`route-inventory.json`), lock
`/run/lock/traefik-transaction.lock` (exclusive, non-blocking `flock`), record
schema 1 with the phases `clear`, `pending`, `recovery` and `degraded`. Records
written by either engine load unchanged in the other, a controller journal
pairs with either, and the two engines exclude each other on the lock. The
full-deploy guard above checks the same directory. The request format is the
one in ops-library's `TRANSACTIONS.md` (`action`, `policy`, `controller_state`,
`evidence`, `baseline_probe`, `acceptance_probe`, `cleanup_probe`,
`compatibility`, `release`, `archive_path`, `recovery_review_reference`);
`release.arch` is not read, the caller fetches the archive.

**Output.** One JSON object on stdout. Exit 0: `inspect` prints `identity` and
`state`; `binary`, `resume` and `rebaseline` print `changed` and the new
record as `state`.
Exit 1: the binary transaction failed after its `pending` record was written;
the original binary was put back and verified (`recovery`), or that did not
verify (`degraded`). Exit 2: refused (always before the binary is touched) or
an unexpected error, as `error`.

`binary` checks and acts in the reference engine's order:

1. policy: a canonical host name, `/usr/bin/traefik` or
   `/usr/local/bin/traefik`, `/etc/traefik/traefik.toml`,
   `/etc/traefik/dynamic`;
2. root, a root-owned `0700` state directory, the lock;
3. the host record; the live identity (machine ID, binary hash and version, the
   running executable is the installed one, exactly `--configFile=<config>` as
   startup arguments, no `TRAEFIK_` environment, the static config with only
   the directory file provider and its hash, the hash of the dynamic tree, the
   hash of the unit text); evidence at most an hour old and tied to that
   identity; the controller's copy of the record equal to the host's, and the
   record `clear` at that identity;
4. the baseline probe; the compatibility proof (same baseline, native
   architecture, passed, baseline pair passed, a report reference);
5. a transaction directory with the request; no downgrade; the release
   archive's exact SHA256, one bounded regular `traefik` member and the version
   it reports; the candidate's hash and the unchanged static config hash must be
   the ones the compatibility proof tested;
6. the installed release again is a no-op: acceptance and cleanup probes, no
   restart;
7. `prechange.tar.gz` of the configured backup set, which must cover the
   binary, `/etc/traefik`, the unit, `/etc/letsencrypt` and unit drop-ins when
   present, and the approved ACME stores; a copy of the original binary; the
   identity once more; the `pending` record;
8. atomic replacement, restart, the new identity within 15 tries a second
   apart, acceptance probe, cleanup probe (always), the identity again:
   `clear`;
9. on any failure, an interrupt included: cleanup probe, the original put back,
   restart, baseline and cleanup probes: `recovery` with `review_due`; if any of
   that fails: `degraded`. Both wait for a reviewed `resume`.

### Route-only rebaseline

Every service deploy rewrites files in `/etc/traefik/dynamic`, so the dynamic
tree hash in the live identity soon differs from the host record, and `binary`
refuses with `active recovery or unreviewed baseline drift` until a reviewed
`resume`. `rebaseline` reconciles exactly that drift and nothing else (owner
decision for unattended patch updates). After the common checks (policy, root,
state directory, lock, host record, live identity, evidence at most an hour old
and tied to the live identity, controller copy equal to the host record,
enrollment) it requires, in this order:

1. the record is `clear`; `pending`, `recovery` and `degraded` are refused
   (`rebaseline requires a clear record; anything else needs a reviewed
   resume`);
2. every identity field but `dynamic_sha256` equals the record's: machine ID,
   binary path, hash and version, static config path and hash, unit hash; any
   other difference is refused and named (`rebaseline reconciles route drift
   only; also differs: binary_sha256, version`);
3. `dynamic_sha256` does differ (`no route drift to rebaseline` otherwise);
4. the request's `baseline_probe` passes; capturing a fresh probe set for the
   current routes is the caller's job;
5. the route tree and the whole identity are unchanged after the probe.

Then it writes `route-inventory.json` (relative path and SHA256 of every route
file, `0600`) and the new `clear` record for the live identity, with
`rebaselined_from` (the previous revision), `owner`, and `rebaseline`: the
previous and new `dynamic_sha256`, the evidence's `review_reference`, and
`changed_files` (`added`, `modified`, `removed`: file names only, never
contents). The file names come from the first basis that reproduces the
previous record's `dynamic_sha256` exactly: the inventory of the last
rebaseline (`changed_files_basis: route_inventory`), else the route files in
the `prechange.tar.gz` of the transaction the previous record names
(`prechange_archive`); with neither, `changed_files` is `null` and the basis
`unavailable`. Refusals write nothing and leave Traefik alone; a rebaseline
never restarts Traefik or touches the binary. Exit codes as above (0 or 2).

The reference engine refuses `rebaseline` as `unknown action`, and the Ansible
controller (`traefik_control.py`) does not offer it; the reference engine loads
the rebaselined record unchanged and runs `binary` on it.
`tests/test_traefik_tx_rebaseline.py` covers each refusal, the bases and the
hand-over to both engines.

Differences from the reference engine, on purpose: only the three actions (and
`rebaseline`); a
host record that is valid JSON but not an object is refused as `invalid
recovery state` (the reference engine stops with an uncaught `AttributeError`);
`main` takes its arguments for tests.

Not part of the port yet: the compatibility proof (the release resolver is a
module of its own, see
[Patch-line release resolver](#patch-line-release-resolver)). The pre-change
archive stays where the reference engine writes it, in the transaction directory
on the system disk, and is never pruned; its place and retention change before
the engine runs unattended.

`tests/test_traefik_tx_parity.py` runs this engine and the reference one
(vendored byte for byte under `tests/parity/traefik_deploy/`;
`tests/test_traefik_tx_engine.py` checks it against `OPS_LIBRARY_PATH`)
through the same requests on the same fake host. Results, refusals and the
files left behind (records, transaction directory, binary) must be identical
byte for byte, and so must identity, policy, evidence, archive, backup-set,
probe and command-line behaviour, compared function by function.

## Detached transactions

`ops_deploy.infra.traefik_tx.transport` (controller side) and
`ops_deploy.infra.traefik_tx.runner` (host side, a standard-library program like
the engine) run the engine's `binary`, `resume` and `rebaseline` actions in a
transient systemd unit on the host. The Ansible entry runs the engine inside the SSH
session, so a dropped connection or a killed controller between the binary
replacement and its acceptance leaves a new binary, a `pending` record and no
rollback. Here nothing outside the host takes part once the unit runs: the
controller polls the result over new connections, and when the unit fails, an
`OnFailure=` unit puts the original binary back. Nothing calls the transport
yet; the controller journal stays with its caller (ops-control).

```python
from ops_deploy.backups.remote import SshTarget, ssh_runner
from ops_deploy.infra.traefik_tx import transport

runner = ssh_runner(SshTarget(hostname="canary.example", user="root"))
tx = transport.new_transaction_id()
transport.stage_transaction(runner, request, tx)  # before the controller's pending record
# ... the controller writes its pending record ...
transport.start_transaction(runner, tx, runtime_max_sec=900)
status = transport.wait_for_transaction(runner, tx, timeout=1560)
record = status.host_record  # None: the outcome is unknown, keep the pending record
transport.cleanup_transaction(runner, tx)
```

Each step is one bash script over a new connection (a
`ops_deploy.backups.remote.Runner`, as the backups use). It carries the host
program and, for staging, the engine and the request, base64-encoded into a
private `mktemp -d` directory that it removes again; the request (evidence,
probe commands) never appears on a command line. Failures are `TransportError`
with a fixed reason and no host name.

| Call | On the host |
|---|---|
| `stage_transaction(runner, request, id)` | `/var/lib/traefik-transport/<id>/` (root, `0700`) with `engine.py`, `runner.py`, `request.json` (`binary`, `resume` or `rebaseline`); for `binary` the host downloads the release archive from GitHub (`release.version` for `release.arch`, which must be the host's) and refuses it unless it has exactly `release.sha256`, and `archive_path` is set to it; the safe-restore unit template (below), with `systemctl daemon-reload` when it was missing or differed; last `staged.json` with the files' SHA256, which must be the ones sent. A refusal leaves no directory, and nothing ran: it needs no `pending` record |
| `start_transaction(runner, id, runtime_max_sec=900)` | the staged files unchanged and never started, then `systemd-run --unit=traefik-tx-<id>.service --collect` with `Type=exec`, `RuntimeMaxSec=<n>` (60 to 3600), `TimeoutStopSec=30`, `KillMode=control-group` and `OnFailure=traefik-tx-safe-restore@<id>.service`; returns once the unit runs. A failure here does not prove that nothing started: poll |
| the unit | `started.json` (written durably before the engine starts), the engine on `request.json`, then `result.json` (`engine_exit`, `response` = the engine's JSON, `host_phase`, `restore_expected`); the archive is deleted afterwards. The unit fails, and so starts the safe-restore unit, when the engine gave no usable result or left the host record `pending`; a timeout, a kill and a stop (its `SIGTERM` exits 143, not as a clean stop) fail it too |
| `poll_transaction(runner, id)` | read-only status; `wait_for_transaction(runner, id, timeout=..., interval=5)` polls until the status is final or `timeout` has passed, and takes a failed poll as "ask again" |
| `cleanup_transaction(runner, id)` | removes the transport directory; refused while `running` or `restoring` |
| `inspect_host(runner, policy)` | the engine's read-only `inspect` (identity and host record), in the foreground; it writes nothing but the private directory |

Statuses: `absent` (no transport directory), `incomplete` (staging did not
finish), `staged` (never started: the engine did not run), `running`,
`restoring` (the safe-restore unit runs or is due), `finished` (the engine's
result is final), `interrupted` (the engine gave no result); `unknown` from
`wait_for_transaction` when no poll answered. `absent`, `finished` and
`interrupted` are final. `started` tells whether the engine was started.
`host_record` is the record the host returned: the safe-restore unit's when it
acted, else the engine's `state` once finished. `None` (a refusal, an
interrupted run that was not restored) means the outcome names no record, and
the controller keeps its `pending` one, as ops-library's controller does.

**Safe-restore.** `traefik-tx-safe-restore@.service` is a runtime template in
`/run/systemd/system` (`Type=oneshot`, `TimeoutStartSec=600`) that runs the
transaction's `runner.py safe-restore <id>`. It acts only when, under the
engine lock:

- the host record is `pending` for a `binary` operation;
- its transaction directory is below `/var/lib/traefik-transactions` and holds
  exactly this transport's request (with this transport's archive path), and
  the record's `previous_revision` is the request's controller record: a
  transaction of the Ansible entry or of another transport is never touched;
- that directory has the `original` binary;
- the installed or the running binary differs from it (no running Traefik
  counts as different).

Then it does what the engine's rollback does: cleanup probe, `original` put
back (if the installed binary differs), restart, the pre-transaction identity
within 15 tries, baseline and cleanup probes. That gives `recovery` (`reason:
EngineInterrupted`, `safe_restore: <id>`, `review_due` an hour later), or
`degraded` with `recovery_error` when any of it failed, a stop or the unit's
timeout included; never `clear`.
Otherwise it writes nothing: a record left `pending` with the original binary in
place (an engine killed before the replacement) waits for a reviewed `resume`,
as before. `safe-restore.json` says what it did (`acted`, `reason`, `phase`,
`state`). Both engines load its records, refuse a binary update on them and
resume from them.

**Time budget.** The engine allows each probe 120 s and each restart 60 s;
`runtime_max_sec` bounds the whole run, after which systemd stops the unit and
the safe-restore unit (up to 600 s) takes over. Wait at least
`runtime_max_sec` plus 600 s and a poll interval before taking a missing result
as unknown.

Only root can read the transport directory: the request holds the evidence and
the probe commands. The staged archive is deleted once the engine ran;
`cleanup_transaction` removes the rest. The engine's transaction directory and
its pre-change archive are unchanged (see above).

`tests/test_traefik_tx_runner.py` runs the host program with the real engine
on the engine tests' fake host (systemd, the download and root faked),
including engines killed before the replacement, before the restart, during
acceptance and inside their own rollback; `tests/test_traefik_tx_transport.py`
covers the controller side with a fake runner and the real scripts in a local
bash.

## Nothing unchecked goes live

Traefik fronts every service on a host; a static config it cannot read takes
all routes down at the next restart. So:

- the rendered static config is parsed as TOML on the controller, and must
  have `[entryPoints]`, `[providers]` and `[certificatesResolvers]`, before
  any operation is added; a config that fails stops the deploy with nothing
  written and nothing restarted (`tests/test_infra_traefik.py`);
- the config itself refuses entrypoints sharing a port and an unbracketed
  IPv6 metrics address, which Traefik cannot listen on;
- the file-provider certificate list is parsed as YAML the same way, and every
  certificate and key file must exist on the host. Traefik watches the dynamic
  directory and loads the list as soon as it is written;
- a newly installed binary must report the wanted version before the restart;
  if it does not, the deploy fails before restarting;
- Traefik restarts only when the static config, certificate list, unit or
  binary changed, and only if it was running (a stopped Traefik is started
  with the new files). The run ends with read-only checks: port `http_port`
  open, unit active.

## Coexistence with the roles

`traefik.toml`, `traefik.service`, `dynamic/certificates.yml` and
`/etc/logrotate.d/traefik` are byte-identical to the role's
(`tests/test_infra_traefik.py` renders the vendored templates, the log
rotation one included).

The log rotation has two blocks, as in the role (2.39.2): `traefik.log` is
rotated with `copytruncate` (Traefik never reopens its own log; lines written
between the copy and the truncate are lost), `access.log` is renamed and
Traefik is sent `SIGUSR1` in `postrotate` (only if `traefik.service` is
active) so it reopens the file. The unit has no `ExecReload`, so the former
`systemctl reload traefik || true` never worked: Traefik kept writing to the
renamed `access.log.1` and the fresh `access.log` stayed empty. The binary is only replaced when its version differs, as in the role,
and UFW rules are the ones `community.general.ufw` adds. A host set up by one
tool shows no change and no restart when the other runs; ops-control's
`just smoke-traefik-coexistence` checks this both ways, and that each tool
restores the other's ACME backup payload and finishes the other's removal.
That historical smoke does not establish dynamic-route recovery.

## deploy_traefik

`deploy_traefik(cfg)`

| Field | Default | |
|---|---|---|
| `version` | `"3.7.13"` | the role's default |
| `checksum` | required | `sha256:<hex>` of the release archive; the role allows none |
| `arch` | `None` | `None`: from `uname -m` (`x86_64`, `aarch64`, `armv7l`, `armv6l`) |
| `letsencrypt_email` | required | the role refuses its `CHANGEME@` placeholder; here a plain address is required |
| `config_dir`, `log_dir`, `binary_path` | `/etc/traefik`, `/var/log/traefik`, `/usr/local/bin/traefik` | |
| `dynamic_dir`, `acme_dir`, `static_config`, `acme_storage` | `None` | `None`: below `config_dir` as in the role |
| `file_certificates` | `()` | `FileCertificate(cert_file, key_file)`; `certificates.yml` is written only when set |
| `log_level`, `log_format` | `INFO`, `json` | |
| `dashboard_enabled`, `dashboard_port`, `dashboard_firewall_open` | `True`, `8090`, `False` | |
| `http_port`, `https_port`, `http_redirect_to_https` | `80`, `443`, `True` | |
| `metrics_enabled`, `metrics_bind_address`, `metrics_port` | `True`, `127.0.0.1`, `8080` | the bind is used only without the dashboard |
| `force_update` | `False` | reinstall the binary even at the wanted version |
| `configure_firewall` | `True` | UFW rules on Debian-family hosts with `ufw` |
| `logrotate_days` | `7` | |
| `mask_conflicting_web_services`, `conflicting_web_services` | `True`, nginx/apache2/caddy/lighttpd | |
| `transaction_required` | `False` | refuse the host (see above) |
| `alias_policy` | `{}` | entrypoint to `delete`; must cover every rendered entrypoint and needs 3.7.12+ (the role's assert) |

Steps: refuse transaction-managed hosts; render and validate; directories
(`acme` `0700`, the others `0755`, root); the release archive downloaded,
checked against `checksum` and the binary renamed into place when the
installed version differs (or `force_update`), then its version checked;
static config, certificate list and unit; `acme.json` created `0600` if
missing (never rewritten); log rotation; UFW `allow <port>/tcp` for HTTP and
HTTPS (and the dashboard when `dashboard_firewall_open`) when missing; installed
distro web servers among `conflicting_web_services` stopped, disabled, masked
and their failed state cleared; `daemon-reload` when the unit changed;
Traefik enabled and running; restart on change; read-only port and unit
checks.

Differences from the role, on purpose:

- A checksum is required, so nothing unverified is installed.
- Only the `traefik` binary is installed, renamed over the old one; the role
  unpacks the whole archive (including `LICENSE.md` and `CHANGELOG.md`) into
  the binary's directory.
- A replaced binary restarts Traefik; the role keeps the old process running
  until something else restarts it.
- Armv7/armv6 hosts get the `armv7`/`armv6` release (the role's `arm` has no
  release archive). Only Linux is supported.
- The static config and certificate list are validated before anything is
  written, and certificate files must exist on the host.

## deploy_traefik_backup

`deploy_traefik_backup(cfg)`; `TraefikBackupConfig` fields: `root`
(`/opt/backups/traefik`), `prefix` (`manual`), `dynamic_dir`
(`/etc/traefik/dynamic`), `include_dynamic` (`True`, matching ops-library
2.48.1), `acme_path`, `include_acme` (`False`), `create_archive` (`True`),
`fetch_local` (`True`), `local_dir` (`None`: `~/backups/traefik`), and
`required_mount`, `retain_count`, `retain_days` (`None`, `0`, `0`; see
[Local backups](concepts/local-backups.md)).

The default now captures the **whole dynamic directory**, including nested,
hidden and non-YAML files, into `dynamic/` regardless of the source directory's
basename or trailing slash. Entries below `dynamic/` keep their source
permissions; `dynamic/` itself is reset to `root:root 0700` after the copy (a
plain `cp -a` would give it the source directory's owner and mode), inside the
root-only `<root>/<prefix>-<timestamp>/` container. `metadata.yml` (`0600`) records the
timestamp, both configured sources and both inclusion flags in the role's
format. Optional ACME state is copied into `acme/` as `root:root 0600`.

The payload directory is the only top-level entry in
`<root>/<prefix>-<timestamp>.tar.gz` (`umask 077`). With `fetch_local`, the
controller directory is `0700` and the fetched archive is restricted to `0600`.
The controller directory itself must be a real, accessible directory: a symlink
(such as a link to an external volume) deliberately refuses with an explicit
error. Configure the real destination path instead. This fetch-phase refusal
can leave a completed remote backup; it does not mean the backup was fetched.
An existing linked or special archive destination also refuses before download;
the permission checks use no-follow file descriptors. Dynamic configs can
contain authentication hashes or credentials, so these protections apply even
when ACME is disabled. `include_acme` controls only the separate ACME payload;
all regular files within the selected dynamic tree are included.

With `include_dynamic=False` the tree is neither inspected nor copied. With
`create_archive=False`, only the remote payload directory is produced; nothing
is fetched. Missing enabled sources fail before any operation. Source and
backup roots cannot overlap or contain parent traversal, both as configured and
after resolving symlinks on the host (`realpath -m`, so an absent root under an
aliased ancestor is resolved too; this needs GNU coreutils, and an unresolvable
answer refuses). Link checks apply to the path with trailing `/` and `.`
components removed, so `link/` or `link/.` still counts as a link. The backup
root must be a real directory (or absent); an existing payload/archive attempt, including
a dangling link, refuses before writes rather than overwriting history. Use a trusted source
tree: unlike the role's recursive copy, this implementation refuses symlinks
and special entries rather than following them outside the chosen tree, and
rechecks the copied tree before allowing an archive. A failed copy never packs
or fetches the partial payload. With `required_mount` the run first checks
that the mount is there and `root` resolves below it, and stops before any
write otherwise; with `retain_count`/`retain_days` it prunes the snapshots it
recorded after packing (also without an archive), never the one just written
and never an unrecorded one ([Local backups](concepts/local-backups.md)).

**Backup coverage does not qualify restoration.** Dynamic payloads are never
published by `deploy_traefik_restore`: it remains ACME-only, has no `dry_run`
option and still refuses transaction-managed hosts. Do not copy an archived
Native route into a watched directory; recovery needs the owning service's
reviewed canonical/quarantine workflow. No new private lifecycle registration,
deployment or positive restore/removal qualification is implied by this change.

## deploy_traefik_restore

`deploy_traefik_restore(cfg)`; `TraefikRestoreConfig` fields: `archive`
(`latest`, a name below `root` or an absolute path), `root`, `staging_dir`
(`/tmp/traefik-restore`), `acme_path`, `include_acme` (`False`),
`transaction_required` and `required_mount` (`None`; `staging_dir` must lie
below it, and the mount is checked before the staging directory is made).

`latest` picks the newest `*.tar.gz` in `root` by modification time. The
archive is unpacked into a fresh `staging_dir` (`0700`), its first top-level
directory is the payload, and with `include_acme` its `acme/acme.json` is put
back as `root:root 0600` (directory `0700`); `staging_dir` is removed
whether the restore succeeds or fails (an `EXIT` trap). As in the role,
Traefik is not restarted. Without `include_acme` nothing is
restored.

## deploy_traefik_remove

`deploy_traefik_remove(cfg)`; `TraefikRemoveConfig` fields: `confirm`
(`False`; required), `preserve_certificates` and `preserve_dynamic_configs`
(`True`), `force_complete` (`False`; overrides both), `binary_path`,
`config_dir`, `log_dir`, `remove_firewall_rules` (`True`), `http_port`,
`https_port`, `dashboard_port` and `transaction_required`.

Steps: refuse transaction-managed hosts and unconfirmed runs; stop and
disable Traefik (failures ignored, as in the role); remove the unit file and
reload systemd; remove the binary and `traefik.toml`; the dynamic configs and
the ACME directory unless preserved; `config_dir` when nothing but hidden
entries is left in it (the role's `find` skips hidden entries; never `/etc`);
the log directory and log rotation; the UFW rules for the HTTP, HTTPS and
dashboard ports; every non-hidden `/tmp/traefik*` entry. Each step runs only
when there is something to remove, so a second run changes nothing.

## Patch-line release resolver

`ops_deploy.infra.traefik_release` decides which Traefik release an
unattended binary update of a transaction-managed host may install. It is a
pure function: it neither opens a socket nor reads a file nor the clock, and
its tests (`tests/test_infra_traefik_release.py`) use fixture release lists
only. The caller fetches the release list and the checksums text; nothing
here installs anything, and the guarded transaction workflow above stays the
only path that changes the binary.

```python
from datetime import UTC, datetime

from ops_deploy.infra.traefik_release import PatchPolicy, parse_releases, resolve_patch_release

releases = parse_releases(github_json)  # decoded GET /repos/traefik/traefik/releases
result = resolve_patch_release(
    releases,
    PatchPolicy(line="3.7", cooldown_hours=72),
    installed="3.7.14",
    now=datetime.now(UTC),
    fetch_checksums=fetch_text,  # url -> text of traefik_v<version>_checksums.txt
)
if result.status == "update":
    pin = (result.target.version, result.target.archive_url, result.target.sha256)
```

A release is eligible when:

- its tag is exactly `v<line>.<n>` (no suffix such as `-rc.1`, no leading
  zeros), it is neither a draft nor a prerelease, and `n` is greater than the
  installed patch: never a downgrade, never a reinstall;
- its `published_at` (with a UTC offset) is at least `cooldown_hours` before
  `now`; the boundary counts as old enough;
- it has the `traefik_v<version>_linux_<arch>.tar.gz` archive and the
  `traefik_v<version>_checksums.txt` asset, each at its canonical
  `https://github.com/traefik/traefik/releases/download/v<version>/` URL;
- the checksums text has exactly one line naming that archive, and it is a
  well-formed `<sha256>  <name>` line (an optional `*` before the name;
  upper-case hex is lowered); a second line for it, or one in another shape,
  skips the release.

The newest eligible release is chosen, so a host may go from 3.7.14 straight
to 3.7.16. The checksums text is fetched only for a release that passed every
other check, newest first, and no more once one yields a digest; an exception
from `fetch_checksums` propagates unchanged (the caller reports it as
"unavailable"). The digest is pinned in the result; the host verifies the
archive against it again.

`Resolution` fields:

| Field | |
|---|---|
| `status` | `update` (`target` is set), `cooldown` (nothing is eligible yet, but a newer patch of the line waits out its cooldown) or `current` |
| `installed` | the parsed installed `Version` |
| `target` | `Candidate(version, arch, published_at, archive_url, checksums_url, sha256)` or `None` |
| `minor_available` | a stable release of a newer minor or major (`3.8.0`, `4.0.0`) exists; it is only reported, never a candidate. Changing the line is an owner decision |
| `skipped` | newer patches of the line that were passed over, newest first, each with a closed reason: `draft`, `prerelease`, `invalid_published_at`, `cooldown`, `missing_archive_asset`, `missing_checksums_asset`, `unexpected_asset_url`, `checksum_entry_missing`, `checksum_entry_ambiguous`, `checksum_entry_malformed` |

Releases of an older line (the interleaved `2.11.x`) are ignored. Refusals
raise instead of resolving: `PolicyError` for a patch line that is not
`major.minor`, a `cooldown_hours` that is not an int in `0..8760`, an
installed version that is not plain `major.minor.patch` or not on the line,
a naive `now` or an arch other than `amd64`/`arm64`; `ReleaseDataError` for
a release list that is not the API's shape (a non-string tag or asset field,
a non-boolean `draft`/`prerelease`, assets that are not a list of objects)
or that names a version or an asset twice. Entries with any other tag are
dropped before their other fields are read.

## Health probes

The read-only ingress acceptance probes of the transaction workflow: the
role's `health_probe_capture` and `health_probe` task entries, checked against
ops-library `3110a0f1`. The probe program `infra/files/traefik_health_probe.py`
is the role's `files/traefik_health_probe.py` byte for byte
(`tests/test_ops_library_drift.py` compares it with `OPS_LIBRARY_PATH`), so
both tools install the same program with the same SHA256 and a transaction
request can name it either way.

```python
from ops_deploy.backups import SshTarget, ssh_runner
from ops_deploy.infra import (
    ProbeSpec,
    TraefikHealthProbesConfig,
    capture_traefik_health_probes,
    deploy_traefik_health_probes,
    verify_traefik_health_probes,
)

runner = ssh_runner(SshTarget(hostname="proxy.example.org", user="root"))
spec = ProbeSpec(
    probes=[{"host": "app.example.org", "scheme": "https", "port": 443, "address": "192.0.2.10"}],
    entrypoints=["web", "web-secure"],
    tls_fingerprints=True,
)
baseline = capture_traefik_health_probes(runner, spec)  # read-only
deploy_traefik_health_probes(TraefikHealthProbesConfig(baseline=baseline))  # in a pyinfra deploy
commands = verify_traefik_health_probes(runner)  # read-only; argv + sha256 per probe
```

| Entry | Writes | Returns |
|---|---|---|
| `capture_traefik_health_probes(runner, spec)` | only a private temporary directory, removed afterwards | `ProbeBaseline`: the spec plus `observations` and `dynamic` hashes |
| `deploy_traefik_health_probes(cfg)` (pyinfra) | `/var/lib/traefik-update-probes` (`0700`), `health.py` (`0755`), `checks.json` (`0600`), all `root:root` | nothing; the closing check is read-only |
| `verify_traefik_health_probes(runner)` | nothing | `ProbeCommands`: `baseline_probe`, `acceptance_probe`, `alias_acceptance_probe`, `metrics_bind_acceptance_probe`, `cleanup_probe`, each `argv` and `sha256` (`as_request()`: plain JSON for the request) |

The spec has `probes` (each `host`, `scheme` `http`/`https`, `port`,
`address`, an IP literal, IPv6 without brackets, and optional `path`,
default `/`), the complete `entrypoints` list and optional
`tls_fingerprints` (record the served TLS leaf of each HTTPS probe; health then
refuses any change of it; Traefik generates a new default certificate at each
restart and whenever its TLS configuration changes, so fingerprint only probes
whose certificate is stable). Capture curls each probe at its `address` (TLS
verification on, so a failing route is recorded as a failure, not called
healthy) and hashes every file below `/etc/traefik/dynamic`. `health`
requires the same results (or a 5xx backend recovering to 2xx, never with a
changed TLS leaf) and an unchanged dynamic tree; `alias` and `metrics_bind`
also check the static config; `cleanup` checks the dynamic tree. Capture
before a change, never after a failed one: a fresh baseline must not make a
regression look healthy.

As in the role:

- an empty probe list is refused, by the configs (before anything runs) and by
  the program itself;
- `/usr/bin/python3` must be 3.11 or newer (checked before capture, install
  and verify; the transaction runs the probes with it through the shebang);
- capture copies the program (`0700`) and spec (`0600`) into a fresh
  `mktemp -d` directory named `traefik-probe-capture-*`, runs `capture` there
  and removes only that directory, also on failure;
- `checks.json` is the role's `to_nice_json` output byte for byte, so a
  baseline installed by one tool shows no change when the other installs the
  same baseline; the commands have the role's keys and argv.

Differences, on purpose:

- Capture and verify run from the controller through a
  [`Runner`](backups.md) (ssh, script on stdin) instead of inside a pyinfra
  run: their result decides what the caller does next, and a pyinfra
  operation is planned before it runs and cannot hand a result back. Only the
  install is a pyinfra deploy.
- The spec and baseline are strict: unknown keys (a misspelt
  `tls_fingerprints` would silently turn fingerprints off), a port given as a
  string, an explicit `null` path or flag, an `address` that is a name (curl's
  `--resolve` takes only IP literals and fails before connecting, which
  capture would record as the baseline and health would then accept),
  observations not matching the probes one to one, and a baseline with
  `tls_fingerprints` but without the captured TLS leaves are refused.
  Validation errors do not echo the values.
- Failures are reported as fixed reasons (`ingress changed`, `permanent
  routing changed`, `no probes`, a refused path or mode, ...), never with the
  program's own output, which names the probed hosts; run `health.py health
  checks.json` on the host for the details. This also applies to the deploy's
  closing check.
- The baseline is written through `secret_file` (stdin, never a command line
  or a diff), as the role's `no_log` copy keeps it out of the output.
- Verify refuses unless `health.py` is exactly the vendored program, root-owned,
  executable and not writable by group or others below root-owned directories
  nobody else can write (what the transaction engine requires of a probe), and
  `checks.json` is a root-owned `0600` regular file; it then runs `health` the
  way the engine runs a probe, directly through the program's
  `/usr/bin/python3` shebang. The role only checks the installed program's
  SHA256 after copying it and runs it through `/usr/bin/python3` explicitly.
