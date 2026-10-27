# Changelog

## Unreleased

- Make installed Rust release validation genuinely read-only on a current layout.
  Classify needed root metadata or owned staging repairs as managed changes,
  preserve existing-binary restart/prune semantics, and refuse symlink roots.

- Add the full ordinary Unbound/DNS deployment with conditional blocklist/DDNS jobs, validated owned configuration replacement and rollback, authenticated status endpoint and explicit no-write convergence. Keep current package and endpoint runtime selections. DNS alone opts into change-gated transient metrics validation; existing helper callers retain their defaults.

- Add the Mailgun relay deployment and Traefik ingress with the existing
  Python/Rust switch, strict staged archives, shared secret configuration and
  live implementation verification. Preserve Python source/runtime by default;
  installing/updating it requires an explicit choice. Retain rollback independently
  of a working Rust release and recover restart intent after an interrupted deploy.

- `thermal_monitoring` `fan_control`: `active` now returns positions an
  earlier run still holds but no longer manages (a changed managed set) to BMC
  auto, read back, before it takes control, instead of leaving them manual
  and dropping them from the record the stop helper acts on; it refuses (exit
  78, no write) when that record is from another board, BMC or firmware. The
  calibration guard now treats an unknown scan state (failed `zpool status`,
  a missing pool, no scan line) as "scan state unknown" and does not
  calibrate, instead of as "no scan running". `observe` is unchanged.

- Add native macOS Ollama Homebrew/LaunchDaemon deployment, preserving installed
  formulas and retained model contents, with role-compatible identity,
  directory, conflict and service behavior. Unchanged running jobs are retained
  without staging/helper writes or restarts; intentional plist changes restart
  the selected label. Add an isolated hosted macOS integration workflow.

- Preserve the monitor relay service account’s absent home directory, matching
  the original role’s `create_home: false`.

- Add native monitor mailbox/Maildir and mail cleanup/relay probe provisioning,
  with unchanged role templates, Dovecot stdin password transport and scoped SQL.
  Add IMAP SiteCheck validation and opt-in managed privacy/processing-lease guards.

- Add ordinary Traefik deployment for declared transaction-managed hosts using the existing engine, isolated candidate proof, detached complete-file recovery and a no-staging converged path. Preserve the separate patch updater and non-enrolled installation API.

- Add standalone mail and torrent VPN metrics endpoint deploys using the existing
  Python/Rust switch, Basic Auth, role templates and service identities. Preserve
  recursive queue ACLs, probe-state exports and the torrent root collector/timer.
  Converged repeats perform no deploy mutations; collector output is initialized
  only when absent, invalid, stale, affected by changed inputs or needed to seed
  an unarmed timer. The mail Python wrapper verifies passwords on stdin, matching
  the paired role security repair.

- Wait for UniFi JSON readiness (`meta.up=true`) before completing deployment; HTTP200 startup pages are not readiness. Create usable string-valued HA privilege references and repair legacy-only references in place while preserving working mixed layouts and record IDs.

- Add initialized-controller UniFi routine deployments with explicit verified package updates, Java/Mongo package presence, authenticated Mongo/HA reconciliation and a disposable real Linux integration workflow. Initialize the absent controller's private external-database selectors before vendor startup; preserve existing controller configuration and database selection. Missing-controller admission requires empty application/statistics/audit databases and effective write/index privileges before vendor initialization.

- Add native MeTube Git/Angular/uv deployment with staged runtime/UI qualification,
  retained media/state, queue protection and role-compatible systemd/Traefik artifacts.

- Vector producers: validate converged Logyard/Graphyard fragments in place
  without temporary staging writes. Retain staging before content or metadata
  repairs and classify those temporary writes as mutations. Preserve source
  tokens, package choices, other fragments and restart conditions.

- Allow Graphyard's `Influx.data_dir_mode` to preserve an existing private
  `0700` data directory during ordinary stack convergence. The default remains
  the role's `0755`; no data, container or source selection changes.

- Minecraft: add explicit started/stopped deployment state, preserving enabled
  stopped servers without runtime start/restart or live health claims. Maintain
  UFW rules without activating an inactive firewall for stopped deployment;
  require active UFW before all mutations for a running deployment. Add a real
  Forge first-deploy, repeat, normal-update and stopped-preservation smoke test.
  Accept Forge's clean RCON stop status 143 and treat absent mcrcon/configuration
  as expected first-install states before strict output verification.

- Keep Mastodon dependency inspection read-only with Bundler checks in dry-run
  mode, preserving lockfile timestamps and avoiding false restart debt after a
  runtime update. Genuine after-start input changes still require rollout.

- Reject shell syntax that cannot remain literal in Mastodon unquoted environment
  assignments before any host fact or operation; preserve quoted From addresses.

- `nyxmon`: the Python agent fallback is retired (port of ops-library
  2.75.0). `NyxmonConfig.agent_impl` is removed (an unknown field now), and
  `deploy_nyxmon` stops before any operation without `agent_rust_version`.
  `nyxmon-monitor.service` starts the versioned Rust binary itself instead of
  the venv `start-agent`; the `agent-impl.conf` template is gone. On a host
  deployed before, the version the old drop-in selected is read for
  `.previous-version`, then exactly
  `/etc/systemd/system/nyxmon-monitor.service.d/agent-impl.conf` is removed
  (anything there but a regular file stops the deploy), with one reload and
  restart of the monitor; the other drop-ins stay. The agent check accepts
  only the versioned binary (`/proc/<pid>/exe`); a unit change or the
  removal also re-runs the pruning. Rollback is pinning the previous release
  again. `tests/smoke/test_nyxmon_smoke.py` needs `NYXMON_AGENT_ARCHIVE`
  (an archive built for the VM) and skips without it. The vendored role
  templates follow (`nyxmon_deploy__nyxmon-monitor.service.j2` updated,
  `nyxmon_deploy__agent-impl.conf.j2` removed); the `nyxmon_deploy` digest in
  `tests/parity/ops_library_roles.json` is not updated here (it was already
  behind ops-library main before this change).

- Add the existing-install Mastodon selected-release API: immutable candidate
  and ruby-build provenance, protected Git updates, rbenv/nvm runtime and locked
  dependency convergence, secret-safe env, migration identities, genuine asset
  outputs, durable retry debt, ordered single application rollout, maintenance
  schedule and federation-cache verification. Retain the configuration-only
  compatibility API; do not bootstrap databases/users or add lifecycle actions.

- Extend Mastodon existing-install configuration mapping to existing delegated
  domains, explicit process sizing, federation nginx caching/timing and local
  domain discovery routing. Role defaults/templates and immutable source,
  runtime, environment, data and maintenance boundaries remain unchanged.

- `thermal_monitoring`: optional `fan_control` block, a drive-aware case-fan
  controller (`drive-fan-control.service`, `files/drive_fan_control.py`,
  standard library only) for boards whose BMC drives the case fans from the
  CPU alone. Modes `observe` (compute and record, never write the BMC),
  `active` and `calibrate` (once per id: header mapping and duty staircase,
  BMC restored). HDD temperatures only for spinning disks (`hdparm -C`, then
  `smartctl -n standby`) every `hdd_interval_s`, NVMe and CPU from hwmon every
  cycle, scrub/resilver feed-forward, piecewise linear curves, slewed
  decreases. Only the managed positions go to manual; protected ones (the CPU
  fan) stay auto. Board and firmware must match (exit 78 otherwise); every
  BMC write attempt keeps the other bytes as read right before it and is read
  back. 100 % on missing, stale or failing inputs and stalled fans; a clean
  stop restores BMC auto (read back), any other stop sets 100 %, both only on
  the board and firmware control was taken on; `observe` never writes the
  BMC, also not positions an earlier run left. Calibration is skipped
  (retried at the next start) or aborted while inputs fail, a scrub runs or
  the drives warm up, and does not run while an earlier run still holds fans.
  `Type=notify` with a watchdog; numeric metrics
  files for the thermal endpoint's `sysfs_sensors`. The deploy refuses before
  any operation unless board, BMC identity and firmware match and every
  unmanaged fan position is auto, and checks that the started service reports
  a healthy cycle of its own in the configured mode. Without the block the
  plans are unchanged (golden test). ASRock Rack AST2600 commands (TSDQA-72).

- `tests/test_become_environment_secrets.py` follows calls by function name
  only within one program. The package is one: its modules and every host
  script one of them imports or loads as a module (a module loader such as
  `spec_from_file_location`, under any name, in a module that names the
  script), all of them seeing all of its names. Every other host script
  under `files/` is a program of its own and sees the package only if it
  imports it. Before, all modules and host scripts shared one name space: a
  further host script with generic method names (`update`, a runner called
  as `run`) linked package code through `base/files/stale_exe_restart.py`'s
  `run()` to its `runuser` call and flagged `django_site`'s env-file
  `DATABASE_URL`. A file that uses a module loader must now name the host
  script it loads or be listed in `LOADS_NO_HOST_SCRIPT` (the Traefik
  transaction runner and retention, which load their engine, and
  FastDeploy's `ensure_token_user.py`). New tests pin a package leak and a
  host script's own leak (both still caught), that false positive, a
  package module reaching a host script's user switch through an import, a
  module loader (also an aliased one) or the loaded module passed on, a
  loaded script reaching the package's through a module handed to it, and
  a host script reaching the package or the script next to it through an
  import. Test and docs only.

- `ssh_guard` (`ops_deploy.base`) fixes fail2ban's CVE-2026-109786 and is
  extended (docs/base.md, "ssh_guard"). New `fail2ban_sshd_filter_fix`
  (default `auto`) writes `/etc/fail2ban/filter.d/sshd.local` with the two
  lines of upstream fail2ban ddd879d while the packaged sshd filter still
  accepts `on <token>`, removes it once the package is fixed, and refuses a
  `sshd.local` it did not write. New jail keys `fail2ban_banaction`
  (`nftables…`/`iptables…` only), `fail2ban_journalmatch`,
  `fail2ban_ban_only`; `fail2ban_no_recommends`; `python3-systemd` for the
  systemd backend is installed first, fail2ban and `nftables` (for an
  nftables ban action) after fail2ban has loaded the fixed filter. Gates after every fail2ban
  change (and when the running jail still lacks the fix) stop fail2ban and
  fail the deploy on a vulnerable loaded filter or a missing/foreign ban
  action. New sshd fields `max_startups`, `per_source_net_block_size`,
  `per_source_penalties`, `per_source_penalty_exempt_list`, refused at plan
  time on an OpenSSH too old for them (`ssh -V`); a changed drop-in is
  checked with `sshd -t` and its effective values with `sshd -T` (numbers by
  value) before the reload. Plan-time refusals: an `sshd-session` the filter ignores, an
  enabled `nftables.service`, an unresolvable port name. Without a configured
  ban action, `nftables` is installed when the jail inherits an nftables
  action from fail2ban's other jail files. With only the role's fields the
  jail and drop-in stay byte-identical to the role; the default config now
  also manages the filter override, the gates and `python3-systemd`. The
  Docker fixture test now runs an exposed host (vulnerable filter loaded, nft
  missing) through the fix, spoof regression, IPv4/IPv6 nftables bans and the
  gates.

- `stale_exe_restart` docs: the removal steps first make the oneshot
  impossible to start (timer disabled, apt hook and service unit file deleted,
  `daemon-reload`) and then stop a queued or running run, which has already
  loaded the allowlist and could still restart a unit. Docs only.

- New base deploy `stale_exe_restart` (`ops_deploy.base`, no ops-library role):
  restarts allowlisted units that still run a replaced package binary, e.g. an
  nginx a service runs under its own unit, which no reload and no maintainer
  script ever restarts. Installs a host program
  (`/usr/local/libexec/ops-deploy/stale-exe-restart`), its allowlist, a oneshot
  with an hourly timer and an apt `DPkg::Post-Invoke` hook that only queues the
  oneshot. A unit is restarted at most once per installed binary and only when
  dpkg is idle, every process of the unit runs the stale image in the host
  namespace, the binary is the configured package's (`dpkg -S`, `ii`,
  `dpkg --verify`), `ExecStart` is exactly the approved argv (D-Bus), no unit
  edit is pending and the configuration test passes as the unit's user; all of
  it is checked again right before a `systemctl try-restart`, and a damaged
  state file blocks every action. Post checks verify the new image and an
  optional local HTTP probe. Other
  units are only reported (stale executables, deleted libraries). The deploy
  never restarts a consumer unit itself; a read-only `report` runs while
  planning. Tests: decision table, fake connector, Docker (trixie, systemd,
  nginx, real apt reinstall through the hook).

- `thermal_monitoring`: `ThermalCheckConfig` / `deploy_thermal_check`, only
  the endpoint's Nyxmon json-metrics check (the same `JsonMetricsCheck` and
  upsert as `nyxmon_check`, the endpoint password as its login), for a play
  that upserts the check into a Nyxmon on another host than the endpoint. The
  check's user and database (`site_path/db.sqlite3`) must be that Nyxmon's;
  the password is checked before any operation, also without a login.
  `deploy_thermal_monitoring` is unchanged.

- Traefik compatibility proof (`ops_deploy.infra.traefik_tx.proof`): a
  `.yaml`/`.yml` dynamic file whose content starts with `{` is read as the JSON
  document it is (JSON is YAML; Traefik loads it) with the standard library's
  `json`, giving the same router names as the same data in block style: the
  keys below `http`/`tcp`/`udp` `routers`, none for a file with middlewares
  only. Before, the proof refused such a file as unsupported YAML, so a host
  with one could not be updated. Only strict JSON is read; a syntax error
  (with its line), duplicate keys, `NaN`/`Infinity`, `<<` keys or a section
  that is neither an object nor `null` are refused, and a file that is not
  UTF-8 or not valid TOML is now refused by name and position, without the
  decoder's text (which can quote the file). Block-style YAML and TOML
  are read as before. New read-only `proof.py --routes request.json`: reads
  the live dynamic files exactly as the proof does (no lock, no unit, nothing
  written) and prints the route file and router counts or the same refusal,
  so a controller can find an unreadable route file before a transaction
  writes anything. The proof record format is unchanged.

- `sync_tree` no longer reports a mutation for rsync
  cannot-delete-nonempty diagnostics and their exact impossible directory
  deletion candidates. Protected descendants remain untouched; real transfers,
  permission changes, removable file/directory deletions and unknown output
  retain their existing change/error handling.

- Add deploy-only `minecraft_java` for vanilla/Forge servers, guarded loader
  switches, verified JARs, mods, UFW and change-gated systemd rollout. RCON
  credentials remain on stdin/in protected files, including graceful stop.
  Existing backup jobs and archives are left untouched. Download staging runs
  as the service user, loader transitions resume safely after partial failure,
  and semantic config comparison tolerates Java startup rewrites/added UUIDs.
  First deploys tolerate absent JARs and missing/unsupported mcrcon via strict
  probes, with a required post-build version check. Pending-loader manual
  recovery is documented.

- Mastodon configuration convergence now refuses a changed Traefik route while
  a transaction holds its host lock, through the existing guarded route writer.
  An unchanged route runs no guard and remains free of mutations.

- Traefik rollback set (`ops_deploy.infra.traefik_tx`): an optional policy key
  `rollback_archive` (`root` below `mount`) makes the engine's `binary` write
  its full pre-change archive to `<root>/<transaction>.tar.gz` on an external
  disk and name it in `backup.json`. The transaction is refused before anything
  is written unless `mount` is a read-write mount point, root's and writable by
  nobody else, and refused when a directory below it is a symlink, not root's,
  writable by others or on another device. The directories are opened through
  descriptors and the archive is created exclusively in the opened directory,
  so an unmount or a swapped directory after the checks cannot redirect it;
  nothing falls back to the system disk. Without the key the
  engine is unchanged (parity with ops-library 3110a0f1). A rebaseline reads
  the route files from the external archive too. New host program
  `retention.py` (run by `runner.py retention` and
  `transport.retention_host`): keeps the `keep_minimal` newest transaction
  directories with their rollback artifact (`original`, `request.json`,
  `backup.json`), the `keep_full` newest of them with `prechange.tar.gz`, the
  recorded transaction always, and removes older directories and `candidate`
  files. By default a read-only listing (no lock, no writes); `apply` takes the
  engine lock, needs a `clear` record and writes `retention.json` into trimmed
  directories. External archives are listed, never removed. Nothing runs it
  automatically.

- Route writers refuse while a Traefik transaction holds its host lock: a
  read-only guard (`/proc/locks`, never takes the lock) runs in front of every
  change of a file in `/etc/traefik/dynamic` by `traefik_route`, the new
  `services._traefik_routes.route_put`/`route_absent` (gotosocial,
  django_site noindex, unifi, vaultwarden, zellij ingress, work_app removal),
  `_lifecycle.remove_path` below the dynamic directory (compose_app,
  fastdeploy, nyxmon removal), the work_app restore's route and the fastdeploy
  restore (checked once up front, not on a dry run). The guard fails the
  operation before the write. Unchanged deploys run no guard and stay at zero
  changes; a changed one shows one more command.

- `ops_deploy.infra.traefik_tx.proof` (new): the isolated native
  compatibility proof the transaction engine's `binary` action requires. On
  the host, as root and standard library only, it holds the transaction lock,
  copies the static config (only `api.insecure = true` added), the dynamic
  tree and the approved ACME stores into a work directory, takes the
  candidate from the checksum-pinned archive, and starts the installed and the
  candidate executable, both checked to be native builds, each in a transient
  systemd unit with `PrivateNetwork=yes`, a read-only file system and the
  copies bound over the live paths. A pair passes when every router is
  `enabled` and the `@file` routers are exactly the ones the dynamic files
  define; the proof passes when both pass with the same routers and the live
  identity is unchanged. The proof file under
  `/var/lib/traefik-update-proofs/` keeps the 2026-09 format's keys first and
  is never overwritten; `proof.compatibility()` turns it into the engine's
  block. Golden format test, tests that run the whole proof with a stand-in
  Traefik, and a VM proof with real Traefik 3.7.14/3.7.16 (broken route,
  undecodable file, interrupts, engine update with the resulting block).
  Nothing uploads or runs it yet; no deploy changes.

- `ops_deploy.infra.traefik_tx.transport` and `.runner` (new): detached Traefik
  transactions. `stage_transaction` puts engine, host program and request into
  a root-only `/var/lib/traefik-transport/<id>` and has the host download the
  exact release archive (refused unless it has the approved SHA256, before any
  `pending` record is needed); `start_transaction` launches
  `traefik-tx-<id>.service` with `systemd-run` (`RuntimeMaxSec`, `--collect`),
  so an SSH drop or a killed controller no longer interrupts replace, verify
  and rollback; `poll_transaction`/`wait_for_transaction` read the result over
  new connections; `cleanup_transaction` and a read-only `inspect_host`. When
  the unit fails (killed, timed out, stopped, no usable result, record left
  `pending`), `OnFailure=` runs `traefik-tx-safe-restore@<id>.service`: only
  for this transport's own `pending` binary transaction with the `original`
  binary at hand and a live binary that differs, it puts the original back,
  restarts and probes like the engine's rollback and records `recovery` (or
  `degraded`), never `clear`. Each step is a script on stdin over a new
  connection; errors are fixed reasons without host names. Nothing calls the
  transport yet; no deploy changes.

- Traefik health probes (`ops_deploy.infra.traefik_probes`): port of the
  `health_probe_capture` and `health_probe` task entries of ops-library's
  `traefik_deploy` role, checked against ops-library `3110a0f1`. The probe
  program is vendored byte for byte (`infra/files/traefik_health_probe.py`,
  also in the drift test). `capture_traefik_health_probes` captures a fresh
  baseline read-only from a private temporary directory;
  `deploy_traefik_health_probes` installs program and baseline under
  `/var/lib/traefik-update-probes` (`checks.json` byte-identical to the role's,
  through `secret_file`) and verifies live ingress with a read-only check;
  `verify_traefik_health_probes` checks the installed probes, runs `health`
  and returns the argv/SHA256 commands of a transaction request. Capture and
  verify run through a `Runner` and report fixed reasons, never the probed
  hosts. Specs are strict (addresses must be IP literals) and an empty probe
  list is refused. No transaction, prepare or live wiring; see the Traefik
  page.

- UniFi existing-install admission now requires an explicit
  `installed_package_version`, compared exactly with the installed Debian
  package and status. Only the qualified `9.5.21-31260-1` build of role
  release `9.5.21` is accepted; the former configurable `version` option is
  removed. Other builds/revisions/releases require reviewed qualification,
  never silent equivalence or upgrades.

- `ops_deploy.infra.traefik_tx.engine`: new `rebaseline` action (ops-deploy
  only; the reference engine refuses it as unknown). On a `clear` record whose
  identity differs from the live one only in the dynamic route tree hash, and
  once the baseline probe passes, it writes a new `clear` record with
  `rebaselined_from`, the previous and new route digests and the names of the
  added, modified and removed route files (from the last rebaseline's
  `route-inventory.json` or the previous transaction's `prechange.tar.gz`,
  each used only when it reproduces the previous digest exactly; otherwise
  `unavailable`). Pending, recovery and degraded records, any binary, static
  config, unit or machine drift, no route drift, a failing probe and a change
  during the probe are refused without writing anything. Never restarts
  Traefik. Nothing calls it yet. Tests: `tests/test_traefik_tx_rebaseline.py`.

- `ops_deploy.infra.traefik_tx.engine` (new): the host side of the guarded
  Traefik transaction workflow, ported from ops-library's
  `traefik_transaction.py` (3110a0f1) for `inspect`, `binary` and `resume`.
  Same state directory, lock, record schema, request format, refusal messages
  and exit codes, so records written by either engine load unchanged in the
  other and the two exclude each other on the lock. `enroll`, `alias`,
  `metrics_bind` and `acme_storage` are refused before anything is read or
  written and stay with the Ansible entry. Standard library only, under 1,500
  lines. `tests/test_traefik_tx_parity.py` runs both engines (the reference
  vendored under `tests/parity/traefik_deploy/`) through the same requests on a
  fake host and requires identical results, refusals and files. Nothing uploads
  or runs the engine yet; no deploy changes.

- `ops_deploy.infra.traefik_release` (new): a pure patch-line release
  resolver for unattended Traefik binary updates. From a decoded GitHub
  release list, a `PatchPolicy(line, cooldown_hours)`, the installed version
  and `now` it picks the newest release `v<line>.<n>` above the installed
  patch that is neither draft nor prerelease, is at least `cooldown_hours`
  old, has the Linux archive and `checksums.txt` at their canonical GitHub
  download URLs and exactly one well-formed sha256 line for the archive (the
  checksums text comes from an injected callable, newest candidate first).
  It never downgrades or reinstalls, ignores older lines such as the
  interleaved 2.11.x and only reports a newer minor or major
  (`minor_available`). Every passed-over patch is listed with a closed skip
  reason; bad policy, version or release data raise. Nothing installs from
  it yet; the transaction workflow stays the only binary write path. Tests
  use fixtures only (no network). See "Patch-line release resolver" on the
  Traefik page.

- `nyxmon_site_checks`: new `remove_checks`, names of checks of the service to
  delete. A named check goes with its `check_result` and
  `check_notification_state` rows, as Nyxmon's dashboard deletes one
  (`HealthCheck.delete()`); a name that is not there is converged. The run
  refuses before any write when another table references `health_check` or
  when a check to delete is claimed by an agent (`status='processing'`).
  `checks` may now be empty when `remove_checks` names a check, and a missing
  service row is then not created. Configs without `remove_checks` send the
  same stdin payload (the plain list of checks) and behave as before.

- Add `unifi` existing-install configuration convergence with strict MongoDB/HA
  admission, secret Java argument file, role-identical unit/route/log templates,
  change-gated restart and optional UFW rules. No installation, upgrade, database
  provisioning or lifecycle support; check mode uses a private temporary mongosh
  HOME. Ansible remains the default until separately authorized live proof.

- Add bounded Mastodon existing-install configuration convergence. Source,
  environment, dependencies and assets must already match; bootstrap, upgrades,
  migrations and lifecycle operations remain unsupported. No live proof yet.

- Local backups and restore work directories (`nyxmon`, `fastdeploy`,
  `work_app`, `traefik`): new `required_mount` on the backup and restore
  configs and `retain_count`/`retain_days` on the backup configs (new
  "Local backups" concept page). With `required_mount` the run checks on the
  host, before its first write, that the mount point carries a real
  filesystem (`findmnt --types noautofs`, an automount alone does not count)
  and that the backup root, the restore's work directory and FastDeploy's
  safety-backup root resolve below it, and stops otherwise; the configs
  refuse such paths outside the mount. With retention, each backup records
  its snapshot in `<root>/.ops-deploy-snapshots/` and prunes recorded ones
  beyond the newest `retain_count` per prefix or older than `retain_days`;
  such a backup refuses a name already taken (directory, either archive or
  record); the snapshot just written and unrecorded snapshots (Ansible's,
  older ones) are never removed, and a restore never prunes
  (`FastdeployRestoreConfig.safety_backup_retention` records its safety
  backup). `FastdeployRestoreConfig.safety_backup_root` names the safety
  backup's root (default unchanged); with `required_mount` the FastDeploy
  restore's passfile directory moves from `/tmp` below `temp_dir`. Restore
  work directories now go on
  failure too: the Traefik restore traps `EXIT` (nyxmon checks the mount
  before its cleanup trap), and the work_app restore
  removes its staging directory right after the last step that reads it and,
  with `cleanup`, when any step before that fails (formerly it stayed until
  the next restore). Defaults are unchanged otherwise: no mount check, no
  retention, same archive contents and restore semantics.
- `ops_deploy.backups` (new package, outside the size-capped shared layer):
  the steps a deploy or an explicit backup command runs before it changes
  anything, from the controller over ssh (script on stdin, `BatchMode=yes`).
  `run_echoport_backup` runs a registered Echoport target synchronously
  (`manage.py backup <target> --triggered-by <label>` as the Echoport user),
  parses run ID, object and size (and a checksum when Echoport prints one),
  checks the object with `mc stat` through Echoport's mc alias (exact size;
  with a checksum also `sha256sum` over the object) and returns the run ID
  with a restore hint; any failure raises `EchoportBackupError`.
  `require_mount` (`findmnt`, optionally fstype/source, read-write) raises
  `MountMissingError` and never creates anything. `local_snapshot` writes a
  rollback `tar.gz` only under an explicitly configured directory on a
  mounted disk (walked down from the mount point without following any
  symlink, each missing level created alone with mode 0700, then checked with
  `pwd -P` and `findmnt --target`), through an exclusive `mktemp` partial
  file that a failed or interrupted run removes, with retention by count and
  age that never removes the new archive or files of another name and fails
  the run when a listing fails. A timeout stops the work: the local process
  group gets `SIGTERM`, then `SIGKILL`, and over ssh the remote command runs
  under coreutils `timeout`. The guard and the snapshot also come as pyinfra
  commands.
  See the new "Backups before a deploy" page.

- `bind`: port of the `bind_authoritative_deploy` role (deploy only),
  checked against ops-library main `06394c81` (2.64.5), as
  `ops_deploy.infra.bind` (`BindConfig`, `deploy_bind`; its own "BIND" page).
  The role's five templates ship unchanged and render as Ansible renders
  them, so `named.conf`, `named.conf.options`, `named.conf.local` and
  `named.conf.keys` are byte-identical to files Ansible rendered from the
  role (`tests/parity/bind_authoritative_deploy/`). A small bash script
  (`files/bind_config.sh`, standard tools only) compares the files on the
  host (the TSIG key file only on stdin) and plans nothing on a converged
  host. Before it changes a file it runs `named-checkzone` on changed zone
  files (with a greater serial for a changed static zone) and
  `named-checkconf -t` on a copy of the configuration tree with every
  candidate in place; only then are the changed files renamed into place in
  the role's order, so a configuration named rejects is never installed or
  reloaded. No backups or rollback: an I/O error between renames leaves the
  files installed so far, as the role would, and the next run completes them;
  a reload a run never reached is made by the next run (a file newer than
  named's last configuration load). Dynamic (RFC 2136) zone files are only
  seeded when neither the file nor its journal exists, and never read,
  replaced or reset; a lone journal, a journal next to a changing static
  zone, non-regular managed paths and a clock behind named's last
  configuration load are refused before any change. Only the role's default
  paths (`/etc/bind`, `/var/cache/bind`, `/var/lib/bind`, `named.conf.keys`,
  the role's builtin zones file) and zone files that are `db.*` names of their
  own (no `.jnl`, none of the package's zone files) are deployed; anything
  else is refused before the host is contacted. Adds an
  opt-in Docker test against real named (`BIND_DOCKER_CONTAINER`, including
  an `nsupdate` followed by deploys that leave the dynamic zone and its
  journal untouched) and the role's digest to the drift manifest.

- `graphyard` core: `graphyard-web.service` and `graphyard-agent.service`
  declare `Wants=` + `After=` on `graphyard-runtime.service` instead of
  `Requires=`. The role templates are shipped unchanged (ops-library
  `graphyard_deploy`, "Unit dependencies"). Before, the container CA
  activation's stop and start of the runtime stopped web and agent and did not
  start them again (macmini, 2026-10-21, four hours down). Now a restart, a
  stop and start or a failed start of the runtime leaves both running. The Rust agent
  drop-in is unchanged. The first deploy with this change rewrites both unit
  files and restarts web and agent once. Vendored parity templates and
  `tests/parity/ops_library_roles.json` (`graphyard_deploy`) follow ops-library
  main `d8eba948`.

- `ssh_guard`: `SshGuardConfig.fail2ban_maxretry` is a strict int. A bool,
  string or float was coerced (`True` to `1`, `"03"` to `3`), so the jail file
  differed from the role's render of the same value; such a value is now
  refused when the config is built. Ints render as before.

- `traefik_route`: a route file that holds a basic-auth hash, in its new or
  its deployed content, is now written with `secret_file` instead of
  `files.put`, so `--diff` (ops-control's `just pyinfra-check`, `--dry
  --diff`) no longer prints the old and new bcrypt hash; such a route shows
  only as a changed operation. pyinfra 3.10 has no per-operation diff switch
  (`DIFF` is global). Bytes, `root:root 0644`, hash reuse, change detection
  and Traefik restarts are unchanged; routes without a hash are still diffed.
  With `secret_file` an owner- or mode-only difference rewrites the file, a
  symlinked route path is refused, and every route operation reads the
  deployed file. Test harness: `run_deploy_fake(..., pyinfra_config=...)` and
  `FakeRun.secret_files`, `written_paths` and `written(path)`; new
  `tests/test_traefik_route_diff.py` and jellyfin/homelab `--diff` tests.

- `django_site`: optional `echoport: EchoportTarget | None` registers a generic
  paths backup target through the shared Echoport upsert after health checks.
  Configure SQLite online backup and/or file/directory paths, restore service
  and owner, and schedule policy. Unset keeps the existing deploy behavior.
  See [optional Echoport backups](services/django_site.md#optional-echoport-backups).

- `thermal_monitoring`, `logyard` (the health endpoint) and `static_site`:
  select the endpoint's HTTP server, the role's Python script or the pinned
  Rust `metrics-httpd`, the port of ops-library's `metrics_httpd_switch`
  (`rust/metrics-httpd/PLAN.md` 7.2 and 7.4, slice S5e). New config fields
  `httpd_impl` (`python` | `rust`, default `python`), `httpd_rust_version`
  and `httpd_rust_sha256` (on `ThermalMonitoringConfig`,
  `StaticSiteConfig` and logyard's `HealthEndpoint`). With a version the
  release is installed through `helpers.rust_release` and its
  `--check-config` runs as the unit's user in the unit's sandbox, also on
  Python (a failure there only warns); `rust` writes the drop-in
  `<unit>.service.d/metrics-httpd-impl.conf` (the role's template, vendored
  in `tests/parity/ansible` and checked like the other copies), which
  reloads systemd and restarts the unit. After the restart every run checks,
  read-only, that the unit runs the selected server and answers an
  unauthenticated request as the role expects; then the unit's pin moves
  and old releases are pruned. The shared module is
  `services/_metrics_httpd` (outside the size-capped layer) with ops-library's
  `plugins/filter/metrics_httpd.py` vendored byte for byte as `rules.py`
  (`tests/test_ops_library_drift.py`). The default (`python`, no version)
  installs nothing and renders the same files as before; every run now adds
  one read-only check of the endpoint unit. The drift manifest records
  `thermal_metrics_endpoint` and `metrics_httpd_switch` at ops-library main
  `be348cdb`. See [metrics-httpd switch](services/metrics_httpd.md).

- `helpers.rust_release`: an `Install` that only validated an installed
  version (`Install.validated`) still skips `prune_releases(after=[...])`
  when it failed, but no longer counts as a change that reruns the prune, so
  a converged deploy of a pinned release plans no mutating operation.

- Size cap on the shared layer raised from 1,500 to 1,650 code lines (owner
  decision 2026-10-21), to make room for `helpers.rust_release`, which all
  Rust ports share; the shared layer is at 1,633 code lines. See
  [development](development.md#size-cap-on-the-shared-layer).

- New helper `ops_deploy.helpers.rust_release` (`install_release`,
  `pin_release`, `prune_releases`), the pyinfra side of ops-library's
  `rust_release_binary` role (ops-library `rust/PLAN-foundation.md` 6.3,
  slice F4). It manages pinned Rust release binaries under
  `/opt/<crate>/<version>/` with `.archive-sha256` and the
  `.pins/<consumer>`/`.pins/<consumer>.previous` pins, writing the same files
  with the same bytes as the role and making the same pin moves and prune
  decisions (`protect`, unknown live state, fail closed). The decisions are
  ops-library's `plugins/filter/rust_release.py`, vendored byte for byte as
  `helpers/templates/rust_release.py.txt` and checked by
  `tests/test_ops_library_drift.py`, which also records the role
  `rust_release_binary` at ops-library main `d8cac44c`. The host steps run as
  `/usr/bin/python3 -I -` with the script on stdin. No service uses the
  helper yet, so no deploy changes. `tests/test_rust_release.py` compares the
  helper with the role on twin trees when `OPS_LIBRARY_PATH` and
  `ansible-playbook` are available.

- `graphyard` core: select the agent implementation, the port of
  `graphyard_deploy`'s `agent_rust.yml` and `agent_verify.yml` (ops-library
  `08faab6a`, graphyard `agent-rs/PLAN.md` 8.3). New `GraphyardConfig` fields
  `agent_impl` (`python` | `rust`, default `python`), `agent_rust_version`,
  `agent_rust_sha256`, `agent_rust_release_url`, `agent_rust_local_archive`,
  `agent_rust_install_root` (`/opt/graphyard-agent`) and
  `agent_rust_keep_versions` (`3`), validated like the role's settings. A
  pinned release is installed after the migrations with either
  implementation, validated as the service user (`--version`,
  `--check-schema`), selected by the drop-in
  `graphyard-agent.service.d/agent-impl.conf` (the role's template, vendored
  in `tests/parity/ansible`), verified by `/proc/<pid>/exe` (Rust) or argv
  (Python) after the restarts, and old versions are pruned after that check.
  The module `services/graphyard/agent.py` and its host script
  `files/agent.sh` are ported from nyxmon's, which stays unchanged.
  `agent-rs/target/` joins `SOURCE_EXCLUDES`. The default (`python`, no
  version) installs nothing; every run now adds one read-only check that the
  agent unit runs the venv's `manage.py start_agent`. The drift manifest
  records `graphyard_deploy` at ops-library main `6342a60c`.

- `django_site` (and so every site deployed through it): refuse a source
  `uv.lock` that locks certifi below 2026.10.19 or upstream pip below 26.2.2
  before any operation, and verify after the dependency sync, read-only and on
  every run, that the venv's certifi/pip meet those floors and that their
  bundles hold neither emSign ECC Root CA - G3 nor AAA Certificate Services
  (eMudhra/emSign CA compromise, GHSA-6q48-6c7w-9gw2). New helpers
  `ops_deploy.helpers.python_security.require_lock_floors` and `verify_trust`.
  A site whose source lock is stale now fails to deploy until the lock is
  updated in its source or a reviewed source revision with a current lock is
  deployed; nothing is added to environments without certifi/pip.

- Fail LiveKit, Loki and Graphyard runtime deployments before service changes when explicitly enabled replacement CA stores have not been prepared.

- Support optional prepared replacement container CA stores for LiveKit, Graphyard and Logyard without changing application images.
- LiveKit optionally binds a prepared managed Chrome distrust policy into Egress, with required-file preflight before application changes.

- Traefik routes no longer advertise HSTS `preload`: port of ops-library
  `abae172` (2026-10-19), checked against ops-library main `121564c4`
  (2.61.0). `stsPreload: true` is gone from the shared `traefik_route`
  template (nyxmon, fastdeploy, compose_app, toyweb), the native_app route,
  the route templates of archive, chesslab, delve, echoport, graphyard
  ingress, logyard ingress, recorder and work_app, and django_site's Wagtail
  route, as well as from the vendored role templates in
  `tests/parity/ansible`, which match ops-library main again. HSTS
  lifetimes, `includeSubDomains`, `forceSTSHeader` and all other headers are
  unchanged. No domain was submitted to the browser preload list.
  `tests/test_traefik_hsts.py` refuses `stsPreload` in any template and the
  service tests check each rendered route. In the drift manifest
  `graphyard_ingress_deploy`, `work_app_deploy` and `fastdeploy_deploy` get
  their main digests: `abae172` was the last unported change of each (the
  fastdeploy entries below ported the others; `3221e0c4` changed only a
  comment in its tasks, ops-deploy already reuses the deployed hash).
  `nyxmon_deploy` keeps its old digest (it also carries `13ca7465`, not
  ported), as does `minio_deploy` (its basic-auth hash reuse, `3221e0c4`;
  ops-deploy does not port the MinIO route).
  Operational effect: the next pyinfra deploy of a service whose live route
  still has `stsPreload: true` rewrites that route file once, exactly as an
  Ansible run with current ops-library would. Traefik's file provider picks
  the change up without a restart; archive, chesslab and echoport restart
  Traefik once for the changed route, as their roles' `reload traefik`
  handler does, and so does toyweb (the helper's default `restart="traefik"`).
  The run after that changes nothing.

- `fastdeploy`: `service_token_admin_users` (with
  `service_token_admin_initial_user` for the secret initial user) and
  `restore_policies` write FastDeploy's `SERVICE_TOKEN_ADMIN_USERS` and
  `RESTORE_POLICIES` (FastDeploy main `8faa9bd`, which refuses API token
  issuance and every restore without them). Each is written only when set, as
  compact JSON in single quotes in `.env` and `.env.shell`, byte-identical to
  the `fastdeploy_deploy` role of ops-library 2.59.0 (re-vendored
  `fastdeploy.env.j2`). The role's drift digest stayed at its old value
  until the HSTS preload change (ops-library `abae172`) was ported (see
  above). Invalid
  user names, buckets and prefixes fail the config.

- Pin the managed uv installer to 0.13.4 with verified Linux release checksums and refresh certifi to 2026.10.19 for the eMudhra trust incident. The updated `uv_install` mirror digest is from the paired incident ops-library branch; other digests retain their recorded source baseline.

- `jellyfin`: port of the `jellyfin_deploy` role (deploy only; with the
  `jellyfin_shared` defaults), checked against ops-library main `540ede2b`
  (2.56.0). `JellyfinConfig` mirrors the role's variables, except that the
  repository's distribution, release and architecture are configuration the
  deploy checks against the host's os-release and `uname -m` (mapped as the
  role maps its facts) before any operation. `deploy_jellyfin` keeps a
  dearmored keyring and downloads the key (with `curl` and `gpg`, which must
  be on the host then; checked while planning) only while it is missing or
  armored, writes the role's one-line `jellyfin.list`, refreshes the apt
  cache only before an install or after a repository change, installs
  missing packages without upgrading and never removes one
  (`--no-remove`), and treats an installed `jellyfin-ffmpeg*` (current
  `jellyfin` depends on `-ffmpeg7`/`-ffmpeg8`, which conflict with the
  role's candidates) as the ffmpeg pick; otherwise it picks the first
  candidate with `apt-cache policy` as the role's pick is written (while
  planning, or after the base install). It enforces the
  data, config and log directories and the configured media directories
  with exactly the configured mode (`chmod =<mode>` after a `stat` compare,
  so special bits are set and cleared as Ansible's `file` does),
  ships the role's Traefik template unchanged with the deployed bcrypt hash
  kept while it matches, never reloads Traefik or restarts Jellyfin, and
  ends with read-only port and HTTP checks. `mounts_required` (not in the
  role) stops the deploy before any change when a mount is missing. A
  converged host gets read-only operations only. `jellyfin_deploy` and
  `jellyfin_shared` added to the drift manifest.

- `gotosocial`: port of the `gotosocial_deploy` role (deploy only), checked
  against ops-library main `540ede2b` (2.56.0). `GotosocialConfig` mirrors the
  role's variables and `validate.yml` assertions; `deploy_gotosocial` ships
  the role's four templates unchanged and renders them as Ansible does, so
  `config.yaml` (`to_nice_yaml` over the settings merged with
  `extra_config`), the unit, the `gotosocial-admin` wrapper and the route are
  byte-identical to files Ansible rendered from the role
  (`tests/parity/gotosocial_deploy/`). The domain-layout marker guard refuses
  a recorded `host account-domain` pair other than the requested one (unless
  `allow_domain_layout_change`) while planning, before any change, and the
  pair is recorded after the health check, as in the role; a marker that is
  not a regular file is refused. A missing release is fetched, checksum
  verified and unpacked with `tar --no-same-owner` in a staging directory,
  then renamed into place; `config.yaml` goes through `secret_file` (the
  optional SMTP password only on stdin); GoToSocial restarts only when the
  `current` link, `config.yaml` or the unit changed, or when one of them is
  newer than the running process (microsecond start time against nanosecond
  mtimes); `/readyz` is checked only when started, in Python like the role's
  `uri` (no curl needed).
  Packages install only when missing; Traefik is never reloaded. A converged
  host gets read-only operations only. New owned systemd Docker fixture test
  (`tests/test_gotosocial_docker.py`): real install, second run without a
  change, refused layout change, and the role and the deploy taking turns
  without a restart. `gotosocial_deploy` added to the drift manifest.

- `vaultwarden`: port of the `vaultwarden_deploy` role (deploy only) and of
  its playbook's port preflight, checked against ops-library main `540ede2b`
  (2.56.0). `VaultwardenConfig` mirrors the role's variables;
  `deploy_vaultwarden` adds the vendor's apt repository (signing key
  downloaded once, `vaultwarden.list` as `apt_repository` writes it; the
  Ubuntu releases use the `bookworm` suite), installs `vaultwarden` and
  `vaultwarden-web-vault` when missing and requires a version for each,
  creates the data and log directories, and ships the role's env, drop-in
  and Traefik templates unchanged, so `/etc/vaultwarden.env` (through
  `secret_file`), the drop-in and the route are byte-identical to the
  role's. With SMTP configured, an existing `data/config.json` gets the
  role's SMTP settings merged in on the host (`files/smtp_config_sync.py`,
  request on stdin): every other key is kept, the file never leaves the
  host, and it is rewritten in `to_nice_json` layout only when a setting
  differs in value or JSON type (or fixed in place when only its owner or
  mode differ). Vaultwarden restarts only after a package install or a
  change to a file it reads; systemd reloads only for the drop-in; Traefik
  is never restarted. Package pins and the apt hold are not ported (the
  playbook sets none, so the deploy never touches either). `admin_enabled`
  comes from the secrets, as in the playbook. `vaultwarden_deploy` added to
  the drift manifest.

- `homelab`: port of the `homelab_deploy` role (deploy only; with the
  `homelab_shared` defaults), checked against ops-library main `540ede2b`
  (2.56.0). `HomelabConfig` mirrors the role's variables; `deploy_homelab`
  ships the role's `env.j2`, unit and Traefik templates unchanged, so the
  `.env`, unit and route are byte-identical to the role's, and the deployed
  bcrypt hash is kept while it matches (as the role since 2.49.1; Traefik is
  never restarted). `src/` (and `media/` when present) are synced without
  `--delete` with the role's excludes; `manage.py`, `pyproject.toml` and
  `uv.lock` are copied with the role's modes. A venv that does not run or
  runs another Python is removed and recreated with `uv venv`; `uv sync
  --frozen`, `migrate`, `collectstatic`, `add_default_services` and the
  recursive owner fix run only when a change or a read-only probe calls for
  them, so a converged host gets no mutating operation. The default-services
  probe runs the command with SQL and file-storage writes refused inside a
  rolled-back transaction. `db.sqlite3` keeps the role's `0644`. The
  playbook's `uv_install` runs only with `uv=UvInstallConfig()` (graphyard's
  precedent); otherwise a missing uv fails the deploy before any Python
  step. `django_secret_key` must be a value systemd and bash read alike.
  `homelab_deploy`, `homelab_shared` and `uv_install` added to the drift
  manifest.
- `homelab`: the planning probes that run Python as the service user
  (venv `python --version`, `uv sync --check`, `migrate --check --plan`,
  `collectstatic --dry-run`, the default-services probe; also when probed
  again) run with `PYTHONDONTWRITEBYTECODE=1`. An existing service user whose
  primary group is not `group` wrote bytecode caches with that group while
  planning, so the next run's ownership probe planned a `chown` on a converged
  host. Steps that change the host, the unit and `.env` are unchanged (the
  role's end state); the owner fix stays before the Python steps, as in the
  role. Regression tests cover the probe environment and that an ownership
  and route repair runs no Python as the service user.

- `thermal_monitoring`: port of the `thermal_metrics_exporter` and
  `thermal_metrics_endpoint` roles (checked against ops-library 2.56.0
  `540ede2b`; both roles unchanged since `49d2f168`) and the play around
  them: the exporter, HTTP server script and three units byte for byte from
  the vendored role templates, the endpoint bound to `tailscale ip --4`, the
  htpasswd entry checked against the password on the controller and written
  through `secret_file` only when it does not verify (a verifying file only
  gets its owner and mode enforced), restarts only on
  change, the collector run while the metrics file is missing or the
  collector changed, the role's timer re-arm and armed check. A converged
  host gets read-only operations only. Both roles added to the drift
  manifest.
- `_nyxmon_json_metrics`: the shared json-metrics Nyxmon check upsert of the
  private host monitoring playbooks (`tasks/upsert-nyxmon-json-metrics-check.yml`)
  as a step for deploys: the database privacy guard (database and sidecars
  regular, owned by the Nyxmon user, `0600`), a digest probe that needs no
  secret, and the task's upsert (ambiguous rows and processing leases
  refused, umask 077, `BEGIN IMMEDIATE`, 7 retries 5 s apart) with the
  check data, which holds a monitor login, only on stdin: never in argv or
  the environment of the Nyxmon user's process.

- No check payloads on command lines or in the environment of user-switched
  commands. `nyxmon_site_checks`, the `echoport` Nyxmon check and the
  `weeknotes_home` Nyxmon checks passed their check list as
  `NYXMON_CHECKS_JSON=...` in `runuser -u nyxmon -- env ...`, so it was in
  the process list (`/proc/<pid>/cmdline`, readable by every local user)
  while the command ran, in pyinfra's debug output and in the Nyxmon
  process's environment. The checks now reach the scripts as JSON on stdin,
  in the planning probe, the upsert and the repeated probe alike; the
  scripts read `sys.stdin` instead of `NYXMON_CHECKS_JSON`. None of today's
  checks holds a credential, but `nyxmon_site_checks` accepts any check
  `data`, which can carry a monitor login. Consumers that run
  `files/site_checks.py` themselves must feed the checks on stdin.
  `helpers.probes.probe` and `verify_probe` take `stdin=` for this.
- Fact stdin is redacted in pyinfra's logs. pyinfra prints a fact's
  arguments, `_stdin` included, in its debug output ("Loaded fact ..."), so
  `compose_app`'s planning probes (`stdin_probe`: env-file render check,
  `json_key_copy`, `http_json` and qBittorrent preference probes, host
  secret owners) logged their request, base64 only, credentials included,
  with `--debug`. Fact stdin now goes through
  `helpers.probes.stdin_arguments`, whose `StdinLines` carrier prints as
  `<stdin redacted>`; tests capture the debug log and require it.
- New guard `tests/test_become_environment_secrets.py` (part of `just test`),
  the counterpart of ops-control's and ops-library's guards of the same name:
  a static scan that fails on pyinfra's `_env`, on secret-looking or payload
  (`*_JSON`, `*_DATA`, `*_SPEC`) names in the environment dicts of functions
  that build a user-switched command (`runuser`, directly or through a
  helper), and on such names assigned on a command line by `env`,
  `docker exec -e`, `systemd-run --setenv`/`-E` or `sudo`/`su`/`runuser`/
  `setpriv`/`doas` in Python strings, shell scripts and templates. The
  allowlist is explicit and empty. Audit of the whole package found no
  password, token or key on a command line or in another user's
  environment: secrets already travel on stdin or in 0600 files, and host
  scripts read them there and export them only to the program that uses
  them (Redis `REDISCLI_AUTH`, the FastDeploy backup's `PGPASSWORD` for
  `pg_dump` as `postgres`, as ops-library's role does, the Graphyard
  bootstrap user, Django admin users).

- `infra.certbot_dns`: port of the `certbot_dns_deploy` role as of
  ops-library 2.51.0 (checked against main `540ede2b`, 2.56.0; the frozen
  2.48.1 reference predates the stray-dir removal). `CertbotDnsConfig` and
  `deploy_certbot_dns(cfg, secret)` install certbot and the `gandi` or
  `rfc2136` plugin, write the provider credentials (`secret_file`, root
  `0600`) and the deploy hook byte for byte as the role's templates, keep
  `certbot.timer` running, switch the lineage with `certbot reconfigure` when
  its authenticator differs, drop the old provider's settings and remove its
  unused credentials file after the role's `grep -l` scan, and delete listed
  `stray_config_dirs` only after the role's vendored `certbot_stray_guard.py`
  accepts them. A read-only probe (renewal configuration, live links,
  archive, certificate dates, names and key type through `openssl`) makes
  certbot 2.9's renewal decision while planning, so `certonly` (the role's
  argv) runs only when certbot would act and a converged host gets no certbot
  command and no mutating operation; steps that depend on an earlier step of
  the same run check again on the host. A guard refusal fails before any
  change. New read-only checks `single_lineage` (symlinked `renewal/*.conf`
  entries count, as certbot renews them) and `consumer_units` port a consumer
  playbook's post tasks. `config_dir` accepts only `/etc/letsencrypt` (the
  role's certbot commands pass no `--config-dir`); a renewal configuration
  configobj might read otherwise (duplicate keys, stray lines, inline
  comments) counts as due. Templates vendored for parity,
  `certbot_dns_deploy` added to the drift manifest and the guard to its
  vendored files (keys now relative to the package); `infra/files` is
  excluded from ruff and mypy like `services/*/files`. Tests: fake connector,
  the host script on temp trees, and an owned Docker fixture with real
  certbot (no network) whose own decision the probe must match.

- `work_app` and `nyxmon` backups: the SQLite copy follows ops-library
  2.53.0's SQLite runners. Every `sqlite3 .backup` passes `.timeout 30000`
  first (a committing writer is waited for instead of failing with "database
  is locked"), and a copy counts only when `PRAGMA integrity_check` prints
  exactly `ok` (a failed copy is removed). `work_app` keeps its
  `sqlite_retries` attempts 2 s apart and the offline fallback for a failing
  `.backup`; the offline copy is checked after the service is started again,
  and a hot copy that fails its integrity check fails the backup without
  stopping the service. `nyxmon` (`use_sqlite_backup`) retries up to 3 times
  5 s apart, as the role now does. CI installs the `sqlite3` CLI for the new
  real-`sqlite3` tests (`tests/test_sqlite_backup_scripts.py`).

- `livekit`: port of the `livekit_deploy` role (LiveKit SFU and Egress) on
  `compose_app`. `LivekitConfig` maps the role's inputs onto one Compose
  project (`livekit`, containers `livekit-server` and `livekit-egress`, host
  network with a reason, Egress `SYS_ADMIN` and 1 GiB `/dev/shm`, the two
  config files bind-mounted read-only, `livekit.yaml` root `0600`,
  `egress.yaml` root `0640`); images are digest-pinned by the consumer.
  `deploy_livekit` then writes the role's Traefik route byte for byte (one
  public router with the forwarded-header middleware) without restarting
  Traefik. A converged host gets no mutating operation and no container
  command; a changed config file restarts only its reader; an image bump
  recreates through `up`; the role's `down` + `up` restart and Traefik
  restart are gone. The switch from role-written files applies once (both
  containers recreated, then their config readers restarted). Secrets
  (`api_key`, `api_secret`, `redis_password`, `s3_access_key`,
  `s3_secret_key`) must be set; an empty Redis password is refused instead
  of omitted. Role templates vendored for parity; `livekit_deploy` added to
  the drift manifest.

- `compose_app`: `SecretKeyed` config-file mappings (one entry whose key is
  a secret); a config mapping that has a `secret` key among other keys is
  now data instead of a refused reference; `HttpCheck.retries` (default 10,
  unchanged behaviour); `user: root` without a `users` entry for root-run
  apps (root in `users` is refused; an Echoport target of such an app
  defaults `restore_owner` to `root:root`).

- `fastdeploy`: port of ops-library 2.49.0's root-owned runner layout. The
  services root is `root:root 0755` and fastdeploy-owned leftovers below it
  (older Ansible deploys chowned the whole site, root-run backup scripts
  included) get owner root and lose the `fastdeploy` group;
  `/usr/local/libexec/fastdeploy` is created `root:root 0755`. The restore
  writes the services root `root:root` and, with the re-vendored
  `sudoers_blanket_check.py`, no longer restores sudoers rules naming scripts
  below the FastDeploy site. `tests/parity/ops_library_roles.json` records the
  new `fastdeploy_restore`; `fastdeploy_deploy` kept its old digest until
  the HSTS preload change (ops-library `abae172`) was ported (see above).

- Traefik backup now captures the whole dynamic route-config tree by default,
  matching ops-library 2.48.1 coverage and metadata flags. Source modes are kept
  under a private container; archives and fetched copies stay `0600`. Missing,
  overlapping, symlinked or special dynamic sources refuse, and copy failure cannot
  proceed to packing/fetching. Dynamic-route restore and dry-run validation are
  not implemented; existing ACME-only restore/transaction guards are unchanged.
  No private registration or live qualification is included.

- Traefik backup fixes: the archived `dynamic/` directory is reset to
  `root:root 0700` after copying instead of inheriting the source directory's
  owner and mode (setuid/setgid bits included, which GNU `chmod 0700` would keep
  on a directory); `link/` and `link/.` spellings of a symlinked backup root or
  dynamic source now refuse; and source/root overlap is also checked after
  resolving symlinks on the host (GNU `realpath -m`) before anything is written.

- `zellij_ingress`: port of the `zellij_ingress_deploy` role. Writes only
  `/etc/traefik/dynamic/zellij.yml` (`root:root 0644`, directory ensured
  `0755`) from the role's template shipped unchanged, so the file is
  byte-identical to the role's: routers `zellij-secure` and `zellij-http`,
  both restricted to `Host` plus the `ClientIP` allowlist, the
  `zellij-redirect-target` temporary redirect (`permanent: false`) to a fixed
  URL and `noop@internal`, no backend. Disabled is a no-op (nothing is
  removed). Unlike the role, nothing reloads or restarts Traefik; its file
  provider watches the directory. Host name, target URL (http(s), no
  credentials, query, quotes or `$`), entry points, resolver, allowlist and
  route path (directly in the dynamic directory) are checked before any
  operation. `tests/parity/ops_library_roles.json` now records the role.

- Add `nyxmon_site_checks`: one Nyxmon service row and its `http`,
  `json-metrics` and `tcp` health checks, upserted in Nyxmon's SQLite
  database as the Nyxmon user (`python3 -I`), the pyinfra counterpart of
  site-check provisioning playbooks. Same comparison and writes as those
  playbooks (type, URL, interval, sorted-JSON data and the `disabled` flag;
  an update re-enables the check and resets `status`, `next_check_time` and
  `processing_started_at`), decided while planning by a read-only check
  mode, so a converged database gets no mutating operation. Optional
  `require_literal` stops the run before any write when a deployed file
  lacks a literal. Intended differences: umask 077, `BEGIN IMMEDIATE`, and
  `mode=rw`/`mode=ro` URIs that never create a database file. Data keeps its
  JSON types exactly; non-JSON values, control characters and backslashes
  are refused before any connection.

- `ops_deploy.base`: `deploy_ssh_guard` and `SshGuardConfig`, a port of
  ops-library's `ssh_guard_deploy` role (fail2ban jail for sshd and an sshd
  hardening drop-in). Both files are byte-identical to the role's templates
  (vendored under `tests/parity/ansible`). fail2ban is restarted only when
  the jail changed; a changed drop-in is checked with `sshd -t` and, when the
  check fails, removed before the deploy fails, so ssh is reloaded only for a
  configuration sshd accepts. The role's asserts are config validators, and
  rendered values refuse line breaks and other control characters. Unlike
  the role, the fail2ban restart is not deferred behind the drop-in check,
  and only a failing check (not a failed write) removes the drop-in. Linux
  with systemd and apt only. `tests/test_base_ssh_guard_docker.py` runs it
  against real sshd, fail2ban and systemd in an owned container (skipped
  without one).

- Add `ops_deploy.base.dpkg_arch_remove` (`DpkgArchRemoveConfig`,
  `deploy_dpkg_arch_remove`), a port of ops-library's `dpkg_arch_remove`
  role: drops the configured foreign dpkg architectures (default `i386`) and
  updates the apt cache, after strict reads of the foreign architectures and
  installed packages. A host without a foreign target gets no operation; a
  target architecture that still has installed packages fails the deploy
  before any change, listing them. Intended difference from the role:
  `purge_packages`/`autoremove` (package removal) are refused when the config
  is built instead of being implemented.

- Add the `journald_config` base deploy (`JournaldConfig`,
  `deploy_journald_config`), a port of the ops-library role: one drop-in,
  byte-identical to the role's template, present or absent, the role's value
  checks and ordered extra settings. journald restarts only when the drop-in
  changed (owner and mode included) or was removed, and `journalctl --flush`
  follows only a written persistent drop-in; a converged host is left alone.
  A symlinked drop-in is replaced or unlinked, never followed; a directory or
  other special file in its place is refused (file types are read in the C
  locale, so non-English hosts work too). With `state="absent"` the
  settings are ignored, as in the role. No retention sizing, vacuum or
  journal deletion. Covered by fake-connector
  tests, a parity test against the vendored role template and an opt-in real
  systemd Docker fixture test (`docs/base.md`).

- Add a standalone read-only Native venv metadata inventory probe with bounded
  trust/classification and Docker fixture coverage. A matching metadata
  candidate does not authorize execution, adoption, installation or deletion;
  PyPI source dispatch, hooks, interpreter/content trust and liveness remain
  separate prerequisites. Mixed missing/extra/older inventory drift stays
  different even when another Python/package declaration is newer.

- `compose_app`: an `echoport` part registers the app's Echoport backup
  target (SQLite database plus listed files, directories and `HostSecret`
  files; default unit and owner from the app). Paths are checked before any
  operation; host secrets a restore handed to `restore_owner` go back to root
  `0600` on the next deploy. The five copies of `echoport_target.py`
  (archive, chesslab, opaq_app, weeknotes_home, work_app) are one shared
  script in `services/_echoport`. Behaviour changes for those services:
  `schedule_required` is now set on every registered target (Echoport
  migration 0008 is required; targets registered without it, such as
  opaq_app, weeknotes_home and work_app, update that one field on their next
  deploy, while archive and chesslab already set it), and archive and
  opaq_app pass their parameters as `PARAMS` instead of an environment
  variable.

- `delve`: Delve's server ad analysis, mirroring ops-library 2.48.0's
  `delve_deploy` (`delve_smart_skip_analysis`). New `DelveConfig` fields
  `smart_skip_analysis` (default off; off renders nothing new, so existing
  deploys are unchanged), the profile (`smart_skip_analysis_profile_src`,
  copied to `<config_dir>/smart-skip-analysis-profile.json`), the media
  directory (`delve:delve 0700`, an own `ReadWritePaths` line outside
  `data_dir`), disk cap, ffprobe/ffmpeg paths, apt `ffmpeg`, the voxhelm and
  detector origins with their secrets `voxhelm_token` and `detector_api_key`
  written to their own `root:delve 0640` files (never into `delve.env`), and
  the optional timeouts. The secrets must be single lines of at least 32
  characters and not `CHANGEME`, checked before any operation; the detector
  API key must also be at least 32 of `A-Z a-z 0-9 . _ ~ + / = -`
  (`DETECTOR_API_KEY_PATTERN`; llama-server skips key-file lines starting
  with `#`). The vendored `delve.env.j2` and `delve.service.j2` follow the
  role.

- Add the minimal native_app release/TOML/custom-unit and route-only runtime,
  with canonical rendering, restart/resume markers, stable routes and
  read-only preflight checks. Release preflight refuses unsafe ownership/write
  permissions before version execution and classifies undecodable tracked
  drift for verified repair. Package-manager sources remain deferred.

- Django-site database workers with resumable per-unit restart gates, uv
  transport environment, controller Python-pin assertions, optional env
  references and opt-in cache ownership repair. Existing site defaults stay
  unchanged; source sync preserves worker launchers.

- Preserve Django sites' existing `venv` aliases even without fish, and exclude
  controller Ruff caches from source sync. A canonical conversion no longer
  deletes the Wagtail-origin alias or deploys local lint-cache files. Preserve
  existing in-tree PostgreSQL media permissions; create missing media with
  the origin mode 0755 and refuse symlink/file substitutes.

- Add local PostgreSQL Django sites without shared-server management, Wagtail
  route/security preservation, required static paths, and resumable bootstrap
  step groups with secrets on stdin. SQLite defaults remain unchanged.

- `django_site`: an optional Next.js standalone frontend (`NextStandalone`:
  its own unit and `next.sh`, `npm ci` and `next build` gated on the source
  and a build-environment stamp, the middleware installed from a source file,
  purged public directories, a read-only legacy-code guard; the route sends
  its path prefixes to it at priority 200). Also: `BootstrapSuperuser`
  (`createsuperuser` when missing, the password set once), `app.env_dir`,
  `media.private_root` and data directories outside the site (`0750`),
  `steps.migrate_args`, `route.name` and `route.backend`, `hardening:
  "strict"`, typed public URL checks and a CSRF check (`checks.public`,
  `checks.csrf_path`), `Joined` env values, `Secret.strip`, `min_length` and
  `equals`, and `env.url_paths` (admin path secrets checked before any
  operation). A step group's `source` trigger now means the source changed
  (or a pending marker is left), not a dependency change alone. The launchers,
  the `venv` link and the frontend's middleware and purged directories are
  always excluded from the sync. A deploy stops before any change when the
  site holds markers of the old split-site module. marina's and heis's files
  render byte for byte as before. The split site's module (never merged) is
  replaced; its files and their differences are documented in
  [django_site](services/django_site.md), and an equivalence test runs its
  scenarios through the vendored old module and django_site.
- compose_app: typed steps `http_json_settings` and `http_json_items` for an
  app's JSON API (Servarr: host settings, root folders, download clients,
  Prowlarr applications and indexer proxies). Declarative: a read-only probe
  while planning, an apply only on drift, a verifying second read; items are
  created from a schema entry or corrected in place and never deleted;
  Servarr `fields` lists and tag labels are handled; masked write-only values
  are tracked by digest on the host. API keys may be `HostSecret` files read
  on the host. Config files may carry `{"env_var": NAME}` YAML leaves
  (`!env_var NAME`, for Recyclarr).

- New service `ops_deploy.services.compose_app`: one deploy for the Docker
  Compose apps, configured per app with a typed `ComposeAppConfig` (users,
  groups, directories with setgid modes, required mounts and paths, external
  networks, env files and config files with `Secret`, `HostId` and
  `HostSecret` values, `ComposeService`s with the keys the fleet uses and
  nothing passed through, a route, typed API steps, checks, legacy paths). It
  renders the compose file (long binds with `create_host_path: false`,
  loopback ports, `$` escaped, a provider's dependents with `depends_on`
  healthy and `restart: true`), single-quoted env files (completed on the host
  by `files/compose_host.py` when they hold a host secret or id; a host secret
  is created once and an existing one adopted unchanged) and a oneshot unit
  with `ExecReload` and `RequiresMountsFor=`. Images must be pinned by digest
  and are pulled only when missing. Every decision is made while planning
  from read-only probes and an applied stamp (`applied.json` and `pending` in
  `/var/lib/ops-deploy/<service>/`, root-only), so a converged host gets no
  mutating operation, an interrupted or failed run is finished by the next,
  only the services whose inputs changed are recreated (`systemctl reload`),
  the readers of a changed config file restart, a unit-only change touches no
  container, and a namespace provider's dependents are stopped before it can
  be replaced and start only once it is healthy. Typed steps:
  `qbittorrent_preferences` (qBittorrent 5.2's 204 login, the temporary
  password bootstrap, preferences by drift, no secret in the output) and
  `json_key_copy`. Read-only checks: the port preflight before any change,
  running and healthy services, shared network namespaces, ports listening on
  their address only. `remove_compose_app` (`ComposeAppRemoveConfig`) keeps
  the data. Its route has no router on the HTTP entrypoint. Documented in
  [compose_app](services/compose_app.md) with the
  torrent switch and a worked *arr example; torrent is its first consumer.
- New service `ops_deploy.services.shared_tree`: a group-writable setgid tree
  (ops-control's `media_storage`) with a plan-time-gated, idempotent repair.
- `helpers.traefik`: `TraefikRoute.internal_only` renders one internal
  router (`<name>-int`, ClientIP ranges; `-http` with the same rule) and no
  external one; compose_app's `access: internal`. Shared layer: 1,413 of
  1,500 code lines.
- `docker_install`: the apt cache update after a changed Docker repository
  is decided while planning, so a converged dry run (`pyinfra-check`) no
  longer lists it.

- `services/heis` is removed, with its tests, the vendored `heis_deploy`
  templates, its smoke and page, and `tests/test_django_site_equivalence_heis.py`:
  heis production and staging run django_site since 2026-10-16. The
  django_site smoke now deploys heis's shape from nothing.

- `django_site` makes the service group the primary group of an existing
  user that has another one (heis's user was created by the Ansible role
  with `users`, so the files it wrote had that group and every run repaired
  their ownership again): `usermod -g`, then a `chgrp` of the user's own
  files with the old group in its home and the site (`find -xdev`), with the
  old group kept in `~/.ops-deploy-regroup` until the move succeeded. The
  deploy stops before any change when `usermod`'s own move would touch
  files of other owners or other mounts in the home. Both steps are marked
  as owing the unit's restart and fold into the run's one restart; a user
  with the right group changes nothing.
- `django_site` keeps its markers (pending, restart, step groups, the
  regroup state) in `/var/lib/ops-deploy/<service_name>/` (`root:root 0700`,
  created with the first marker) instead of the service user's home, where
  the user could have planted a symlink that root's `touch` or write would
  follow. The usermod step also stops when the user's home in passwd is not
  the configured one.

- `django_site` takes heis's shape: `apt_packages` (installed before the
  user), `StepGroup.after` (`"migrate"` runs a group before `collectstatic`,
  like heis's content reconcilers; group markers are cleared by
  "Clear <group> marker") and the route's `canonical_redirect_regex`/
  `canonical_redirect_replacement` (heis's permanent redirect to the
  canonical host). `tests/test_django_site_equivalence_heis.py` runs every
  `test_heis.py` scenario, staging and production shape, through both
  modules. `services/marina` is removed (marina runs on django_site since
  2026-10-16), with its tests, parity templates, smoke and page; the
  django_site smoke now switches heis from `services/heis`.

- New service `ops_deploy.services.django_site`: one deploy for the
  Django/Wagtail sites, configured per site with a typed `DjangoSiteConfig`
  (source, app, SQLite database, local media, `.env` entries with `Secret`
  references, management-command `StepGroup`s with triggers and markers,
  `EnsureSuperuser`, the route with a required `public_reason`, local
  checks). It writes one canonical file set for every site: a single-quoted
  `.env`, a launcher that sources it and `exec`s gunicorn, the classic unit
  with `Group=` and `RestartSec=5`, the classic route and fish config, each
  with a "managed by" header. Markers in the home directory
  (`~/.ops-deploy-pending`, `~/.ops-deploy-restart-<unit>`) make the next run
  finish what a failed one left undone; a converged run changes nothing.
  `required_secret_keys` follows from the config. Switching marina from
  `services/marina` rewrites `.env`, `gunicorn.sh`, the unit, the route and the
  fish config once and restarts marina once; the differences are listed in
  [django_site](services/django_site.md). `services/marina` stays until the
  transitional equivalence test (every marina scenario through both modules)
  is removed. New dev dependencies python-dotenv and django-environ: the
  `.env` values are read back by the real parsers in the tests.

- `graphyard`: ports of `graphyard_deploy`, `graphyard_vector_deploy`,
  `graphyard_ingress_deploy` and `graphyard_auth_bootstrap_deploy` with the
  playbooks around them (`ops_deploy.services.graphyard`: core, Vector,
  ingress, auth bootstrap and the stack). Templates are shipped unchanged and
  byte-identical (`tests/test_graphyard_parity.py`; role digests recorded at
  ops-library 94047183). Secret files (env, compose, metric specs, Vector
  fragment) are written with `secret_file`; credentials reach the host on
  stdin only (the InfluxDB v1 login is created through InfluxDB's HTTP API,
  not `influx v1 auth create --password`; env-file secrets that bash would
  read differently are refused). Steps are skipped when the host already
  matches: the InfluxDB v1 login, bucket retention and static files are
  probed, the metric collection specs are compared by digest, and the auth
  bootstrap (a deploy-time reconcile) checks the Django user and Grafana's
  admin password on the controller and resets only on a difference (`grafana cli --password-from-stdin`). The core takes a
  git source (`source_commit`). `logyard.vector.env_line` (was `_env_line`)
  is shared by both Vector producers.
- Graphyard and Logyard share the Grafana tree in Graphyard's site under one
  ownership rule: Logyard owns its datasource file and `dashboards/logyard`
  (`root:root`), Graphyard everything else. Graphyard's ownership step skips
  Logyard's paths (`GraphyardConfig.foreign_paths`) and Logyard's deploy no
  longer sets the shared `datasources/` and `dashboards/` directories to
  root, which ended the role's ping-pong (an owner change and a Grafana
  restart after every deploy of the other). The Graphyard sync keeps
  Docker's `dashboards-json` mount point, which the role's sync deletes
  (detaching Grafana's dashboards until it restarts).

- `nyxmon`: the Rust monitoring agent is ported (the role's `agent_rust.yml`
  and `agent_verify.yml`, ops-library 2.32.0). `agent_impl` accepts `python`
  and `rust`. The new `agent_rust_version`, `agent_rust_sha256`,
  `agent_rust_release_url` (with a `{version}` placeholder),
  `agent_rust_local_archive` and `agent_rust_keep_versions` take the role's
  defaults and are checked like the role checks them. A pinned release is
  downloaded (or uploaded) and must have the pinned sha256 and hold only the
  regular files `nyxmon-agent` and `LICENSE`. It is installed root-owned to
  `/opt/nyxmon-agent/<version>/` and validated with `--version` and
  `--check-schema` as the service user. A rejected fresh install is removed
  again, and an installed version from another archive stops the deploy.
  `rust` writes the role's `agent-impl.conf` (vendored, compared byte for
  byte), `python` removes it; a switch restarts only `nyxmon-monitor`, and
  `.previous-version` keeps the rollback target. The agent check follows the
  selected implementation, and old versions are pruned after it. The host
  steps are `services/nyxmon/files/agent.sh`; the new smoke test
  `tests/smoke/test_nyxmon_agent_smoke.py` runs it on the smoke VM against
  bad archives, failing candidates and the pruning rules.
- Git source: `ops_deploy.core.git_source.fetch_source` fetches a service's
  code from its git remote at a branch, tag or full commit (default: the
  remote's default branch) on the controller, with the operator's own git and
  SSH setup, into a fresh directory that the deploy syncs like a checkout;
  hosts need no git credentials. It fails closed on a missing ref, a name
  that is both a branch and a tag, another commit than asked for or a file
  that is not byte for byte its committed blob (attributes and filters are
  switched off; LFS and submodules are refused), and refuses repository URLs
  with credentials. `MarinaConfig` and `HeisConfig` gain
  `source_commit`; their deploys end with `record_source` (new in
  `ops_deploy.helpers`), which keeps the commit in
  `<site>/.ops-deploy-source` (removed for a local working tree), so a re-run
  of the same ref changes nothing. See [Git source](concepts/git-source.md).

- `traefik_deploy`: the log rotation file follows ops-library 2.39.2: Traefik
  gets `SIGUSR1` after `access.log` is rotated (the old
  `systemctl reload traefik || true` did nothing, so the renamed file kept
  growing), and `traefik.log` is rotated with `copytruncate`. The role's
  template is vendored and compared byte for byte for several configs, and
  `traefik_deploy` joins the roles `tests/test_ops_library_drift.py` watches.
- Ports caught up with ops-library main (fd6b4cf1), ops-control main and the
  live hosts:
  - `fastdeploy`: the deploy removes the retired wildcard rule
    `/etc/sudoers.d/fastdeploy` instead of installing it (`fastdeploy_deploy`
    2.35.0); `templates/sudoers.j2` and its vendored role template are gone.
    The restore never brings back retired services and runners
    (`fastdeploy-self`, `fastdeploy-self-playbook.yml`, `apt_upgrade_local`,
    `apt_upgrade_staging`) or retired sudoers files, and restores another
    sudoers file only when the role's `sudoers_blanket_check.py` (vendored
    under `files/`) passes it, so no `deploy ALL=(root) NOPASSWD: ALL` rule
    comes back from an older archive (`fastdeploy_restore` 2.35.0).
  - `fastdeploy` and `nyxmon`: a changed Traefik route no longer restarts
    Traefik (ops-library 2.31.47); its file provider loads the change.
  - `nyxmon`: `agent_impl` mirrors the role's `nyxmon_agent_impl`: with
    `python` the Rust agent drop-in `agent-impl.conf` is removed and a
    read-only check proves the monitor runs the venv's `start-agent` (the
    role's `agent_verify.yml`). Installing and selecting the Rust agent
    followed later (see the `nyxmon` entry above).
  - `work_app` restore: `safe_snapshot_delete` defaults to `False`; the
    pre-restore copy is kept and its path reported (ops-library a811bc16).
  - `tests/test_ops_library_drift.py`: with `OPS_LIBRARY_PATH` set, fails
    when a vendored role file or a mirrored role changes in ops-library
    (digests in `tests/parity/ops_library_roles.json`). See
    [Testing](concepts/testing.md#drift-from-ops-library).
- echoport and archive no longer use the MinIO root credentials, following
  ops-control's `deploy-echoport.yml` and `deploy-archive.yml`.
  `EchoportConfig.minio_account` (`MinioAccount`, default `echoport-retention`)
  ports `minio_deploy`'s `backup_account` include: the policy
  `backup-echoport-retention` (the role's template, vendored for parity:
  list, read and delete in the whole bucket, no writes) and the user
  `bk-<sha256(name)[:17]>` are created or updated through root's MinIO admin
  alias `local` (required: `mc admin info local` must succeed first), only
  when a probe finds them missing or different; the cleanup user's `mc` alias
  then uses that account (`minio_access_key` is refused with an account,
  `minio_secret_key` needs 32 to 40 characters). archive's `MinioBootstrap`
  drops `root_env_file` for `admin_alias` (`local`): probe and bootstrap make
  their admin calls through it after the same required check, the app secret
  and the app's alias (JSON for `mc alias import` into a temporary mc
  configuration) reach the bootstrap and the media migration on stdin, and
  `minio_root_user`/`minio_root_password` are refused. No script puts
  credentials into `MC_HOST_*` any more. `minio_deploy` joins the roles
  `tests/test_ops_library_drift.py` watches.
- Commands no longer depend on the SSH user's login shell. Root's on macmini
  and staging is fish, which halves backslash pairs inside single quotes, so
  the weeknotes_home env loader (`python -c` with a regex) crashed live with
  `re.PatternError`. The loader is now a file the deploy installs
  (`/home/weeknotes-home/env-exec.py`, run with `python -I`), and the
  FastDeploy restore builds its pgpass escapes without backslashes in the
  script. `run_deploy_fake` fails any deploy test that would send a command
  fish reads differently (`fish_unsafe` on the exact `wire_command`, also for
  `_if`-gated operations), and `tests/test_remote_shell_execution.py` runs
  generated commands through real bash and fish. The smoke VM gives root the
  fish login shell (`smoke/provision.sh`); smoke checks go through `sh`
  (`SmokeHost.run`).
- Strict probes (`ops_deploy.helpers.probes`): migrations, static files,
  dependency (`uv sync --check`/`--dry-run`), admin, wiring, MinIO, Nyxmon and
  FastDeploy probes of archive, chesslab, echoport, fastdeploy, heis, logyard,
  marina, nyxmon, opaq_app, weeknotes_home and work_app no longer read an
  error as "not current". States normal before a first deploy are explicit
  answers; a failed probe runs the step it gates and then probes again
  ("Probe again: ..."), failing the deploy if the probe still fails. See
  [Deploy helpers](concepts/helpers.md#strict-probes-ops_deployhelpersprobes).

- `ops_deploy.services.nyxmon` and `ops_deploy.services.fastdeploy`: backup,
  restore and removal, ports of the `nyxmon_backup`/`_restore`/`_remove` and
  `fastdeploy_backup`/`_restore`/`_remove` roles. Archives and snapshot
  directories have the roles' layout and metadata, so either tool restores
  the other's backups. Backup and restore each run as one bash script on the
  host, which keeps the roles' structure: services always restart after a
  backup, and a failed restore puts back the safety copy or safety backup and
  still fails. The FastDeploy database password reaches the host on stdin
  only. Removals need `confirm`, only act on what exists and change nothing
  on a second run. Shared pieces live in `ops_deploy.services._lifecycle`,
  outside the size-capped layer. Fake connector tests and two lifecycle smoke
  tests; see [nyxmon](services/nyxmon.md) and
  [fastdeploy](services/fastdeploy.md).

- `ops_deploy.services.echoport`: `deploy_echoport`, a port of the
  `echoport_deploy` role (rsync method, uv) plus the steps ops-control's
  `deploy-echoport.yml` runs around it (loopback listener check, Nyxmon
  health check upsert). Ships the role's templates unchanged, so the env file,
  unit, Traefik route and staging refresh script are byte-identical. The
  service user's crontab is edited in Ansible's `cron` format, so the two
  tools never add a second copy of a job. migrate runs when code changed or a
  migration is pending; the admin account, the cleanup user's `mc` alias
  (credentials on stdin, not the role's `mc alias set` arguments), the
  crontab and the Nyxmon check are probed read-only and written only when
  they differ. Fake connector, parity, host script and smoke tests; see
  [echoport](services/echoport.md).

- `ops_deploy.services.logyard`: `deploy_logyard`, `deploy_logyard_core`,
  `deploy_logyard_ingress` and `deploy_logyard_vector`, ports of the
  `logyard_deploy`, `logyard_ingress_deploy` and `logyard_vector_deploy` roles
  and the playbook steps around them (Nyxmon checks upsert). Templates shipped
  unchanged, files byte-identical to the roles'; Grafana is restarted only
  when its datasource, dashboards or network changed. See
  [logyard](services/logyard.md).

- `ops_deploy.infra`: `deploy_docker_install` and `deploy_vector_apt_install`,
  ports of the `docker_install` and `vector_apt_install` roles (the repository
  files are the ones the roles write). See [infra](infra.md).

- `ops_deploy.services.work_app`: `deploy_work_app_backup`,
  `deploy_work_app_restore` and `deploy_work_app_remove`, ports of the
  `work_app_backup`, `work_app_restore` and `work_app_remove` roles. The
  archive layout and `metadata.yml` match the roles', so either tool restores
  the other's archives. Restore checks the archive (slug, metadata, version)
  from its listing before it changes anything. Fake connector and smoke
  tests; see [work_app](services/work_app.md).

- `ops_deploy.services.work_app`: `deploy_work_app`, a port of the
  `work_app_deploy` role (rsync method) and of the port preflight, Echoport
  backup target and Nyxmon health check in ops-control's
  `deploy-work-app.yml`. `.env`, unit and Traefik route are byte-identical to
  the role's (parity tests against the vendored templates). `src/` and
  `ledger/` are synced with `--delete` inside each, the SQLite database,
  `.env`, venv and static files never are. Migrations, `collectstatic` and the
  upserts run only when needed (the upserts probe read-only first), so a
  converged deploy changes nothing. Fake connector tests and
  `tests/smoke/test_work_app_smoke.py`; see [work_app](services/work_app.md).

- `ops_deploy.services.heis`: `deploy_heis`, a port of the `heis_deploy`
  role (rsync method). `.env`, unit, launcher, fish config and the Traefik
  route (TLS rule, canonical redirect) are byte-identical to the role's
  (parity tests against the vendored templates, including production's
  shape). The Wagtail content reconcilers follow the role's switches
  (production: off) and run only when the source, dependencies or schema
  changed; the SQLite database and media are never shipped or deleted. Fake
  connector, parity and smoke tests; see heis (its page was removed with the module).

- `ops_deploy.services.archive`: `deploy_archive`, a port of the
  `archive_deploy` role (rsync method) plus the steps ops-control's
  `deploy-archive.yml` runs around it (MinIO bucket and service account,
  local media migration, Echoport backup target). Ships the role's templates
  unchanged, so env files, units and the Traefik route are byte-identical.
  migrate/collectstatic, the admin account, MinIO and Echoport are probed
  read-only and written only when they differ; credentials travel on stdin
  only. Fake connector, parity and smoke tests; see
  [archive](services/archive.md).

- `ops_deploy.services.chesslab`: `deploy_chesslab`, a port of the
  `chesslab_deploy` role (rsync method) and of the Echoport backup target and
  Nyxmon health check upserts in ops-control's `deploy-chesslab.yml`.
  `.env`, unit and Traefik route are byte-identical to the role's (parity
  tests against the vendored templates). Like the playbook, it checks the app
  port before any change and stops when the SQLite database is missing.
  Migrations, `ensure_admin` and the upserts run only when something needs
  them (the upserts probe read-only first), so a converged deploy changes
  nothing. App users (a JSON list secret) reach the host only on stdin. Fake
  connector tests and `tests/smoke/test_chesslab_smoke.py`; see
  [chesslab](services/chesslab.md).

- `ops_deploy.services.delve`: `deploy_delve` and `build_delved`, a port of
  the `delve_deploy` role (the Delve backend Go binary behind Traefik, plus
  the Discovery collector oneshot and timer). The binary is cross-compiled on
  the controller as the playbook does; reproducible builds keep an unchanged
  checkout a no-op. A new binary is staged next to the old one and renamed
  in, since writing into the running executable fails. Env file, units and
  route are byte-identical to the role's; Traefik picks the route up through
  its file watcher (the role's reload handler is a no-op). Optional
  `public_health_check` checks `/health` through Traefik on the host. Fake
  connector, parity and smoke tests; see [delve](services/delve.md).

- `ops_deploy.services.recorder`: `deploy_recorder`, port of the
  `recorder_deploy` role plus the controller build (`npm ci`, `npm run build`,
  `go build` for linux/`goarch`) and the external-URL smoke gate of
  ops-control's recorder playbook. Env file, unit and Traefik route are
  byte-identical to the role's (parity tests against the vendored
  templates); recorder restarts only when the binary, env file or unit
  changed, and Traefik is never restarted (the role's reload is a no-op).
  Fake connector tests and `tests/smoke/test_recorder_smoke.py`; see
  [recorder](services/recorder.md).

- `ops_deploy.services.static_site`: `deploy_static_site`, port of the
  `static_site_deploy` role. Controller-side source validation (regular files
  only, no symlinks, optional exact file allowlist), rsync publish, hardened
  loopback HTTP server unit and Traefik route; server script, unit and route
  are byte-identical to the role's (parity tests against the vendored
  templates). The service restarts only when the server script or unit
  changed; Traefik is never restarted. Fake connector tests and
  `tests/smoke/test_static_site_smoke.py`; see
  [static_site](services/static_site.md).

- `sync_tree` takes `chmod` (rsync `--perms --chmod=...`): modes are enforced
  on existing files too and a mode-only difference counts as a change. Used
  for the static site's `D0755,F0644` / private `D0750,F0640` publication.

- `ops_deploy.services.marina`: `deploy_marina`, a port of the `marina_deploy`
  role (rsync method, uv). `.env`, `gunicorn.sh`, unit, fish config and Traefik
  route are byte-identical to the role's (parity tests against the vendored
  templates). The source sync never deletes, as in the role, so the database,
  media and collected static files stay. Migrations, `collectstatic` and
  `ensure_superuser` run only when something needs them, so a converged deploy
  changes nothing; the admin account travels on stdin only. Fake connector tests
  and `tests/smoke/test_marina_smoke.py`; its page was removed with the module (see [django_site](services/django_site.md)).

- `ops_deploy.services.opaq_app`: `deploy_opaq_app`, port of the
  `opaq_app_deploy` role together with the steps of `deploy-opaq-app.yml`
  around it (the guard against taking over a name a static page routes, the
  login and allowlist checks, the Echoport backup target and the Nyxmon
  health check) and the playbook's port preflight (nothing but opaq-app
  may listen on the app port). Environment file, unit and Traefik route are byte-identical
  to the role's (parity tests against the vendored templates); the route is
  written without a Traefik restart, as the role does. The database lives
  outside the synced tree and is never touched by a sync. The Echoport and
  Nyxmon entries are probed first and written only when they differ. Fake
  connector tests and `tests/smoke/test_opaq_app_smoke.py`; see
  [opaq_app](services/opaq_app.md).

- `ops_deploy.services.weeknotes_home`: `deploy_weeknotes_home`, a port of the
  `weeknotes_home_deploy` role (rsync method) and of the FastDeploy service
  row, Echoport backup target (with its FastDeploy service token, issued only
  when the stored one is unusable and piped, never written) and Nyxmon check
  upserts in ops-control's `deploy-weeknotes-home.yml`. Env file, unit and
  Traefik route are byte-identical to the role's (parity tests against the
  vendored templates). Like the playbook, it checks the app port before any
  change. Migrations and `collectstatic` run only when needed, and
  `src/daybook.egg-info` is not removed by the sync, so a converged deploy
  changes nothing (the role restarts the service on every run). Fake
  connector tests and `tests/smoke/test_weeknotes_home_smoke.py`; see
  [weeknotes_home](services/weeknotes_home.md).

- `ops_deploy.infra`: `deploy_traefik`, `deploy_traefik_backup`,
  `deploy_traefik_restore` and `deploy_traefik_remove`, ports of the
  `traefik_deploy` (full deploy), `traefik_backup`, `traefik_restore` and
  `traefik_remove` roles. Static config, unit, certificate list and log
  rotation are byte-identical to the role's (parity tests against the
  vendored templates). Deploy, restore and remove refuse transaction-managed
  hosts before any change, as the role's guard does. The static config and
  certificate list are validated before anything is written, a new binary
  must report its version before Traefik restarts, and Traefik restarts only
  on a real change (also a new binary, which the role leaves running old).
  A release checksum is required. Fake connector tests and
  `tests/smoke/test_traefik_smoke.py`; see [Traefik](traefik.md). PyYAML is
  now a runtime dependency (certificate list validation).
- The vendored-template check accepts templates in role subdirectories
  (`<role>__<dir>__<file>`).

- `ops_deploy.infra` (outside the size-capped layer): `deploy_postgres_install`
  and `deploy_redis_install`, ports of the `postgres_install` and
  `redis_install` roles. `pg_hba.conf`, the `conf.d` drop-in, `redis.conf` and
  the PGDG `.sources` file are byte-identical to what the roles write (parity
  tests against the vendored templates and macmini's files). Databases go
  through `postgres_database`, which never drops or recreates; `redis.conf`
  (it may hold `requirepass`) is written with `secret_file` and the old file
  kept as a backup like the role's; a server that answers without its
  password or started before its current `redis.conf` is restarted. Fake
  connector tests and `tests/smoke/test_infra_smoke.py`; see
  [PostgreSQL and Redis](infra.md).
- `postgres_database`: while the server is not installed or not running at
  planning time (the same deploy sets it up) the plan treats the role and
  database as new instead of failing; new `port` (cluster) and `enabled`
  arguments; psql now always passes `-p`.

- Base deploys in `ops_deploy.base` (outside the size-capped layer), ported
  from the ops-library base roles: `hostname`, `headless_mode`,
  `systemd_unit_masks`, `ssh_authorized_keys` (whole file, byte-identical to
  the role's template, installed atomically), `uv_install` and
  `shell_basics` (pinned, checksum-verified downloads renamed into place),
  `nodejs_install` (NodeSource line, apt pin, read-only version check).
  Fake connector tests for each and `tests/smoke/test_base_smoke.py` (two
  runs per deploy, the second without change); see [base deploys](base.md).

- Size cap: `just size-cap` (`scripts/size_cap.py`, also a CI step and a
  test) fails when helpers + ops + core exceed 1,500 code lines; see
  [development](development.md#size-cap-on-the-shared-layer).
- `BaseServiceConfig` no longer imports pydantic's private
  `ModelMetaclass`; `Config(...)` and the `model_validate*` methods still
  raise `ConfigValidationError`. Constructor calls on config classes are
  now type-checked against the field types (previously typed `Any`), so
  pass `SecretRef(...)` rather than a plain string in typed code.
- `systemd_unit` drops its unused `unit_dir` argument.

- `fastdeploy` service: port of the `fastdeploy_deploy` role (rsync method)
  with `FastdeployConfig`, byte-identical env, unit and sudoers files (parity
  tests against the vendored role templates), host-state
  `persistent_excludes` (registered services, env files, venv, build output),
  NodeSource Node.js, a frontend build gated on a digest of its inputs, change
  -gated `uv sync`/`syncservices`, initial and legacy token users created only
  when missing, the role's unconditional restart and a token-minting auth
  check; fake connector scenarios and a smoke test (`FASTDEPLOY_SOURCE`).
- `postgres_database` helper: login role, database and schema owner; the
  password goes to PostgreSQL as a SCRAM verifier computed on the controller.
- `sudoers_file` helper: sudoers drop-in validated with `visudo` before it
  replaces the installed rule.
- `secret_stdin` operation: run a command with a secret on stdin.
- Smoke VM: PostgreSQL 17 from PGDG and `build-essential` (asyncpg has no
  wheel for Python 3.14 on arm64).

- `sync_tree` compares files by checksum and no longer syncs times
  (`-rl --checksum` instead of `-rlt`): a fresh clone of unchanged code is a
  no-op. Real-rsync test for time-only differences; the nyxmon smoke deploys
  from a fresh export and expects no mutating change.
- `nyxmon` service: port of the `nyxmon_deploy` role (rsync method) with
  `NyxmonConfig`, byte-identical env and unit files (parity tests against the
  vendored role templates), host-state `persistent_excludes`, SQLite privacy
  (umask drop-ins, `0600` database), an OpsGate live-environment check, fake
  connector scenarios and a smoke test (`NYXMON_SOURCE`).
- Deploy helpers in `ops_deploy.helpers`: `system_user`, `systemd_unit`,
  `service_rollout` (daemon-reload and restart only on change; optional
  unconditional restart), `uv_sync` and `django_manage` (run as the service
  user via `runuser`, gated with `when_changed`), `traefik_route` with
  `TraefikRoute`/`BasicAuth` (controller-side bcrypt in `htpasswd -B` format,
  reusing a deployed hash that still matches), and the read-only checks
  `wait_port` and `http_check`.
- Test harness: `OpResult.read_only` and `FakeRun.mutating_changed_ops`, so a
  converged second run can be asserted while ignoring read-only checks.
- `system_user` leaves an existing user's home, shell and primary group
  unchanged, as the roles do, and logs a warning on any difference.
- `toyweb` service: a toy uv/Django app that uses every helper plus
  `sync_tree` and `secret_file`, with deploy-level scenarios.
- Parity tests against the nyxmon and fastdeploy Traefik role templates.
- New dependency `bcrypt`; new dev dependencies `pyyaml`, `types-pyyaml`.

## 0.1.0 (unreleased)

- Project skeleton: uv, ruff, mypy (strict), pytest, mkdocs, GitHub Actions CI.
  pyinfra pinned to `3.10.*`, Python 3.12+.
- `BaseServiceConfig` with `CHANGEME` rejection (input, defaults and
  validated values), sanitized `ConfigValidationError`, `ServiceName` and `UnixUser`
  field types, and `required_secret_keys`.
- `SecretRef`, `SecretValues` (redacted, unpicklable) and the `SecretStore`
  protocol.
- `ops_deploy.testing`: `run_deploy_fake` with recording of facts, shell
  commands, uploads and `FunctionCommand` callbacks; `RecordingRsyncRunner`.
- Injectable controller-side rsync runner (`ops_deploy.core.rsync`).
- `toy` service deploy with first-run, no-op and change-run tests.
- `ops_deploy.ops.sync_tree`: rsync a controller directory to the host,
  replacing `ansible.posix.synchronize`. Plan-time itemized dry run (cached, so
  it runs once per deploy), owner set with `--chown` and never preserved,
  mandatory excludes for VCS/tool state and deploy state markers. The toy
  service uses it.
- `ops_deploy.ops.secret_file` and `SecretContent`: install a secret sent over
  stdin with a host-side Python installer that never follows symlinks and
  works through descriptors: a private 0700 staging directory next to the
  destination (checked on its descriptor), a 0600 `O_EXCL` file inside it,
  `fchown`/`fchmod`/`fsync`, and a rename as the commit point (directory
  `fsync` and staging cleanup after it are best effort). Interrupted or failed
  writes leave the destination untouched and remove the staging directory;
  leftovers from a killed run are removed by the next run. Forces
  `_get_pty=False`. Hosts need `python3` 3.8+.
- Harness: `FakeRun.stdin` records command stdin (excluded from `all_text()`),
  and `OpResult.args` records pyinfra's operation argument strings (included
  in `all_text()`).
- Smoke target: `smoke/vm.sh` and `just smoke-up`/`smoke`/`smoke-ssh`/`smoke-down`
  manage a local lima Ubuntu 24.04 VM with root SSH (pinned host key), uv and
  Traefik. `just smoke` deploys toyweb twice over pyinfra's ssh connector
  (second run: no mutating changes) and runs `secret_file` fault and leak
  tests on the VM.
- `ops_deploy.testing.run_deploy_ssh` and `SshRun`; `DeployRun` is the shared
  base of `FakeRun` and `SshRun` (`succeeded`, `changed_ops`,
  `mutating_changed_ops`, `op`).
- `sync_tree` passes `--omit-dir-times`: an app writing into a synced
  directory no longer makes every later deploy resync and restart. It also
  passes `ssh_key`, `ssh_known_hosts_file` and `ssh_strict_host_key_checking`
  from host data to rsync's ssh.
