# minecraft_java

Deploy-only port of the public `minecraft_java_deploy` role at ops-library
`3110a0f1` (2.68.0): Debian/Ubuntu, OpenJDK, mcrcon 0.7.2, vanilla or Forge,
mod JARs, server properties, whitelist/operators, UFW and a systemd service,
the port of the `minecraft_java_remove` role (see [Removal](#removal)) and
the ports of `minecraft_java_backup` and `minecraft_java_restore` (see
[Backup and restore](#backup-and-restore)). The deploy neither creates nor
changes nor removes existing backup jobs, scripts, directories or archives.

```python
from ops_deploy.core import SecretRef
from ops_deploy.services.minecraft_java import MinecraftJavaConfig, deploy_minecraft_java

cfg = MinecraftJavaConfig(
    secrets=SecretRef("secrets/minecraft.yml"),
    eula_agreed=True,
    server_jar_url="https://example.org/server.jar",
    server_jar_sha256="a" * 64,  # replace with the artifact's SHA256
    firewall_allowed_networks=("192.0.2.0/24",),
)
deploy_minecraft_java(cfg, store.load(cfg.secrets))
```

`eula_agreed=True` explicitly accepts the Minecraft EULA. The only required
secret is `rcon_password` (at least eight ASCII characters from
`A-Za-z0-9_+/.=:@%-`; ambiguous properties/EnvironmentFile escaping is refused).
`server.properties` is `0640`, the environment file is `0600`, both owned by
the service user. Secrets travel on stdin; errors never include their values.
The unit inherits `MCRCON_PASS` and invokes mcrcon without a password argument.
The environment retains `RCON_PASSWORD` for existing backup scripts.

## Configuration

| Fields | Defaults / behavior |
|---|---|
| `service_name`, `user`, `group` | `minecraft-java`, `minecraft`, `minecraft` |
| `home`, `site_path` | `/opt/minecraft`, `/opt/minecraft/server`; absolute plain paths without parent traversal |
| `loader_mode` | `vanilla`; `forge` requires the inputs below |
| `server_jar_url`, `server_jar_sha256` | required in vanilla mode |
| `forge_version`, `forge_installer_url`, `forge_installer_sha256` / `forge_installer_sha1` | required in Forge mode; SHA256 preferred; installer reruns if version/checksum markers or runtime artifacts differ |
| `java_version`, `memory_min`, `memory_max`, `extra_args` | `21`, `2G`, `4G`, the role's optimized G1 flags |
| `java_arch` | `amd64` (or `arm64`); the unit, the Forge wrapper and the Forge installer run `/usr/lib/jvm/java-<java_version>-openjdk-<java_arch>/bin/java`, verified after the package install, never the `/usr/bin/java` alternative |
| `startup_timeout` | 60 seconds for vanilla, 300 for Forge |
| `world_name`, `allow_mode_switch_same_world` | `world`, false; an absent loader marker means vanilla; same-world loader changes fail before mutations unless acknowledged |
| `mods_enabled`, `mods_prune_unmanaged`, `mods` | false, false, empty; Forge only. Entries require `name`, HTTPS `url`, SHA256; optional `filename`, `version`, `enabled` (true). A missing filename uses the URL basename. Disabled entries are removed; pruning removes unmanaged regular `*.jar` files only when explicitly enabled |
| `port`, `rcon_port` | 25565, 25575; must differ |
| `firewall_allowed_networks` | required nonempty CIDR list; no private network defaults |
| `service_state` | `started`; `stopped` keeps the unit stopped while converging runtime/configuration; enablement remains true |
| `rcon_enabled`, `firewall_enabled` | true required; disabling either is deliberately unsupported |
| `difficulty`, `gamemode`, `max_players`, `pvp` | normal, survival, 20, true |
| `motd`, `seed`, `level_type` | A Minecraft Server, empty, `minecraft:normal`; MOTD/seed are printable ASCII without backslashes |
| `online_mode`, `view_distance`, `simulation_distance`, `spawn_protection` | true, 10, 10, 16 |
| `allow_flight`, `allow_nether`, `generate_structures`, `max_world_size` | false, true, true, 29999984 |
| `whitelist_enabled`, `whitelist_players`, `ops` | false, empty, empty; empty operators and disabled whitelist retain existing files, matching the role |

Artifact URLs must use HTTPS without credentials, query strings or fragments.
Downloaded JARs are verified and atomically replaced entirely as the service
user, including staging and permission changes; no root write runs inside a
service-owned download stage. Forge runs as the service user. mcrcon 0.7.2
is checked through the strict planning probe and built from verified commit
`b5951e96349ec2ecf72b468459fc503a7067ba1f` in a unique private temporary
directory with cleanup on success and failure. A missing binary or failed/unsupported
version probe schedules the build; a strict version check after the build must
succeed before runtime files are installed. Missing server, Forge installer and
mod JARs are downloaded without first trying to hash their absent destinations.
No world data is
removed. Forge artifacts remain when changing back to vanilla.

Several JDKs can be installed side by side; the deploy installs
`openjdk-<java_version>-jre-headless` and removes none. Installing a newer JDK
moves Debian's `/usr/bin/java` alternative to it, which is why the runtime
names its JDK explicitly: Minecraft 26.x needs Java 25, Forge 1.20.1 runs on
Java 21, and switching `loader_mode` back to Forge with `java_version="21"`
starts Forge on Java 21 even though Java 25 stays installed.

For `service_state="started"`, UFW must already be active; this is checked
before any package, file or service mutation. A stopped deployment maintains
the same rules even if UFW is inactive, matching the role, and never enables
it. This is offline configuration coverage, not proof that RCON is protected
while running. Starting the service later requires active UFW and auditing
rule ordering. The deploy never enables/resets UFW, adds game
allow rules for the configured networks and an external RCON deny, and fails
before starting the service if UFW is inactive. Existing unrelated firewall
rules remain operator-owned; audit rule ordering before the first live use.
Forge's clean RCON shutdown exit status 143 is accepted by systemd.
Missing mcrcon/configuration files are normal bootstrap states; strict probes
still verify the installed outputs and surface failures of existing files.
The unit is reloaded only if changed, the service restarts only for changed
runtime inputs, and game TCP plus authenticated RCON are required after start.
For a stopped deployment the service is stopped before changing runtime inputs,
remains enabled (as in the role), and must finish inactive (or in the legacy
clean-stop failed/exit-code/143 state) with no game or RCON
listener. No running health probe is claimed for that state. This does not
prevent an operator or reboot from subsequently starting the enabled unit.
A pending loader/world transition is recorded before changing properties,
retaining the previous pair across partial failure. A retry must resume that
candidate; unrelated pending-state drift is refused. After verification the
legacy `.loader_mode` and completed `.loader_state.json` are persisted. A
completed sidecar never overrides a later Ansible deployment's current marker
and properties. Converged runs write neither a pending nor a completed marker.

### Recovering a pending loader transition

The normal recovery is to correct the failure (for example, the installer URL)
and rerun the **same** pending loader/world pair. The guard refuses a different
candidate, including a return to the original pair, even with
`allow_mode_switch_same_world=True`. That flag only acknowledges the risk of a
same-world loader switch; it does not cancel a pending transaction.

To abandon a pending candidate, use an explicitly approved maintenance window:

1. Stop the service and keep it stopped throughout recovery. Preserve a private
   copy of `.loader_state.json`, `.loader_mode`, `server.properties`, the runtime
   files and all affected worlds before editing anything. Properties contain the
   RCON password; do not paste them into logs or review artifacts.
2. Read the original `loader_mode`/`world_name` and pending pair from
   `.loader_state.json`. Restore the original loader's known-good runtime,
   configuration and original world from the matching pre-transition backup.
   If a loader has opened that world, restore its snapshot as well; changing a
   marker alone cannot undo a world-format change. Keep new-world data separate.
3. Verify the restored `.loader_mode` and `level-name` match the original pair.
   Only after this restoration, replace `.loader_state.json` atomically with a
   JSON object containing just the original `loader_mode` and `world_name`
   (remove both `pending_loader_mode` and `pending_world_name`). Retain service
   ownership and mode `0644`; keep the saved pending sidecar for diagnosis.
4. Configure the original pair, run the guard/plan, and inspect it before any
   deployment. Complete the approved deploy, verify game TCP and authenticated
   RCON, then run again to prove convergence before ending maintenance.

Do not delete the sidecar or clear its pending keys merely to bypass a failed
transition. If no matching known-good runtime/world backup exists, keep the
service stopped and investigate instead of claiming rollback is safe. This is
manual recovery guidance; the deploy performs no automatic rollback.

`server.properties` compares managed values semantically: Java's startup
comment/timestamp, key order and unrelated added defaults cause no rewrite or
restart. This deliberately supports only single-line ASCII `key=value` files
with Java punctuation/Unicode escapes; continuations, whitespace separators,
duplicate keys, control escapes and unsupported syntax fail before mutations.
Configurable MOTD/seed values are printable ASCII without backslashes or
leading spaces (Java otherwise strips unescaped leading value whitespace). Player
JSON compares names and managed fields while retaining server-added UUIDs. All
managed text writes reuse the descriptor-pinned installer; comparison requests
carry their contents on redacted stdin and run as the service user. Run twice to prove real
convergence before switching an engine.

## Removal

`remove_minecraft_java(MinecraftJavaRemoveConfig(confirm_removal=True))` ports
the `minecraft_java_remove` role at ops-library `55a23d33` (the role files are
recorded under `tests/parity/minecraft_java/remove`). Without `confirm_removal`
it fails before any host probe. The defaults are the role's, not the deploy's:
`user`/`group` `minecraft`, `home` `/home/minecraft`, `service_name`
`minecraft-java`, `port` 25565, `rcon_port` 25575 and
`firewall_allowed_networks` `192.168.0.0/16`, `10.0.0.0/8`, `100.64.0.0/10`.
A root account, `/`, a top-level directory or a traversal as `home` is refused.

The role's order, with its ignored failures (marked *ignored*):

1. stop the service (*ignored*), then disable it (*ignored*), with the
   `systemd` module's semantics (an absent unit is a failure, ignored);
2. remove `/etc/systemd/system/<service_name>.service` and reload systemd;
3. remove the user crontab job named `Minecraft world backup` the way the
   `cron` module does (every `#Ansible: Minecraft world backup` line with the
   line after it; the crontab is rewritten only on a change) (*ignored*);
4. `pkill -u <user>` when the user runs a process (`|| true`, as the role);
5. remove `home` (file, directory or leaf link, not followed), then
   `userdel -r <user>` when the account exists (a failure stops the removal),
   then, beyond the role, the user's crontab file in Debian's spool
   `/var/spool/cron/crontabs/<user>` when it is there, whatever it holds
   (the `cron` module leaves it empty and `userdel` keeps it), then the
   group when it still exists (*ignored*);
6. with `ufw` installed: `ufw delete allow from <network> to any port <port>
   proto tcp` per network and `ufw delete deny from any to any port
   <rcon_port> proto tcp` (*ignored*; ufw reports a rule that is not there
   and changes nothing, so these run on every removal);
7. the role's `reload systemd` handler, when the unit file was removed.

`/opt/backups/minecraft-java`, the Echoport archives and UFW's own state stay.

## Backup and restore

`ops_deploy.services.minecraft_java` ports the `minecraft_java_backup` and
`minecraft_java_restore` roles at ops-library `55a23d33`
(`ops_deploy/services/minecraft_java/lifecycle.py`, host program
`files/lifecycle_host.py`). Archives written by either tool restore with the
other: the role restores the configured world of an archive written here, and
the port restores the role's archives.

| Function | Config | Role |
|---|---|---|
| `deploy_minecraft_java_backup(cfg, secrets)` | `MinecraftJavaBackupConfig(world_name=...)` | `minecraft_java_backup` |
| `deploy_minecraft_java_restore(cfg)` | `MinecraftJavaRestoreConfig(world_name=..., confirm=True)` | `minecraft_java_restore` |

The fields are the roles' variables without the `minecraft_java_backup_`,
`minecraft_java_restore_` or `minecraft_java_` prefix, with the roles'
defaults: `prefix` (`manual`), `root` (`/opt/backups/minecraft-java`),
`server_dir` (`/home/minecraft/server`), `service_name` (`minecraft-java`),
`port` (25565), `rcon_port` (25575), the restore's `archive` (`latest`),
`user`/`group` (`minecraft`) and `dry_run`. New: `world_name` (required, no
default), `save_wait`/`save_timeout` (the role's 2 and 30 seconds),
`staging_dir` (`<root>/.restore-work`), `start_timeout` (300 seconds),
`confirm`, `required_mount` and, for the backup, `retain_count`/`retain_days`
([local backups](../concepts/local-backups.md)). The backup needs the
`rcon_password` secret (validated as for the deploy); it reaches the host on
stdin only and is used by a small RCON client inside the host program, so it
is in no command line, environment, file or log.

**Backup.** `<root>/<prefix>-<UTC timestamp>.tar.gz`, `root:root 0600` in a
`root:root 0700` root, with every world of the server, `server.properties` and
those of `ops.json`, `whitelist.json`, `banned-ips.json`,
`banned-players.json` that exist, with paths relative to the server directory
and a world's own directory entry left out (the layout of the role's
`archive` task). The worlds are the configured world and each other top-level
directory with a regular `level.dat`; hidden names, pre-restore copies
(`*.pre-restore-*`) and links are not worlds, and a link or special file
inside a world fails the backup before an archive exists. While the unit is
`active` (or `reloading`) the archive is bracketed with RCON `save-off`, `save-all flush`
(which must answer "Saved the game") and, always, `save-on`; a stopped server
is never started, and a stopped unit while something answers on the game or
RCON port, or a unit that is `activating`/`deactivating`, is refused. The
archive is written to a private temporary name and linked into place, so a
failed run never leaves a partial archive and never replaces one.

**Restore.** `archive` is `latest` (the newest `*.tar.gz` directly in the
root by mtime, the role's rule), a name in the root or an absolute path below
it; links are refused. The check reads the whole archive (gzip and tar
integrity), requires the configured world with its `level.dat` and, when the
archive has a `server.properties`, its `level-name` to be that world; the live
`server.properties` must select it too. The unit must be loaded or genuinely
absent (the role's assertion); a stopped or absent unit while something
answers on the game port (`port`; the restore has no RCON port setting) is
refused before anything changes, as in the backup. The worlds of the archive (its top-level
directories with a `level.dat`) are restored, each through its own
pre-restore copy; other top-level entries are left out.

- `dry_run=True` runs only these checks and prints the plan (archive, worlds
  with entry counts and whether a live copy exists, files, the unit and
  whether it would be stopped and started). It creates no work directory,
  touches no unit and changes no file.
- Without `dry_run`, `confirm=True` is required (the deploy fails before any
  probe otherwise). The restore unpacks the selected members into
  `staging_dir`, stops a running unit, keeps each live world of the archive
  as `<world>.pre-restore-<utc>-<random>` (ops-library's `preserve.py`,
  unchanged; a world that does not exist yet, as on a fresh installation, has
  nothing to snapshot), copies the worlds in with the service account's
  ownership, restores `server.properties` (`0640`; the previous one stays as
  `server.properties.pre-restore-<utc>` when it differed) and the player files
  in the archive (`0644`), and starts the unit only when it ran before,
  waiting up to `start_timeout` for the game port.
- When replacing fails, the restore rolls back while the unit is stopped:
  renamed copies move back, copies taken across filesystems are copied back
  (and kept), a world that did not exist before goes again, and the replaced
  files are put back with their owner and mode. The unit stays stopped. A
  failed start after a complete restore is not rolled back; the copies stay.
  `staging_dir` is emptied whether the restore succeeds or fails; no path
  removes a pre-restore copy.

Deliberate differences from the roles:

- Every world is backed up and restored, not only `minecraft_java_world_name`;
  the server keeps several (macmini: six). The role restores only the
  configured world of an archive written here.
- `world_name` has no default and must be the `level-name` the live (and the
  archived) `server.properties` selects. The playbooks never set it, so the
  role archived its default `world`, not the world the server plays.
- "Running" is the unit's state, not `pgrep -f server.jar` (which misses
  Forge). `save-all flush` must answer "Saved the game" (the role accepted any
  answer containing "save"), and a failed `save-on` fails the run (the role
  only warned).
- The backup timestamp is UTC (`YYYYmmddTHHMMSS`), the role's was host-local.
- The role's retention (the 10 newest `*.tar.gz`, whoever wrote them) and its
  `chmod 0600` of every archive in the root are not ported: nothing written by
  another tool or by hand is touched. `retain_count`/`retain_days` prune only
  the snapshots this port recorded.
- The restore needs `confirm`, never enables the unit, starts it only when it
  ran before (the role started and enabled any loaded unit), waits up to
  `start_timeout` (the role 60 seconds), rolls back on failure (the role left
  the copy for the operator), writes `server.properties` `0640` (the deploy's
  mode; the role wrote `0644`) and unpacks into `staging_dir` instead of a
  `/tmp` directory.
- Archive members that are links, special files, absolute or parent paths are
  refused, and so is an archive path outside `root`.

Tests: `tests/test_minecraft_java_lifecycle.py` (configs, planned operations,
and the host program end to end against temporary directories with a fake
RCON server, stubbed `systemctl`/`findmnt` and the real `preserve.py`).

## Parity and limits

Selected templates from the current source live separately in
`tests/parity/minecraft_java_3110a0f1`; older frozen parity inputs are unchanged.
All selected templates render byte-identically except the deliberate env/unit
change that keeps the RCON password out of process arguments and accepts
Forge's successful RCON shutdown status, and the explicit JDK binary in place
of `/usr/bin/java` (unit and Forge wrapper). The public path
and network defaults are generic, and RCON/firewall disabling and custom Forge
artifact paths are refused instead of being silently ignored. The role's local
cron backup path is intentionally excluded: use an independently approved
backup integration. Live qualification belongs in the private controller receipt.

The opt-in real Forge integration test uses an isolated Ubuntu smoke VM:
`MINECRAFT_FORGE_SMOKE=1 just smoke tests/smoke/test_minecraft_java_smoke.py`.
It installs Forge 1.20.1-47.4.0 into a fixture tree, starts it with active UFW,
checks authenticated RCON, proves an unchanged repeat, applies an ordinary
player-limit update with restart, then converges stopped with inactive UFW
and verifies the fixture world remains unchanged. It enables UFW on the
fixture and stops/disables its fixture unit and disables UFW on exit; use a
disposable isolated VM with no pre-existing firewall policy. Do not point this
test at an inventory host. `MINECRAFT_SMOKE_RECEIPT=/absolute/path.json` records
per-phase operations and preservation assertions.
