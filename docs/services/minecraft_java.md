# minecraft_java

Deploy-only port of the public `minecraft_java_deploy` role at ops-library
`3110a0f1` (2.68.0): Debian/Ubuntu, OpenJDK, mcrcon 0.7.2, vanilla or Forge,
mod JARs, server properties, whitelist/operators, UFW and a systemd service.
Backup, restore and removal are outside this package. Existing backup jobs,
scripts, directories and archives are neither created nor changed nor removed.

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

## Parity and limits

Selected templates from the current source live separately in
`tests/parity/minecraft_java_3110a0f1`; older frozen parity inputs are unchanged.
All selected templates render byte-identically except the deliberate env/unit
change that keeps the RCON password out of process arguments and accepts
Forge's successful RCON shutdown status. The public path
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
