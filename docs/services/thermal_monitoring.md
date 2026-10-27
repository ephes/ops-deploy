# thermal_monitoring

Bounded thermal and fan metrics of one host as an authenticated, cached HTTP
endpoint, optionally the Nyxmon check that watches the endpoint's freshness,
and optionally a drive-aware case-fan controller ([fan_control](#fan_control)). A port of ops-library's `thermal_metrics_exporter` and
`thermal_metrics_endpoint` roles (ops-library 2.56.0, `540ede2b`; both
roles are unchanged since the frozen reference `49d2f168`) together with the
play around them on the private side: the endpoint bound to the host's
Tailscale IPv4 address, then one json-metrics check upserted into Nyxmon's
database like the shared `tasks/upsert-nyxmon-json-metrics-check.yml`.

```python
from ops_deploy.services.thermal_monitoring import ThermalMonitoringConfig, deploy_thermal_monitoring

cfg = ThermalMonitoringConfig(
    secrets="secrets/example.yml",  # provides endpoint_password
    auth_user="nyxmon",
    timer_on_boot_sec=75,
    timer_randomized_delay_sec=15,
    exporter={
        "packages": ["python3"],
        "sysfs_sensors": [
            {
                "id": "cpu_package",
                "source_entity_id": "sysfs:coretemp:package_id_0",
                "value_path_glob": "/sys/devices/platform/coretemp.0/hwmon/*/temp1_input",
                "sensor_label": "cpu_package",
                "sensor_class": "cpu",
                "metric_kind": "temperature",
                "unit": "celsius",
                "scale": 0.001,
            },
        ],
    },
    nyxmon_check={
        "service_name": "example-host",
        "name": "Example Thermal Freshness",
        "check_interval": 300,
        "auth_username": "nyxmon",
        "data": {
            "url": "http://host.example.invalid:9104/.well-known/thermal",
            "timeout": 10.0,
            "retries": 1,
            "retry_delay": 2.0,
            "checks": [
                {"path": "$.meta.age_seconds", "op": ">=", "value": 0, "severity": "warning"},
                {"path": "$.meta.age_seconds", "op": "<", "value": 600, "severity": "warning"},
            ],
        },
    },
)
deploy_thermal_monitoring(cfg, secrets)
```

## Configuration (`ThermalMonitoringConfig`)

The `thermal_metrics_endpoint_*` role variables without the prefix, with the
role's defaults:

| Field | Default | Meaning |
|---|---|---|
| `secrets` | (required) | the secrets file; it must provide `endpoint_password` (`PASSWORD_KEY`) |
| `auth_user` | (required) | the endpoint's basic-auth user (letters, digits, `.`, `_`, `@`, `-`; not the role's `CHANGE_ME`) |
| `service_name` | `thermal-metrics-endpoint` | the endpoint's systemd unit |
| `user` / `group` | `metrics` / the user | the endpoint's no-login system account |
| `site_path` | `/var/lib/thermal-metrics` | the role's `data_dir`; the metrics land in `thermal.json` there |
| `bind` | `tailscale` | an IPv4 address, or `tailscale`: what `tailscale ip --4` prints on the host |
| `port` / `path` | `9104` / `/.well-known/thermal` | where the endpoint answers |
| `packages` | `python3`, `apache2-utils` | the endpoint's packages |
| `server_path` | `/usr/local/bin/thermal_metrics_httpd.py` | the HTTP server script |
| `htpasswd_dir` | `/etc/thermal-metrics-endpoint` | holds `htpasswd` |
| `timer_name` | `thermal-metrics-collector` | the collector's `.service` and `.timer` |
| `timer_interval`, `timer_on_boot_sec`, `timer_accuracy_sec`, `timer_randomized_delay_sec` | `300`, `30`, `10`, `30` | seconds (integers) |
| `timer_on_calendar` | `*:0/5` | the wall-clock backstop |
| `exporter` | see below | the `thermal_metrics_exporter_*` variables |
| `nyxmon_check` | none | the Nyxmon json-metrics check (`JsonMetricsCheck`), see below |
| `fan_control` | none | the drive-aware case-fan controller (`FanControl`), see [fan_control](#fan_control) |
| `httpd_impl` | `python` | the endpoint's HTTP server: the role's Python script or the pinned Rust `metrics-httpd` (the role's `thermal_metrics_endpoint_impl`); see [metrics-httpd switch](metrics_httpd.md) |
| `httpd_rust_version`, `httpd_rust_sha256` | `""`, `""` | the release pin (`metrics_httpd_rust_version`/`_sha256`); with a version the release is installed and checked even on Python; `rust` needs both |

`exporter` (`ThermalExporter`): `packages` (`python3`, `lm-sensors`,
`ipmitool`), `bin_path` (`/usr/local/bin/thermal-metrics-exporter`, also the
path the collector runs) and the three sensor lists, validated like the
role:

- `lm_sensors`: `id`, `source_entity_id`, `chip_name_regex` or an absolute
  `device_path`, `feature_name`, `value_key`; optional `sensor_label`,
  `sensor_class`, `metric_kind`, `unit`.
- `sysfs_sensors`: `id`, `source_entity_id`, an absolute `value_path_glob`;
  optional `sensor_label`, `sensor_class`, `metric_kind`, `unit` and a
  numeric `scale` (an integer stays an integer, a float a float).
- `ipmi_sensors`: `id`, `sensor_name`, `source_entity_id`; optional
  `sensor_label`, `sensor_class`, `metric_kind`.

`id` must match `[A-Za-z0-9_]+`. The exporter embeds each list as JSON in
the order of the fields above, leaving out fields that are not set, so a
list written in that order renders byte for byte as the role renders it
(the private side's tests compare its inventory against the role
template).

`nyxmon_check` (`JsonMetricsCheck`, from `ops_deploy.services._nyxmon_json_metrics`):
`service_name` and `name` (the Nyxmon service and check), `check_interval`
(a positive integer), `data` (the check settings; its `url`, an http(s)
URL, is also the row's url, and its `checks` rules list must not be empty)
and `auth_username`. With `auth_username` (which must be `auth_user`) the
stored data gets `auth: {username, password}` with the endpoint password.
`data` must not carry `auth` itself. `user` (`nyxmon`) and `db_path`
(`/home/nyxmon/site/db.sqlite3`) say where Nyxmon lives. Data types are kept
exactly (`10.0` stays a float), because the upsert compares JSON text.

Refused before any connection: unknown keys, control characters in any
value, single quotes in sensor values (they could end the exporter's
`r'''...'''` literal), non-finite or boolean scales, paths outside
`[A-Za-z0-9._/-]`, NaN in check data, backslashes in check names or data.
Refused by the deploy before any operation: a missing, empty or `CHANGE_ME`
password, one with a control character (a line break or NUL would make
`htpasswd` check another password than the controller verified) or longer
than 72 bytes (bcrypt), and a
`tailscale` bind when `tailscale ip --4` does not print exactly one IPv4
address. Validation errors never echo the input.

## What the deploy does

1. Exporter: its packages (apt, no cache refresh), then the exporter
   rendered from the role template, `root:root 0755`.
2. Endpoint: its packages; the system group and the no-login user without a
   home directory (an existing user is left alone with a warning when it
   differs); `site_path` and `htpasswd_dir` `root:<group> 0750`; the HTTP
   server script `root:root 0755`.
3. Credentials: the installed `htpasswd` is read and the user's bcrypt
   hash checked against the password on the controller (the role's
   `htpasswd -v`). Only when it does not verify (no file, no line for the
   user, another hash format, a wrong password) a new entry `user:hash`
   (`htpasswd -nB` format, cost 5) is written as `root:<group> 0640` through
   `secret_file`. A verifying file keeps its content; only its owner and
   mode are brought back to `root:<group> 0640` (the endpoint reads it as
   its user), without a restart.
4. The collector `.service`, `.timer` and the endpoint unit (`root:root
   0644`); the HTTP server switch's select step ([metrics-httpd
   switch](metrics_httpd.md): `python` removes the drop-in, a pinned release
   is installed and its `--check-config` runs as `metrics` in the unit's
   sandbox, `rust` writes the drop-in); then one `daemon-reload` if any unit
   or the drop-in changed.
5. The collector runs once (`systemctl start <timer_name>.service`) while
   there is no `thermal.json` yet or the exporter or the collector unit
   changed.
6. The timer is enabled and started, and restarted when its unit changed.
   If the timer was already installed and reports no next elapse (realtime
   or monotonic; `''`, `infinity`, `0`, `n/a`) while planning, it is
   restarted (the role's re-arm). Every run then reads the timer again, up
   to six times 2 s apart, and fails if it still has no next elapse.
7. The endpoint is enabled and started, and restarted when its unit, the
   server script, the htpasswd file or the drop-in changed (not right after
   it was started by this run). Then the switch's verify step: the unit runs
   the selected server and answers an unauthenticated `GET` with 401 and
   realm `thermal-metrics`; only then the `metrics-httpd` pin of the unit
   moves and old releases are pruned.
8. With `fan_control`: the controller's packages, files and unit, the
   service enabled, started (restarted on change) and checked; see
   [fan_control](#fan_control). Its board check runs while planning, before
   step 1.
9. With `nyxmon_check`: the shared json-metrics upsert below.

A converged host gets read-only operations only: the armed-timer check, the
HTTP server check (and, with a pinned release, its validation and
`--check-config`) and, with a check, the Nyxmon database privacy check.

## The check on another host (`ThermalCheckConfig`)

When the play around the roles upserts its freshness check into a Nyxmon that
runs on another host than the endpoint (one play for the endpoint's host, one
for the Nyxmon host), the second play is `deploy_thermal_check` with a
`ThermalCheckConfig`: the same `nyxmon_check` (`JsonMetricsCheck`), the same
upsert below and the endpoint password as the check's login
(`endpoint_password` from `secrets`; required and checked before any
operation like the endpoint deploy's, also for a check without a login).
`service_name`, `user` and `site_path` (defaults `nyxmon`, `nyxmon`,
`/home/nyxmon/site`) name that Nyxmon; the check's `user` must be its user and
its database `site_path/db.sqlite3`. Nothing else happens on that host. A
converged check plans only the database privacy check.

## The json-metrics check upsert

`ops_deploy.services._nyxmon_json_metrics` is the port of the shared
`tasks/upsert-nyxmon-json-metrics-check.yml` (json-metrics checks; its IMAP
form is not ported); other host monitoring deploys can call
`upsert_json_metrics_check(check, password)` the same way. It runs
`files/json_metrics_check.py` as the Nyxmon user with
`runuser -u <user> -- python3 -I -c`:

1. `guard` (read-only, every run): the database is a regular file, not a
   symlink, owned by the Nyxmon user with mode `0600`, and so is every
   regular file next to it whose name starts with the database's name (the
   task's sidecar check). The run fails otherwise ("Deploy Nyxmon first").
2. While planning, `probe` checks the required columns and prints `service
   absent`, `check absent` or `check <digest>`: the sha256 of the stored
   type, url, interval, data and disabled flag in the task's comparison
   form. The controller computes the same digest for the desired row; when
   they match, nothing else runs. The login is never read back or printed.
3. Otherwise `apply` reads `{check_interval, data}` from stdin and upserts
   exactly as the task: a missing service is inserted (two with the name are
   refused), a missing check is inserted `idle` with `next_check_time`,
   `processing_started_at` and `disabled` 0, a check whose type, url,
   interval, data (sorted JSON; non-JSON stored data is compared as text) or
   disabled flag differs is updated, re-enabled and reset to `idle` with 0
   schedule values, unless Nyxmon is processing it right now (then the run
   fails). The step is retried 7 times 5 s apart, like the task.
4. If the planning probe failed (an error, not an answer), the probe runs
   again after the apply and must succeed.

The check data travels only on the apply's stdin: service and check names
and the database path are its only arguments, and nothing is put in the
process environment (sudo and `/proc` can show both).

## Parity with the roles and the play

The exporter, the HTTP server script and the three units are the roles'
templates, shipped unchanged and rendered like Ansible's `template` module
(`trim_blocks`, Ansible's `to_json`); `tests/test_thermal_monitoring.py`
compares them with the vendored copies under `tests/parity/ansible`, which
`test_traefik_parity.test_vendored_templates_match_ops_library` keeps equal
to ops-library, and `tests/parity/ops_library_roles.json` records both
roles' digests (`thermal_metrics_endpoint` with its metrics-httpd switch,
ops-library `be348cdb`). Intended differences (for the HTTP server switch see
[metrics-httpd switch](metrics_httpd.md#differences-from-the-role)):

- The password is checked against the bcrypt hash on the controller, so the
  host never sees it on a command line, and an unchanged password never
  rewrites the file or restarts the endpoint; a file whose entry is not
  bcrypt is replaced (`htpasswd -v` would accept other formats). The owner
  and mode of a verifying file are enforced too (the role leaves them).
- The collector runs once only while the metrics file is missing or the
  exporter or collector unit changed; the role starts it on every run. The
  timer refreshes the file every `timer_interval` seconds anyway.
- `daemon-reload` runs only when a unit changed (the role's final
  `daemon_reload: true` tasks reload every run), and the timer and endpoint
  restarts run after the collector instead of before it.
- The role's "exporter script exists" check is not needed: the deploy
  writes the exporter itself, before the endpoint.
- An existing service account is never modified (the role's `user` task
  would reset its group and shell).
- Sensor specs are typed: unknown keys are refused instead of passed
  through to the exporter, and explicit `null` optional fields are left out.
- The upsert opens the database by URI (`mode=rw`/`mode=ro`), so a missing
  database is an error instead of a new file; its ambiguous-service and
  lease refusals, umask 077, busy timeout and `BEGIN IMMEDIATE` are the
  task's.

## fan_control

On some server boards the BMC drives the case fans from a CPU-derived index
only: it never sees a drive temperature, and the OS has no PWM path because
every fan header belongs to the BMC. `fan_control` adds a small controller
service, `drive-fan-control`, that reads the drives itself and sets the duty
of the configured case-fan positions through the BMC. Without the block the
deploy plans exactly what it planned before: `tests/test_thermal_monitoring_golden.py`
compares every operation, command, upload and stdin of four host states with
a record taken before `fan_control` existed.

The controller is `files/drive_fan_control.py` (standard library only), run
by systemd as `/usr/local/libexec/drive-fan-control/drive_fan_control.py`
with `/etc/drive-fan-control/config.json`. The deploy never writes the BMC;
the service owns every write.

```python
fan_control = {
    "mode": "observe",  # observe | calibrate | active
    "board": {
        "dmi_board_vendor": "ExampleRack",
        "dmi_board_name": "EX650D4U",
        "bmc_manufacturer_id": 49622,
        "bmc_product_id": 8217,
        "bmc_firmware": ["6.09"],
    },
    "managed": [{"position": 0, "sensor": "FAN1_1"}, {"position": 1, "sensor": "FAN2_1"}],
    "protected": [{"position": 5, "sensor": "FAN6_1"}],  # the CPU fan: stays BMC auto
    "cpu": {"hwmon_name": "k10temp", "label": "Tctl"},
    "nvme": [{"name": "fast-nvme", "device": "/dev/disk/by-id/nvme-Example_0001"}],
    "hdd": [{"name": "hdd-1", "device": "/dev/disk/by-id/ata-Example_0001"}],
    "scan_pools": [{"pool": "tank", "min_pct": 60}],
    "curves": {
        "hdd": [[36, 35], [40, 45], [44, 75], [47, 100]],
        "nvme": [[48, 35], [55, 50], [65, 80], [72, 100]],
        "cpu": [[60, 35], [75, 60], [85, 100]],
    },
}
```

### Configuration (`FanControl`)

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false`: the service is stopped and disabled (its clean stop restores BMC auto on the positions it held); files stay, no board probe |
| `mode` | `observe` | `observe`: compute and record what it would set, never write the BMC. `active`: control the managed fans. `calibrate`: run the calibration once per `calibration.id`, then observe |
| `backend` | `asrock_rack_ast2600` | the BMC command set (below) |
| `board` | (required) | DMI `board_vendor`/`board_name`, the BMC's manufacturer and product ID and the allowed firmware revisions; anything else is refused |
| `managed` | (required) | the fan positions (0 = FAN1 … 15) the controller sets, each with its `ipmitool sdr` sensor |
| `protected` | (required) | positions that must stay in BMC auto mode (the CPU fan); never managed |
| `floor_pct` | `35` | the lowest duty (at least 25) |
| `interval_s` | `30` | the cycle: CPU, NVMe, scan state and fan RPM every cycle |
| `hdd_interval_s` | `300` | how often the HDDs are polled (at least `interval_s`) |
| `cpu` | (required) | the hwmon `name` and temperature `label` of the CPU sensor |
| `nvme` | `()` | NVMe drives by device path; the Composite temperature comes from the hwmon of the drive's controller |
| `hdd` | `()` | HDDs by device path and `smart_type` (`sat`, `ata`, `auto`) |
| `scan_pools` | `()` | ZFS pools whose running scrub or resilver raises the duty to at least `min_pct` |
| `curves` | (required) | `hdd`, `nvme`, `cpu`: (°C, %) points; below the first point its duty, above the last its duty, linear in between |
| `decrease_step_pct`, `decrease_hold_cycles`, `min_change_pct` | `5`, `3`, `3` | the slew (below) |
| `failure_cycles`, `stall_cycles` | `2`, `2` | when a failing input or a stopped fan forces 100 % |
| `calibration` | none | required for `calibrate` (below) |
| `packages` | `ipmitool`, `smartmontools`, `hdparm` | installed with apt (`zpool` comes with ZFS) |

The controller's own parser checks the configuration while the config is
built (the same code that reads it on the host), so the host never gets one
the service would refuse: positions 0–15 and unique, managed and protected
disjoint, curves rising in temperature and never falling in duty, duties
0–100, the floor at least 25, device paths absolute below `/dev/` without
`..`, `cpu`/`fans` not used as drive names, `calibrate` only with a
`calibration` block.

### What the controller does

- **HDDs are never woken.** Every `hdd_interval_s` it runs `hdparm -C`
  (CHECK POWER MODE) and only for a spinning disk `smartctl -n standby -d
  <type> -A -j`, which itself skips a disk that went to standby in between. A
  disk in standby asks for nothing; that is not an error. A failed poll is
  retried the next cycle instead of after `hdd_interval_s`. `drivetemp` is not
  used: its reads are not standby-aware.
- **Demand**: the highest duty any curve asks for (CPU, every NVMe drive, the
  hottest spinning HDD) or any running scan's `min_pct`, rounded up and
  clamped to [`floor_pct`, 100].
- **Slew**: increases apply at once (smaller than `min_change_pct` are
  ignored, except to 100 %); a decrease needs the target to stay at least
  `decrease_step_pct` below the duty for `decrease_hold_cycles` cycles and
  then steps down `decrease_step_pct` per cycle. A gap smaller than
  `decrease_step_pct` (e.g. what remains of the last step, or a short rise
  that ended) closes to the target once it has lasted `decrease_hold_cycles`
  cycles in a row, so the duty does not stay above a steady target; a target
  back at or above the duty, a larger gap or a fail-safe restarts that count.
  The duty starts at 100 % and slews down, in every mode.
- **Freshness**: each cycle reads the fan RPM, the disks (when due) and the
  scan state first and the hwmon sensors last, right before it decides; every
  input carries the time it was read, and staleness is measured at the time
  of the decision.
- **Fail-safe**: a required input (the CPU, every NVMe drive, every HDD's
  power state and the temperature of a spinning HDD; in `active` mode also
  the fan RPM read) that is missing, unparsable, timed out, or fails
  `failure_cycles` polls in a row, or whose last good value is older than
  three of its intervals, forces 100 % (`failsafe`). In `active` mode a
  managed fan that reads "No Reading" or 0 RPM for `stall_cycles` cycles does
  too. The scan state is not required: without it there is no feed-forward
  (a calibration does not run without it, see below).
- **BMC writes** (`active`): it takes control with the duty bytes first (100 %,
  inactive while auto), then the mode bytes (manual) of the managed positions.
  Every write attempt reads the 16 bytes right before and sends them back with
  only the managed positions changed, so a byte someone else changed is never
  written over, and is read back; a write whose read-back differs is attempted
  once more from a fresh read, then the managed positions go back to auto
  (read back) and the process exits 75. The vendor commands time out after
  5 s. Every 20 cycles it checks that the managed fans are still manual at
  its duty and puts back what someone else changed on them. Before it takes
  control, positions an earlier `active` or `calibrate` run still holds (its
  runtime state says so) that are not managed now, for example after the
  managed set changed while that run's stop did not restore them, go back to
  BMC auto (read back, only their bytes), and the runtime state then records
  only what is still held; a position it never recorded (someone else's) is
  left alone. If that record is from another board, BMC or firmware than the
  one validated at this start, it exits 78 without a BMC write; if the
  release does not read back, it exits 75 and the record still names every
  position the earlier run held, so the stop helper acts on all of them.
- **Board check**: at every start, DMI board, BMC manufacturer and product ID
  and firmware must be the configured ones, otherwise it exits 78 without a
  BMC write (`RestartPreventExitStatus=78`); an unreadable BMC exits 75 and is
  retried. The identity it validated is recorded with the control state.
- **Stop** (`ExecStopPost=`, `stop-post`): it acts only while the controller
  holds the BMC, as its runtime state `/run/drive-fan-control/control.json`
  says, whatever the configuration says by then, and only when the board, BMC
  and firmware are still the ones recorded there (otherwise it writes
  nothing and fails). After a clean stop (`SERVICE_RESULT=success`) it
  restores BMC auto on the managed positions; after anything else (crash,
  watchdog, timeout) it sets them to 100 % manual, and to auto if that fails;
  all read back. `observe` and `calibrate` never write positions an earlier
  `active` or `calibrate` run still holds: the run reports them
  (`leftover_control` in the status, `healthy` 0) and keeps the state, so the
  stop helper releases them at the service's next clean stop.
- **systemd**: `Type=notify` (`READY=1` after the board check and, in
  `active`, after taking control), `WatchdogSec=90` (pinged after every
  command and while sleeping), `Restart=always` with `RestartSec=15`, at most
  five starts in 30 minutes, `TimeoutStopSec=180` (the stop helper's worst
  case), `ProtectSystem=strict` with its runtime and state directories.
- **Metrics**: one number per file in `/run/drive-fan-control/metrics/`
  (`na` when unknown): `duty_pct` (held, or would hold), `target_pct`,
  `healthy` (every required input read, and in `active` every managed fan
  turning), `failsafe`, `bmc_control` (it holds the managed fans),
  `managed_auto` (the managed positions read as BMC auto), `hdd_max_c`,
  `hdd_active`, `scan_active` (`FAN_CONTROL_METRICS`, `FAN_CONTROL_METRICS_DIR`).
  A thermal exporter `sysfs_sensors` entry per file serves them through the
  endpoint. `/run/drive-fan-control/status.json` has the whole cycle (inputs,
  reasons, errors, fan RPM, the BMC write count). The journal gets a line per
  change of the (would-be) duty, the target or the fail-safe state, and a
  summary every 20 cycles.

### Calibration (`mode: calibrate`)

Once per `calibration.id` (recorded in
`/var/lib/drive-fan-control/calibration.json`), with every managed and
protected position in BMC auto mode first. It does not run while positions an
earlier run left under control are still held (nothing written or recorded;
the same id runs at a start after the stop helper released them). Before it
touches the BMC, and at every sample while it holds it, every required input
must read (a single failed read is enough to stop it; `failure_cycles` does
not apply), the scan state of every pool in `scan_pools` must be known (an
unreadable or failed `zpool status`, a missing pool or a pool shown without
its `scan:` line count as "scan state unknown", never as "no scan"), no
scrub or resilver may run, and the curves must ask for less
than `abort_target_pct` (default 60); before the first BMC write that only
skips the calibration (nothing written, the same id runs at the next start),
later it aborts it. Then: a
baseline, then each managed
position alone at 100 % manual for `mapping_hold_s` (its own sensor must rise
by at least two `tach_step_rpm`, the other managed fans by at most one), then
all managed positions through the `steps_pct` staircase, `step_hold_s` each,
sampling every `sample_interval_s` after `settle_s`. It aborts at once when an
input fails or warms up as above, when a managed fan stops, when the RPM
within a step spreads over `oscillation_steps` tach steps, or when the mode
byte of a position it does not manage changes. In every case the managed positions' mode and duty bytes
go back to what they were before (read back). The report lists the mapping,
RPM per step and `suggested_floor_pct` (the lowest step whose fans all stayed
at or above `min_rpm`). Then it observes. Calibration and `active` are meant
to be run supervised; each is a separate decision.

### BMC commands (`asrock_rack_ast2600`)

ASRock Rack's documented commands for AST2600 boards (technical document
TSDQA-72), through `ipmitool -I open`: `raw 0x3a 0xd0 0x12` reads the 16 mode
bytes (`0x00` default/auto, `0x02` manual) and `raw 0x3a 0xd0 0x0f` the 16
duty bytes (0–100); `0x11` and `0x0e` followed by 16 bytes write them. The
mapping of byte position to fan header is the board's; check it with the
calibration or the BMC's fan settings page. `ipmitool sdr type fan` gives the
RPM.

### What the deploy does

1. While planning, before anything else: a read-only probe prints the DMI
   board vendor and name, `ipmitool mc info` and the mode bytes (vendor GET).
   The deploy refuses unless board, manufacturer, product and firmware match
   and every position that is not managed is in auto mode.
2. The packages; `/usr/local/libexec/drive-fan-control` and
   `/etc/drive-fan-control` `root:root 0755`; the controller `0755` and its
   config `0644`; the unit `drive-fan-control.service`.
3. `daemon-reload` when the unit changed; the service enabled and started, and
   restarted when the script, the config or the unit changed (not right after
   this run started it).
4. A read-only check: within 90 s the service reports a healthy cycle of its
   own process in the configured mode (`bmc_control` 0 in `observe`, 1 in
   `active`); `calibrate` only needs the unit active.

A converged host plans only the read-only checks. With `enabled: false` the
deploy only stops and disables the service (no board probe, no file
operation). Rollback: `mode: observe` (the restart's clean stop restores BMC
auto) or `enabled: false`; dropping the block leaves the service as it is.
The emergency return of every position to auto is
`ipmitool -I open raw 0x3a 0xd0 0x11` with sixteen `0x00`.

## Tests

- `tests/test_thermal_monitoring.py`: template parity for the role defaults,
  the monitoring play and every field changed; the exporter reading back its
  sensor lists with their types; config refusals; plans on the fake
  connector: fresh host, converged host (read-only checks only, no uploads,
  no stdin), changed password (htpasswd and endpoint restart only), every
  htpasswd that does not verify, a verifying file kept (its owner and mode
  repaired without a rewrite), exporter, server
  script, timer unit, collector unit and Tailscale address drift, a missing
  metrics file, the timer re-arm (and none after a restart this run), an
  unarmed timer failing the run, refused Tailscale answers and passwords,
  the password never outside stdin, the check data only on the upsert's
  stdin, the task's retries, the privacy guard before any upsert, shell
  syntax.
- `tests/test_thermal_check.py`: the check-only deploy: a converged check
  (only the privacy check), a missing check upserted with the password on
  stdin only, a failing probe, nothing else on the host, the privacy guard
  before any upsert, unusable passwords (with and without a login), a check
  without a login storing no password, a check whose user or database
  (another path, another file name) is not this Nyxmon's.
- `tests/test_thermal_monitoring_golden.py`: without `fan_control` the plans
  of four host states are the ones recorded before it existed.
- `tests/test_fan_control.py`: config refusals (also the controller's own),
  the controller parses the JSON the deploy writes, the identity guard
  (board, vendor, firmware, product, manufacturer, an unmanaged position in
  manual mode, unreadable bytes, a failed probe) before any operation, plans
  for a converged host (read-only checks only), a fresh host, a new mode, a
  changed script or unit, a stopped service, `enabled: false` (stop and
  disable, no board probe; nothing when the service is gone), the status
  check, shell syntax, no BMC write command in any plan.
- `tests/test_drive_fan_control.py`: the controller against fake `ipmitool`,
  `hdparm`, `smartctl` and `zpool` executables and a fake sysfs: config
  refusals, curves, demand, slew and hysteresis (a sub-step gap settles to
  the target, also in `observe` and `active`), scan feed-forward, standby
  disks never queried further, every reader error and timeout, staleness,
  fail-safe after repeated failures, the hwmon sensors read after the slow
  inputs, `observe` without a BMC write, `active` taking only the managed
  positions with unmanaged bytes kept, writes built from a fresh read (a
  foreign change before a retry or after a write is kept), stepping down, a
  stalled fan, unreadable fans, a write that does not read back (auto
  restored, exit 75), protected fans not in auto, retaking changed fans, board
  and firmware refusals, `stop-post` for every `SERVICE_RESULT` (clean: auto;
  otherwise 100 %, auto if that fails; nothing without control, without a
  recorded identity or on another firmware), control left behind (never
  written by `observe`, reported, released by the next clean stop),
  calibration (success, skipped while an input fails or a scrub runs and
  retried, skipped and retried when an input fails or another fan's mode
  changes before its first write, aborted when a drive warms up or a single
  read of any input fails meanwhile, not run while an earlier run still holds
  fans, skipped while the scan state is unknown (failed `zpool status`, no
  scan line, a missing pool) and aborted when it turns unknown meanwhile,
  stall, a foreign mode change, a wrong mapping), `active` releasing the
  positions of an earlier run's set it no longer manages (also one that is
  protected now; nothing released for the same or a larger set, not on
  another firmware record, the whole record kept when the release does not
  read back; never by `observe` or `calibrate`), `observe` unchanged with an
  unknown scan state, `READY`/`WATCHDOG` on
  a real notify socket, argv without backslashes.
- `tests/test_nyxmon_json_metrics.py`: the host script against real SQLite
  files: fresh insert (probe leaves the file byte-identical), existing
  service, converged no-op with a running schedule untouched, data spelling,
  every drifting field (also a changed login) repaired with the schedule
  reset, a processing check refused, ambiguous rows, unrelated rows
  untouched, a check without login, missing columns, a missing database never
  created, non-private database modes, a symlinked database, non-private
  sidecars, bad usage, no login in any output, no backslash in the script.
