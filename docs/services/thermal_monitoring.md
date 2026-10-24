# thermal_monitoring

Bounded thermal and fan metrics of one host as an authenticated, cached HTTP
endpoint, and optionally the Nyxmon check that watches the endpoint's
freshness. A port of ops-library's `thermal_metrics_exporter` and
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
8. With `nyxmon_check`: the shared json-metrics upsert below.

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
- `tests/test_nyxmon_json_metrics.py`: the host script against real SQLite
  files: fresh insert (probe leaves the file byte-identical), existing
  service, converged no-op with a running schedule untouched, data spelling,
  every drifting field (also a changed login) repaired with the schedule
  reset, a processing check refused, ambiguous rows, unrelated rows
  untouched, a check without login, missing columns, a missing database never
  created, non-private database modes, a symlinked database, non-private
  sidecars, bad usage, no login in any output, no backslash in the script.
