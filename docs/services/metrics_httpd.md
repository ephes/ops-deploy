# metrics-httpd switch

`ops_deploy.services._metrics_httpd` selects, for one endpoint unit, the
role's Python HTTP server or the pinned Rust `metrics-httpd` release. It is
the pyinfra side of ops-library's internal role `metrics_httpd_switch`
(ops-library `rust/metrics-httpd/PLAN.md` 7.2 and 7.4, slice S5e) and is
shared by the three deploys that render a metrics-httpd endpoint role:

| Deploy | Unit | Role | Mode |
|---|---|---|---|
| [`thermal_monitoring`](thermal_monitoring.md) | `thermal-metrics-endpoint` | `thermal_metrics_endpoint` | `json-file` |
| [`logyard`](logyard.md) (core) | `logyard-health-endpoint` | `logyard_deploy` | `logyard-health` |
| [`static_site`](static_site.md) | `<service_name>` | `static_site_deploy` | `static` |

Each unit keeps its unit file and Python script exactly as before. Rust is
selected by one systemd drop-in, the role's template rendered byte for byte:

```ini
# /etc/systemd/system/<unit>.service.d/metrics-httpd-impl.conf
# Managed by ops-library metrics_httpd_switch: selects the Rust metrics-httpd.
# Remove this file (daemon-reload, restart) to fall back to Python.
[Service]
ExecStart=
ExecStart=/opt/metrics-httpd/<version>/metrics-httpd <argv>
```

Ansible and pyinfra write the same drop-in, the same install directory
(`helpers.rust_release`) and the same pin files, so the two engines can take
turns on a host (the Ansible playbooks stay the rollback engine).

## Configuration

Each deploy's config gets three fields (`HttpdSwitchFields`; for logyard
they sit on `HealthEndpoint`):

| Field | Default | Meaning |
|---|---|---|
| `httpd_impl` | `python` | `python` or `rust`: the role's `<role>_impl` (`thermal_metrics_endpoint_impl`, `logyard_health_impl`, `static_site_impl`) |
| `httpd_rust_version` | `""` | the fleet pin `metrics_httpd_rust_version`, e.g. `0.1.0`; empty installs nothing |
| `httpd_rust_sha256` | `""` | the fleet pin `metrics_httpd_rust_sha256`: the sha256 of the release archive |

`rust` needs a release version and its 64-hex sha256 (refused before any
connection otherwise). With `python` a malformed pin only warns and installs
nothing, so it never blocks the switch back. The private side maps the
inventory to these fields as the role defaults resolve them
(`<role>_impl`, else `metrics_httpd_impl`, else `python`).

## What the deploy does

`select` (after the unit file, before the unit's reload and restart):

1. The unit name must be usable as a pin name (`[a-z0-9][a-z0-9_-]*`).
   Inputs only the Rust path uses (the argv: no `%`, `$`, `"`, `\` or control
   character, a metrics-httpd mode first; the sandbox: `Key=Value` lines
   without `User=`/`Group=`; the unit's user and group) stop `rust` before
   any operation and only warn for `python` (the check of step 4 is then
   skipped). These rules are ops-library's `plugins/filter/metrics_httpd.py`,
   vendored byte for byte as `rules.py`.
2. `python`: the drop-in is removed first.
3. With a release version: `helpers.rust_release.install_release` installs it
   under `/opt/metrics-httpd/<version>/` and runs `metrics-httpd --version` as
   the unit's user. A failure stops `rust`; with `python` it only warns. An
   installed version is only validated (read-only).
4. If the release is (or just got) installed: `systemd-run --wait --pipe
   --collect --quiet --property=User=<user> --property=Group=<group>
   --property=<sandbox line>... <binary> <argv> --check-config`, read-only.
   It binds nothing and prints no hash or password. A refusal stops `rust`
   before anything is switched; with `python` it is an ignored error (the
   unit stays on Python), shown as `Error (ignored)`.
5. `rust`: `/etc/systemd/system/<unit>.service.d` (`root:root 0755`) and the
   drop-in (`root:root 0644`). A drop-in that appears, changes or disappears
   reloads systemd and restarts the unit (through the deploy's own
   `daemon-reload` and restart triggers); an unchanged one restarts nothing.

`verify` (after the restart), read-only and on every run:

6. `files/verify_host.py`, sent on stdin to `/usr/bin/python3 -I -` as root:
   up to 15 reads 2 s apart until the unit is active with a main process that
   runs the selected implementation (`rust`: `/proc/<pid>/exe` is the
   versioned binary or its resolved path; `python`: the role's script is a
   word of `/proc/<pid>/cmdline`), then up to 15 unauthenticated `GET
   http://<bind>:<port><path>` (no proxy, no redirect, no credentials) until
   the answer is right: `401` with `WWW-Authenticate: Basic
   realm="<realm>"` (thermal), `200` with a JSON object holding `status`
   (logyard, with a timeout covering Loki and the listed units), `200` for
   `/` (static). A bind address the unit's `IPAddressAllow=` would not let
   the probe in from, or a host name, skips the probe with a message. A
   failure stops the deploy before any pin moves or anything is pruned.
7. `pin_release`: `rust` pins the version for the unit; `python` removes the
   unit's pin and keeps its version as the rollback pin.
8. `prune_releases` keeps the three newest versions, every pin of every unit,
   the selected binary, the binary the drop-in named before this run and the
   executable the unit ran while planning; it deletes nothing when that
   executable could not be read, and is skipped after a failed install.

A converged host gets read-only operations only: the validation of an
installed release, its `--check-config`, and the check of step 6.

## Rollback

- Normal: `httpd_impl: python` (inventory: `<role>_impl: python` or
  `metrics_httpd_impl: python`) and deploy. The drop-in disappears and the
  unit restarts the Python script every deploy keeps installed.
- Emergency, on the host as root: `rm
  /etc/systemd/system/<unit>.service.d/metrics-httpd-impl.conf && systemctl
  daemon-reload && systemctl restart <unit>`; flip the inventory before the
  next deploy.

## Differences from the role

- The check of step 6 is one host script instead of the role's shell task
  and `uri` probe; the expectations and retries are the role's.
- The executable the unit ran while planning is protected from prune on top
  of the role's list (the live executable after the check and the drop-in's
  previous binary), and an unreadable one blocks the prune.
- A release pin that is not a version with a sha256 is not installed with
  `python` (the role tries the install, which then fails softly).
- No `local_archive` and no install root other than `/opt/metrics-httpd`.

## Tests

`tests/test_metrics_httpd_switch.py`: the packaged and vendored template
are equal and render like Ansible; the release grammar is the vendored
`rust_release` one; the config refusals; the plans of select and verify on
the fake connector (Python with no, an installed and a new release, an
ignored refusal, a failed soft install, a malformed pin, inputs Rust would
refuse; Rust in order, refused, not running, converged; the switch back;
an unreadable live state; probe addresses and skipped probes); each
deploy's inputs against its unit (thermal: argv, IP filter; static: the
sandbox is the unit's `[Service]` lines; logyard: its `Environment=` lines,
the probe timeout) and a switch to Rust on a converged host of each deploy
(only the install, the drop-in, `daemon-reload`, the unit's restart, pin and
prune change). With `OPS_LIBRARY_PATH`: the drop-ins equal the role's
goldens and each role's switch inputs equal the deploy's. `verify_host.py`
runs locally against a fake `systemctl`, a fake `/proc` and a local HTTP
server (every probe expectation, wrong executables, inactive units, no
credentials even with a `.netrc`).
