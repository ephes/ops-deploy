# nyxmon_site_checks

One Nyxmon service and its health checks, written straight into Nyxmon's
SQLite database on the Nyxmon host: the service row is created if it is
missing, each listed check is inserted or brought back to the listed
settings, and each check named in `remove_checks` is deleted. It is the pyinfra counterpart of site-check provisioning playbooks
that run on the Nyxmon host only: the monitored sites are never contacted,
Nyxmon itself is not restarted, and no secrets are involved.

```python
from ops_deploy.services.nyxmon_site_checks import NyxmonSiteChecksConfig, deploy_nyxmon_site_checks

cfg = NyxmonSiteChecksConfig(
    service_name="example-site",
    checks=(
        {
            "name": "Example Public Site",
            "check_type": "http",
            "url": "https://site.example.invalid/",
            "check_interval": 300,
            "data": {"timeout": 10.0, "retries": 3, "retry_delay": 10.0, "retry_status_codes": [502, 503, 504]},
        },
        {
            "name": "Example TLS Certificate",
            "check_type": "tcp",
            "url": "site.example.invalid",
            "check_interval": 3600,
            "data": {"host": "site.example.invalid", "port": 443, "check_cert_expiry": True, "min_cert_days": 21},
        },
    ),
    # Optional: only write the checks once the deployed Nyxmon understands them.
    require_literal={"path": "/home/nyxmon/site/src/nyxmon/domain/http_config.py", "literal": "expected_location"},
    # Optional: delete checks of this service that are retired.
    remove_checks=("Example Retired Check",),
)
deploy_nyxmon_site_checks(cfg)
```

## Configuration (`NyxmonSiteChecksConfig`)

| Field | Default | Meaning |
|---|---|---|
| `service_name` | (required) | name of the Nyxmon `service` row (the service-name rule: lower case, digits, `_`, `-`) |
| `user` | `nyxmon` | user the upsert runs as (`runuser -u`) |
| `site_path` | `/home/nyxmon/site` | Nyxmon's site directory (informational) |
| `db_path` | `/home/nyxmon/site/db.sqlite3` | Nyxmon's database; letters, digits, `.`, `_`, `-`, `/` only |
| `checks` | `()` | the `health_check` rows, see below; names must be unique |
| `remove_checks` | `()` | names of the service's checks to delete; unique, plain text (as a check name), none also in `checks`. `checks` and `remove_checks` together must name at least one check |
| `require_literal` | none | `{path, literal}`: `grep -Fq` must find `literal` in `path` before anything is written |

A check (`SiteCheck`) has `name` (at most 255 characters), `check_type`
(`http`, `json-metrics` or `tcp`; other Nyxmon types are refused until a
deploy needs them), `url` (an http(s) URL for `http` and `json-metrics`, a
host name for `tcp`), `check_interval` (a positive integer; booleans,
strings and floats are refused) and `data`, a mapping of JSON values. The
types in `data` are kept exactly: `10.0` stays a float and `10` an integer,
because the upsert compares the stored data as JSON text and `10.0` and `10`
differ there. Tuples become lists. Refused, before any connection: NaN and
infinite numbers, values that are not JSON (sets, bytes), keys that are not
non-empty strings (checked before pydantic could coerce a `bytes` key), nesting deeper than 16 levels, and control characters or
backslashes in any name, URL or data string (names, URLs and literals must
be `str`; every pattern must match the whole value, so a trailing newline is
refused too) (every command stays one line
that a fish login shell passes unchanged). Validation errors never echo the
input.

## What the deploy does

1. With `require_literal`: `grep -Fq -e <literal> -- <path>` (read-only); the
   run stops before any write if the file lacks the literal or is missing.
   This also stops a run that has nothing to write, as the playbook's assert
   does.
2. `test -e <db_path>` (read-only); the run stops without the database.
3. While planning, `files/site_checks.py check` runs as `user` with
   `python3 -I` on a read-only connection (`mode=ro`) and prints whether the
   apply would write. `changed=false` ends the deploy: a converged database
   gets no mutating operation.
4. Otherwise `files/site_checks.py apply` upserts, in one transaction:
    - a missing service row is inserted;
    - a missing check is inserted with `status='idle'`, `next_check_time=0`,
      `processing_started_at=0`, `disabled=0` and `data` as sorted JSON;
    - an existing check (same service, same name) whose `check_type`, `url`,
      `check_interval`, `data` (both sides as sorted JSON; stored data that
      is not JSON is compared as text) or `disabled` differs is updated,
      re-enabled (`disabled=0`) and reset to `status='idle'`,
      `next_check_time=0`, `processing_started_at=0`;
    - each check of the service named in `remove_checks` (every row with
      that name) is deleted the way Nyxmon's dashboard deletes one
      (`HealthCheck.delete()`): its `check_result` and
      `check_notification_state` rows first (where those tables exist), then
      the `health_check` row. A name that is not there is converged. Before
      any write the run stops when another table has a foreign key on
      `health_check` (a dependent this deploy does not know) or when a check
      to delete is claimed by an agent (`status='processing'`, whose result
      would outlive the check); rerun it once the agent is done;
    - a missing service row is inserted only when there are checks to write:
      removals alone never create it;
    - checks of the service that are neither listed nor named in
      `remove_checks`, and other services, are left alone.
   The checks reach the script as JSON on stdin (the playbooks' plain list
   of checks, or `{"checks": [...], "remove": [...]}` when `remove_checks`
   is set), in the check pass, the upsert and the repeated probe alike: never in an environment variable or
   on a command line, which every local user can read while it runs (check
   data can carry a monitor login). The playbooks' `NYXMON_CHECKS_JSON` is
   gone from the pyinfra path.
5. If the planning probe itself failed (an error, not an answer), the apply
   runs and the probe runs again afterwards; it must then answer
   `changed=false`.

## Parity with the playbooks

The comparison and the writes are the playbooks' own: the same columns, the
same reset of the schedule on every update, the same insert values, and an
answer of `changed=true` only when something was written. Intended
differences:

- `os.umask(0o077)` before the database is opened, so a journal or WAL file
  SQLite creates is private to the Nyxmon user, like the newer shared
  json-metrics upsert does.
- `BEGIN IMMEDIATE` before the first read, so the comparison and the write
  see the same rows when Nyxmon writes at the same time.
- The database is opened by URI with `mode=rw` (apply) or `mode=ro` (check):
  a database file that disappeared between the check and the upsert is an
  error instead of a new empty file, and the existence check follows
  symlinks (`test -e`), so a dangling symlink is refused.
- The planning check decides whether the upsert runs at all; pyinfra
  reports the upsert as a change whenever it runs, also in the rare case
  that someone else converged the rows between plan and apply.
- Only `http`, `json-metrics` and `tcp` checks, unique check names and plain
  values are accepted (see above); the playbooks do not validate.
- `remove_checks` has no playbook counterpart (the playbooks never delete);
  its operation keeps the name `Upsert Nyxmon checks for <service>`.

## Tests

- `tests/test_nyxmon_site_checks.py`: config validation (every refusal
  above, no input in errors), JSON type fidelity of the stdin payload;
  the payload only on stdin (a sentinel in check data is in no command);
  plans on the fake connector: converged (only the read-only requirements),
  drift and missing rows (one upsert as the Nyxmon user with `python3 -I`),
  requirement order, refusal without the literal (also when converged) or
  without the database, the failing-probe repair, shell syntax and fish
  safety of every command; and the host script run with `python3 -I`
  against a real SQLite file: fresh insert (check mode leaves the file
  byte-identical), converged no-op in both modes with a running schedule
  untouched, reuse of an existing service row, single-field drift of type,
  URL, interval, data type (`10` vs `10.0`) and non-JSON data, re-enabling a
  disabled check, key-order-insensitive data, unlisted checks and other
  services untouched, a missing database never created, and a failed apply
  rolled back. For `remove_checks`: config refusals, the payload (the plain
  list without removals), the plan (converged: only the guards; pending: one
  apply), and on a real file with Nyxmon's dependent tables: the check, its
  results and notification state deleted while the same name in another
  service, other checks and their rows stay, every row of a name, a database
  without the dependent tables, an absent name converged without creating
  the service, refusal (nothing written, both modes) on an unknown table
  referencing `health_check` or a check being processed, and malformed
  payloads.
