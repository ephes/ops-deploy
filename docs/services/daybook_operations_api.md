# Daybook Operations API

`services.daybook_operations_api` ports the original Operations API deployment,
including its PostgreSQL and uv dependencies, exported or Git source, separate
Python3.14 environment, protected configurations, genuine Django management,
systemd units and private Traefik router. Fresh installations are disabled.
Select enabled state explicitly; the public backend does not infer desired
state from an existing process or remember an earlier enable operation.

```python
from pathlib import Path
from ops_deploy.infra.postgres_install import PostgresInstallConfig
from ops_deploy.services.daybook_operations_api import (
    OperationsApiConfig,
    OperationsApiPins,
    OperationsProfile,
    deploy_daybook_operations_api,
)

cfg = OperationsApiConfig(
    source_path=Path("/prepared/daybook-export"),
    deploy_method="rsync",
    enabled=False,
    domain="operations.home.example.com",
    postgres=PostgresInstallConfig(manage_conf_d=False, manage_pg_hba=False),
)
pins = OperationsApiPins(
    secret_key=secrets["django_secret_key"],
    database_password=secrets["postgres_password"],
    signing_key_id="v1",
    signing_keys=signing_keys,
    profiles=(
        OperationsProfile(
            name="worker",
            host="worker",
            profile="operations-worker",
            enabled=True,
            tokens=(secrets["worker_token"],),
        ),
    ),
)
deploy_daybook_operations_api(cfg=cfg, pins=pins)
```

For Git, select `deploy_method="git"`, an exact40-character `git_revision`,
and optional `git_repo`. Rsync requires a prepared source directory and retains
the original excludes for Git, virtual environments, environment files, Python
caches, nested site/cache and experiments. The private caller resolves current
Daybook Main and owns the exported tree for the complete operation lifetime.
An existing exported tree must remain explicitly rsync in desired inventory;
changing it to Git is not an automatic migration strategy.

The original defaults include user/home `daybook-operations` and
`/home/daybook-operations`, site and separate `venv` underneath that home,
configuration `/etc/daybook-operations`, backups
`/opt/backups/daybook_operations`, loopback port10063, PostgreSQL17 and
`daybook_operations` database/owner. `site`, `venv`, `storage_path`, configuration,
backup, uv and router paths remain configurable. Record and capacity thresholds,
profile identities and purposes, allowed networks and signing-key selection
retain the original validations and defaults. Shared PostgreSQL listener/access
policy can be left unmanaged through `PostgresInstallConfig` as shown.

The four0600 configurations use the original templates: systemd environment,
quoted management shell companion, schema4 profiles and lifecycle metadata.
Profiles contain only principal identity and executor/monitor credentials;
source bindings, schedules and machine offers are not deployment inputs.
Management sources the companion inside the service-user shell. Secret values
never enter the controller's command arguments, and failure output is replaced
with the original bounded failure categories. An application failure stops the
remaining operations; it is not evidence that no preceding database write ran.

`migrate --noinput` and `provision_operations` execute as managed operations on
every normal deployment. Provisioning may save unchanged principal/credential
enabled values and disable omitted credentials. A semantic repeat therefore
still performs genuine management and database I/O. It does not edit source
bindings or machine offers. Determine pending migrations and source/dependency
effects before a production update, including changes in imported shared
Daybook modules even when the direct API files are unchanged.

A read-only `uv sync --check` determines dependency drift. A real frozen sync
runs for drift or changed source. Service restart follows source, dependency,
configuration or unit changes only when explicitly enabled; disabled installs
remain stopped. The enabled `/healthz` check establishes database readiness,
not successful source work or end-to-end client behavior.

The API and reconciliation processes share the installed source tree. An update
can change imported code before the restart; no transactional rollout or
application rollback is claimed. After partial management failure, inspect the
retained outcome and schema state before retrying or selecting another source.

The private playbook also has an original loopback-port ownership preflight.
`operations_api_port_preflight(cfg)` queues that read-only check before the
backend; it allows listeners belonging to `daybook-operations.service` and
refuses another owner. The standalone role did not contain this preflight, so
it is separate from the public backend rather than an added mandatory policy.

## Exact Git revision and original source ownership

The Git option runs under the dedicated service identity through the shared
`runuser` helper. A fresh clone keeps a valid index so a failed later fetch can resume. It fetches the exact
40-character revision, checks out detached, and verifies HEAD. A clean detached
repeat queues no Git mutation; tracked local changes are refused without force
or reset. The pyinfra SDK branch argument cannot represent a commit SHA and its
global become arguments are deliberately not used.

Rsync uses the established checksum/omit-directory-times helper with the original
exclusions and SDK tooling markers. On the original root connection the remote
binary is `/usr/bin/rsync`; no redundant `sudo rsync` shell wrapper is needed.
Transferred files get the service identity and a metadata-only inspection finds
remaining descendant ownership mismatches. Only mismatches are chowned, so a
converged repeat does not change unrelated inode timestamps. This is source
metadata enumeration, not a promise of globally zero read I/O.
