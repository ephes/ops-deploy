# Mail database foundation

Internal API shared by core mail and its web applications. Core mail owns the
mail login role; an existing web application can require it without reconciling
the role, its password or the mail catalog.

```python
from pydantic import SecretStr
from ops_deploy.services._mail_database import (
    MailDatabaseConfig,
    ensure_mail_database,
    require_mail_database,
)

database = MailDatabaseConfig(name="mail", role="mail", port=5432, admin_user="postgres")
ensure_mail_database(database, role_password=SecretStr("owned-fixture-password"))
require_mail_database(database, required_privileges=("CONNECT",))
```

`ensure_mail_database` returns `MailDatabaseOperations(role, database)` operation
metadata. It creates a missing login role and database, using PostgreSQL's default
database owner (the administering role). Existing database/schema owners and
grants remain untouched. A valid matching SCRAM verifier is retained byte for
byte; a login-only repair retains it too. An explicit password change updates
the verifier. An unknown query/tool state, unsupported legacy MD5 verifier or
malformed SCRAM verifier fails before credential reconciliation. A valid-length
verifier with only one matching derived key is inconsistent and also refuses;
it is not evidence of a requested password change.

`require_mail_database` is a read-only operation requiring the database and login
role. Its optional `required_privileges` tuple checks DATABASE privileges from
`CONNECT`, `CREATE`, `TEMPORARY`; it neither grants privileges nor checks app
table/schema privileges. Web applications own only their app-specific additions.

Identifiers use simple PostgreSQL names; the admin connects by local peer auth
to the selected port. This API does not install/start PostgreSQL, change schema
ownership, grant/revoke privileges, or reconcile app rows. PostfixAdmin's `ALL`
pseudo-domain and its admin mapping belong to the web application. Passwords and
verifiers stay in protected stdin/child-process memory; host output contains
fixed state/error markers only.

Qualification of this foundation is separate from complete mail deployment:
focused fake-connector checks cover the operation boundary, while owned native
PostgreSQL tests cover create/update/repeat, preserved owners/grants/verifiers,
login repair and refusal of unsupported/malformed state. Complete service and
AMD64 qualification remain part of the surrounding mail migration.

Existing roles with NULL password verifiers are refused, like unsupported MD5;
this API does not interpret unknown credentials as permission to initialize them.
Passwords currently use the explicit nonempty ASCII contract (excluding CR, LF
and NUL). Non-ASCII inputs refuse before verification or mutation; no Unicode
normalization or SASLprep equivalence is claimed. Database-only requests contain
no password.
