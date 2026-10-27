"""Mail's existing PostgreSQL foundation without database/schema ownership changes.

Core mail owns the login role. Web applications may require this foundation
and add their own narrowly scoped privileges; they do not reconcile its user.
Application catalogs, including PostfixAdmin's reserved ALL domain and its
admin mapping, are outside this module.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Generator
from dataclasses import asdict, dataclass
from pathlib import Path

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.ops import secret_stdin

SCRIPT = (Path(__file__).parent / "files" / "mail_database_host.py").read_text()
_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_-]{0,62}$")
_PRIVILEGES = frozenset({"CONNECT", "CREATE", "TEMPORARY"})


@dataclass(frozen=True)
class MailDatabaseConfig:
    name: str = "mail"
    role: str = "mail"
    port: int = 5432
    admin_user: str = "postgres"

    def __post_init__(self) -> None:
        if not all(_IDENTIFIER.fullmatch(value) for value in (self.name, self.role, self.admin_user)):
            raise ValueError("mail database identifiers must use simple PostgreSQL identifiers")
        if type(self.port) is not int or not 0 < self.port < 65536:
            raise ValueError("mail database port must be between 1 and 65535")


@dataclass(frozen=True)
class MailDatabaseOperations:
    role: OperationMeta
    database: OperationMeta


def command(mode: str) -> str:
    if mode not in {"role-check", "role-apply", "database-check", "database-apply", "require"}:
        raise ValueError("unknown mail database action")
    return shlex.join(["python3", "-I", "-c", SCRIPT, mode])


@operation()
def _ensure_step(payload: SecretStr, kind: str) -> Generator[StringCommand, None, None]:
    raw = payload.get_secret_value()
    state = probe(command(kind + "-check"), name=f"Mail database {kind}", stdin=raw)
    if state not in {"current", "pending"}:
        # Unknown must never become an instruction to rotate a credential.
        raise DeployError("Mail database state could not be established; no credential reconciliation attempted")
    if state == "current":
        host.noop(f"Mail database {kind} is current")
        return
    yield StringCommand(command(kind + "-apply"), _stdin=StdinLines(raw), _get_pty=False, _shell_executable="sh")


def _ensure(config: MailDatabaseConfig, password: SecretStr, kind: str) -> OperationMeta:
    values = asdict(config)
    if kind == "role":
        values["password"] = password.get_secret_value()
    payload = SecretStr(json.dumps(values))
    return _ensure_step(name=f"Ensure mail database {kind}", payload=payload, kind=kind)


def ensure_mail_database(config: MailDatabaseConfig, *, role_password: SecretStr) -> MailDatabaseOperations:
    """Create missing DB/role and reconcile its password, preserving existing ownership/grants.

    The original mail role creates a database with PostgreSQL's default owner
    (the administering user), not the mail login role. Existing owners are never
    rewritten. No PostgreSQL package, service, schema or app row is managed here.
    """
    value = role_password.get_secret_value()
    if not value or not value.isascii() or any(c in value for c in "\r\n\0"):
        raise ValueError("mail database password must be nonempty ASCII without CR/LF/NUL")
    return MailDatabaseOperations(
        role=_ensure(config, role_password, "role"),
        database=_ensure(config, role_password, "database"),
    )


def require_mail_database(config: MailDatabaseConfig, *, required_privileges: tuple[str, ...] = ()) -> OperationMeta:
    """Read-only requirement for web apps, optionally checking DATABASE privileges.

    Table/schema privileges remain app specific. Failure never creates a DB,
    changes a role or grants/revokes privileges.
    """
    if any(value not in _PRIVILEGES for value in required_privileges):
        raise ValueError("mail database privileges must be CONNECT, CREATE or TEMPORARY")
    payload = json.dumps({**asdict(config), "required_privileges": required_privileges})
    return mark_read_only(
        secret_stdin(
            name="Require existing mail database",
            command=command("require"),
            content=SecretContent(payload),
        )
    )
