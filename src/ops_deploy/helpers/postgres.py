"""PostgreSQL login role and database owned by it.

Replaces the database part of ``postgres_install`` (``postgres_install_users``
and ``postgres_install_databases``); installing and configuring the server
stays with that role for now. All SQL runs as the cluster's admin user
(``runuser -u postgres -- psql``, peer auth) and reaches ``psql`` on stdin.

The password never leaves the controller: the SCRAM-SHA-256 verifier
PostgreSQL stores is computed here and sent instead (PostgreSQL accepts a
pre-hashed password). To decide whether the role needs a new one, the host
reports the stored verifier's salt and iteration count plus a SHA-256 of the
whole verifier; the controller recomputes the verifier with that salt and
compares the digests. A role whose password matches is left alone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import shlex
from collections.abc import Generator
from dataclasses import dataclass

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import OperationValueError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import systemd

SCRAM_ITERATIONS = 4096  # PostgreSQL's scram_iterations default
_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_-]{0,62}$")


def scram_verifier(password: str, *, salt: bytes, iterations: int = SCRAM_ITERATIONS) -> str:
    """The ``rolpassword`` PostgreSQL stores for ``password`` (RFC 5802/7677).

    PostgreSQL SASLprep-normalises the password first; that is the identity
    for ASCII, so callers keep passwords ASCII.
    """

    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    stored = hashlib.sha256(hmac.digest(salted, b"Client Key", "sha256")).digest()
    server = hmac.digest(salted, b"Server Key", "sha256")
    b64 = base64.b64encode
    return f"SCRAM-SHA-256${iterations}:{b64(salt).decode()}${b64(stored).decode()}:{b64(server).decode()}"


def password_matches(password: str, salt_spec: str, digest: str) -> bool:
    """Whether a stored verifier (given as ``<iterations>:<salt>`` and its SHA-256) is ``password``'s."""

    iterations, _, salt = salt_spec.partition(":")
    try:
        verifier = scram_verifier(password, salt=base64.b64decode(salt, validate=True), iterations=int(iterations))
    except ValueError:
        return False
    return hmac.compare_digest(hashlib.sha256(verifier.encode()).hexdigest(), digest)


@dataclass(frozen=True)
class DatabaseState:
    role_exists: bool = False
    can_login: bool = False
    password_salt: str = ""  # "<iterations>:<base64 salt>" of a SCRAM verifier, else empty
    password_digest: str = ""  # SHA-256 (hex) of the stored verifier
    database_owner: str | None = None  # None: no such database
    schema_owner: str | None = None


def parse_state(lines: list[str] | None) -> DatabaseState:
    values: dict[str, list[str]] = {}
    for line in lines or ():
        kind, _, rest = line.partition("|")
        values[kind] = rest.split("|")
    role = values.get("role")
    login, salt, digest = [*role, "", "", ""][:3] if role is not None else ("", "", "")
    return DatabaseState(
        role_exists=role is not None,
        can_login=login in ("t", "true"),  # text concatenation prints "true"
        password_salt=salt,
        password_digest=digest,
        database_owner=values["db"][0] if "db" in values else None,
        schema_owner=values["schema"][0] if "schema" in values else None,
    )


def _psql(admin_user: str, database: str | None = None, port: int = 5432) -> str:
    # The port picks the cluster (Debian's pg_wrapper), not just the socket.
    argv = ["runuser", "-u", admin_user, "--", "psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-p", str(port)]
    if database is not None:
        argv += ["-d", database]
    return shlex.join(argv)


def state_command(name: str, owner: str, admin_user: str, port: int = 5432) -> str:
    """Read-only probe; prints ``role|``, ``db|`` and ``schema|`` lines. No secret material."""

    role = (
        "select 'role|' || rolcanlogin || '|' || "
        "case when rolpassword like 'SCRAM-SHA-256$%' then split_part(rolpassword, '$', 2) else '' end || '|' || "
        "coalesce(encode(sha256(convert_to(rolpassword, 'UTF8')), 'hex'), '') "
        f"from pg_authid where rolname = '{owner}'"
    )
    db = f"select 'db|' || pg_get_userbyid(datdba) from pg_database where datname = '{name}'"
    schema = "select 'schema|' || pg_get_userbyid(nspowner) from pg_namespace where nspname = 'public'"
    # The schema query needs the database; it fails harmlessly while that is missing.
    # A server not installed or not running yet (the same deploy sets it up)
    # reads as empty: everything is planned as new, and a CREATE of something
    # that does exist fails at execution instead of changing it.
    return (
        f"{{ {_psql(admin_user, port=port)} -c {shlex.quote(role)} -c {shlex.quote(db)} && "
        f"{{ {_psql(admin_user, name, port)} -c {shlex.quote(schema)} 2>/dev/null || true; }}; }} 2>/dev/null || true"
    )


def _probe(name: str, owner: str, admin_user: str, port: int) -> DatabaseState:
    output = host.get_fact(Command, command=state_command(name, owner, admin_user, port))
    return parse_state((output or "").splitlines())


@operation()
def _role(
    database: str, owner: str, password: SecretStr, admin_user: str, port: int
) -> Generator[StringCommand, None, None]:
    state = _probe(database, owner, admin_user, port)
    secret = password.get_secret_value()
    matches = state.role_exists and password_matches(secret, state.password_salt, state.password_digest)
    if state.can_login and matches:
        host.noop(f"PostgreSQL role {owner} is up to date")
        return
    verifier = scram_verifier(secret, salt=secrets.token_bytes(16))
    verb = "ALTER" if state.role_exists else "CREATE"
    # The verifier rides on stdin; the command line names nothing secret.
    sql = f"{verb} ROLE \"{owner}\" WITH LOGIN PASSWORD '{verifier}';"
    yield StringCommand(_psql(admin_user, port=port), _stdin=sql, _get_pty=False, _shell_executable="sh")


@operation()
def _database(database: str, owner: str, admin_user: str, port: int) -> Generator[StringCommand, None, None]:
    state = _probe(database, owner, admin_user, port)
    if state.database_owner == owner and state.schema_owner == owner:
        host.noop(f"PostgreSQL database {database} is up to date")
        return
    if state.database_owner is None:
        yield StringCommand(
            _psql(admin_user, port=port), "-c", shlex.quote(f'CREATE DATABASE "{database}" OWNER "{owner}"')
        )
    elif state.database_owner != owner:
        yield StringCommand(
            _psql(admin_user, port=port), "-c", shlex.quote(f'ALTER DATABASE "{database}" OWNER TO "{owner}"')
        )
    if state.schema_owner != owner:
        alter = f'ALTER SCHEMA public OWNER TO "{owner}"'
        yield StringCommand(_psql(admin_user, database, port), "-c", shlex.quote(alter))


@dataclass(frozen=True)
class PostgresDatabase:
    service: OperationMeta | None
    role: OperationMeta
    database: OperationMeta


def postgres_database(
    name: str,
    *,
    owner: str,
    password: SecretStr,
    admin_user: str = "postgres",
    service: str = "postgresql",
    port: int = 5432,
    enabled: bool = True,
    manage_service: bool = True,
) -> PostgresDatabase:
    """Ensure login role ``owner`` with ``password`` and database ``name`` owned by it.

    Like ``postgres_install`` by default: ``service`` is enabled and running, the role
    has ``LOGIN`` (other attributes are left alone), the database and its
    ``public`` schema belong to ``owner``. ``port`` selects the cluster;
    ``enabled=False`` leaves the service disabled. The server must be running
    when the operations run. ``manage_service=False`` leaves its state and
    enablement untouched and returns ``service=None``; callers must check server
    availability first. While it is not installed or not running yet
    (the same deploy sets it up) the plan treats everything as new.
    """

    for value in (name, owner, admin_user):
        if not _IDENTIFIER.match(value):
            raise OperationValueError(f"not a supported quoted PostgreSQL identifier: {value!r}")
    if not password.get_secret_value() or not password.get_secret_value().isascii():
        raise OperationValueError("the PostgreSQL password must be non-empty ASCII")
    service_op = (
        systemd.service(name=f"Ensure {service} is running", service=service, running=True, enabled=enabled)
        if manage_service
        else None
    )
    role = _role(
        name=f"Ensure PostgreSQL role {owner}",
        database=name,
        owner=owner,
        password=password,
        admin_user=admin_user,
        port=port,
    )
    database = _database(
        name=f"Ensure PostgreSQL database {name}", database=name, owner=owner, admin_user=admin_user, port=port
    )
    return PostgresDatabase(service=service_op, role=role, database=database)
