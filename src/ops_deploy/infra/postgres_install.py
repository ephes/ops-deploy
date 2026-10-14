"""PostgreSQL server, its configuration and service databases (the ``postgres_install`` role).

The databases and their login roles use the shared
:func:`~ops_deploy.helpers.postgres_database` helper, which never drops or
recreates anything: it creates what is missing and fixes the owner and the
password of what exists.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Generator, Mapping
from io import StringIO
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.server import Command, Which
from pyinfra.operations import apt, files, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux
from ops_deploy.helpers import postgres_database
from ops_deploy.infra._common import apt_repository, codename, directory, sources_path

# What PostgreSQL accepts unquoted and what the database helper insists on.
Identifier = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]
# Extension names may contain dashes (``uuid-ossp``).
ExtensionName = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,62}$")]
# One pg_hba.conf field: no whitespace, no quotes, no comment sign.
HbaField = Annotated[str, Field(pattern=r"^[^\s\"'#]+$")]
SettingName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.]*$")]
PackageName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]*$")]
RepoWord = Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")]
Url = Annotated[str, Field(pattern=r"^https://\S+$")]


class PgHbaRule(RoleConfig):
    type: Literal["local", "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"]
    database: HbaField
    user: HbaField
    # Not written for ``local`` rules; others default to 0.0.0.0/0 like the role.
    address: HbaField = "0.0.0.0/0"
    auth_method: HbaField
    # Written verbatim after the method (may hold several ``key=value`` words).
    auth_options: str | None = Field(default=None, pattern=r"^[^\n#]+$")
    comment: str | None = Field(default=None, pattern=r"^[^\n]*$")


DEFAULT_PG_HBA = (
    PgHbaRule(type="local", database="all", user="postgres", auth_method="peer"),
    PgHbaRule(type="local", database="all", user="all", auth_method="peer"),
    PgHbaRule(type="host", database="all", user="all", address="127.0.0.1/32", auth_method="scram-sha-256"),
    PgHbaRule(type="host", database="all", user="all", address="::1/128", auth_method="scram-sha-256"),
)


class PostgresInstallConfig(RoleConfig):
    version: str = Field(default="17", pattern=r"^\d+$")
    cluster_name: Identifier = "main"
    service_name: str = Field(default="postgresql", pattern=r"^[A-Za-z0-9_.@-]+$")

    use_pgdg_repo: bool = True
    repo_name: str = Field(default="postgresql", pattern=r"^[a-z0-9-]+$")
    repo_url: Url = "https://apt.postgresql.org/pub/repos/apt"
    # None: the host's release codename, as the role's ansible_distribution_release.
    repo_codename: RepoWord | None = None
    repo_components: tuple[RepoWord, ...] = ("main",)
    repo_key_url: Url = "https://www.postgresql.org/media/keys/ACCC4CF8.asc"
    repo_keyring: AbsolutePath = "/etc/apt/keyrings/postgresql.asc"

    # None: postgresql-, postgresql-client-, postgresql-contrib-<version> and libpq-dev.
    packages: tuple[PackageName, ...] | None = None
    extra_packages: tuple[PackageName, ...] = ("python3-psycopg2",)

    listen_addresses: tuple[str, ...] | str = ("localhost",)
    port: int = Field(default=5432, ge=1, le=65535)
    manage_conf_d: bool = True
    conf_d_filename: str = Field(default="20-ops-library.conf", pattern=r"^[A-Za-z0-9._-]+\.conf$")
    config_overrides: Mapping[SettingName, str | int | float | bool] = Field(default_factory=dict)
    manage_pg_hba: bool = True
    pg_hba_rules: tuple[PgHbaRule, ...] = DEFAULT_PG_HBA

    admin_user: Identifier = "postgres"
    service_enabled: bool = True
    restart_on_change: bool = True
    manage_cluster_service: bool = True

    @field_validator("listen_addresses")
    @classmethod
    def _listen(cls, value: tuple[str, ...] | str) -> tuple[str, ...] | str:
        for address in (value,) if isinstance(value, str) else value:
            if not re.fullmatch(r"[A-Za-z0-9.:*_-]+", address):
                raise ValueError(f"not a listen address: {address!r}")
        return value

    @field_validator("config_overrides")
    @classmethod
    def _plain_values(cls, value: Mapping[str, str | int | float | bool]) -> Mapping[str, str | int | float | bool]:
        if any(isinstance(item, str) and "\n" in item for item in value.values()):
            raise ValueError("config_overrides values must be single-line")
        return value

    @property
    def config_dir(self) -> str:
        return f"/etc/postgresql/{self.version}/{self.cluster_name}"

    @property
    def pg_hba_path(self) -> str:
        return f"{self.config_dir}/pg_hba.conf"

    @property
    def conf_d_path(self) -> str:
        return f"{self.config_dir}/conf.d/{self.conf_d_filename}"

    @property
    def cluster_service_name(self) -> str:
        return f"postgresql@{self.version}-{self.cluster_name}"

    @property
    def all_packages(self) -> tuple[str, ...]:
        default = (*(f"postgresql-{part}{self.version}" for part in ("", "client-", "contrib-")), "libpq-dev")
        return (*(default if self.packages is None else self.packages), *self.extra_packages)


class DatabaseSpec(RoleConfig):
    """A database, its owner (a login role) and the owner's password.

    The role takes users and databases as two lists; every caller pairs one
    user with one database, which is what this models.
    """

    name: Identifier
    owner: Identifier
    password: SecretStr

    @field_validator("password")
    @classmethod
    def _ascii(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value() or not value.get_secret_value().isascii():
            raise ValueError("the password must be non-empty ASCII")
        return value


class ExtensionSpec(RoleConfig):
    name: ExtensionName
    database: Identifier


def render_conf_d(cfg: PostgresInstallConfig) -> str:
    """``ops_postgresql.conf.j2`` from the role, byte for byte."""

    listen = cfg.listen_addresses if isinstance(cfg.listen_addresses, str) else ",".join(cfg.listen_addresses)
    text = f"# Managed by Ansible (postgres_install role)\n\nlisten_addresses = '{listen}'\nport = {cfg.port}\n\n"
    # Jinja's dictsort: keys compared case-insensitively.
    for key, value in sorted(cfg.config_overrides.items(), key=lambda item: item[0].lower()):
        rendered = "'" + value.replace("'", "''") + "'" if isinstance(value, str) else str(value)
        text += f"{key} = {rendered}\n"
    return text


def render_pg_hba(cfg: PostgresInstallConfig) -> str:
    """``pg_hba.conf.j2`` from the role, byte for byte (each rule is followed by a blank line)."""

    text = "# Managed by Ansible (postgres_install role)\n# See pg_hba.conf(5) for format details\n\n"
    for rule in cfg.pg_hba_rules:
        if rule.comment is not None:
            text += f"# {rule.comment}\n"
        parts = [rule.type, rule.database, rule.user]
        if rule.type != "local":
            parts.append(rule.address)
        parts.append(rule.auth_method)
        if rule.auth_options is not None:
            parts.append(rule.auth_options)
        text += " ".join(parts) + "\n\n"
    return text


def missing_packages(packages: tuple[str, ...]) -> list[str]:
    """``packages`` neither installed nor provided by an installed package.

    PGDG's ``postgresql-<version>`` provides ``postgresql-contrib-<version>``,
    which is a virtual package from version 10 on: it is never "installed",
    so pyinfra's ``apt.packages`` alone would report a change on every run
    (Ansible's ``apt`` counts the provider).
    """

    have: set[str] = set()
    query = "dpkg-query -W -f='${db:Status-Abbrev}|${Package}|${Provides}\\n'"
    for line in output(query).splitlines():
        status, _, rest = line.partition("|")
        if not status.startswith("ii"):
            continue
        name, _, provides = rest.partition("|")
        have.add(name)
        have.update(item.split()[0] for item in provides.split(",") if item.strip())
    return [package for package in packages if package not in have]


def _psql(admin_user: str, database: str, port: int) -> str:
    argv = [
        "runuser",
        "-u",
        admin_user,
        "--",
        "psql",
        "-XAtq",
        "-v",
        "ON_ERROR_STOP=1",
        "-p",
        str(port),
        "-d",
        database,
    ]
    return shlex.join(argv)


@operation()
def _extension(extension: str, database: str, admin_user: str, port: int) -> Generator[StringCommand, None, None]:
    probe = f"select 1 from pg_extension where extname = '{extension}'"
    # Empty while the database (or the server) does not exist yet: planned as new.
    command = f"{_psql(admin_user, database, port)} -c {shlex.quote(probe)} 2>/dev/null || true"
    present = host.get_fact(Command, command=command)
    if (present or "").strip() == "1":
        host.noop(f"PostgreSQL extension {extension} is installed in {database}")
        return
    yield StringCommand(
        _psql(admin_user, database, port), "-c", shlex.quote(f'CREATE EXTENSION IF NOT EXISTS "{extension}"')
    )


@deploy("PostgreSQL")
def deploy_postgres_install(
    cfg: PostgresInstallConfig,
    databases: tuple[DatabaseSpec, ...] = (),
    extensions: tuple[ExtensionSpec, ...] = (),
) -> None:
    """Install, configure and start PostgreSQL, then ensure ``databases`` and ``extensions``."""

    require_linux("postgres_install")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("postgres_install needs a Debian-family host")
    names = [db.name for db in databases]
    if len(set(names)) != len(names):
        raise DeployError("postgres_install: a database is listed twice")
    owners = {db.owner: db.password.get_secret_value() for db in databases}
    if any(db.password.get_secret_value() != owners[db.owner] for db in databases):
        raise DeployError("postgres_install: one owner has two different passwords")

    if cfg.use_pgdg_repo:
        suite = f"{cfg.repo_codename or codename()}-pgdg"
        if suite == "-pgdg":
            raise DeployError("postgres_install: cannot tell the host's release codename; set repo_codename")
        repo = apt_repository(
            name=cfg.repo_name,
            key_url=cfg.repo_key_url,
            keyring=cfg.repo_keyring,
            uris=cfg.repo_url,
            suites=(suite,),
            components=cfg.repo_components,
        )
        apt.update(name="Update apt cache for the PostgreSQL repository", _if=repo.did_change)
    else:
        # deb822_repository with state absent: the sources file and a key stored under the repo's name.
        for path in (
            sources_path(cfg.repo_name),
            *(f"/etc/apt/keyrings/{cfg.repo_name}.{ext}" for ext in ("asc", "gpg")),
        ):
            files.file(name=f"Remove {path}", path=path, present=False)

    # Like the role, a failing cache update does not stop the install.
    apt.update(name="Update apt cache", cache_time=3600, _ignore_errors=True)
    missing = missing_packages(cfg.all_packages)
    if missing:
        apt.packages(name="Install PostgreSQL packages", packages=missing)

    directory(cfg.config_dir, user="postgres", group="postgres", mode="0755")
    changes = []
    if cfg.manage_conf_d:
        conf_d = f"{cfg.config_dir}/conf.d"
        directory(conf_d, user="postgres", group="postgres", mode="0755")
        changes.append(
            files.put(
                name="Render PostgreSQL drop-in configuration",
                src=StringIO(render_conf_d(cfg)),
                dest=cfg.conf_d_path,
                user="postgres",
                group="postgres",
                mode="0644",
            )
        )
    if cfg.manage_pg_hba:
        changes.append(
            files.put(
                name="Render pg_hba.conf",
                src=StringIO(render_pg_hba(cfg)),
                dest=cfg.pg_hba_path,
                user="postgres",
                group="postgres",
                mode="0640",
            )
        )

    units = [cfg.service_name] + ([cfg.cluster_service_name] if cfg.manage_cluster_service else [])
    for unit in units:
        systemd.service(name=f"Ensure {unit}", service=unit, running=True, enabled=cfg.service_enabled)
    if changes and cfg.restart_on_change:
        # Restarting the umbrella unit restarts its clusters (PartOf=); the
        # role restarts both units, which restarts the cluster twice.
        systemd.service(
            name=f"Restart {cfg.service_name} for the new configuration",
            service=cfg.service_name,
            restarted=True,
            _if=any_changed(*changes),
        )

    for db in databases:
        postgres_database(
            db.name,
            owner=db.owner,
            password=db.password,
            admin_user=cfg.admin_user,
            service=cfg.service_name,
            port=cfg.port,
            enabled=cfg.service_enabled,
        )
    for ext in extensions:
        _extension(
            name=f"Ensure PostgreSQL extension {ext.name} in {ext.database}",
            extension=ext.name,
            database=ext.database,
            admin_user=cfg.admin_user,
            port=cfg.port,
        )
