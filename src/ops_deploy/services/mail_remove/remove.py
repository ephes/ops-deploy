"""Port of the ``mail_remove`` role: its defaults, component selection, order and ignored failures.

Never dispatched without ``confirm`` and at least one component (``backend``:
Postfix, Dovecot, OpenDKIM; ``relay``: the edge Postfix and postgrey; ``spam``:
rspamd). For the selected components it stops and disables the services the
host knows (failures ignored), purges the packages, and removes the config
and state directories. The Maildir and backup paths, the vmail account and
the PostgreSQL database and role go only when their flags are set, as with
the role (its defaults keep them). Mail data never passes through the
controller.
"""

from __future__ import annotations

from collections.abc import Generator, Iterable
from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import Field, StrictBool, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, FunctionCommand, OperationError, StringCommand, deploy, operation
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.base._common import AbsolutePath, RoleConfig, output, require_linux
from ops_deploy.core.config import ServiceName, UnixUser
from ops_deploy.services._lifecycle.ansible_remove import absent, service_absent, user_absent
from ops_deploy.services._lifecycle.apt_purge import Package, purge

# Quoted as an SQL identifier and an SQL string literal.
PgName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")]


class MailRemoveConfig(RoleConfig):
    """``mail_remove``'s defaults."""

    confirm: StrictBool = False
    backend: StrictBool = False
    relay: StrictBool = False
    spam: StrictBool = False
    purge_packages: StrictBool = True
    remove_configs: StrictBool = True
    remove_state: StrictBool = True
    remove_data: StrictBool = False
    remove_vmail_user: StrictBool = False
    drop_database: StrictBool = False
    drop_db_user: StrictBool = False
    db_force_disconnect: StrictBool = False
    postgres_database: PgName = "mail"
    postgres_user: PgName = "mail"
    postgres_become_user: UnixUser = "postgres"
    vmail_path: AbsolutePath = "/mnt/cryptdata/vmail"
    backup_path: AbsolutePath = "/mnt/cryptdata/backups/mail"
    vmail_user: UnixUser = "vmail"
    vmail_group: UnixUser = "vmail"
    backend_services: tuple[ServiceName, ...] = ("postfix", "dovecot", "opendkim")
    relay_services: tuple[ServiceName, ...] = ("postfix", "postgrey")
    spam_services: tuple[ServiceName, ...] = ("rspamd",)
    packages_backend: tuple[Package, ...] = (
        "postfix",
        "postfix-pgsql",
        "dovecot-core",
        "dovecot-imapd",
        "dovecot-lmtpd",
        "dovecot-pgsql",
        "dovecot-sieve",
        "dovecot-managesieved",
        "opendkim",
        "opendkim-tools",
        "libsasl2-modules",
    )
    packages_relay: tuple[Package, ...] = ("postfix", "postgrey", "libsasl2-modules", "sasl2-bin")
    packages_spam: tuple[Package, ...] = ("rspamd",)
    config_paths_backend: tuple[AbsolutePath, ...] = ("/etc/postfix", "/etc/dovecot", "/etc/opendkim")
    state_paths_backend: tuple[AbsolutePath, ...] = (
        "/var/spool/postfix",
        "/var/lib/postfix",
        "/var/lib/dovecot",
        "/var/lib/opendkim",
    )
    config_paths_relay: tuple[AbsolutePath, ...] = ("/etc/postfix", "/etc/postgrey")
    state_paths_relay: tuple[AbsolutePath, ...] = ("/var/spool/postfix", "/var/lib/postfix", "/var/lib/postgrey")
    config_paths_spam: tuple[AbsolutePath, ...] = ("/etc/rspamd",)
    state_paths_spam: tuple[AbsolutePath, ...] = ("/var/lib/rspamd", "/var/log/rspamd")

    @model_validator(mode="after")
    def bounded(self) -> Self:
        paths = (
            self.vmail_path,
            self.backup_path,
            *self.config_paths_backend,
            *self.state_paths_backend,
            *self.config_paths_relay,
            *self.state_paths_relay,
            *self.config_paths_spam,
            *self.state_paths_spam,
        )
        for value in paths:
            path = PurePosixPath(value)
            if len(path.parts) < 3 or ".." in path.parts:
                raise ValueError("removal paths must not be root, a top-level directory or contain traversal")
        if "root" in (self.vmail_user, self.vmail_group):
            raise ValueError("root cannot be the vmail account")
        return self

    def _selected(self, backend: Iterable[str], relay: Iterable[str], spam: Iterable[str]) -> tuple[str, ...]:
        # The role's ``[] | union(...) | union(...) | union(...)``: first occurrence wins.
        chosen: list[str] = []
        for enabled, items in ((self.backend, backend), (self.relay, relay), (self.spam, spam)):
            if enabled:
                chosen.extend(items)
        return tuple(dict.fromkeys(chosen))

    @property
    def target_services(self) -> tuple[str, ...]:
        return self._selected(self.backend_services, self.relay_services, self.spam_services)

    @property
    def target_packages(self) -> tuple[str, ...]:
        return self._selected(self.packages_backend, self.packages_relay, self.packages_spam)

    @property
    def target_config_paths(self) -> tuple[str, ...]:
        return self._selected(self.config_paths_backend, self.config_paths_relay, self.config_paths_spam)

    @property
    def target_state_paths(self) -> tuple[str, ...]:
        return self._selected(self.state_paths_backend, self.state_paths_relay, self.state_paths_spam)


def _psql(cfg: MailRemoveConfig, sql: str) -> str:
    # community.postgresql as become_user postgres: peer auth over the local socket.
    psql = "psql -X -q -t -A -v ON_ERROR_STOP=1 -d postgres"
    return f"cd / && runuser -u {cfg.postgres_become_user} -- {psql} -c '{sql}'"


def _postgres_unavailable(what: str) -> FunctionCommand:
    def fail() -> None:
        raise OperationError(f"Cannot inspect the mail PostgreSQL {what}")

    return FunctionCommand(fail, (), {})


@operation()
def _postgres_absent(cfg: MailRemoveConfig, kind: str) -> Generator[StringCommand | FunctionCommand, None, None]:
    """``postgresql_db``/``postgresql_user`` with ``state: absent``: drop only what exists."""

    if kind == "database":
        name = cfg.postgres_database
        lookup = f"SELECT 1 FROM pg_database WHERE datname = $q${name}$q$"
        drop = f'DROP DATABASE "{name}"' + (" WITH (FORCE)" if cfg.db_force_disconnect else "")
    else:
        name = cfg.postgres_user
        lookup = f"SELECT 1 FROM pg_roles WHERE rolname = $q${name}$q$"
        drop = f'DROP USER "{name}"'
    state = host.get_fact(
        Command,
        command=f'if found=$({_psql(cfg, lookup)}); then echo "state=${{found}}"; else echo error; fi',
    )
    if state == "state=1":
        yield StringCommand(_psql(cfg, drop))
    elif state != "state=":
        yield _postgres_unavailable(kind)


def _warn_on_queue() -> None:
    queue = output("postqueue -p")
    if queue and "Mail queue is empty" not in queue:
        logger.warning(f"{host.print_prefix}WARNING: Mail queue is not empty. Consider flushing before removal.")


@deploy("Remove mail")
def remove_mail(cfg: MailRemoveConfig) -> None:
    if not cfg.confirm or not (cfg.backend or cfg.relay or cfg.spam):
        raise DeployError(
            "Mail removal not confirmed or no components selected. "
            "Set confirm and enable one of backend, relay or spam."
        )
    require_linux("Mail removal")
    if cfg.backend or cfg.relay:
        _warn_on_queue()
    # service_facts, then the units it lists: stop and disable, failures ignored.
    for service in cfg.target_services:
        service_absent(
            name=f"Stop and disable {service}",
            service=service,
            label="Mail removal",
            skip_missing=True,
            _ignore_errors=True,
        )
    if cfg.purge_packages:
        purge(name="Purge the mail packages", packages=cfg.target_packages, label="Mail removal")
    if cfg.remove_configs:
        for path in cfg.target_config_paths:
            absent(f"Remove {path}", path)
    if cfg.remove_state:
        for path in cfg.target_state_paths:
            absent(f"Remove {path}", path)
    if cfg.remove_data:
        for path in (cfg.vmail_path, cfg.backup_path):
            absent(f"Remove {path}", path)
    if cfg.remove_vmail_user:
        user_absent(name=f"Remove user {cfg.vmail_user}", user=cfg.vmail_user, remove_home=cfg.remove_data)
        server.group(name=f"Remove group {cfg.vmail_group}", group=cfg.vmail_group, present=False)
    if cfg.drop_database:
        _postgres_absent(name=f"Drop PostgreSQL database {cfg.postgres_database}", cfg=cfg, kind="database")
    if cfg.drop_db_user:
        _postgres_absent(name=f"Drop PostgreSQL user {cfg.postgres_user}", cfg=cfg, kind="user")
