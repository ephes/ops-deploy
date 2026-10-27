"""PostfixAdmin release, existing database and application settings."""

from __future__ import annotations

import ipaddress
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, StrictBool, field_validator

from ops_deploy.core.config import UnixUser
from ops_deploy.services._mail_web.config import Domain, MailWebConfig, Name, PathText


class PostfixAdminConfig(MailWebConfig):
    service_name: Literal["postfixadmin"] = "postfixadmin"
    site_path: PurePosixPath = PurePosixPath("/opt/postfixadmin")
    user: UnixUser = "www-data"
    version: str = "4.0.5"
    release_build: Literal["php84"] = "php84"
    install_path: PathText = "/opt/postfixadmin"
    listen_port: Annotated[int, Field(ge=1, le=65535)] = 8082
    db_type: Literal["pgsql"] = "pgsql"
    db_host: Literal["localhost", "127.0.0.1"] = "localhost"
    db_port: Annotated[int, Field(ge=1, le=65535)] = 5432
    db_name: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]*$")] = "mail"
    db_user: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_]*$")] = "mail"
    db_admin_user: UnixUser = "postgres"
    admin_email: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+$")]
    encrypt_method: Literal["dovecot:SHA512-CRYPT"] = "dovecot:SHA512-CRYPT"
    dovecotpw_path: Literal["/usr/bin/doveadm pw"] = "/usr/bin/doveadm pw"
    domain_path: Literal["YES", "NO"] = "YES"
    domain_in_mailbox: Literal["YES", "NO"] = "NO"
    quota_enabled: StrictBool = False
    vacation_enabled: StrictBool = False
    fetchmail_enabled: StrictBool = False
    totp_enabled: StrictBool = True
    default_aliases: Annotated[int, Field(ge=0)] = 0
    default_mailboxes: Annotated[int, Field(ge=0)] = 0
    user_can_edit_alias: StrictBool = False
    user_can_edit_forward: StrictBool = False
    default_domain_aliases: dict[Name, Name] = Field(
        default_factory=lambda: {
            "abuse": "postmaster",
            "hostmaster": "postmaster",
            "webmaster": "postmaster",
        }
    )
    totp_exceptions: tuple[str, ...] = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")
    emailcheck_resolve_domain: StrictBool = False
    traefik_host_aliases: tuple[Domain, ...] = ()
    traefik_ip_whitelist_enabled: StrictBool = True
    traefik_ip_whitelist: tuple[str, ...] = ("100.64.0.0/10", "fd7a:115c:a1e0::/48")
    login_rate_limit: Annotated[str, Field(pattern=r"^[0-9]+r/[sm]$")] = "5r/m"
    login_rate_burst: Annotated[int, Field(ge=0)] = 3

    @field_validator("totp_exceptions", "traefik_ip_whitelist")
    @classmethod
    def networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("mail web networks must be valid IP networks") from None
        return value
