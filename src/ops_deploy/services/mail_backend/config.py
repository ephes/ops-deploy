"""Typed variables for the original mail_backend_deploy role."""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser

Domain = Annotated[str, Field(pattern=r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")]
Address = Annotated[str, Field(pattern=r"^[A-Za-z0-9_+.-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")]


class RequiredAlias(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    localpart: Annotated[str, Field(pattern=r"^[A-Za-z0-9_+.-]+$")]
    destination_localpart: str = ""


class DomainAlias(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    alias_domain: Domain
    target_domain: Domain


class ForwardAlias(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    address: Address
    destinations: tuple[Address, ...]


class MailBackendConfig(BaseServiceConfig):
    domains: tuple[Domain, ...]
    sender_only_domains: tuple[Domain, ...] = ()
    postfixadmin_domain_aliases: tuple[DomainAlias, ...] = ()
    forward_aliases: tuple[ForwardAlias, ...] = ()
    required_aliases: tuple[RequiredAlias, ...] = (
        RequiredAlias(localpart="postmaster"),
        RequiredAlias(localpart="abuse"),
    )
    initial_user: str = ""
    initial_user_domain: str = ""
    relay_user: str = "relay"
    dovecot_mail_location: str | None = None
    sieve_dir: str | None = None
    sieve_active: str | None = None
    service_name: ServiceName = "mail-backend"
    user: UnixUser = "vmail"
    site_path: PurePosixPath = PurePosixPath("/mnt/cryptdata/vmail")
    hostname: str = "macmini.home.wersdoerfer.de"
    mydomain: str = "wersdoerfer.de"
    imap_hostname: str = "imap.home.wersdoerfer.de"
    smtp_hostname: str = "smtp.home.wersdoerfer.de"
    inet_interfaces: str = "all"
    inet_protocols: Literal["all", "ipv4", "ipv6"] = "all"
    mynetworks: tuple[str, ...] = ("127.0.0.0/8", "[::1]/128", "213.239.212.206/32", "[2a01:4f8:a0:82dc::2]/128")
    local_delivery_clients: tuple[str, ...] = ()
    relay_host: str = "mail.wersdoerfer.de"
    relay_port: StrictInt = 587
    vmail_path: str = "/mnt/cryptdata/vmail"
    vmail_user: str = "vmail"
    vmail_group: str = "vmail"
    vmail_uid: StrictInt = 5000
    vmail_gid: StrictInt = 5000
    maildir_format: str = "%d/%n/"
    postgres_host: str = "localhost"
    postgres_port: StrictInt = 5432
    postgres_database: str = "mail"
    postgres_user: str = "mail"
    tls_enabled: StrictBool = True
    tls_cert: str = "/etc/letsencrypt/live/home.xn--wersdrfer-47a.de/fullchain.pem"
    tls_key: str = "/etc/letsencrypt/live/home.xn--wersdrfer-47a.de/privkey.pem"
    smtp_tls_security_level: str = "encrypt"
    smtpd_tls_security_level: str = "encrypt"
    tls_protocols: str = ">=TLSv1.2"
    dovecot_protocols: str = "imap lmtp sieve"
    dovecot_auth_mechanisms: str = "plain login"
    dovecot_disable_plaintext_auth: str = "yes"
    sieve_enabled: StrictBool = True
    spam_to_junk_enabled: StrictBool = False
    spam_junk_mailbox: str = "Junk"
    sieve_before_dir: str = "/etc/dovecot/sieve/before.d"
    dkim_enabled: StrictBool = True
    dkim_selector: str = "mail"
    dkim_key_path: str = "/etc/opendkim/keys"
    dkim_key_bits: StrictInt = 2048
    extra_milters: tuple[str, ...] = ()
    password_scheme: Literal["SHA512-CRYPT"] = "SHA512-CRYPT"
    recipient_delimiter: str = "-"
    submission_rate_limit: StrictInt = 100
    smtputf8_enable: StrictBool = False
    maillog_file: str = "/var/log/mail.log"
    schema_mode: Literal["legacy", "postfixadmin"] = "legacy"
    packages: tuple[str, ...] = (
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
        "ca-certificates",
    )

    @model_validator(mode="after")
    def _mail_contract(self) -> MailBackendConfig:
        if not self.domains or "all" in self.domains or "all" in self.sender_only_domains:
            raise ValueError("ordinary hosted domains must be nonempty and exclude the reserved admin domain")
        if set(self.domains) & set(self.sender_only_domains):
            raise ValueError("hosted and sender-only domains must be disjoint")
        if self.sender_only_domains and self.schema_mode != "postfixadmin":
            raise ValueError("sender-only domains require the PostfixAdmin schema")
        for domain_alias in self.postfixadmin_domain_aliases:
            if domain_alias.target_domain not in self.domains or domain_alias.alias_domain == "all":
                raise ValueError("domain aliases must target hosted domains and exclude the reserved admin domain")
            if self.schema_mode == "legacy" and domain_alias.alias_domain not in self.domains:
                # Legacy mappings join two mail_domains rows; only hosted domains get one.
                raise ValueError("legacy domain aliases need a hosted alias domain")
        for alias in self.forward_aliases:
            if not alias.destinations or alias.address.rsplit("@", 1)[1] not in self.domains:
                raise ValueError("forward aliases need destinations and an ordinary hosted source domain")
        if self.initial_user and (
            not re.fullmatch(r"[A-Za-z0-9_+.-]+", self.initial_user) or self.initial_user_domain not in self.domains
        ):
            raise ValueError("initial user must have a valid localpart and ordinary hosted domain")
        for client in self.local_delivery_clients:
            network = ipaddress.ip_network(client, strict=True)
            if network.prefixlen != network.max_prefixlen or str(network) != client:
                raise ValueError("local-delivery clients must be canonical single-host CIDRs")
        for path in (self.vmail_path, self.dkim_key_path, self.sieve_before_dir, self.tls_cert, self.tls_key):
            if not path.startswith("/") or ".." in PurePosixPath(path).parts:
                raise ValueError("mail paths must be absolute without parent traversal")
        for value in self.model_dump().values():
            if isinstance(value, str) and re.search(r"[\x00-\x1f\x7f]", value):
                raise ValueError("mail configuration text must not contain control characters")
        if not 0 < self.relay_port < 65536 or not 0 < self.postgres_port < 65536:
            raise ValueError("mail ports must be between 1 and 65535")
        return self
