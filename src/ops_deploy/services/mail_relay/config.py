"""Typed variables for the original mail_relay_deploy role."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser


class RecipientRewrite(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True, populate_by_name=True)
    source: Annotated[str, Field(alias="from", pattern=r"^(@[^@\s]+|[^@\s]+@[^@\s]+)$")]
    to: Annotated[str, Field(pattern=r"^(@[^@\s]+|[^@\s]+@[^@\s]+)$")]


class MailRelayConfig(BaseServiceConfig):
    domains: tuple[Annotated[str, Field(pattern=r"^[\w.-]+$")], ...]
    srs_exclude_domains: tuple[str, ...] | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    service_name: ServiceName = "mail-relay"
    user: UnixUser = "postfix"
    site_path: PurePosixPath = PurePosixPath("/etc/postfix")
    recipient_rewrites: tuple[RecipientRewrite, ...] = ()
    hostname: str = "mail.wersdoerfer.de"
    mydomain: str = "wersdoerfer.de"
    backend_host: str = "smtp.home.xn--wersdrfer-47a.de"
    backend_port: StrictInt = 25
    inet_interfaces: str = "all"
    inet_protocols: Literal["all", "ipv4", "ipv6"] = "all"
    smtp_address_preference: Literal["any", "ipv4", "ipv6"] = "any"
    mynetworks: tuple[str, ...] = ("127.0.0.0/8", "[::1]/128")
    tls_enabled: StrictBool = True
    smtp_tls_security_level: str = "may"
    smtpd_tls_security_level: str = "may"
    backend_tls_security_level: str = "encrypt"
    smtputf8_enable: StrictBool = False
    tls_protocols: str = ">=TLSv1.2"
    greylisting_enabled: StrictBool = True
    greylisting_port: StrictInt = 10024
    greylisting_delay: StrictInt = 300
    greylisting_max_age: StrictInt = 35
    greylisting_retry_window: StrictInt = 48
    postgrey_whitelist_clients_extra: tuple[str, ...] = ()
    verify_recipients: StrictBool = False
    unverified_recipient_reject_code: StrictInt = 550
    verify_external_transport: str = "discard:verified-by-srs-reverse"
    postscreen_enabled: StrictBool = False
    postscreen_dnsbl_sites: tuple[str, ...] = (
        "zen.spamhaus.org=127.0.0.[2..11]*3",
        "list.dnswl.org=127.0.[0..255].0*-2",
        "list.dnswl.org=127.0.[0..255].1*-4",
        "list.dnswl.org=127.0.[0..255].[2..3]*-6",
    )
    postscreen_dnsbl_threshold: StrictInt = 3
    postscreen_dnsbl_action: str = "enforce"
    postscreen_greet_action: str = "enforce"
    postscreen_access_extra: tuple[str, ...] = ()
    local_recursor_enabled: StrictBool = False
    local_recursor_address: str = "127.0.0.1"
    local_recursor_dropin: str = "/etc/systemd/resolved.conf.d/10-mail-relay-local-recursor.conf"
    submission_enabled: StrictBool = True
    sasl_user: str = "relay"
    submission_discard_spam: StrictBool = False
    submission_discard_spam_regexp: str = "/^X-Spam-Status:[[:space:]]*Yes,/"
    client_connection_rate_limit: StrictInt = 10
    client_recipient_rate_limit: StrictInt = 100
    smtpd_recipient_limit: StrictInt = 100
    maillog_file: str = "/var/log/mail.log"
    packages: tuple[str, ...] = ("postfix", "postgrey", "libsasl2-modules", "sasl2-bin", "ca-certificates")
    srs_enabled: StrictBool = False
    srs_domain: str = ""
    srs_listen_addr: str = "127.0.0.1"
    srs_forward_port: StrictInt = 10001
    srs_reverse_port: StrictInt = 10002
    srs_secret_file: str = "/etc/postsrsd.secret"

    @model_validator(mode="after")
    def _mail_contract(self) -> MailRelayConfig:
        if not self.domains or not self.backend_host:
            raise ValueError("relay requires hosted domains and a backend")
        if self.unverified_recipient_reject_code not in (450, 550):
            raise ValueError("recipient verification rejection code must be 450 or 550")
        if self.postscreen_enabled and not self.postscreen_dnsbl_sites:
            raise ValueError("postscreen requires DNSBL sites")
        if self.srs_enabled and not self.srs_domain:
            raise ValueError("SRS requires its domain")
        for value in self.model_dump().values():
            if isinstance(value, str) and re.search(r"[\x00-\x1f\x7f]", value):
                raise ValueError("relay configuration text must not contain controls")
        for port in (self.backend_port, self.greylisting_port, self.srs_forward_port, self.srs_reverse_port):
            if not 0 < port < 65536:
                raise ValueError("relay ports must be between 1 and 65535")
        return self
