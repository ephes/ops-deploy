"""Typed variables for the original mail_spam_deploy role."""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser


class MonitoringProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    source_ip: str
    sender: str
    recipient: str
    subject_prefix: str

    @model_validator(mode="after")
    def _exact_probe(self) -> MonitoringProbe:
        if ipaddress.ip_address(self.source_ip).version != 4:
            raise ValueError("monitoring probe needs one literal IPv4 source")
        if not all(re.fullmatch(r"[^@\s]+@[^@\s]+", value) for value in (self.sender, self.recipient)):
            raise ValueError("monitoring probe needs exact sender and recipient identities")
        if not self.subject_prefix or re.search(r"[\x00-\x1f\x7f]", self.subject_prefix):
            raise ValueError("monitoring probe subject must be nonempty without controls")
        return self


class MailSpamConfig(BaseServiceConfig):
    monitoring_probe: MonitoringProbe | None = None
    milter_socket: str | None = None
    milter_socket_postfix: str | None = None
    service_name: ServiceName = "mail-spam"
    user: UnixUser = "_rspamd"
    site_path: PurePosixPath = PurePosixPath("/etc/rspamd")
    redis_enabled: StrictBool = True
    install_redis: StrictBool = False
    redis_host: str = "localhost"
    redis_port: StrictInt = 6379
    web_enabled: StrictBool = True
    web_bind: str = "127.0.0.1"
    web_port: StrictInt = 11334
    milter_socket_dir: str = "/var/spool/postfix/rspamd"
    milter_socket_name: str = "milter.sock"
    milter_mode: str = "0660"
    reject_score: StrictInt | float | None = 15
    add_header_score: StrictInt | float | None = 6
    greylist_score: StrictInt | float | None = 4
    rewrite_subject_score: StrictInt | float | None = 8
    subject_prefix: str = "[SPAM]"
    dkim_signing_enabled: StrictBool = False
    learn_spam_header: str = "X-Spam-Learn: spam"
    learn_ham_header: str = "X-Spam-Learn: ham"
    milter_headers: tuple[str, ...] = ("x-spamd-bar", "x-spam-level", "x-spam-status", "authentication-results")
    local_addrs_default: tuple[str, ...] = (
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "fd00::/8",
        "169.254.0.0/16",
        "fe80::/10",
    )
    local_addrs_extra: tuple[str, ...] = ()
    resolver_enabled: StrictBool = False
    resolver_install_packages: StrictBool = False
    resolver_listen: str = "127.0.0.1"
    resolver_port: StrictInt = 5335
    resolver_fallback: str = "127.0.0.1:53"
    resolver_service: str = "unbound-rspamd"
    resolver_config: str = "/etc/unbound/rspamd-resolver.conf"
    resolver_state_dir: str = "/var/lib/unbound/rspamd"
    external_relay_enabled: StrictBool = False
    local_config_path: str = "/etc/rspamd/local.d"
    override_config_path: str = "/etc/rspamd/override.d"
    rspamd_repo_url: str = "https://rspamd.com/apt-stable/"
    rspamd_legacy_repo_url: str = "http://rspamd.com/apt-stable/"
    rspamd_repo_key_url: str = "https://rspamd.com/apt-stable/gpg.key"
    rspamd_repo_keyring: str = "/etc/apt/keyrings/rspamd.asc"
    rspamd_repo_legacy_key_id: str = "BF21E25E"
    rspamd_cleanup_legacy_key: StrictBool = True
    packages: tuple[str, ...] = ("rspamd",)

    @model_validator(mode="after")
    def _mail_contract(self) -> MailSpamConfig:
        for port in (self.redis_port, self.web_port, self.resolver_port):
            if not 0 < port < 65536:
                raise ValueError("spam service ports must be between 1 and 65535")
        for value in self.model_dump().values():
            if isinstance(value, str) and re.search(r"[\x00-\x1f\x7f]", value):
                raise ValueError("spam configuration text must not contain controls")
        for score in (self.reject_score, self.add_header_score, self.greylist_score, self.rewrite_subject_score):
            if score is not None and score < 0:
                raise ValueError("spam scores must be nonnegative or null")
        if self.monitoring_probe is not None:
            # Role parity: a local or trusted-relay source would let external
            # mail relayed through it inherit the exemption, and external_relay
            # never reports such a hop as the sender.
            source = ipaddress.ip_address(self.monitoring_probe.source_ip)
            networks = (*self.local_addrs_default, *self.local_addrs_extra, "127.0.0.0/8", "::1/128")
            if any(source in ipaddress.ip_network(network, strict=False) for network in networks):
                raise ValueError("monitoring probe source must not be a local or trusted-relay address")
        return self
