"""SnappyMail code and narrowly owned persistent configuration."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, StrictBool, model_validator

from ops_deploy.core.config import UnixUser
from ops_deploy.services._mail_web.config import Domain, MailWebConfig, PathText


class SnappyMailConfig(MailWebConfig):
    service_name: Literal["snappymail"] = "snappymail"
    site_path: PurePosixPath = PurePosixPath("/opt/snappymail")
    version: str = "2.38.2"
    install_dir: PathText = "/opt/snappymail"
    data_dir: PathText = "/mnt/cryptdata/snappymail"
    user: UnixUser = "snappymail"
    group: UnixUser = "snappymail"
    shell: Literal["/usr/sbin/nologin"] = "/usr/sbin/nologin"
    listen_port: Annotated[int, Field(ge=1, le=65535)] = 8088
    php_pm_max_children: Annotated[int, Field(ge=1, le=128)] = 8
    php_memory_limit: Annotated[str, Field(pattern=r"^[0-9]+M$")] = "256M"
    php_max_execution_time: Annotated[int, Field(ge=1)] = 120
    php_upload_limit: Annotated[str, Field(pattern=r"^[0-9]+M$")] = "25M"
    nginx_client_max_body_size: Annotated[str, Field(pattern=r"^[0-9]+m$")] = "25m"
    admin_user: UnixUser = "admin"
    imap_host: Domain
    imap_port: Annotated[int, Field(ge=1, le=65535)] = 993
    imap_security: Literal["SSL", "TLS", "NONE"] = "SSL"
    imap_short_login: StrictBool = False
    imap_timeout: Annotated[int, Field(ge=1)] = 300
    smtp_host: Domain
    smtp_port: Annotated[int, Field(ge=1, le=65535)] = 587
    smtp_security: Literal["SSL", "TLS", "NONE"] = "TLS"
    smtp_auth: StrictBool = True
    smtp_short_login: StrictBool = False
    smtp_set_sender: StrictBool = False
    sieve_enabled: StrictBool = False
    sieve_host: Domain | None = None
    sieve_port: Annotated[int, Field(ge=1, le=65535)] = 4190
    sieve_security: Literal["SSL", "TLS", "NONE"] = "TLS"
    sieve_short_login: StrictBool = False
    force_https: StrictBool = True
    login_default_domain: Annotated[str, Field(pattern=r"^[A-Za-z0-9.-]*$")] = ""
    domains: tuple[Domain, ...] = ()
    remove_domains: tuple[Domain, ...] = ()
    logging_enabled: StrictBool = False
    logging_level: Annotated[int, Field(ge=0, le=7)] = 4
    disable_default_nginx_site: StrictBool = True

    @model_validator(mode="after")
    def separate_persistent_data(self) -> Self:
        root, data = PurePosixPath(self.install_dir), PurePosixPath(self.data_dir)
        if root == data or root in data.parents or data in root.parents:
            raise ValueError("SnappyMail persistent data and release roots must be disjoint")
        if set(self.domains) & set(self.remove_domains):
            raise ValueError("SnappyMail cannot manage and remove the same domain")
        return self
