"""``GotosocialConfig``: the ``gotosocial_deploy`` role's variables, without the prefix.

Defaults follow the role's ``defaults/main.yml`` (``tests/test_gotosocial_parity.py``
compares them with the role when ``OPS_LIBRARY_PATH`` is set). The role's
``validate.yml`` assertions are model validators here, so a config the role
would refuse fails on the controller before any connection. Values that end up
in the unit, the admin wrapper (a ``sh`` script) or the Traefik route are
restricted to characters those files carry unquoted.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from ops_deploy.base._common import RoleConfig
from ops_deploy.core.config import ServiceName, UnixUser

# The role's ``gotosocial_host`` / ``gotosocial_account_domain`` pattern.
DOMAIN_PATTERN = r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$"
# ``gotosocial_guarded_config_keys``: settings the role validates, records or
# binds to paths, which ``extra_config`` must not override.
GUARDED_CONFIG_KEYS = (
    "host",
    "account-domain",
    "protocol",
    "bind-address",
    "port",
    "trusted-proxies",
    "db-type",
    "db-address",
    "storage-backend",
    "storage-local-base-path",
    "letsencrypt-enabled",
    "web-template-base-dir",
    "web-asset-base-dir",
    "accounts-registration-open",
)
# The role's ``select('search', 'password|secret|key')`` on extra_config keys.
_SECRET_KEY = re.compile(r"password|secret|key")
# ``gotosocial_arch_map``: Ansible's architecture fact (``uname -m``) -> release arch.
ARCH_MAP = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}

# Paths land unquoted in the unit and the admin wrapper (``cd <current>``).
Path_ = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/-]*[A-Za-z0-9._-]$")]
Word = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")]
# A single line of text for config.yaml (the YAML dumper quotes it as needed).
Text = Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]*$", max_length=256)]
Checksum = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Package = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]*$")]
Arch = Literal["amd64", "arm64"]
# The role's pinned 0.22.2 checksums (the release's checksums.txt on Codeberg).
RELEASE_CHECKSUMS: dict[Arch, str] = {
    "amd64": "sha256:b8e7406c7eae73a50b7990affb5b1151fe81cfdb1c12951630bb08b0d77f7337",
    "arm64": "sha256:274ddb425444ea06f9f02bbd5abbce0bddc6f0a0d7c359ba8d8f0936ab8f3da5",
}
# JSON-like data for extra_config (what YAML host_vars can hold).
ExtraValue = str | int | float | bool | None | list[Any] | dict[str, Any]


def _plain_path(value: str) -> str:
    if ".." in PurePosixPath(value).parts or "//" in value:
        raise ValueError("paths must be normalised absolute paths without '..'")
    return value


class GotosocialConfig(RoleConfig):
    """The ``gotosocial_*`` variables the deploy reads (role defaults)."""

    # Pinned upstream release; bump version and both checksums together.
    version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")] = "0.22.2"
    release_checksums: dict[Arch, Checksum] = Field(default_factory=lambda: dict(RELEASE_CHECKSUMS), min_length=1)
    download_base_url: str = "https://codeberg.org/superseriousbusiness/gotosocial/releases/download"

    user: UnixUser = "gotosocial"
    group: UnixUser = "gotosocial"
    install_root: Path_ = "/opt/gotosocial"
    config_dir: Path_ = "/etc/gotosocial"
    data_dir: Path_ = "/var/lib/gotosocial"
    admin_wrapper_path: Path_ = "/usr/local/sbin/gotosocial-admin"
    service_name: ServiceName = "gotosocial"

    # Required (the role's CHANGEME fails its own validation).
    host: Annotated[str, Field(pattern=DOMAIN_PATTERN, max_length=253)]
    account_domain: Annotated[str, Field(max_length=253)] = ""
    allow_domain_layout_change: bool = False

    bind_address: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: int = Field(default=10070, gt=1024, lt=65536)
    trusted_proxies: tuple[str, ...] = ("127.0.0.1/32", "::1")

    application_name: Text = "gotosocial"
    landing_page_user: Text = ""
    instance_languages: tuple[Text, ...] = ()
    accounts_registration_open: bool = False
    instance_expose_public_timeline: bool = False
    instance_robots_allow_indexing: bool = False
    media_remote_cache_duration: Text = "7 days"
    cache_memory_target: Text = "100MiB"
    log_level: Text = "info"
    log_client_ip: bool = False

    # Optional SMTP (empty host disables mail); the password is a deploy argument.
    smtp_host: Text = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: Text = ""
    smtp_from: Text = ""

    extra_config: dict[str, ExtraValue] = Field(default_factory=dict)

    packages: tuple[Package, ...] = ("ca-certificates", "sqlite3", "tar")

    service_enabled: bool = True
    service_state: Literal["started", "stopped"] = "started"
    systemd_memory_max: Annotated[str, Field(pattern=r"^[A-Za-z0-9.%]*$")] = "1G"

    traefik_enabled: bool = True
    traefik_config_path: Path_ = "/etc/traefik/dynamic/gotosocial.yml"
    # None: ``host`` (the role's ``"{{ gotosocial_host }}"``).
    traefik_host: Annotated[str, Field(pattern=DOMAIN_PATTERN, max_length=253)] | None = None
    traefik_entrypoints: tuple[Word, ...] = Field(default=("web-secure",), min_length=1)
    traefik_http_entrypoint: Word = "web"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^([A-Za-z0-9][A-Za-z0-9_.-]{0,63})?$")] = ""
    traefik_middlewares: tuple[Word, ...] = ()

    healthcheck_enabled: bool = True
    healthcheck_retries: int = Field(default=30, ge=1, le=1000)
    healthcheck_delay: int = Field(default=2, ge=0, le=60)

    @field_validator("install_root", "config_dir", "data_dir", "admin_wrapper_path", "traefik_config_path")
    @classmethod
    def _paths(cls, value: str) -> str:
        return _plain_path(value)

    @field_validator("download_base_url")
    @classmethod
    def _base_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if (
            not re.fullmatch(r"[A-Za-z0-9._~:/%-]+", value)
            or parts.scheme not in ("https", "http")
            or not parts.hostname
            or "@" in parts.netloc
            or parts.query
            or parts.fragment
            or value.endswith("/")
        ):
            raise ValueError("download_base_url must be an http(s) URL without credentials, query or trailing slash")
        return value

    @field_validator("trusted_proxies")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not re.fullmatch(r"[0-9A-Fa-f:.]+(/[0-9]{1,3})?", item):
                raise ValueError("trusted_proxies must contain IP addresses or networks")
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError("trusted_proxies must contain IP addresses or networks") from None
        return value

    @field_validator("extra_config")
    @classmethod
    def _extra_config(cls, value: dict[str, Any]) -> dict[str, Any]:
        # validate.yml: no secrets and none of the guarded settings.
        if any(_SECRET_KEY.search(key) for key in value):
            raise ValueError(
                "extra_config must not carry passwords, secrets or keys; use the dedicated settings "
                "(smtp_password is a deploy argument)"
            )
        guarded = sorted(set(value) & set(GUARDED_CONFIG_KEYS))
        if guarded:
            raise ValueError(f"extra_config must not set {guarded}; use the dedicated settings")
        return value

    @model_validator(mode="after")
    def _role_asserts(self) -> Self:
        if self.account_domain and not re.fullmatch(DOMAIN_PATTERN, self.account_domain):
            raise ValueError("account_domain must be empty or a lower-case DNS name")
        # GoToSocial refuses to start otherwise, after everything was installed.
        if self.account_domain and not (
            self.host == self.account_domain or self.host.endswith("." + self.account_domain)
        ):
            raise ValueError("host must equal account_domain or be a subdomain of it")
        if self.smtp_host and not self.smtp_from:
            raise ValueError("smtp_from is required when smtp_host is set")
        return self

    # -- the role's derived paths (defaults/main.yml) ---------------------------------

    @property
    def release_dir(self) -> str:
        return f"{self.install_root}/releases/{self.version}"

    @property
    def current_link(self) -> str:
        return f"{self.install_root}/current"

    @property
    def config_path(self) -> str:
        return f"{self.config_dir}/config.yaml"

    @property
    def db_path(self) -> str:
        return f"{self.data_dir}/sqlite.db"

    @property
    def storage_dir(self) -> str:
        return f"{self.data_dir}/storage"

    @property
    def cache_dir(self) -> str:
        return f"{self.data_dir}/.cache"

    @property
    def layout_marker_path(self) -> str:
        return f"{self.data_dir}/.ops-domain-layout"

    @property
    def unit_path(self) -> str:
        return f"/etc/systemd/system/{self.service_name}.service"

    @property
    def route_host(self) -> str:
        return self.traefik_host or self.host

    @property
    def domain_layout(self) -> str:
        """``layout.yml``'s ``"<host> <account-domain or host>"`` (trimmed, as recorded)."""

        return f"{self.host} {self.account_domain or self.host}"

    def download_url(self, arch: str) -> str:
        return f"{self.download_base_url}/v{self.version}/gotosocial_{self.version}_linux_{arch}.tar.gz"
