"""Mailgun HTTP→SMTP relay, including its retained Python rollback installation."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, StrictInt, field_validator, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.services.metrics_endpoint.common import PlainPath

Positive = Annotated[StrictInt, Field(ge=1)]
Port = Annotated[StrictInt, Field(ge=1, le=65535)]
Host = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.:-]*$")]
VERSION = r"^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?$"
RELEASE_URL = (
    "https://github.com/ephes/mailgun-relay/releases/download/rs-v{version}/"
    "mailgun-relay-{version}-x86_64-unknown-linux-gnu.tar.gz"
)
RSYNC_EXCLUDES = (
    ".vault_password",
    ".git",
    ".venv/",
    "__pycache__/",
    "*.pyc",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    "dist/",
    "build/",
    ".env",
    ".env.local",
    "/rust/",
)


class MailgunRelayConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = (
        "smtp_username",
        "smtp_password",
        "envelope_sender",
        "tokens",
    )
    service_name: ServiceName = "mailgun-relay"
    user: UnixUser = "mailgun-relay"
    group: UnixUser = "mailgun-relay"
    home: PlainPath = PurePosixPath("/opt/apps/mailgun-relay")
    site_path: PlainPath = PurePosixPath("/opt/apps/mailgun-relay/site")
    venv_path: PlainPath | None = None
    env_dir: PlainPath = PurePosixPath("/etc/mailgun-relay")
    env_path: PlainPath | None = None
    secrets_path: PlainPath | None = None
    # Existing source/interpreter/dependencies are never refreshed implicitly.
    # A Python installation/update requires an explicit rsync or git selection.
    python_deploy: Literal["preserve", "rsync", "git"] = "preserve"
    source_path: Path | None = None
    git_repo: str = "https://github.com/ephes/mailgun-relay.git"
    git_version: str = "main"
    rsync_excludes: tuple[str, ...] = RSYNC_EXCLUDES
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]{1,2}$")] = "3.14"
    uv_sync_args: tuple[Annotated[str, Field(pattern=r"^--[a-z-]+$")], ...] = (
        "--no-default-groups",
        "--no-dev",
    )
    impl: Literal["python", "rust"] = "python"
    rust_version: str = ""
    rust_sha256: Annotated[str, Field(pattern=r"^([0-9a-f]{64})?$")] = ""
    rust_release_url: str = RELEASE_URL
    rust_local_archive: Path | None = None
    rust_install_root: PlainPath = PurePosixPath("/opt/mailgun-relay")
    rust_keep_versions: Positive = 3
    bind_host: Host = "127.0.0.1"
    bind_port: Port = 8085
    public_host: Host = "mailgun.home.xn--wersdrfer-47a.de"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    smtp_host: Host = "smtp.home.xn--wersdrfer-47a.de"
    smtp_port: Port = 587
    smtp_starttls: bool = True
    smtp_timeout_s: Positive = 30
    smtp_max_concurrency: Positive | None = None
    # Application-supported optional trust override; absent in the legacy role.
    smtp_ca_file: PlainPath | None = None
    max_body_bytes: Positive = 26214400
    max_attachments: Positive = 10
    max_attachment_bytes: Positive = 10485760
    max_recipients: Positive = 100
    max_header_value_length: Positive = 998
    healthcheck_enabled: bool = True
    healthcheck_retries: Positive = 20
    healthcheck_delay_seconds: Positive = 1
    healthcheck_timeout_seconds: Positive = 5
    healthcheck_url: str | None = None
    ingress_enabled: bool = False
    ingress_host: Host = "mailgun.home.xn--wersdrfer-47a.de"
    ingress_backend_url: str = "http://127.0.0.1:8085"
    ingress_traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    ingress_traefik_config_path: PlainPath = PurePosixPath("/etc/traefik/dynamic/mailgun-relay.yml")
    ingress_max_request_body_bytes: Positive = 26214400

    @field_validator("rust_version")
    @classmethod
    def _version(cls, value: str) -> str:
        if value and not re.fullmatch(VERSION, value):
            raise ValueError("rust_version must be empty or a release version")
        return value

    @field_validator("rust_release_url", "healthcheck_url", "ingress_backend_url")
    @classmethod
    def _url(cls, value: str | None) -> str | None:
        if value is None:
            return value
        parsed = urlsplit(value.replace("{version}", "0.0.0"))
        if (
            parsed.scheme not in {"https", "http"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or re.search(r"[\s\x00'\"$`\\]", value)
            or "{" in value.replace("{version}", "")
            or "}" in value.replace("{version}", "")
        ):
            raise ValueError("URL must be HTTP(S), without credentials or unsafe characters")
        return value

    @model_validator(mode="after")
    def _contract(self) -> Self:
        if self.impl == "rust" and not self.rust_version:
            raise ValueError("Rust selection requires a pinned version")
        if self.rust_version and not self.rust_sha256 and self.rust_local_archive is None:
            raise ValueError("a release requires its checksum or a local archive")
        if not self.rust_version and (self.rust_sha256 or self.rust_local_archive):
            raise ValueError("checksum/local archive require a version")
        if self.rust_install_root == self.site_path or self.rust_install_root.is_relative_to(self.site_path):
            raise ValueError("Rust installation must be outside the Python source tree")
        if self.python_deploy == "rsync":
            if self.source_path is None or not self.source_path.is_dir():
                raise ValueError("explicit rsync needs an existing source directory")
            for path in ("src/mailgun_relay", "pyproject.toml", "uv.lock"):
                if not (self.source_path / path).exists():
                    raise ValueError("source directory lacks a required project path")
        if self.impl == "rust" and self.rust_local_archive is not None and not self.rust_local_archive.is_file():
            raise ValueError("local archive must be a regular controller file")
        return self

    @property
    def venv(self) -> PurePosixPath:
        return self.venv_path or self.site_path / ".venv"

    @property
    def environment_path(self) -> PurePosixPath:
        return self.env_path or self.env_dir / "mailgun-relay.env"

    @property
    def policy_path(self) -> PurePosixPath:
        return self.secrets_path or self.env_dir / "secrets.yml"

    @property
    def binary(self) -> PurePosixPath:
        return self.rust_install_root / self.rust_version / "mailgun-relay"

    @property
    def dropin(self) -> PurePosixPath:
        return PurePosixPath("/etc/systemd/system") / f"{self.service_name}.service.d/impl.conf"

    @property
    def state_dir(self) -> PurePosixPath:
        return PurePosixPath("/var/lib/ops-deploy") / self.service_name
