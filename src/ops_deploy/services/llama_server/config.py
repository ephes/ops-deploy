"""The existing pinned native llama_server_deploy contract."""

from __future__ import annotations

import ipaddress
from pathlib import Path, PurePosixPath
from typing import Annotated, Self
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from ops_deploy.base import RoleConfig
from ops_deploy.base._common import Sha256
from ops_deploy.core.config import UnixUser


class LlamaServerConfig(RoleConfig):
    enabled: bool = True
    user: UnixUser | None = None
    group: UnixUser = "staff"
    home: PurePosixPath | None = None
    brew_bin: PurePosixPath | None = None
    brew_user: UnixUser | None = None
    brew_formula: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_@./+-]*$")] = "llama.cpp"
    binary: PurePosixPath = PurePosixPath("/opt/homebrew/bin/llama-server")
    build: Annotated[str, Field(pattern=r"^b[0-9]+-[0-9a-f]{7,40}$")] = "b11669-620d2225c"
    wrapper_source: Path | None = None
    install_dir: PurePosixPath = PurePosixPath("/opt/llama-server")
    wrapper_path: PurePosixPath | None = None
    model_dir: PurePosixPath | None = None
    model_file: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+\.gguf$")] = "Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
    model_url: str = (
        "https://huggingface.co/unsloth/Qwen3-4B-Instruct-2507-GGUF/resolve/"
        "a06e946bb6b655725eafa393f4a9745d460374c9/Qwen3-4B-Instruct-2507-Q4_K_M.gguf"
    )
    model_sha256: Sha256 = "3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597"
    alias: Annotated[str, Field(pattern=r"^[A-Za-z0-9._-]+$")] = "qwen3-4b-instruct-2507-q4km-3605803b"
    config_dir: PurePosixPath = PurePosixPath("/etc/llama-server")
    api_key_path: PurePosixPath | None = None
    bind_host: str = "tailnet"
    port: int = Field(default=8177, ge=1, le=65535)
    log_dir: PurePosixPath = PurePosixPath("/var/log/llama-server")
    stdout_log: PurePosixPath | None = None
    stderr_log: PurePosixPath | None = None
    launchd_label: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")] = "de.wersdoerfer.llama-server"
    launchd_plist_path: PurePosixPath | None = None
    launchd_path: Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f]+$")] = (
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    )
    healthcheck_enabled: bool = True
    healthcheck_retries: int = Field(default=30, ge=1)
    healthcheck_delay: int = Field(default=2, ge=0)

    @field_validator(
        "home",
        "brew_bin",
        "binary",
        "install_dir",
        "wrapper_path",
        "model_dir",
        "config_dir",
        "api_key_path",
        "log_dir",
        "stdout_log",
        "stderr_log",
        "launchd_plist_path",
    )
    @classmethod
    def _absolute(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        if value is not None and (
            not value.is_absolute()
            or str(value) == "/"
            or ".." in value.parts
            or any(ord(char) < 32 or ord(char) == 127 for char in str(value))
        ):
            raise ValueError("native paths must be absolute non-root paths without traversal/control characters")
        return value

    @model_validator(mode="after")
    def _defaults(self) -> Self:
        if self.enabled and (self.user is None or self.wrapper_source is None):
            raise ValueError("enabled detector requires an existing service user and controller wrapper")
        if not self.alias.endswith("-" + self.model_sha256[:8]):
            raise ValueError("detector alias must end with its model SHA prefix")
        url = urlsplit(self.model_url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or any(ord(char) < 32 or ord(char) == 127 for char in self.model_url)
        ):
            raise ValueError("detector model URL must use HTTPS without embedded credentials")
        if self.bind_host != "tailnet":
            try:
                address = ipaddress.ip_address(self.bind_host)
            except ValueError:
                raise ValueError("detector binding must be loopback or Tailscale IPv4") from None
            if address.version != 4 or not (address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10")):
                raise ValueError("detector binding must be loopback or Tailscale IPv4")
        defaults = {
            "home": PurePosixPath("/Users") / self.user if self.user else None,
            "wrapper_path": self.install_dir / "detector-server.sh",
            "model_dir": self.install_dir / "models",
            "api_key_path": self.config_dir / "api-key",
            "stdout_log": self.log_dir / "llama-server.log",
            "stderr_log": self.log_dir / "llama-server.err.log",
            "launchd_plist_path": PurePosixPath("/Library/LaunchDaemons") / (self.launchd_label + ".plist"),
        }
        for name, value in defaults.items():
            if getattr(self, name) is None:
                object.__setattr__(self, name, value)
        managed_files = [
            self.wrapper_path,
            self.api_key_path,
            self.launchd_plist_path,
            self.stdout_log,
            self.stderr_log,
        ]
        assert self.model_dir is not None
        managed_files.append(self.model_dir / self.model_file)
        if len(set(managed_files)) != len(managed_files):
            raise ValueError("detector managed file paths must be distinct")
        if set(managed_files) & {self.install_dir, self.model_dir, self.config_dir, self.log_dir}:
            raise ValueError("detector managed files must not replace its directories")
        return self

    @property
    def required_secret_keys(self) -> tuple[str, ...]:
        return ("api_key",) if self.enabled else ()
