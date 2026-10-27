"""macOS Homebrew/LaunchDaemon contract from ollama_install."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser

Line = Annotated[str, Field(pattern=r"^[^\r\n\x00]*$")]
Package = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_@./+-]*$")]


class OllamaConfig(BaseServiceConfig):
    service_name: ServiceName = "ollama"
    user: UnixUser = "ollama"
    group: UnixUser = "ollama"
    site_path: PurePosixPath = PurePosixPath("/usr/local/var/ollama")
    enabled: bool = True
    brew_package: Package = "ollama"
    brew_update: bool = False
    brew_bin: PurePosixPath | None = None
    brew_user: UnixUser | None = None
    disable_brew_service: bool = True
    brew_service_name: Package = "ollama"
    stop_conflicting_processes: bool = True
    conflicting_process_pattern: Line = "[/]ollama serve"
    binary_path: PurePosixPath | None = None
    launchd_label: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]+$")] = "com.ollama.ollama"
    launchd_plist_path: PurePosixPath | None = None
    launchd_command: Annotated[str, Field(min_length=1, pattern=r"^[^\r\n\x00]*$")] = "serve"
    launchd_command_args: tuple[Line, ...] = ()
    manage_user: bool = True
    uid: int | None = Field(default=None, ge=1)
    gid: int | None = Field(default=None, ge=1)
    models_dir: PurePosixPath = PurePosixPath("/usr/local/var/ollama/models")
    log_dir: PurePosixPath = PurePosixPath("/usr/local/var/ollama/logs")
    env: dict[str, Line] | None = None
    health_url: Annotated[str, Field(pattern=r"^http://[^\s]+$")] | None = None

    @field_validator("site_path", "models_dir", "log_dir", "brew_bin", "binary_path", "launchd_plist_path")
    @classmethod
    def _path(cls, value: PurePosixPath | None) -> PurePosixPath | None:
        if value is not None and (
            not value.is_absolute()
            or value == PurePosixPath("/")
            or ".." in value.parts
            or any(c in str(value) for c in "\r\n\x00")
        ):
            raise ValueError("paths must be absolute non-root paths without traversal or control characters")
        return value

    @model_validator(mode="after")
    def _defaults(self) -> OllamaConfig:
        if self.launchd_plist_path is None:
            object.__setattr__(
                self, "launchd_plist_path", PurePosixPath(f"/Library/LaunchDaemons/{self.launchd_label}.plist")
            )
        if self.env is None:
            object.__setattr__(self, "env", {"OLLAMA_HOST": "127.0.0.1:11434", "OLLAMA_MODELS": str(self.models_dir)})
        if any(not key or any(c in key for c in "\r\n\x00") for key in self.env or {}):
            raise ValueError("environment variable names must be nonempty single lines")
        return self
