"""Native MeTube deployment contract; all persistent paths are retained."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.git_source import GitSource
from ops_deploy.helpers.traefik import Hostname

SafeLine = Annotated[str, Field(pattern=r"^[^\r\n\x00]*$")]


class MetubeConfig(BaseServiceConfig):
    service_name: ServiceName = "metube"
    user: UnixUser = "metube"
    site_path: PurePosixPath = PurePosixPath("/opt/metube")
    home: PurePosixPath = PurePosixPath("/var/lib/metube")
    state_dir: PurePosixPath = PurePosixPath("/var/lib/metube")
    download_dir: PurePosixPath = PurePosixPath("/srv/metube/downloads")
    audio_download_dir: PurePosixPath = PurePosixPath("/srv/metube/downloads")
    temp_dir: PurePosixPath = PurePosixPath("/srv/metube/downloads")
    build_root: PurePosixPath = PurePosixPath("/var/cache/metube")
    env_dir: PurePosixPath = PurePosixPath("/etc/metube")
    source: GitSource = GitSource(repo="https://github.com/alexta69/metube.git", ref="master")
    python_version: Annotated[str, Field(pattern=r"^3\.[0-9]+(?:\.[0-9]+)?$")] = "3.14.0"
    uv_version: Annotated[str, Field(pattern=r"^0\.[0-9]+\.[0-9]+$")] = "0.13.4"
    node_major: int = Field(default=24, ge=1)
    node_min_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")] = "24.15.0"
    ui_build_configuration: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")] = "production"
    host: Annotated[str, Field(pattern=r"^[A-Za-z0-9.:-]+$")] = "127.0.0.1"
    port: int = Field(default=8081, ge=1, le=65535)
    traefik_host: Hostname = "metube.example.com"
    internal_ip_ranges: tuple[str, ...] = (
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
    )
    extra_groups: tuple[UnixUser, ...] = ("jellyfin",)
    download_template: SafeLine = "%(title)s [%(id)s].%(ext)s"
    default_theme: SafeLine = "auto"
    max_concurrent_downloads: int = Field(default=3, ge=1)
    enable_accesslog: bool = False
    loglevel: SafeLine = "INFO"
    ytdl_options: dict[str, object] = Field(
        default_factory=lambda: {
            "merge_output_format": "mp4",
            "subtitles_langs": ["en"],
            "write_subs": True,
            "write_auto_subs": True,
        }
    )
    traefik_enabled: bool = True
    protect_queue: bool = True
    mounts_required: tuple[PurePosixPath, ...] = ()

    @field_validator(
        "site_path", "home", "state_dir", "download_dir", "audio_download_dir", "temp_dir", "build_root", "env_dir"
    )
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        if (
            not value.is_absolute()
            or value == PurePosixPath("/")
            or ".." in value.parts
            or any(c in str(value) for c in "\r\n\x00")
        ):
            raise ValueError("paths must be absolute non-root paths without traversal/control characters")
        return value

    @model_validator(mode="after")
    def _separate(self) -> MetubeConfig:
        # Source/UI operations can replace their own trees, never retained state/media.
        def overlaps(a: PurePosixPath, b: PurePosixPath) -> bool:
            return a.is_relative_to(b) or b.is_relative_to(a)

        if overlaps(self.site_path, self.build_root):
            raise ValueError("source and staging trees must be separate")
        for path in (
            self.home,
            self.state_dir,
            self.download_dir,
            self.audio_download_dir,
            self.temp_dir,
            self.env_dir,
        ):
            if overlaps(path, self.site_path) or overlaps(path, self.build_root):
                raise ValueError("retained/config directories must be separate from source and staging")
        for path in (self.home, self.state_dir, self.download_dir, self.audio_download_dir, self.temp_dir):
            if overlaps(self.env_dir, path):
                raise ValueError("config directory must be separate from retained directories")
        return self

    @property
    def venv_path(self) -> PurePosixPath:
        return self.site_path / "venv"

    @property
    def env_file(self) -> PurePosixPath:
        return self.env_dir / "metube.env"

    @property
    def build_dir(self) -> PurePosixPath:
        return self.build_root / "src"

    @property
    def health_url(self) -> str:
        return f"http://{self.host}:{self.port}/"
