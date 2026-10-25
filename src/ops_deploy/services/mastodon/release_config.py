"""Role-equivalent inputs for an existing-install selected-release deploy."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Self

from pydantic import Field, field_validator, model_validator

from ops_deploy.core.git_source import CommitSha, GitSource
from ops_deploy.services.mastodon.config import MastodonConfig, Path_


class MastodonReleaseConfig(MastodonConfig):
    """An immutable candidate description, not a fresh-install provisioner.

    Candidate paths and migration identities come from the resolved source tree.
    ``runtime_tool_commits`` records the ruby-build object selected by this run.
    Neither a version override nor an approval token is needed to update source.
    """

    git_repo: str = "https://github.com/mastodon/mastodon.git"
    git_ref: str
    node_version: Annotated[str, Field(pattern=r"^[0-9]+(?:\.[0-9]+){0,2}$")]
    source_tracked_paths: list[str]
    migration_versions: list[Annotated[str, Field(pattern=r"^[0-9]+$")]]
    runtime_tool_commits: dict[str, CommitSha]
    rbenv_root: Path_ = "/home/mastodon/.rbenv"
    rbenv_repo: str = "https://github.com/rbenv/rbenv.git"
    ruby_build_repo: str = "https://github.com/rbenv/ruby-build.git"
    ruby_build_update: bool = True
    ruby_configure_opts: str = "-with-jemalloc"
    nvm_dir: Path_ = "/home/mastodon/.nvm"
    nvm_repo: str = "https://github.com/nvm-sh/nvm.git"
    nvm_version: str = "v0.40.8"
    bundle_install: bool = True
    bundle_path: Path_ = "/home/mastodon/live/vendor/bundle"
    bundle_without: str = "development test"
    bundle_jobs: int = Field(default=4, gt=0)
    bundle_retry: int = Field(default=3, ge=0)
    bundle_deployment: bool = False
    yarn_install: bool = True
    yarn_use_corepack: bool = True
    yarn_global_install: bool = False
    yarn_flags: str = "--immutable"
    run_migrations: bool = True
    precompile_assets: bool = True
    clear_rails_cache_on_deploy: bool = True
    nginx_federation_cache_prime: list[dict[str, str]] = Field(
        default_factory=lambda: [
            {"path": "/actor", "accept": "application/activity+json"},
            {"path": "/.well-known/host-meta", "accept": "application/xrd+xml"},
            {"path": "/.well-known/nodeinfo", "accept": "application/json"},
            {"path": "/nodeinfo/2.0", "accept": "application/json"},
        ]
    )
    nginx_federation_cache_prime_hosts: list[str] = Field(default_factory=list)
    nginx_federation_cache_prime_extra: list[dict[str, str]] = Field(default_factory=list)
    maintenance_enabled: bool = True
    maintenance_on_calendar: str = "*-*-* 03:00:00"
    maintenance_randomized_delay_sec: str = ""
    maintenance_persistent: bool = True
    maintenance_timer_enabled: bool = True
    maintenance_unit_dir: Path_ = "/etc/systemd/system"
    maintenance_service_name: str = "mastodon-maintenance"
    maintenance_timer_name: str = "mastodon-maintenance"
    maintenance_service_unit: Path_ | None = None
    maintenance_timer_unit: Path_ | None = None
    maintenance_script_path: Path_ = "/usr/local/bin/mastodon-maintenance"
    maintenance_script_mode: Annotated[str, Field(pattern=r"^0[0-7]{3}$")] = "0755"
    maintenance_media_days: int = Field(default=4, ge=0)
    maintenance_preview_days: int = Field(default=4, ge=0)
    maintenance_status_days: int = Field(default=4, ge=0)
    maintenance_tootctl_commands: list[str] | None = None
    maintenance_extra_commands: list[str] = Field(default_factory=list)
    maintenance_ignore_errors: bool = False
    maintenance_run_now: bool = False

    @field_validator("git_repo", "rbenv_repo", "ruby_build_repo", "nvm_repo")
    @classmethod
    def _repository(cls, value: str) -> str:
        return GitSource(repo=value).repo

    @field_validator("rbenv_root", "nvm_dir", "bundle_path", "maintenance_unit_dir", "maintenance_script_path")
    @classmethod
    def _release_path(cls, value: str) -> str:
        return MastodonConfig._normal_path(value)

    @field_validator("maintenance_service_unit", "maintenance_timer_unit")
    @classmethod
    def _optional_unit_path(cls, value: str | None) -> str | None:
        return MastodonConfig._normal_path(value) if value is not None else None

    @field_validator("source_tracked_paths")
    @classmethod
    def _tracked_paths(cls, paths: list[str]) -> list[str]:
        protected = (
            ".env.production",
            "public/system",
            "vendor/bundle",
            "node_modules",
            ".bundle",
            "log",
            "tmp",
            ".git",
        )
        for value in paths:
            path = PurePosixPath(value)
            if not value or path.is_absolute() or ".." in path.parts or str(path) != value or "\x00" in value:
                raise ValueError("candidate tracked paths must be normal relative paths")
            if value not in {"log/.keep", "tmp/.keep"} and any(
                value == p or value.startswith(p + "/") or p.startswith(value + "/") for p in protected
            ):
                raise ValueError("candidate source collides with retained environment/media/dependencies/runtime paths")
        return paths

    @field_validator("maintenance_service_name", "maintenance_timer_name")
    @classmethod
    def _unit_name(cls, value: str) -> str:
        import re

        if not re.fullmatch(r"[A-Za-z0-9_.@-]+", value):
            raise ValueError("maintenance unit name must be literal")
        return value

    @model_validator(mode="after")
    def _release_contract(self) -> Self:
        import re
        import shlex

        if set(self.runtime_tool_commits) != ({"ruby_build"} if self.ruby_build_update else set()):
            raise ValueError("ruby_build_update requires its controller-resolved exact runtime_tool_commits entry")
        GitSource(repo=self.git_repo, ref=self.git_ref)
        GitSource(repo=self.nvm_repo, ref=self.nvm_version)
        for entry in self.nginx_federation_cache_prime + self.nginx_federation_cache_prime_extra:
            if set(entry) - {"host", "path", "accept"} or not entry.get("path", "").startswith("/"):
                raise ValueError("cache priming entries need a local path and accept type")
            if any(any(c in value for c in "\r\n\x00") for value in entry.values()):
                raise ValueError("cache priming values must be single-line literals")
            if "accept" not in entry:
                raise ValueError("cache priming entries need accept")
        for domain in [
            *self.nginx_federation_cache_prime_hosts,
            *[
                entry["host"]
                for entry in self.nginx_federation_cache_prime_extra + self.nginx_federation_cache_prime
                if "host" in entry
            ],
        ]:
            if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", domain):
                raise ValueError("cache priming hosts must be domain names")
        if self.maintenance_run_now:
            raise ValueError(
                "maintenance_run_now executes cleanup; routine release deployment only converges its schedule"
            )
        commands = self.maintenance_tootctl_commands
        if commands is None:
            commands = [
                f"media remove --days {self.maintenance_media_days}",
                "media remove-orphans",
                f"preview-cards remove --days {self.maintenance_preview_days}",
                "accounts prune",
                f"statuses remove --days {self.maintenance_status_days}",
            ]
        for command in commands + self.maintenance_extra_commands:
            if not re.fullmatch(r"[A-Za-z0-9 ._=/:,+-]+", command):
                raise ValueError("maintenance commands must use the role's safe literal character set")
            words = shlex.split(command)
            if not words:
                raise ValueError("maintenance commands must not be empty")
            if "emoji".startswith(words[0]):
                full = words[:2] in (["emoji", "import"], ["emoji", "export"])
                scoped = (
                    words[:2] == ["emoji", "purge"]
                    and len(words) > 2
                    and all(word in {"--remote-only", "--suspended-only"} for word in words[2:])
                )
                if not (full or scoped):
                    raise ValueError(
                        "emoji commands need full names; purge permits only --remote-only/--suspended-only"
                    )
        for value in (self.git_ref, self.nvm_version, self.maintenance_on_calendar):
            if not value or any(c in value for c in "\r\n\x00"):
                raise ValueError("release configuration values must be nonempty single-line literals")
        if any(c in self.maintenance_randomized_delay_sec for c in "\r\n\x00"):
            raise ValueError("maintenance delay must be a single-line literal")
        return self
