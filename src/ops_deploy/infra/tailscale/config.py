"""Original Tailscale package/repository/join policy, with explicit selected prefs."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from pydantic import model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.infra.netplan.config import Hostname, UnitName
from ops_deploy.infra.postgres_install import PackageName, RepoWord


class TailscaleConfig(RoleConfig):
    hostname: Hostname
    manual_up: bool = False
    accept_routes: bool = False
    accept_dns: bool = False
    exit_node: str = ""
    advertise_exit_node: bool = False
    args_extra: tuple[str, ...] = ()
    binary: AbsolutePath = "/usr/bin/tailscale"
    socket: AbsolutePath = "/var/run/tailscale/tailscaled.sock"
    service_name: UnitName = "tailscaled"
    enable_service: bool = True
    package_name: PackageName = "tailscale"
    package_version: str = "latest"
    channel: RepoWord = "stable"
    repo_base: str = "https://pkgs.tailscale.com"
    repo_component: RepoWord = "main"
    repo_name: RepoWord = "tailscale"
    repo_keyring: AbsolutePath = "/usr/share/keyrings/tailscale-archive-keyring.gpg"
    repo_distro: RepoWord | None = None
    repo_release: RepoWord | None = None

    @model_validator(mode="after")
    def _safe(self) -> TailscaleConfig:
        if self.package_version != "latest" and not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.+:~_-]*", self.package_version
        ):
            raise ValueError("package version must be latest (present) or an explicit native version")
        url = urlsplit(self.repo_base)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or any(c.isspace() or ord(c) < 32 for c in self.repo_base)
        ):
            raise ValueError("repository base must be a public HTTP(S) URL without credentials/query/fragment")
        if any(c in self.exit_node for c in "\r\n\0"):
            raise ValueError("invalid exit node")
        for value in self.args_extra:
            if (
                not value
                or any(ord(c) < 32 for c in value)
                or value.lstrip("-").split("=", 1)[0].lower() in {"auth-key", "authkey"}
            ):
                raise ValueError("extra join arguments must be nonsecret tokens; auth comes from private stdin")
        for path in (self.binary, self.socket, self.repo_keyring):
            if path == "/" or ".." in path.split("/"):
                raise ValueError("native Tailscale paths must be absolute without traversal")
        return self
