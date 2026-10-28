"""The existing local-owner/Aqua macos_ssh_tunnel role contract."""

from __future__ import annotations

import os
import re
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator

from ops_deploy.base import RoleConfig

Username = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,63}$")]
Hostname = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]+$")]


class MacosSshTunnelConfig(RoleConfig):
    owner: Username
    home: PurePosixPath
    host: Hostname
    user: Username
    target: Hostname
    state: Literal["present", "absent"] = "present"
    expected_hostname: Hostname | None = None
    label: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]+$")] = "org.example.ssh-tunnel"
    directory: PurePosixPath | None = None
    plist: PurePosixPath | None = None
    log_directory: PurePosixPath | None = None
    identity: PurePosixPath | None = None
    known_hosts: PurePosixPath | None = None
    target_port: int = Field(default=443, ge=1, le=65535)
    local_port: int = Field(default=18443, ge=1024, le=65535)
    # Bounded extension for explicitly selected relays/owned high-port fixtures;
    # default22 keeps the original template's exact bytes and behavior.
    ssh_port: int = Field(default=22, ge=1, le=65535)
    # Controller transport settings, separate from the unchanged tunnel templates.
    # Callers may mirror their original Ansible connection profile explicitly.
    ssh_connect_timeout: int = Field(default=10, ge=1)
    ssh_control_path: str | None = None
    ignore_ssl_errors: Annotated[bool, Field(strict=True)] = False
    ca_file: PurePosixPath | None = None
    health_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9/_.-]*$")] = "/"
    health_status: int = Field(default=200, ge=100, le=599)
    python: PurePosixPath = PurePosixPath("/opt/homebrew/bin/python3")
    manage_identity: bool = False
    identity_group: Username = "staff"
    identity_comment: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$")] = "restricted-forwarding"
    identity_keygen: PurePosixPath = PurePosixPath("/usr/bin/ssh-keygen")
    # When set, preserve the original Emerge unprivileged authorization step.
    # No root SSH, new authentication or privilege workaround is involved.
    relay_home: PurePosixPath | None = None

    @field_validator(
        "home",
        "directory",
        "plist",
        "log_directory",
        "identity",
        "known_hosts",
        "python",
        "identity_keygen",
        "relay_home",
        "ca_file",
        mode="before",
    )
    @classmethod
    def _path(cls, value: object) -> object:
        if value is not None:
            text = str(value)
            if not re.fullmatch(r"/[A-Za-z0-9_ ./-]+", text) or os.path.normpath(text) != text or text == "/":
                raise ValueError("tunnel paths must be normalized absolute paths with safe literal characters")
        return value

    @field_validator("ssh_control_path")
    @classmethod
    def _control_path(cls, value: str | None) -> str | None:
        if value is not None:
            literal = re.sub(r"%[hpr]", "x", value)
            if not re.fullmatch(r"/[A-Za-z0-9_./-]+", literal) or os.path.normpath(value) != value:
                raise ValueError("SSH control path must be absolute with literal characters and %h/%p/%r tokens")
        return value

    @model_validator(mode="after")
    def _defaults(self) -> Self:
        if any(value == "CHANGEME" for value in (self.owner, self.host, self.user, self.target)):
            raise ValueError("tunnel owner and relay/target settings must be configured")
        defaults = {
            "directory": self.home / "Library/Application Support/SSH Tunnel",
            "plist": self.home / "Library/LaunchAgents" / (self.label + ".plist"),
            "log_directory": self.home / "Library/Logs/SSH Tunnel",
            "identity": self.home / ".ssh/tunnel_ed25519",
            "known_hosts": self.home / ".ssh/known_hosts",
        }
        for name, value in defaults.items():
            if getattr(self, name) is None:
                object.__setattr__(self, name, value)
        for name in defaults:
            value = getattr(self, name)
            if self.home not in value.parents:
                raise ValueError("managed tunnel paths must remain below the configured owner's home")
        if self.relay_home is not None and not self.manage_identity:
            raise ValueError("relay authorization requires the managed forwarding identity")
        assert self.directory is not None
        assert self.plist is not None
        managed = [
            self.plist,
            self.directory / "ssh_config",
            self.directory / "config.json",
            self.directory / "tunnel_control.py",
            self.directory / "config.lock",
        ]
        if self.ssh_control_path is not None:
            expanded = (
                self.ssh_control_path.replace("%h", self.host)
                .replace("%p", str(self.ssh_port))
                .replace("%r", self.user)
            )
            control = PurePosixPath(expanded)
            protected = {self.identity, PurePosixPath(str(self.identity) + ".pub"), self.known_hosts, *managed}
            trees = (self.directory, self.log_directory, self.plist.parent)
            if control in protected or any(tree == control or tree in control.parents for tree in trees):
                raise ValueError("SSH control socket must remain outside protected tunnel resource trees")
        if len(set(managed)) != len(managed) or set(managed) & {
            self.directory,
            self.log_directory,
            self.identity,
            self.known_hosts,
        }:
            raise ValueError("managed tunnel resources must not overlap identity or shared resources")
        return self
