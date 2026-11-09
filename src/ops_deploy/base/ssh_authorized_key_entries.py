"""Reconcile selected public keys while retaining every unrelated byte."""

from __future__ import annotations

import base64
import re
import shlex
from pathlib import PurePosixPath

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.files import File
from pyinfra.facts.server import Command
from pyinfra.operations import files

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.base.ssh_authorized_keys import AuthorizedKey
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_file

# An option field may contain spaces and escaped quotes. Only tokens outside
# quotes can be a key type; a forced command containing a key is never a match.
_TOKEN = re.compile(rb'(?:[^\s"\\]|\\.|"(?:[^"\\]|\\.)*")+')
_TYPE = re.compile(
    rb"(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|"
    rb"sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)\Z"
)


def key_material(line: bytes) -> tuple[bytes, bytes] | None:
    """Find the type and decoded blob, ignoring options and comments."""
    if line.lstrip().startswith(b"#"):
        return None
    tokens = [match.group() for match in _TOKEN.finditer(line)]
    # authorized_keys has either keytype first or one options field first.
    for index in (0, 1):
        if len(tokens) > index + 1 and _TYPE.fullmatch(tokens[index]):
            try:
                blob = base64.b64decode(tokens[index + 1], validate=True)
            except ValueError:
                return None
            return tokens[index], blob
    return None


class SshAuthorizedKeyEntriesConfig(RoleConfig):
    user: UnixUser
    home: AbsolutePath
    group: UnixUser
    present: tuple[AuthorizedKey, ...] = Field(min_length=1)
    absent: tuple[AuthorizedKey, ...] = ()

    @model_validator(mode="after")
    def _keys(self) -> SshAuthorizedKeyEntriesConfig:
        seen: set[tuple[bytes, bytes]] = set()
        for entry in (*self.present, *self.absent):
            material = key_material(entry.key.strip().encode())
            if material is None or not entry.key.strip().encode().startswith(material[0] + b" "):
                raise ValueError("entries require an SSH public key without options")
            if material in seen:
                raise ValueError("duplicate or overlapping present/absent key")
            seen.add(material)
        if ".." in PurePosixPath(self.home).parts:
            raise ValueError("home must not contain parent traversal")
        return self


def reconcile_authorized_keys(content: bytes, cfg: SshAuthorizedKeyEntriesConfig) -> bytes:
    """Collapse managed duplicates; leave foreign lines, CRLF and blanks intact."""
    wanted = {key_material(e.key.strip().encode()): e.line().encode() for e in cfg.present}
    removed = {key_material(e.key.strip().encode()) for e in cfg.absent}
    seen = set()
    result = bytearray()
    for line in content.splitlines(keepends=True):
        material = key_material(line)
        if material in removed:
            continue
        if material in wanted:
            if material not in seen:
                desired = wanted[material]
                # Preserve the existing newline when the entry already matches.
                result.extend(line if line.rstrip(b"\r\n") == desired.rstrip(b"\n") else desired)
                seen.add(material)
        else:
            result.extend(line)
    for material, line in wanted.items():
        if material not in seen:
            if result and not result.endswith(b"\n"):
                result.extend(b"\n")
            result.extend(line)
    return bytes(result)


@deploy("SSH authorized key entries")
def deploy_ssh_authorized_key_entries(cfg: SshAuthorizedKeyEntriesConfig) -> None:
    """Non-exclusive atomic reconciliation on Linux/macOS (remote python3).

    Caller hook for controller orchestration: acquire the shared host lock
    BEFORE this deploy gathers facts, and prove a surviving explicit identity
    can authenticate BEFORE requesting removals. This primitive does not prove
    reachability and must never be used to remove the connection's own key.
    """
    directory = PurePosixPath(cfg.home) / ".ssh"
    path = directory / "authorized_keys"
    info = host.get_fact(File, path=str(path))
    if info is False:
        raise DeployError("authorized_keys must be a regular file")
    content = b""
    if info:
        # FileContents normalizes whitespace/newlines. Base64 transports bytes
        # losslessly on both BSD and GNU systems; failed reads fail closed.
        encoded = host.get_fact(Command, command=f"base64 < {shlex.quote(str(path))}")
        if encoded is None:
            raise DeployError("could not read authorized_keys")
        content = base64.b64decode("".join(encoded.split()), validate=True)
    updated = reconcile_authorized_keys(content, cfg)
    files.directory(path=str(directory), user=cfg.user, group=cfg.group, mode="0700")
    secret_file(path=path, content=SecretContent(updated), user=cfg.user, group=cfg.group, mode="0600")
