"""Manage some lines of a user's ``authorized_keys`` file, keeping all others.

``ssh_authorized_keys`` owns the whole file. This deploy only touches the keys it
is given, so keys other deploys or roles install (forced-command backup keys,
relay keys, the Ansible header) survive every run:

- lines are matched by key material (key type + base64 blob), never by comment
  or options;
- every ``present`` key is added when missing and rewritten in place when its
  options or comment differ; further lines with the same key material are
  removed (one line per key);
- every line carrying an ``absent`` key's material is removed;
- every other line, including comments, blank lines, unparsable lines, CRLF
  line ends and a missing final newline, stays byte for byte;
- removal fails closed: a non-comment line that is not attributed to an
  ``absent`` key but still contains its base64 blob (ignoring every non-base64
  byte, as sshd's decoder skips whitespace) refuses the run, because sshd might
  read it as that key. Lines are split on LF only, as sshd reads them.

The file is read once while planning, merged on the controller and installed
with :func:`~ops_deploy.ops.secret_file` (stdin, private staging directory,
rename), so an interrupted run never leaves a truncated file. It ends up 0600,
``.ssh`` 0700, both owned by ``user``:``group``. ``home`` and ``group`` are
arguments, never derived: macOS accounts live in ``/Users`` or ``/var/root``
with group ``staff`` or ``wheel``. Runs on Linux and macOS (the host needs
``sh``, ``base64`` and ``python3``).

Lock-out protection is the caller's job (ops-control ``controller_keys``,
deploy-controllers plan slice 4): before calling this with ``absent`` keys,
prove with a fresh, non-multiplexed login that a surviving ``present`` key
authenticates, and never remove the key of the connection in use. This deploy
only refuses an empty ``present`` set, unless ``allow_empty_present`` says the
account is meant to keep no managed key (ops-control ``user_keys``: an account
whose retired keys are removed without replacement); a missing file is then
left missing. Concurrent writers are the caller's job too: take the shared
deploy lock before this deploy reads the file.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Annotated

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError, FactBase, deploy
from pyinfra.operations import files

from ops_deploy.base._common import AbsolutePath, RoleConfig
from ops_deploy.base.ssh_authorized_keys import AuthorizedKey
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops import secret_file

OneLine = Annotated[str, Field(pattern=r"^[^\r\n]*$")]
_KEY_TYPE = re.compile(r"^(?:ssh-[A-Za-z0-9@.-]+|ecdsa-sha2-[A-Za-z0-9@.-]+|sk-[A-Za-z0-9@.-]+)$")
KeyMaterial = tuple[str, str]
# sshd separates fields with spaces and tabs only (``strcspn(cp, " \t")``),
# never with other whitespace such as form feed or NBSP.
_BLANK = " \t"


# sshd's base64 decoder skips whitespace inside the blob, so the fail-closed
# check looks for an absent blob in the line with every non-base64 byte removed.
_BASE64_ONLY = re.compile(rb"[^A-Za-z0-9+/=]")


def _fields(text: str) -> list[str]:
    return [field for field in re.split(r"[ \t]+", text) if field]


def key_material(line: str) -> KeyMaterial | None:
    """``(type, base64)`` of an ``authorized_keys`` line, or ``None``.

    ``None`` for blank lines, comments and anything that does not parse; those
    are never matched. Handles a leading options field with quoted values
    (``command="a b",no-pty``).
    """

    text = line.strip(_BLANK)
    if not text or text.startswith("#"):
        return None
    fields = _fields(text)
    if not _KEY_TYPE.match(fields[0]):
        rest = _skip_options(text)
        if rest is None:
            return None
        fields = _fields(rest)
    if len(fields) < 2 or not _KEY_TYPE.match(fields[0]):
        return None
    try:
        base64.b64decode(fields[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    return fields[0], fields[1]


def _skip_options(text: str) -> str | None:
    """The text after the options field, by OpenSSH's ``sshkey_advance_past_options``.

    ``\\"`` is skipped as an escaped quote (inside and outside quotes), a ``"``
    toggles quoting, and the field ends at the first unquoted space or tab.
    """

    quoted = False
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and text[i + 1 : i + 2] == '"':
            i += 2
            continue
        if char == '"':
            quoted = not quoted
        elif char in " \t" and not quoted:
            return text[i:].lstrip(_BLANK)
        i += 1
    return None


def _lines(content: bytes) -> list[bytes]:
    """Lines as sshd reads them: split on LF only (a lone CR stays in the line)."""

    return re.findall(rb"[^\n]*\n|[^\n]+\Z", content)


def _split_ending(raw: bytes) -> tuple[bytes, bytes]:
    for ending in (b"\r\n", b"\n"):
        if raw.endswith(ending):
            return raw[: -len(ending)], ending
    return raw, b""


def merge_authorized_keys(existing: bytes, present: Sequence[str], absent: Sequence[str]) -> bytes:
    """The file after adding/updating ``present`` lines and removing ``absent`` keys."""

    wanted: dict[KeyMaterial, bytes] = {}
    for line in present:
        material = key_material(line)
        if material is None:
            raise ValueError("present entry is not a public key line")
        wanted[material] = line.encode()
    removed = {material for material in map(key_material, absent) if material is not None}
    removed_blobs = [blob.encode() for _, blob in removed]

    out: list[bytes] = []
    seen: set[KeyMaterial] = set()
    for raw in _lines(existing):
        body, ending = _split_ending(raw)
        text = body.decode("utf-8", "surrogateescape")
        material = key_material(text)
        if (
            material not in removed
            and not text.lstrip(_BLANK).startswith("#")
            and any(blob in _BASE64_ONLY.sub(b"", body) for blob in removed_blobs)
        ):
            # Revocation fails closed: sshd may read such a line as the removed key.
            raise ValueError("a line this deploy cannot attribute contains a key that must be removed")
        if material is None or (material not in wanted and material not in removed):
            out.append(raw)
        elif material in removed or material in seen:
            continue
        else:
            seen.add(material)
            out.append(raw if body == wanted[material] else wanted[material] + (ending or b"\n"))

    missing = [line for material, line in wanted.items() if material not in seen]
    if missing and out and _split_ending(out[-1])[1] == b"":
        out[-1] += b"\n"
    out.extend(line + b"\n" for line in missing)
    return b"".join(out)


class SshAuthorizedKeyEntriesConfig(RoleConfig):
    user: UnixUser
    group: UnixUser
    home: AbsolutePath
    # Added or updated; at least one, so a run can never leave no controller
    # key, unless allow_empty_present is set.
    present: tuple[AuthorizedKey, ...] = ()
    # Key lines (options and comment ignored) whose every occurrence is removed.
    absent: tuple[OneLine, ...] = ()
    # True: an empty present set is allowed (the account keeps no managed key;
    # only absent keys are removed, a missing file stays missing).
    allow_empty_present: bool = False

    @model_validator(mode="after")
    def _keys(self) -> SshAuthorizedKeyEntriesConfig:
        if not self.present and not self.allow_empty_present:
            raise ValueError("present needs at least one key (or allow_empty_present)")
        present: set[KeyMaterial] = set()
        for entry in self.present:
            material = key_material(entry.line())
            if material is None:
                raise ValueError("present entry is not a public key")
            if material in present:
                raise ValueError("present lists the same key twice")
            present.add(material)
        for line in self.absent:
            material = key_material(line)
            if material is None:
                raise ValueError("absent entry is not a public key")
            if material in present:
                raise ValueError("a key is both present and absent")
        return self

    @property
    def ssh_dir(self) -> PurePosixPath:
        return PurePosixPath(self.home) / ".ssh"

    @property
    def path(self) -> PurePosixPath:
        return self.ssh_dir / "authorized_keys"

    def present_lines(self) -> list[str]:
        return [entry.line().rstrip("\n") for entry in self.present]


class AuthorizedKeysFile(FactBase[tuple[str, bytes]]):
    """``(kind, content)`` of a file: ``file``, ``missing``, ``symlink``, ``other`` or ``unreadable``.

    The content travels base64-encoded, so CR, a missing final newline and
    non-UTF-8 bytes survive the read.
    """

    @staticmethod
    def default() -> tuple[str, bytes]:
        # A failed fact command (base64 died, permissions) must reach the refusal.
        return "unreadable", b""

    def command(self, path: str) -> str:
        p, parent = shlex.quote(path), shlex.quote(str(PurePosixPath(path).parent))
        return (
            f"if [ -L {p} ]; then echo symlink; elif [ -f {p} ]; then "
            f"if [ -r {p} ]; then echo file; base64 < {p}; else echo unreadable; fi; "
            f"elif [ -e {p} ]; then echo other; "
            f"elif [ -d {parent} ] && [ ! -x {parent} ]; then echo unreadable; else echo missing; fi"
        )

    def process(self, output: list[str]) -> tuple[str, bytes]:
        if not output:
            return "unreadable", b""
        kind = output[0].strip()
        if kind != "file":
            return kind, b""
        return kind, base64.b64decode("".join(line.strip() for line in output[1:]), validate=True)


@deploy("SSH authorized key entries")
def deploy_ssh_authorized_key_entries(cfg: SshAuthorizedKeyEntriesConfig) -> None:
    kind, existing = host.get_fact(AuthorizedKeysFile, path=str(cfg.path))
    if kind not in ("file", "missing"):
        raise DeployError(f"{cfg.path} is not a readable regular file ({kind}); refusing to change it")
    if kind == "missing" and not cfg.present:
        # Nothing to add and nothing to remove: no file, no .ssh created.
        return
    try:
        content = merge_authorized_keys(existing, cfg.present_lines(), cfg.absent)
    except ValueError as exc:
        raise DeployError(f"{cfg.path}: {exc}; refusing to change it") from None
    files.directory(
        name=f"Ensure {cfg.ssh_dir}",
        path=str(cfg.ssh_dir),
        user=cfg.user,
        group=cfg.group,
        mode="0700",
    )
    # Not secret, but secret_file replaces the file atomically and changes
    # nothing when content, owner and mode already match.
    secret_file(
        name=f"Update {cfg.path}",
        path=cfg.path,
        content=SecretContent(content),
        user=cfg.user,
        group=cfg.group,
        mode="0600",
    )
