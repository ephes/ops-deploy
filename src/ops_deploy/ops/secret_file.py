"""``secret_file``: write a secret to a host without it touching a command line.

The content travels base64-encoded over the command's stdin to a small Python
program (``ops_deploy.ops._secret_install``, run as ``python3 -I -c``) that
reaches the destination directory without following symlinks and stages the
file in a private 0700 directory next to the destination, pinned by
descriptor, before renaming it into place. The stream is read and its length
checked before anything is created, so an interrupted upload never touches the
directory. See the installer's docstring for the full sequence and failure
handling.

The host needs ``python3`` (3.8+). Uploads never use ``_sudo``: pyinfra stages
those as plaintext in a shared temp directory. Connect as a user that may
write the destination instead.
"""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
from collections.abc import Generator
from pathlib import Path, PurePosixPath

from pyinfra import host
from pyinfra.api import OperationError, OperationValueError, StringCommand, operation
from pyinfra.facts.files import File, FindDirectories, Sha256File

from ops_deploy.core.secrets import SecretContent
from ops_deploy.ops._secret_install import TEMP_PREFIX
from ops_deploy.ops.quiet import quiet_fact

_MODE = re.compile(r"^0?[0-7]{3}$")
_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]*$")
INSTALLER_SOURCE = (Path(__file__).parent / "_secret_install.py").read_text()


def temp_tag(dest: PurePosixPath) -> str:
    """Hex tag for ``dest``'s temp files: glob-safe whatever the file name."""

    return hashlib.sha256(dest.name.encode()).hexdigest()[:16]


def temp_pattern(dest: PurePosixPath) -> str:
    """``find -name`` pattern matching staging directories for ``dest``."""

    return f"{TEMP_PREFIX}{temp_tag(dest)}.*"


def install_command(
    dest: PurePosixPath,
    size: int,
    *,
    mode: str,
    user: str | None = None,
    group: str | None = None,
) -> str:
    """The host command that installs stdin (base64) at ``dest``.

    It contains no secret material: only paths, owner, mode and the decoded
    length.
    """

    args = [str(dest.parent), dest.name, temp_tag(dest), str(size), mode, user or "", group or ""]
    return shlex.join(["python3", "-I", "-c", INSTALLER_SOURCE, *args])


def encode_payload(content: SecretContent) -> str:
    """Base64 text for stdin; pyinfra's stdin writer is line based and text only."""

    return base64.encodebytes(content.reveal()).decode("ascii")


def _validate(path: PurePosixPath, mode: str, user: str | None, group: str | None) -> None:
    if not path.is_absolute() or ".." in path.parts or path.name in {"", ".", ".."}:
        raise OperationValueError(f"secret_file path must be an absolute file path: {path}")
    if not _MODE.match(mode):
        raise OperationValueError(f"secret_file mode must be octal like 0600: {mode!r}")
    for name in (user, group):
        if name is not None and not _NAME.match(name):
            raise OperationValueError(f"secret_file owner is not a valid name: {name!r}")


@operation()
def secret_file(
    path: str | PurePosixPath,
    content: SecretContent,
    user: str | None = None,
    group: str | None = None,
    mode: str = "0600",
) -> Generator[StringCommand, None, None]:
    """Install ``content`` at ``path`` atomically, without exposing it.

    + path: absolute destination; its directory must exist
    + content: the secret, wrapped in ``SecretContent``
    + user/group: owner to set (needs root unless it is the SSH user)
    + mode: octal permissions, default ``0600``
    """

    if not isinstance(content, SecretContent):
        raise OperationValueError("secret_file content must be a SecretContent")
    dest = PurePosixPath(path)
    _validate(dest, mode, user, group)

    info = host.get_fact(File, path=str(dest))
    if info is False:
        raise OperationError(f"secret_file destination exists and is not a regular file: {dest}")
    leftovers = host.get_fact(FindDirectories, path=str(dest.parent), maxdepth=1, fname=temp_pattern(dest))

    up_to_date = False
    if info:
        up_to_date = (
            info["mode"] == int(mode.lstrip("0") or "0")
            and (user is None or info["user"] == user)
            and (group is None or info["group"] == group)
            and quiet_fact(Sha256File, path=str(dest)) == hashlib.sha256(content.reveal()).hexdigest()
        )
    if up_to_date and not leftovers:
        host.noop(f"secret file {dest} is up to date")
        return

    # Also when only leftovers exist: the installer removes them without
    # following symlinks, which a plain `rm` of fact-reported paths cannot promise.
    yield StringCommand(
        install_command(dest, len(content), mode=mode, user=user, group=group),
        _stdin=encode_payload(content),
        # A pty echoes stdin into the recorded output; never inherit one.
        _get_pty=False,
        _shell_executable="sh",
    )


@operation()
def secret_stdin(command: str, content: SecretContent) -> Generator[StringCommand, None, None]:
    """Run ``command`` with a secret on its standard input.

    For programs that read a secret themselves (a password hash for a
    management command, SQL with a password verifier). The secret is never on
    a command line or in the operation's arguments. pyinfra writes stdin line
    by line, so ``content`` must be text; the command's output must not echo it.

    + command: shell command (``sh``); its exit status decides success
    + content: the stdin text, wrapped in ``SecretContent``
    """

    if not isinstance(content, SecretContent):
        raise OperationValueError("secret_stdin content must be a SecretContent")
    yield StringCommand(command, _stdin=content.reveal().decode(), _get_pty=False, _shell_executable="sh")
