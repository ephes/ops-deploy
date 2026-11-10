"""The forced-command guard of the deploy@macmini backup key (the ``echoport_remote_command_guard`` role).

The Echoport remote runners on macmini log in as root on the source hosts with
one key whose ``authorized_keys`` line carries ``restrict`` and
``command="<forced command>"``. sshd then runs the guard instead of the
requested command; the guard runs it only when it is one of the shapes the
runners send and every database, unit and path is allowed by the host's policy.

This deploy installs, byte for byte as the role does with
``echoport_remote_command_guard_impl: python``:

- the guard program (``files/echoport_remote_command_guard.py.txt``, a verbatim
  copy of the role's ``files/echoport-remote-command-guard.py``; the drift
  manifest records the role) at ``path``, root:root 0755;
- the policy directory (root:root 0755) and the policy, rendered like Ansible's
  ``to_nice_json`` (sorted keys, four spaces, ASCII escapes, final newline),
  root:root 0644. The policy is checked twice before it replaces the live one:
  on the controller with the same guard code while planning, and on the host by
  the installed guard's ``--check-policy`` on a staged copy, which is moved over
  the live file only when the check passes (the role's ``validate:``).

:func:`forced_command` is what the caller writes into the key's line
(``<python> -I <guard> <policy>``), and :func:`forced_commands_for_key` reads a
live ``authorized_keys`` back for the role's ``confirm_live.yml`` check: the
pinned key must have exactly one line, carrying exactly that command.

Only ``impl: python`` is ported. The Rust guard (``shadow``/``rust``, a pinned
release, pin and prune after the live check) is not installed on any host yet
(ops-control pins no release), so this deploy refuses those settings instead of
silently ignoring them. Writing the key's line, the tailnet route on macmini and
the probes through the new line are the caller's (ops-control) job.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import sys
import types
from collections.abc import Generator, Mapping
from functools import cache
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.facts.files import File, Sha256File
from pyinfra.operations import files

from ops_deploy.base._common import RoleConfig, output, require_linux

GUARD_SOURCE = Path(__file__).parent / "files" / "echoport_remote_command_guard.py.txt"
# The role's path assertion: no blanks, quotes or other characters that would
# need quoting inside command="…".
SafePath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/-]+$")]
POLICY_KEYS = frozenset(
    {
        "postgres",
        "units",
        "private_media_paths",
        "path_roots",
        "temp_dirs",
        "sqlite_snapshots",
        "read_files",
        "ready_urls",
    }
)
_STAGED_SUFFIX = ".ops-deploy-new"
_KEY_TYPE_RE = re.compile(
    r"^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|"
    r"sk-(ecdsa-sha2-nistp256|ssh-ed25519)@openssh\.com)(-cert-v01@openssh\.com)?$"
)


@cache
def _guard_module() -> types.ModuleType:
    """The vendored guard, loaded on the controller to validate policies."""

    name = "_ops_deploy_echoport_remote_command_guard"
    module = types.ModuleType(name)
    module.__file__ = str(GUARD_SOURCE)
    sys.modules[name] = module  # dataclasses resolve their module while the class is built
    try:
        exec(compile(GUARD_SOURCE.read_text(), str(GUARD_SOURCE), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def render_policy(policy: Mapping[str, Any]) -> str:
    """The policy as Ansible's ``to_nice_json`` writes it, plus the role's final newline."""

    return json.dumps(policy, indent=4, sort_keys=True, separators=(",", ": ")) + "\n"


def check_policy(policy: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` when the guard would refuse ``policy`` at login."""

    module = _guard_module()
    try:
        module.Policy.from_dict(json.loads(render_policy(policy)))
    except (module.Refused, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError(f"the guard refuses the policy: {exc}") from None


class EchoportCommandGuardConfig(RoleConfig):
    # The role's defaults.
    path: SafePath = "/usr/local/sbin/echoport-remote-command-guard"
    policy_path: SafePath = "/etc/echoport/remote-command-guard.json"
    python: SafePath = "/usr/bin/python3"
    # Only the Python guard is ported (see the module docstring).
    impl: Literal["python"] = "python"
    rust_version: Literal[""] = ""
    # What the Echoport remote runners may do on this host (the role README);
    # every list defaults to empty, which allows nothing.
    policy: dict[str, Any] = Field(default_factory=dict)

    @field_validator("policy")
    @classmethod
    def _policy_shape(cls, value: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(value) - POLICY_KEYS)
        if unknown:
            raise ValueError(f"policy has unknown keys {unknown}; allowed: {sorted(POLICY_KEYS)}")
        if not isinstance(value.get("postgres", {}), dict):
            raise ValueError("policy.postgres must be a mapping")
        for key in POLICY_KEYS - {"postgres"}:
            if not isinstance(value.get(key, []), list | tuple):
                raise ValueError(f"policy.{key} must be a list")
        check_policy(value)
        return value

    @property
    def policy_dir(self) -> str:
        return str(PurePosixPath(self.policy_path).parent)

    def policy_text(self) -> str:
        return render_policy(self.policy)

    def forced_command(self) -> str:
        """The ``command="…"`` value of the pinned key's line (the role's fact)."""

        return f"{self.python} -I {self.path} {self.policy_path}"


def _split_options(line: str) -> tuple[str, str] | None:
    """Split ``options rest`` at the first blank outside quotes (sshd's rule)."""

    quoted = False
    i = 0
    while i < len(line):
        ch = line[i]
        if quoted and ch == "\\" and line[i + 1 : i + 2] == '"':
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch in " \t":
            return line[:i], line[i:].lstrip(" \t")
        i += 1
    return None


def _option_commands(options: str) -> list[str] | None:
    """The values of every ``command="…"`` option, or None if malformed."""

    parts: list[str] = []
    quoted = False
    start = 0
    i = 0
    while i < len(options):
        ch = options[i]
        if quoted and ch == "\\" and options[i + 1 : i + 2] == '"':
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif ch == "," and not quoted:
            parts.append(options[start:i])
            start = i + 1
        i += 1
    if quoted:
        return None
    parts.append(options[start:])
    commands: list[str] = []
    for part in parts:
        name, sep, value = part.partition("=")
        if name.lower() != "command":
            continue
        if not sep or len(value) < 2 or not (value.startswith('"') and value.endswith('"')):
            return None
        commands.append(value[1:-1].replace('\\"', '"'))
    return commands


def forced_commands_for_key(content: str, public_key: str) -> list[list[str]]:
    """For every line of ``content`` with ``public_key``'s material, its ``command=`` values.

    The ``commands`` part of the role's ``echoport_guard_live_state`` filter:
    lines sshd would not parse, comments and blank lines are skipped. The pinned
    key is live exactly when this returns ``[[forced_command]]``.
    """

    key_fields = public_key.split()
    if len(key_fields) < 2 or not _KEY_TYPE_RE.match(key_fields[0]):
        raise ValueError("public_key must be '<type> <base64> [comment]'")
    found: list[list[str]] = []
    for raw in content.split("\n"):
        line = raw.rstrip("\r").strip(" \t")
        if not line or line.startswith("#") or "\0" in line:
            continue
        fields = line.split()
        if _KEY_TYPE_RE.match(fields[0]):
            options, rest = "", line
        else:
            split = _split_options(line)
            if split is None:
                continue
            options, rest = split
        key = rest.split()
        if len(key) < 2 or not _KEY_TYPE_RE.match(key[0]):
            continue
        commands = _option_commands(options) if options else []
        if commands is None:
            continue
        if (key[0], key[1]) == (key_fields[0], key_fields[1]):
            found.append(commands)
    return found


def policy_check_command(cfg: EchoportCommandGuardConfig, staged: str) -> str:
    """Check ``staged`` with the installed guard; move it over the policy only when it passes."""

    check = shlex.join([cfg.python, "-I", cfg.path, "--check-policy", staged])
    move = shlex.join(["mv", "-f", "--", staged, cfg.policy_path])
    remove = shlex.join(["rm", "-f", "--", staged])
    return f"if {check}; then {move}; else {remove}; exit 1; fi"


@operation()
def _policy_file(cfg: EchoportCommandGuardConfig) -> Generator[Any, None, None]:
    text = cfg.policy_text()
    info = host.get_fact(File, path=cfg.policy_path)
    if info is False:
        raise DeployError(f"{cfg.policy_path} exists and is not a regular file")
    if (
        info
        and info["mode"] == 644
        and info["user"] == "root"
        and info["group"] == "root"
        and host.get_fact(Sha256File, path=cfg.policy_path) == hashlib.sha256(text.encode()).hexdigest()
    ):
        host.noop(f"guard policy {cfg.policy_path} is up to date")
        return
    staged = cfg.policy_path + _STAGED_SUFFIX
    yield from files.put._inner(src=StringIO(text), dest=staged, user="root", group="root", mode="0644")
    yield StringCommand(policy_check_command(cfg, staged))


@deploy("Echoport remote command guard")
def deploy_echoport_command_guard(cfg: EchoportCommandGuardConfig) -> None:
    require_linux("echoport_command_guard")
    # Follows symlinks: /usr/bin/python3 is one on Debian and Ubuntu.
    if output(f"test -x {shlex.quote(cfg.python)} && echo present") != "present":
        raise DeployError(f"{cfg.python} is missing; the guard needs Python 3")
    files.put(
        name="Install the forced-command guard",
        src=str(GUARD_SOURCE),
        dest=cfg.path,
        user="root",
        group="root",
        mode="0755",
    )
    files.directory(
        name="Ensure the policy directory exists",
        path=cfg.policy_dir,
        user="root",
        group="root",
        mode="0755",
    )
    _policy_file(name="Install the guard policy", cfg=cfg)
