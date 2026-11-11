"""The forced-command guard of the deploy@macmini backup key (the ``echoport_remote_command_guard`` role).

The Echoport remote runners on macmini log in as root on the source hosts with
one key whose ``authorized_keys`` line carries ``restrict`` and
``command="<forced command>"``. sshd then runs the guard instead of the
requested command; the guard runs it only when it is one of the shapes the
runners send and every database, unit and path is allowed by the host's policy.

:func:`deploy_echoport_command_guard` is the role's main tasks:

- the Python guard (``files/echoport_remote_command_guard.py.txt``, a verbatim
  copy of the role's ``files/echoport-remote-command-guard.py``; the drift
  manifest records the role) at ``path``, root:root 0755. It is installed with
  every ``impl``: it is the rollback target and what ``shadow`` execs;
- with ``rust_version`` set (``rust.yml``): the Rust guard release
  ``<rust_install_root>/<version>/echoport-command-guard`` through
  :func:`ops_deploy.helpers.rust_release.install_release` (checksum, exact
  members, ``--version`` as nobody), then a host check
  (``files/echoport_rust_guard_check.py``): every component of the binary's
  path belongs to root and nobody else can write it, the binary, its version
  directory and the install root are root:root 0755, and the Rust guard's
  ``--check-policy`` accepts the policy about to be installed. It never moves a
  pin and never deletes a version;
- the policy directory (root:root 0755) and the policy, rendered like Ansible's
  ``to_nice_json`` (sorted keys, four spaces, ASCII escapes, final newline),
  root:root 0644. The policy is checked twice before it replaces the live one:
  on the controller with the same guard code while planning, and on the host by
  the installed Python guard's ``--check-policy`` on a staged copy, which is
  moved over the live file only when the check passes (the role's
  ``validate:``).

``impl`` selects who decides (ops-library rust/echoport-command-guard/PLAN.md
6.2): ``python`` (today's command, byte for byte), ``shadow`` (the Rust guard
logs its decision and execs the Python guard, which decides) or ``rust``. With
``python`` every Rust step only warns (rollback independence: a broken release
never blocks a switch back); with ``shadow`` or ``rust`` a Rust failure stops the
deploy before the policy and, in the caller, the key's line are written.
:meth:`EchoportCommandGuardConfig.forced_command` is the line's command;
:meth:`EchoportCommandGuardConfig.scratch_forced_command` the line of the
optional restore scratch key (``--restore-scratch`` before the policy, impl
``python`` only).

:func:`deploy_echoport_command_guard_confirm` is ``confirm_live.yml``: run it
only after the caller wrote the key's line and its probe went through it. It
reads root's ``authorized_keys`` (``live_state``, the vendored ops-library
filter ``plugins/filter/echoport_guard.py``), requires exactly one line for the
pinned key carrying exactly the forced command (and with ``shadow``/``rust`` a
binary that reports the target version), then moves the pin of the consumer
``echoport_remote_command_guard`` (``python``: removes the current pin and keeps
it as the rollback pin) and prunes old releases, protecting every version any
line names; a line that mentions the install root in another form, an
unreadable file or an unresolvable root make the live state unknown, and the
prune deletes nothing. Nothing is pinned or pruned when the install root does
not exist.

Writing the key's line, the tailnet route on macmini and the probes through the
new line are the caller's (ops-control) job.
"""

from __future__ import annotations

import base64
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

from paramiko import SSHException
from pydantic import Field, field_validator, model_validator
from pyinfra import host, logger
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.arguments import CONNECTOR_ARGUMENT_KEYS, pop_global_arguments
from pyinfra.facts.files import File, Sha256File
from pyinfra.facts.server import Command
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig, output, require_linux
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe_command, probe_output, stdin_arguments
from ops_deploy.helpers.rust_release import install_release, pin_release, prune_releases

_FILES = Path(__file__).parent / "files"
GUARD_SOURCE = _FILES / "echoport_remote_command_guard.py.txt"
# ops-library plugins/filter/echoport_guard.py, byte for byte (the drift test compares it).
LIVE_STATE_SOURCE = _FILES / "echoport_guard_live_state.py.txt"
# ops-library plugins/filter/rust_release.py (vendored for ops_deploy.helpers.rust_release).
RUST_RELEASE_SOURCE = Path(__file__).parents[1] / "helpers" / "templates" / "rust_release.py.txt"
RUST_CHECK_SCRIPT = (_FILES / "echoport_rust_guard_check.py").read_text()
RUST_NAME = "echoport-command-guard"
# The pin file name the role's confirm_live.yml uses.
RUST_CONSUMER = "echoport_remote_command_guard"
RUST_INSTALL_ROOT = "/usr/local/lib/echoport-command-guard"
AUTHORIZED_KEYS = "/root/.ssh/authorized_keys"
# The role's path assertion: no blanks, quotes or other characters that would
# need quoting inside command="…".
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
SafePath = Annotated[str, Field(pattern=SAFE_PATH.pattern)]
Impl = Literal["python", "shadow", "rust"]
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


def _load(source: Path, name: str) -> types.ModuleType:
    """A vendored file of ops-library, loaded as a module on the controller."""

    module = types.ModuleType(name)
    module.__file__ = str(source)
    sys.modules[name] = module  # dataclasses resolve their module while the class is built
    try:
        exec(compile(source.read_text(), str(source), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


@cache
def _guard_module() -> types.ModuleType:
    """The vendored guard, loaded on the controller to validate policies."""

    return _load(GUARD_SOURCE, "_ops_deploy_echoport_remote_command_guard")


@cache
def _live_state_module() -> types.ModuleType:
    return _load(LIVE_STATE_SOURCE, "_ops_deploy_echoport_guard_live_state")


@cache
def _rust_release_module() -> types.ModuleType:
    return _load(RUST_RELEASE_SOURCE, "_ops_deploy_rust_release_decisions")


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
    # Who decides: python | shadow | rust (see the module docstring).
    impl: Impl = "python"
    # The Rust release to install (e.g. "0.2.0"). A set version is installed
    # even with impl python, so a switch is quick; empty installs no Rust binary.
    rust_version: str = ""
    # sha256 of the release archive, required unless rust_local_archive is set.
    rust_sha256: str = ""
    # An archive on the controller instead of the GitHub release (dev/tests only).
    rust_local_archive: Path | None = None
    # <root>/<version>/echoport-command-guard; root:root 0755 on every level.
    rust_install_root: str = RUST_INSTALL_ROOT
    # Newest versions the confirm step's prune keeps, on top of the pins and
    # the versions authorized_keys names.
    rust_keep_versions: int = 3
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

    @model_validator(mode="after")
    def _rust_inputs(self) -> EchoportCommandGuardConfig:
        # The role's main.yml assert, then rust.yml's (fatal unless impl python).
        if self.impl == "python":
            return self
        if not self.rust_version or not (self.rust_sha256 or self.rust_local_archive is not None):
            raise ValueError(f"impl {self.impl} needs rust_version and either rust_sha256 or rust_local_archive")
        problems = self.rust_problems()
        if problems:
            raise ValueError(f"impl {self.impl}: {'; '.join(problems)}")
        return self

    def rust_problems(self) -> list[str]:
        """Why the Rust inputs are unusable (empty when they are usable).

        With impl python these only make the Rust steps warn and skip
        (rollback independence); the other impls refuse the config.
        """

        decisions = _rust_release_module()
        problems = []
        if self.rust_version and not decisions.rust_release_version_ok(self.rust_version):
            problems.append(f"rust_version must be a release version, not {self.rust_version!r}")
        root = self.rust_install_root
        if not decisions.rust_release_root_ok(root) or not SAFE_PATH.fullmatch(root):
            problems.append(f"rust_install_root must be a plain normalised absolute path, not {root!r}")
        if self.rust_keep_versions < 1:
            problems.append(f"rust_keep_versions must be at least 1, not {self.rust_keep_versions}")
        return problems

    @property
    def policy_dir(self) -> str:
        return str(PurePosixPath(self.policy_path).parent)

    @property
    def rust_binary(self) -> str:
        return f"{self.rust_install_root}/{self.rust_version}/{RUST_NAME}"

    def policy_text(self) -> str:
        return render_policy(self.policy)

    def python_command(self) -> str:
        return f"{self.python} -I {self.path} {self.policy_path}"

    def forced_command(self) -> str:
        """The ``command="…"`` value of the pinned key's line (the role's fact)."""

        if self.impl == "python":
            return self.python_command()
        if self.impl == "shadow":
            return f"{self.rust_binary} --shadow {self.policy_path} {self.python_command()}"
        return f"{self.rust_binary} {self.policy_path}"

    def scratch_forced_command(self) -> str:
        """The ``command="…"`` value of the restore scratch key's line (the role's
        ``echoport_remote_command_guard_scratch_forced_command``): the same guard
        and policy in ``--restore-scratch`` mode, which allows only a scratch
        restore's commands inside ``<root>/.restore-scratch-*``. Only the
        Python guard has that mode (the role's fact is undefined otherwise)."""

        if self.impl != "python":
            raise ValueError(f"the restore scratch mode needs impl python, not {self.impl!r}")
        return f"{self.python} -I {self.path} --restore-scratch {self.policy_path}"


def live_state(content: str | None, public_key: str, roots: list[str] | None = None) -> dict[str, Any]:
    """The role's ``echoport_guard_live_state`` filter on root's ``authorized_keys``.

    ``content`` is the file's text (None: it could not be read), ``roots`` the
    spellings of the Rust install root. Returns ``commands`` (per line with
    ``public_key``'s material its ``command=`` values), ``versions`` (every
    ``<root>/<version>/echoport-command-guard`` any line names) and ``unknown``
    (why the live state cannot be trusted for a prune).
    """

    result: dict[str, Any] = _live_state_module().echoport_guard_live_state(content, public_key, roots or [])
    return result


def forced_commands_for_key(content: str, public_key: str) -> list[list[str]]:
    """For every line of ``content`` with ``public_key``'s material, its ``command=`` values.

    Lines sshd would not parse, comments and blank lines are skipped. The
    pinned key is live exactly when this returns ``[[forced_command]]``.
    """

    commands: list[list[str]] = live_state(content, public_key)["commands"]
    return commands


def policy_check_command(cfg: EchoportCommandGuardConfig, staged: str) -> str:
    """Check ``staged`` with the installed guard; move it over the policy only when it passes."""

    check = shlex.join([cfg.python, "-I", cfg.path, "--check-policy", staged])
    move = shlex.join(["mv", "-f", "--", staged, cfg.policy_path])
    remove = shlex.join(["rm", "-f", "--", staged])
    return f"if {check}; then {move}; else {remove}; exit 1; fi"


def rust_check_command(cfg: EchoportCommandGuardConfig) -> str:
    """``files/echoport_rust_guard_check.py`` (on stdin) on the binary and the policy about to be installed."""

    policy = base64.b64encode(cfg.policy_text().encode()).decode()
    return shlex.join([cfg.python, "-I", "-", cfg.rust_binary, policy])


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


def _rust_guard(cfg: EchoportCommandGuardConfig) -> None:
    """The role's ``rust.yml``: install the release and check it (no pin, no prune)."""

    problems = cfg.rust_problems()
    if problems:
        # Only reachable with impl python: the config refuses the other impls.
        logger.warning(
            f"{host.print_prefix}WARNING: the Rust guard inputs are invalid ({'; '.join(problems)}); "
            "impl is python, so the deploy goes on with the Python forced command"
        )
        return
    fatal = cfg.impl != "python"
    install = install_release(
        RUST_NAME,
        cfg.rust_version,
        sha256=cfg.rust_sha256,
        install_root=cfg.rust_install_root,
        local_archive=cfg.rust_local_archive,
        fail_hard=fatal,
    )
    # Every run, like the role: the policy it checks may be new. Read-only.
    mark_read_only(
        server.shell(
            name=f"Check the {RUST_NAME} {cfg.rust_version} binary and the policy",
            commands=[rust_check_command(cfg)],
            _if=lambda: not install.failed(),
            # impl python: a failed check is reported and the deploy goes on.
            _ignore_errors=not fatal,
            **stdin_arguments(RUST_CHECK_SCRIPT),
        )
    )


@deploy("Echoport remote command guard")
def deploy_echoport_command_guard(cfg: EchoportCommandGuardConfig) -> None:
    require_linux("echoport_command_guard")
    # Follows symlinks: /usr/bin/python3 is one on Debian and Ubuntu.
    if output(f"test -x {shlex.quote(cfg.python)} && echo present") != "present":
        raise DeployError(f"{cfg.python} is missing; the guard needs Python 3")
    # The Python guard stays installed with every impl: the rollback target and
    # what shadow execs.
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
    if cfg.rust_version:
        _rust_guard(cfg)
    _policy_file(name="Install the guard policy", cfg=cfg)


class EchoportGuardConfirmConfig(RoleConfig):
    """``confirm_live.yml``'s inputs: the guard config the line was written for and the pinned key."""

    guard: EchoportCommandGuardConfig
    # "<type> <base64> [comment]"
    public_key: str
    authorized_keys_path: SafePath = AUTHORIZED_KEYS

    @field_validator("public_key")
    @classmethod
    def _key(cls, value: str) -> str:
        fields = value.split()
        if len(fields) < 2 or not _KEY_TYPE_RE.match(fields[0]):
            raise ValueError("public_key must be '<type> <base64> [comment]'")
        return value.strip()


def _read(command: str) -> str | None:
    """Stdout of ``command`` while planning, or None when it failed (no warning, no retry)."""

    return probe_output(str(host.get_fact(Command, command=probe_command(command)) or ""))


def _read_quietly(command: str) -> str | None:
    """:func:`_read` for content that must stay out of the output, also with ``-vvv``.

    A fact prints its output in verbose mode; this runs the command with the
    fact's connector arguments, but with input and output printing off (the
    role's ``no_log: true``).
    """

    context = dict(host.current_op_global_arguments or {})
    arguments, _ = pop_global_arguments(host.state, host, context)
    executor = {key: value for key, value in arguments.items() if key in CONNECTOR_ARGUMENT_KEYS}
    try:
        ok, result = host.run_shell_command(StringCommand(command), print_input=False, print_output=False, **executor)
    except (OSError, TimeoutError, SSHException):
        # As a fact's connection error: the file cannot be read (the line check then fails).
        return None
    return str(result.stdout) if ok else None


@deploy("Echoport remote command guard: confirm live")
def deploy_echoport_command_guard_confirm(cfg: EchoportGuardConfirmConfig) -> None:
    require_linux("echoport_command_guard")
    guard = cfg.guard
    fatal = guard.impl != "python"
    problems = guard.rust_problems()
    if problems:
        logger.warning(
            f"{host.print_prefix}WARNING: the Rust inputs are invalid ({'; '.join(problems)}); impl is python, "
            "so the line is still verified, but no pin moves and nothing is pruned"
        )
    root = guard.rust_install_root
    roots: list[str] = []
    resolved = False
    if not problems:
        # /proc and a forced command may name the resolved root; a mention of either spelling counts.
        real = _read(f"realpath -- {shlex.quote(root)}")
        resolved = real is not None
        found = (real or "").strip()
        roots = list(dict.fromkeys([root, *([found] if re.fullmatch(r"/[^\n]+", found) and found != "/" else [])]))
    # The file also holds other keys and their from= addresses: it is parsed
    # here and never printed.
    content = _read_quietly(f"cat -- {shlex.quote(cfg.authorized_keys_path)}")
    live = live_state(content, cfg.public_key, roots)
    forced = guard.forced_command()
    if live["commands"] != [[forced]]:
        unread = "; the file cannot be read" if content is None else ""
        raise DeployError(
            f"{cfg.authorized_keys_path} does not hold exactly one line for the pinned key with "
            f'command="{forced}" (found the command= values {json.dumps(live["commands"])} on the lines '
            f"with that key{unread}). No pin moves and nothing is pruned."
        )
    if problems:
        return
    if fatal:
        answer = _read(shlex.join([guard.rust_binary, "--version"]))
        first = (answer or "").splitlines()[:1]
        if answer is None or not first or not first[0].startswith(f"{RUST_NAME} {guard.rust_version} ("):
            raise DeployError(
                f"{guard.rust_binary} --version answered {first[0] if first else '(nothing)'!r}; expected "
                f"{RUST_NAME} {guard.rust_version}. No pin moves and nothing is pruned."
            )
    if _read(f"test -d {shlex.quote(root)} && echo directory") != "directory":
        logger.info(f"{host.print_prefix}{root} does not exist: no Rust release to pin or prune")
        return
    protect = sorted({*live["versions"], *([guard.rust_version] if guard.rust_version else [])})
    unknown = list(live["unknown"]) + ([] if resolved else [f"cannot resolve {root}"])
    for reason in unknown:
        logger.warning(f"{host.print_prefix}live state unknown, the prune deletes nothing: {reason}")
    # shadow/rust: pin the target (its old current pin becomes the previous
    # pin). python: remove the current pin and keep its version as the
    # previous pin, so the last Rust version verified live stays installed.
    _, pin = pin_release(
        RUST_NAME,
        RUST_CONSUMER,
        None if guard.impl == "python" else guard.rust_version,
        install_root=root,
        soft=not fatal,
    )
    prune_releases(
        RUST_NAME,
        install_root=root,
        keep_versions=guard.rust_keep_versions,
        protect=protect,
        live_state_unknown=bool(unknown),
        # Runs again after a pin change; never after a soft pin that failed.
        after=[pin],
        soft=not fatal,
    )
