"""Pinned Rust release binaries of ops-library: install, pin, prune.

The pyinfra side of ops-library's ``rust/PLAN-foundation.md`` 6.3 (F4). It
keeps the on-host layout of 6.1, the same files with the same bytes as the
Ansible helper role ``rust_release_binary`` (F3), so Ansible and pyinfra can
take turns on a host::

    <root>/<version>/<name>              root:root 0755, never modified in place
    <root>/<version>/LICENSE             root:root 0644 (and any other member)
    <root>/<version>/.archive-sha256     root:root 0644, "<archive sha256>\\n"
    <root>/.pins/<consumer>              root:root 0644, "<version>\\n": verified live
    <root>/.pins/<consumer>.previous     root:root 0644, "<version>\\n": the rollback pin
    <root>/.staging-<version>/           transient

The decisions (pin moves, prune plan, the version and consumer grammar) are
ops-library's ``plugins/filter/rust_release.py``, vendored byte for byte as
``templates/rust_release.py.txt`` (``tests/test_ops_library_drift.py``
compares it). The steps run on the host, at execution time, in
``templates/rust_release_host.py.txt``: the helper sends both texts on stdin
to ``/usr/bin/python3 -I -`` as root (standard library only). While planning,
read-only ``--check`` probes decide whether a step is needed, so a converged
run changes nothing.

Nothing here decides *when* to pin or what the live state is: a consumer
pins only after it verified that its unit runs the version, passes the
versions or executables its live state names as ``protect``, and sets
``live_state_unknown`` when it could not read that state.
"""

from __future__ import annotations

import hashlib
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib.resources import files as resources
from pathlib import Path

from pyinfra import host, logger
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory
from pyinfra.operations import files, server

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe

_TEMPLATES = resources("ops_deploy.helpers").joinpath("templates")
# The vendored decisions first: they open with ``from __future__`` and define what the host steps call.
HOST_SCRIPT = (
    _TEMPLATES.joinpath("rust_release.py.txt").read_text() + _TEMPLATES.joinpath("rust_release_host.py.txt").read_text()
)
HOST_PYTHON = "/usr/bin/python3"


@dataclass(frozen=True)
class Install:
    """The install (or read-only validation) of one release; ``failed()`` only after it ran."""

    op: OperationMeta
    binary: str

    def failed(self) -> bool:
        """Whether a ``fail_hard=False`` install was rejected (use it in ``_if`` callbacks)."""

        return not self.op.did_succeed() or any(line.startswith("failed ") for line in self.op.stdout_lines)


def _command(action: str, name: str, root: str, *options: object) -> str:
    argv = [HOST_PYTHON, "-I", "-", action, "--name", name, "--root", root, *(str(o) for o in options)]
    return shlex.join(argv)


def install_release(
    name: str,
    version: str,
    *,
    sha256: str = "",
    install_root: str = "",
    release_url: str = "",
    local_archive: Path | None = None,
    members: Sequence[str] = (),
    executables: Sequence[str] = (),
    validate_user: str = "nobody",
    fail_hard: bool = True,
) -> Install:
    """Install ``version`` of crate ``name`` and run ``<binary> --version`` as ``validate_user``.

    Like the role's ``tasks_from: install``: an installed version is only
    validated (read-only; a different archive for it is refused), a new one
    is downloaded from ``release_url`` (default: the ops-library GitHub
    release) or uploaded from ``local_archive``, checked against ``sha256``,
    required to hold exactly ``members`` (default ``[name, "LICENSE"]``) as
    regular files and moved into place. A failure removes the fresh install
    and fails the deploy, or with ``fail_hard=False`` warns and lets it go on
    (``Install.failed()`` tells later ``_if`` callbacks). Never moves a pin,
    never deletes another version.
    """

    root = install_root or f"/opt/{name}"
    options: list[object] = ["--version", version, "--validate-user", validate_user]
    options += (["--members", ",".join(members)] if members else []) + (
        ["--executables", ",".join(executables)] if executables else []
    )
    options += ["--url", release_url] if release_url else []
    options += [] if fail_hard else ["--soft"]
    installed = host.get_fact(Directory, path=f"{root}/{version}") is not None
    if local_archive is not None:
        actual = hashlib.sha256(local_archive.read_bytes()).hexdigest()
        options += ["--archive-sha256", actual]
        sha256 = sha256 or actual
        if not installed:
            files.directory(name=f"Create the {name} install root", path=root, user="root", group="root", mode="0755")
            upload = f"{root}/.upload-{version}.tar.gz"
            files.put(
                name=f"Upload {name} {version}",
                src=str(local_archive),
                dest=upload,
                user="root",
                group="root",
                mode="0600",
            )
            options += ["--upload", upload]
    command = _command("install", name, root, "--sha256", sha256, *options)
    op = server.shell(
        name=f"{'Validate' if installed else 'Install'} {name} {version}",
        commands=[command],
        **stdin_arguments(HOST_SCRIPT),
    )
    return Install(mark_read_only(op) if installed else op, f"{root}/{version}/{name}")


def _gated(name: str, command: str, after: Iterable[OperationMeta | Install] = ()) -> str:
    """Run ``command`` if its ``--check`` probe asks for a change, failed, or a step in ``after`` changed.

    Never after a failed ``Install`` in ``after``.
    """

    check = f"{command} --check"
    pending = probe(check, name=name, stdin=HOST_SCRIPT)
    ops = [a.op if isinstance(a, Install) else a for a in after]
    installs = [a for a in after if isinstance(a, Install)]
    for line in (pending or "").splitlines():
        if line.startswith("blocked "):
            logger.warning(f"{host.print_prefix}{name}: {line}")
    server.shell(
        name=name,
        commands=[command],
        _if=lambda: (
            not any(i.failed() for i in installs)
            and (pending is None or "remove " in pending or "change " in pending or any(op.did_change() for op in ops))
        ),
        **stdin_arguments(HOST_SCRIPT),
    )
    if pending is None:
        verify_probe(check, name=name, stdin=HOST_SCRIPT)
    return pending or ""


def pin_release(
    name: str,
    consumer: str,
    version: str | None,
    *,
    install_root: str = "",
    previous: str = "",
    keep_previous: bool = True,
) -> str:
    """Pin ``version`` for ``consumer`` (``None``: remove its pin), moving the rollback pin.

    The role's ``tasks_from: pin``: pinning ``V`` over a current pin ``C ≠ V``
    makes ``C`` the previous pin; removing the current pin keeps its version
    as the previous pin unless ``keep_previous`` is false; ``previous``
    replaces the automatic choice. Call it only after the consumer verified
    that it runs ``version``. Returns the planning probe's output.
    """

    options = ["--absent"] if version is None else ["--version", version]
    options += (["--previous", previous] if previous else []) + ([] if keep_previous else ["--no-keep-previous"])
    command = _command("pin", name, install_root or f"/opt/{name}", "--consumer", consumer, *options)
    return _gated(f"Pin {name} for {consumer}", command)


def prune_releases(
    name: str,
    *,
    install_root: str = "",
    keep_versions: int = 3,
    protect: Iterable[str] = (),
    live_state_unknown: bool = False,
    after: Iterable[OperationMeta | Install] = (),
) -> str:
    """Remove the version directories of ``name`` that nobody keeps (the role's ``tasks_from: prune``).

    Kept: the ``keep_versions`` newest by mtime, every version a pin names
    (current and ``.previous`` pins of every consumer) and every ``protect``
    entry (versions, or executable paths as ``readlink /proc/<pid>/exe``
    prints them). Deletes nothing, with a warning, when ``live_state_unknown``
    is set or a pin or ``protect`` entry cannot be interpreted; is skipped when
    an ``Install`` in ``after`` failed in this run. An operation in ``after``
    that changed makes it run again even if the planning probe found nothing.
    Returns the planning probe's output.
    """

    options: list[object] = ["--keep-versions", keep_versions]
    for entry in protect:
        options += ["--protect", entry]
    options += ["--live-state-unknown"] if live_state_unknown else []
    command = _command("prune", name, install_root or f"/opt/{name}", *options)
    return _gated(f"Prune old {name} versions", command, list(after))


__all__ = ["HOST_SCRIPT", "Install", "install_release", "pin_release", "prune_releases"]
