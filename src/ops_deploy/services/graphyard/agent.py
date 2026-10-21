"""The graphyard agent: the Python ``manage.py start_agent`` or the Rust ``graphyard-agent``.

Port of graphyard_deploy's ``agent_rust.yml`` and ``agent_verify.yml``
(ops-library ``08faab6a``; the contract is section 8.3 of graphyard's
``agent-rs/PLAN.md``). A pinned release is installed below
``agent_rust_install_root`` with either implementation; ``agent_impl``
decides whether the drop-in ``agent-impl.conf`` points ``graphyard-agent``
at it. The host-side steps are ``files/agent.sh``.

Ported from :mod:`ops_deploy.services.nyxmon.agent` rather than shared with
it: nyxmon's live deploy stays untouched during the Rust-port campaign, and a
shared helper is a later decision.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from io import StringIO
from pathlib import Path
from typing import TYPE_CHECKING

from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, FileContents
from pyinfra.operations import files, server

from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.services.graphyard._common import render_role

if TYPE_CHECKING:
    from ops_deploy.services.graphyard.core import GraphyardConfig

AGENT_SCRIPT = (Path(__file__).parent / "files" / "agent.sh").read_text()
# The role's drop-in that selects the Rust agent (graphyard_agent_impl: rust).
AGENT_DROPIN = "agent-impl.conf"
# The role's graphyard_agent_rust_release_url, with {version} for the version.
RELEASE_URL = (
    "https://github.com/ephes/graphyard/releases/download/agent-rs-v{version}/"
    "graphyard-agent-{version}-x86_64-unknown-linux-gnu.tar.gz"
)


def _agent(command: str, *args: object) -> str:
    return shlex.join(["bash", "-c", AGENT_SCRIPT, "graphyard-agent", command, *(str(a) for a in args)])


def dropin_dir(cfg: GraphyardConfig) -> str:
    return f"/etc/systemd/system/{cfg.agent_service_name}.service.d"


def render_dropin(cfg: GraphyardConfig) -> str:
    """The role's ``agent-impl.conf.j2``, shipped unchanged."""

    return render_role(
        "agent-impl.conf.j2",
        {"graphyard_agent_rust_binary": cfg.agent_rust_binary, "graphyard_django_path": str(cfg.django_path)},
    )


def _archive_sha256(cfg: GraphyardConfig) -> str:
    """The checksum the installed version must carry; a local archive must match the pinned one."""

    if cfg.agent_rust_local_archive is None:
        return cfg.agent_rust_sha256
    actual = hashlib.sha256(cfg.agent_rust_local_archive.read_bytes()).hexdigest()
    if cfg.agent_rust_sha256 and actual != cfg.agent_rust_sha256:
        raise ValueError(
            f"agent_rust_local_archive {cfg.agent_rust_local_archive} has sha256 {actual}, "
            f"not agent_rust_sha256 {cfg.agent_rust_sha256}"
        )
    return actual


def install_agent(cfg: GraphyardConfig) -> OperationMeta | None:
    """Install and validate the pinned release (after the migrations: ``--check-schema``).

    Returns the install operation, or ``None`` when the version was installed
    already (it is validated read-only then) or none is pinned.
    """

    if not cfg.agent_rust_version:
        return None
    root, version = cfg.agent_rust_install_root, cfg.agent_rust_version
    sha256 = _archive_sha256(cfg)
    db = cfg.db_path
    files.directory(name="Create the Rust agent install root", path=root, user="root", group="root", mode="0755")
    files.directory(name="Remove a staged Rust agent leftover", path=f"{root}/.staging", present=False)
    if host.get_fact(Directory, path=f"{root}/{version}") is not None:
        # An installed version is never modified: the same version must come from the same archive.
        installed = "\n".join(host.get_fact(FileContents, path=f"{root}/{version}/.archive-sha256") or []).strip()
        if installed != sha256:
            raise ValueError(
                f"{root}/{version} is installed from an archive with sha256 {installed or 'unknown'}, "
                f"but this deploy pins {sha256}. An installed version is never replaced in place. Pin the "
                "matching archive, or remove the directory by hand when it is not the active version."
            )
        mark_read_only(
            server.shell(
                name=f"Validate graphyard-agent {version}",
                commands=[_agent("validate", root, version, cfg.user, db)],
            )
        )
        return None
    upload = ""
    if cfg.agent_rust_local_archive is not None:
        upload = f"{root}/.upload.tar.gz"
        files.put(
            name=f"Upload the graphyard-agent {version} archive",
            src=str(cfg.agent_rust_local_archive),
            dest=upload,
            user="root",
            group="root",
            mode="0600",
        )
    return server.shell(
        name=f"Install graphyard-agent {version}",
        commands=[_agent("install", root, version, sha256, cfg.agent_rust_url, cfg.user, db, upload)],
    )


def select_agent(cfg: GraphyardConfig) -> OperationMeta:
    """Write (rust) or remove (python) the drop-in; remember the Rust version it selected so far."""

    root, directory = cfg.agent_rust_install_root, dropin_dir(cfg)
    dropin = f"{directory}/{AGENT_DROPIN}"
    before = "\n".join(host.get_fact(FileContents, path=dropin) or [])
    match = re.search(rf"(?m)^ExecStart={re.escape(root)}/([^/ ]+)/graphyard-agent( |$)", before)
    active = match.group(1) if match else ""
    if cfg.agent_impl == "rust":
        files.directory(name=f"Create {directory}", path=directory, user="root", group="root", mode="0755")
        selected = files.put(
            name=f"Select the Rust agent for {cfg.agent_service_name}",
            src=StringIO(render_dropin(cfg)),
            dest=dropin,
            user="root",
            group="root",
            mode="0644",
        )
    else:
        name = f"Select the Python agent for {cfg.agent_service_name}"
        selected = files.file(name=name, path=dropin, present=False)
    # Kept by the pruning as the rollback target; written only when the selection moves away from it.
    target = cfg.agent_rust_version if cfg.agent_impl == "rust" else ""
    if active and active != target and bool(host.get_fact(Directory, path=f"{root}/{active}")):
        files.put(
            name="Remember the previously selected Rust agent",
            src=StringIO(f"{active}\n"),
            dest=f"{root}/.previous-version",
            user="root",
            group="root",
            mode="0644",
        )
    return selected


def check_agent(cfg: GraphyardConfig) -> OperationMeta:
    """The agent unit runs the selected agent (the role's agent_verify.yml, 10 tries 3 s apart)."""

    unit = shlex.quote(cfg.agent_service_name)
    if cfg.agent_impl == "rust":
        expected = cfg.agent_rust_binary
        runs = f'[ "$(readlink "/proc/$pid/exe")" = {shlex.quote(expected)} ]'
    else:
        # The uv venv interpreter is a symlink to a uv-managed Python outside the
        # venv, so the Python agent is identified by its argv (the base unit's
        # ExecStart), a Rust agent by /proc/<pid>/exe.
        argv = (f"{cfg.venv_bin}/python", "manage.py", "start_agent")
        expected = " ".join(argv)
        greps = "; ".join(f'printf "%s\\n" "$args" | grep -qxF -- {shlex.quote(arg)} || exit 1' for arg in argv)
        runs = (
            f'case "$(readlink "/proc/$pid/exe")" in {shlex.quote(cfg.agent_rust_install_root + "/")}*) exit 1;; esac; '
            f"args=$(tr '\\0' '\\n' < \"/proc/$pid/cmdline\"); {greps}"
        )
    live = (
        f'[ "$(systemctl is-active {unit})" = active ] || exit 1; '
        f"pid=$(systemctl show --property=MainPID --value {unit}); "
        f'[ "${{pid:-0}}" -gt 0 ] || exit 1; {runs}'
    )
    script = (
        f"for i in $(seq 1 10); do ( {live} ) && exit 0; sleep 3; done; "
        f"echo {shlex.quote(f'{cfg.agent_service_name} does not run {expected} (agent_impl {cfg.agent_impl})')} >&2; "
        "exit 1"
    )
    impl = "Rust" if cfg.agent_impl == "rust" else "Python"
    return mark_read_only(
        server.shell(
            name=f"Check {cfg.agent_service_name} runs the {impl} agent", commands=[f"sh -c {shlex.quote(script)}"]
        )
    )


def prune_agents(cfg: GraphyardConfig, changes: list[OperationMeta | None]) -> None:
    """Remove old versions, after :func:`check_agent` (the role prunes only after the live check).

    Planned from the host as it is; an install or a switch in this run can
    change what goes, so either reruns the pruning.
    """

    if not cfg.agent_rust_version:
        return
    args = (cfg.agent_rust_install_root, cfg.agent_rust_version, cfg.agent_service_name, cfg.agent_rust_keep_versions)
    check = _agent("prune", *args, "--dry-run")
    pending = probe(check, name="Rust agent versions to prune")
    server.shell(
        name="Prune old Rust agent versions",
        commands=[_agent("prune", *args)],
        _if=lambda: pending is None or bool(pending.strip()) or any(op.did_change() for op in changes if op),
    )
    if pending is None:
        verify_probe(check, name="Rust agent versions to prune")


__all__ = [
    "AGENT_DROPIN",
    "RELEASE_URL",
    "check_agent",
    "dropin_dir",
    "install_agent",
    "prune_agents",
    "render_dropin",
    "select_agent",
]
