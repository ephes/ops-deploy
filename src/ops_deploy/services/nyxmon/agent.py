"""The monitoring agent: the pinned Rust ``nyxmon-agent`` release.

Port of the role's ``agent_rust.yml`` and ``agent_verify.yml`` (ops-library
2.75.0). The pinned release is installed below ``agent_rust_install_root`` and
``nyxmon-monitor.service`` starts it directly. The Python agent fallback (the
role's ``nyxmon_agent_impl`` and the ``agent-impl.conf`` drop-in that pointed
the unit's Python ``ExecStart`` at the Rust agent) is retired; a host deployed
before keeps that drop-in until :func:`retire_dropin` removes it. The
host-side steps are ``files/agent.sh``.
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
from pyinfra.facts.files import Directory, File, FileContents
from pyinfra.operations import files, server

from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe

if TYPE_CHECKING:
    from ops_deploy.services.nyxmon.deploy import NyxmonConfig

AGENT_SCRIPT = (Path(__file__).parent / "files" / "agent.sh").read_text()
# The drop-in older deploys used to select the Rust agent over the Python
# ExecStart (ops-library < 2.75.0); removed by its fixed name only.
AGENT_DROPIN = "agent-impl.conf"


def _agent(command: str, *args: object) -> str:
    return shlex.join(["bash", "-c", AGENT_SCRIPT, "nyxmon-agent", command, *(str(a) for a in args)])


def _archive_sha256(cfg: NyxmonConfig) -> str:
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


def install_agent(cfg: NyxmonConfig) -> OperationMeta | None:
    """Install and validate the pinned release (after the migrations: ``--check-schema``).

    Returns the install operation, or ``None`` when the version was installed
    already (it is validated read-only then).
    """

    if not cfg.agent_rust_version:
        raise ValueError("nyxmon-monitor runs the Rust agent: pin agent_rust_version (and agent_rust_sha256)")
    root, version = cfg.agent_rust_install_root, cfg.agent_rust_version
    sha256 = _archive_sha256(cfg)
    db = cfg.site_path / "db.sqlite3"
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
                name=f"Validate nyxmon-agent {version}",
                commands=[_agent("validate", root, version, cfg.user, db)],
            )
        )
        return None
    upload = ""
    if cfg.agent_rust_local_archive is not None:
        upload = f"{root}/.upload.tar.gz"
        files.put(
            name=f"Upload the nyxmon-agent {version} archive",
            src=str(cfg.agent_rust_local_archive),
            dest=upload,
            user="root",
            group="root",
            mode="0600",
        )
    return server.shell(
        name=f"Install nyxmon-agent {version}",
        commands=[_agent("install", root, version, sha256, cfg.agent_rust_url, cfg.user, db, upload)],
    )


def retire_dropin(cfg: NyxmonConfig, unit_path: str, dropin_dir: str) -> OperationMeta:
    """Remember the Rust version the unit ran so far, then remove the retired drop-in.

    The version comes from the unit's ``ExecStart``, or from the old drop-in
    while it exists (it overrode the unit). Only ``<dropin_dir>/agent-impl.conf``
    is removed; anything there but a regular file stops the deploy.
    """

    root, dropin = cfg.agent_rust_install_root, f"{dropin_dir}/{AGENT_DROPIN}"
    # The type first: reading anything but a regular file (a FIFO blocks ``cat``) is never attempted.
    present = host.get_fact(File, path=dropin)
    if present is False:
        raise ValueError(f"{dropin} exists but is not a regular file; it is left alone. Inspect and remove it by hand.")
    pattern = rf"(?m)^ExecStart={re.escape(root)}/([^/ ]+)/nyxmon-agent( |$)"
    active = ""
    for path in ([dropin] if present else []) + [unit_path]:
        match = re.search(pattern, "\n".join(host.get_fact(FileContents, path=path) or []))
        if match:
            active = match.group(1)
            break
    # Kept by the pruning as the rollback target; written only when the pin moves away from it.
    if active and active != cfg.agent_rust_version and bool(host.get_fact(Directory, path=f"{root}/{active}")):
        files.put(
            name="Remember the previously selected Rust agent",
            src=StringIO(f"{active}\n"),
            dest=f"{root}/.previous-version",
            user="root",
            group="root",
            mode="0644",
        )
    return files.file(
        name=f"Remove the retired agent drop-in of {cfg.monitor_service_name}", path=dropin, present=False
    )


def check_agent(cfg: NyxmonConfig) -> OperationMeta:
    """The monitor runs the pinned Rust agent (the role's agent_verify.yml, 10 tries 3 s apart)."""

    unit = shlex.quote(cfg.monitor_service_name)
    expected = cfg.agent_rust_binary
    runs = f'[ "$(readlink "/proc/$pid/exe")" = {shlex.quote(expected)} ]'
    live = (
        f'[ "$(systemctl is-active {unit})" = active ] || exit 1; '
        f"pid=$(systemctl show --property=MainPID --value {unit}); "
        f'[ "${{pid:-0}}" -gt 0 ] || exit 1; {runs}'
    )
    script = (
        f"for i in $(seq 1 10); do ( {live} ) && exit 0; sleep 3; done; "
        f'echo "{cfg.monitor_service_name} does not run {expected}" >&2; exit 1'
    )
    return mark_read_only(
        server.shell(
            name=f"Check {cfg.monitor_service_name} runs the Rust agent", commands=[f"sh -c {shlex.quote(script)}"]
        )
    )


def prune_agents(cfg: NyxmonConfig, changes: list[OperationMeta | None]) -> None:
    """Remove old versions, after :func:`check_agent` (the role prunes only after the live check).

    Planned from the host as it is; an install or a switch in this run can
    change what goes, so either reruns the pruning.
    """

    args = (cfg.agent_rust_install_root, cfg.agent_rust_version, cfg.monitor_service_name, cfg.agent_rust_keep_versions)
    check = _agent("prune", *args, "--dry-run")
    pending = probe(check, name="Rust agent versions to prune")
    server.shell(
        name="Prune old Rust agent versions",
        commands=[_agent("prune", *args)],
        _if=lambda: pending is None or bool(pending.strip()) or any(op.did_change() for op in changes if op),
    )
    if pending is None:
        verify_probe(check, name="Rust agent versions to prune")


__all__ = ["AGENT_DROPIN", "check_agent", "install_agent", "prune_agents", "retire_dropin"]
