"""Pieces shared by the base deploys: a strict config base and host probes."""

from __future__ import annotations

import shlex
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field
from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.facts.server import Command, Os, Which
from pyinfra.operations import apt

# A sha256 digest as published next to a release archive.
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
# Something safe to put on a command line unquoted-looking (it is still quoted).
Version = Annotated[str, Field(pattern=r"^[0-9]+(\.[0-9]+)*$")]
AbsolutePath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/+-]*$")]


class RoleConfig(BaseModel):
    """Base for the host-level deploys: unknown keys fail, instances are frozen.

    These configs carry no secrets (public keys at most), so they do not need
    the placeholder and secret handling of
    :class:`~ops_deploy.core.config.BaseServiceConfig`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)


def output(command: str) -> str:
    """Stdout of ``command`` (a fact gathered while planning); empty when it fails."""

    return host.get_fact(Command, command=f"{command} 2>/dev/null || true") or ""


def require_linux(what: str) -> None:
    if host.get_fact(Os) != "Linux":
        raise DeployError(f"{what} supports Linux hosts only")


def require_systemd(what: str) -> None:
    # Like Ansible's ``ansible_service_mgr == "systemd"``: PID 1 is systemd.
    if output("cat /proc/1/comm") != "systemd":
        raise DeployError(f"{what} requires a systemd-managed host")


def ensure_curl(what: str) -> None:
    """The release downloads use ``curl``; install it with apt when missing."""

    if host.get_fact(Which, command="curl"):
        return
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError(f"{what} needs curl on the host")
    apt.packages(name="Install curl", packages=["curl"], update=True, cache_time=3600)


def release_install_script(
    *,
    url: str,
    sha256: str,
    binaries: dict[str, str],
    install_dir: str,
    owner: str = "root",
    group: str = "root",
) -> str:
    """``sh`` script that downloads ``url``, checks ``sha256``, unpacks and installs.

    ``binaries`` maps a path inside the archive to the installed name. The
    archive lives in a private ``mktemp -d`` directory that is removed on exit;
    nothing is installed unless the checksum matches. Each binary is staged
    next to its destination and renamed over it, so a running binary, a
    symlink in its place or an interrupted copy never leaves a broken file.
    """

    installs = ""
    for src, name in binaries.items():
        dest = shlex.quote(f"{install_dir}/{name}")
        staged = shlex.quote(f"{install_dir}/.{name}.ops-deploy-new")
        installs += (
            f' && install -o {shlex.quote(owner)} -g {shlex.quote(group)} -m 0755 "$tmp"/{shlex.quote(src)} {staged}'
            f" && mv -f {staged} {dest}"
        )
    return (
        "set -e; tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT; "
        f'curl -fsSL --max-time 120 -o "$tmp/release.tar.gz" {shlex.quote(url)}; '
        f"echo {shlex.quote(sha256)}'  '\"$tmp/release.tar.gz\" | sha256sum -c --quiet -; "
        f'tar -xzf "$tmp/release.tar.gz" -C "$tmp"{installs}'
    )
