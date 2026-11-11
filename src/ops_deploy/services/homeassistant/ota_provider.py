"""chip-ota-provider-app for Matter device firmware updates.

python-matter-server starts ``chip-ota-provider-app`` without a path, from the
``matter-server`` unit's PATH, when Home Assistant installs a device firmware
update. The official container image ships it; a native install does not, so
updates fail with ``FileNotFoundError``. This installs the pinned release of
``home-assistant-libs/matter-linux-ota-provider`` (root:root 0755).

The download lands in a private temporary directory and is installed only when
its sha256 matches the pinned checksum for the host's architecture; it is
staged next to the destination and renamed over it. An installed file with the
pinned checksum is kept, so a repeat run downloads nothing. The Matter server
is not restarted: it starts the program per update.
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File, Link, Sha256File
from pyinfra.facts.server import Arch
from pyinfra.operations import files, server

from ops_deploy.base._common import ensure_curl

from .ota_provider_config import OTA_ARCHES, ota_provider_url
from .runtime_config import HomeAssistantRuntimeConfig


def install_script(url: str, sha256: str, dest: str) -> str:
    parent = str(PurePosixPath(dest).parent)
    staged = shlex.quote(f"{parent}/.{PurePosixPath(dest).name}.ops-deploy-new")
    return (
        "set -e; tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT; "
        f'curl -fsSL --max-time 300 -o "$tmp/download" {shlex.quote(url)}; '
        f"echo {shlex.quote(sha256)}'  '\"$tmp/download\" | sha256sum -c --quiet -; "
        f'install -o root -g root -m 0755 "$tmp/download" {staged}; '
        # -T: a directory or a symlink to one at dest is replaced, not entered.
        f"mv -fT {staged} {shlex.quote(dest)}"
    )


def install_ota_provider(cfg: HomeAssistantRuntimeConfig) -> OperationMeta:
    """Register the install (only called when the Matter server is managed)."""

    machine = host.get_fact(Arch) or ""
    arch = OTA_ARCHES.get(machine)
    if arch is None or arch not in cfg.matter_server_ota_provider_checksums:
        raise DeployError(f"chip-ota-provider-app: no pinned checksum for architecture {machine or 'unknown'}")
    sha256 = cfg.matter_server_ota_provider_checksums[arch]
    dest = cfg.matter_server_ota_provider_path
    version = cfg.matter_server_ota_provider_version
    is_link = bool(host.get_fact(Link, path=dest))
    info = None if is_link else host.get_fact(File, path=dest)
    if info is False:
        raise DeployError(f"chip-ota-provider-app: {dest} exists and is not a file")
    current = bool(info) and host.get_fact(Sha256File, path=dest) == sha256
    if current:
        # The pinned file is there: only owner and mode are reconciled.
        return files.file(
            name=f"Ensure chip-ota-provider-app {version} owner and mode",
            path=dest,
            user="root",
            group="root",
            mode="0755",
        )
    ensure_curl("chip-ota-provider-app")
    files.directory(name=f"Ensure {PurePosixPath(dest).parent}", path=str(PurePosixPath(dest).parent), mode="0755")
    url = ota_provider_url(cfg.matter_server_ota_provider_url_template, version, arch)
    return server.shell(
        name=f"Install chip-ota-provider-app {version} to {dest}",
        commands=[install_script(url, sha256, dest)],
    )
