"""The pinned S3 client ``mc`` (MinIO Client) at ``/usr/local/bin/mc``.

Echoport's cleanup job, its upload checks and the backup runners talk to the
object store (RustFS) through ``mc`` aliases, so the deploys that configure
those aliases install the client themselves (:func:`install_mc`): the Echoport
deploy and the Echoport runner registrations. The release is pinned by
version and sha256; the download is verified before it replaces the file.
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Sha256File
from pyinfra.operations import files, server

MC_VERSION = "RELEASE.2025-08-13T08-35-41Z"
MC_SHA256 = "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
MC_DOWNLOAD_URL = f"https://github.com/minio/mc/releases/download/{MC_VERSION}/mc.linux-amd64.{MC_VERSION}"
MC_PATH = "/usr/local/bin/mc"


def binary_install_command(path: str, checksum: str, url: str) -> str:
    """Download ``url`` into a private temporary directory next to ``path``, verify it, then replace ``path``."""

    parent = shlex.quote(str(PurePosixPath(path).parent / ".minio-artifact.XXXXXX"))
    script = (
        f"set -eu; umask 077; tmp=$(mktemp -d {parent}); "
        "trap 'rm -rf \"$tmp\"' EXIT; "
        f'curl -fsSL --max-time 120 -o "$tmp/download" {shlex.quote(url)}; '
        f"printf '%s  %s\\n' {shlex.quote(checksum)} \"$tmp/download\" | sha256sum -c --status -; "
        'install -o root -g root -m 0755 "$tmp/download" "$tmp/binary"; '
        f'mv -f "$tmp/binary" {shlex.quote(path)}'
    )
    return shlex.join(["sh", "-c", script])


def pinned_binary(path: str, checksum: str, url: str, title: str) -> OperationMeta:
    """A root-owned 0755 executable at ``path`` with ``checksum``.

    A file that already has the checksum is kept (only owner and mode are
    enforced, so a converged host sees no change); otherwise ``url`` is
    downloaded and verified on the host before it replaces the file.
    """

    if host.get_fact(Sha256File, path=path) == checksum:
        return files.file(name=f"Preserve pinned {title} executable", path=path, user="root", group="root", mode="0755")
    return server.shell(name=f"Download pinned {title}", commands=[binary_install_command(path, checksum, url)])


def install_mc(path: str = MC_PATH) -> OperationMeta:
    """The pinned ``mc`` (linux-amd64) at ``path``, root-owned 0755; no change when it already has the checksum."""

    return pinned_binary(path, MC_SHA256, MC_DOWNLOAD_URL, "MinIO client")


__all__ = [
    "MC_DOWNLOAD_URL",
    "MC_PATH",
    "MC_SHA256",
    "MC_VERSION",
    "binary_install_command",
    "install_mc",
    "pinned_binary",
]
