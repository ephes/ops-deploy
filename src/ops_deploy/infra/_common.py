"""Shared by the infra deploys: apt repositories as ``deb822_repository`` writes them, directories."""

from __future__ import annotations

import shlex
from io import StringIO
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import File
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import output


def codename() -> str:
    """The host's release codename (Ansible's ``ansible_distribution_release``)."""

    return output('. /etc/os-release && echo "${VERSION_CODENAME:-$UBUNTU_CODENAME}"').strip()


def deb822_sources(
    *,
    name: str,
    uris: str,
    suites: tuple[str, ...],
    components: tuple[str, ...],
    signed_by: str,
    architectures: tuple[str, ...] = (),
) -> str:
    """The ``.sources`` text ``deb822_repository`` writes for these arguments.

    It writes one field per argument in sorted argument order (``name`` becomes
    ``X-Repolib-Name``), so equal arguments give byte-identical files and
    switching between the tools rewrites nothing.
    """

    fields = (
        *((("Architectures", " ".join(architectures)),) if architectures else ()),
        ("Components", " ".join(components)),
        ("Enabled", "yes"),
        ("X-Repolib-Name", name),
        ("Signed-By", signed_by),
        ("Suites", " ".join(suites)),
        ("Types", "deb"),
        ("URIs", uris),
    )
    return "".join(f"{key}: {value}\n" for key, value in fields)


def sources_path(name: str) -> str:
    # deb822_repository derives the file name from ``name`` the same way for
    # the plain names used here (lowercase letters, digits and dashes).
    return f"/etc/apt/sources.list.d/{name}.sources"


# First byte of a binary OpenPGP public-key packet: old format with a one-,
# two- or four-byte length (0x98, 0x99, 0x9a) or new format (0xc6).
_KEY_PACKET_TAGS = ("98", "99", "9a", "c6")


def keyring_state_command(keyring: str) -> str:
    """Shell test that prints one word for ``keyring``: ``missing``, ``armored``, ``binary`` or ``other``.

    The decision is made on the host and only that word comes back: a binary
    keyring's bytes (a packet tag such as 0x99) are not UTF-8, and pyinfra
    cannot decode them as a fact's output.
    """

    path = shlex.quote(keyring)
    tags = "|".join(_KEY_PACKET_TAGS)
    return (
        f"if [ ! -s {path} ]; then echo missing; "
        f"elif head -c 5 {path} | grep -q -- -----; then echo armored; "
        f"else case $(od -An -tx1 -N1 {path} | tr -d ' ') in {tags}) echo binary;; *) echo other;; esac; fi"
    )


def keyring_state(keyring: str) -> str:
    """:func:`keyring_state_command` as a fact; ``missing`` when the test itself fails."""

    return output(keyring_state_command(keyring)).strip() or "missing"


def apt_repository(
    *,
    name: str,
    key_url: str,
    keyring: str,
    uris: str,
    suites: tuple[str, ...],
    components: tuple[str, ...],
    dearmor: bool = False,
    architectures: tuple[str, ...] = (),
) -> OperationMeta:
    """Signing key (downloaded once, like ``get_url`` without a checksum) and sources file.

    ``dearmor``: the URL serves an ASCII-armored key but ``keyring`` ends in
    ``.gpg``, which apt reads as binary; the key is converted with ``gpg
    --dearmor``, also when an armored copy is already there (the role stores
    it as served, which apt then ignores). Whether the keyring is already
    binary is decided on the host (:func:`keyring_state`); its bytes are never
    read back.
    """

    files.directory(
        name=f"Ensure {PurePosixPath(keyring).parent}", path=str(PurePosixPath(keyring).parent), mode="0755"
    )
    if not dearmor:
        files.download(name=f"Install {name} apt signing key", src=key_url, dest=keyring, mode="0644")
    elif (state := keyring_state(keyring)) != "binary":
        # Missing or empty, armored (what the role and earlier runs stored) or
        # not a key at all: convert. Refresh the cache only while the
        # repository is not configured yet: with its key missing or armored, a
        # refresh fails before the repair.
        configured = state != "missing" or bool(host.get_fact(File, path=sources_path(name)))
        apt.packages(name="Install curl and gnupg", packages=["curl", "gnupg"], update=not configured, cache_time=3600)
        tmp = shlex.quote(f"{keyring}.ops-deploy-new")
        server.shell(
            name=f"Install {name} apt signing key",
            commands=[
                f"curl -fsSL --max-time 120 {shlex.quote(key_url)} | gpg --dearmor --yes -o {tmp} "
                f"&& chmod 0644 {tmp} && mv -f {tmp} {shlex.quote(keyring)}"
            ],
        )
    content = deb822_sources(
        name=name, uris=uris, suites=suites, components=components, signed_by=keyring, architectures=architectures
    )
    return files.put(
        name=f"Configure {name} apt repository",
        src=StringIO(content),
        dest=sources_path(name),
        user="root",
        group="root",
        mode="0644",
    )


def directory(path: str, *, user: str, group: str, mode: str) -> OperationMeta:
    """``files.directory`` that also clears setuid/setgid/sticky bits, as Ansible's ``file`` does.

    Packages create some directories setgid (``/etc/redis``); ``chmod 755``
    keeps that bit on a directory, so pyinfra alone would report a change on
    every run. A directory missing while planning may be created setgid by a
    package installed earlier in the same run, so it is cleared then too.
    """

    current = output(f"stat -c %a {shlex.quote(path)}").strip()
    meta = files.directory(name=f"Ensure {path}", path=path, user=user, group=group, mode=mode)
    if len(current) != 3:
        server.shell(name=f"Clear special mode bits on {path}", commands=[f"chmod u-s,g-s,o-t {shlex.quote(path)}"])
    return meta
