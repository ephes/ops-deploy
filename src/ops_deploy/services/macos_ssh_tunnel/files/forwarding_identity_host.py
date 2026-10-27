#!/usr/bin/env python3
"""Manage one forwarding identity through no-follow directory descriptors."""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import errno
import grp
import hashlib
import json
import os
import pwd
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any


class IdentityError(RuntimeError):
    """The configured identity path or existing identity is unsafe."""


def _inspection_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_NONBLOCK
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _rename_exclusive_at(parent_fd: int, source: str, destination: str) -> None:
    """Descriptor-relative no-replace rename on Linux or macOS."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        renameatx_np = libc.renameatx_np
        renameatx_np.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameatx_np.restype = ctypes.c_int
        result = renameatx_np(
            parent_fd,
            os.fsencode(source),
            parent_fd,
            os.fsencode(destination),
            0x00000004,
        )
    elif sys.platform.startswith("linux"):
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise IdentityError("exclusive identity rename is unavailable")
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(
            parent_fd,
            os.fsencode(source),
            parent_fd,
            os.fsencode(destination),
            1,
        )
    else:
        raise IdentityError("exclusive identity rename is unsupported")
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), destination)
    raise OSError(error_number, os.strerror(error_number), destination)


def _parts(value: str, label: str) -> tuple[str, ...]:
    if not value.startswith("/") or os.path.normpath(value) != value.rstrip("/"):
        raise IdentityError(f"identity {label} must be absolute and normalized")
    parts = tuple(part for part in value.split("/") if part)
    if any(part in {".", ".."} for part in parts):
        raise IdentityError(f"identity {label} contains traversal")
    return parts


def _open_directory(parent_fd: int, name: str) -> int:
    flags = _inspection_flags() | getattr(os, "O_DIRECTORY", 0)
    return os.open(name, flags, dir_fd=parent_fd)


def open_parent(
    home_text: str,
    identity_text: str,
    *,
    uid: int,
    gid: int,
    create: bool,
    allow_missing: bool = False,
) -> tuple[int, list[str], bool]:
    """Open every component from / without following links, creating only below home."""
    home_parts = _parts(home_text, "home")
    identity_parts = _parts(identity_text, "path")
    if (
        len(identity_parts) <= len(home_parts)
        or identity_parts[: len(home_parts)] != home_parts
    ):
        raise IdentityError("identity path escapes configured home")
    parent_parts = identity_parts[:-1]
    descriptor = os.open("/", _inspection_flags() | getattr(os, "O_DIRECTORY", 0))
    inspected = ["/"]
    changed = False
    try:
        for index, component in enumerate(parent_parts):
            try:
                child = _open_directory(descriptor, component)
            except FileNotFoundError:
                if not create:
                    if allow_missing and index >= len(home_parts) - 1:
                        os.close(descriptor)
                        return -1, inspected, False
                    raise IdentityError(
                        f"identity ancestor does not exist: /{'/'.join(parent_parts[: index + 1])}"
                    ) from None
                if index < len(home_parts):
                    raise IdentityError(
                        f"identity ancestor does not exist: /{'/'.join(parent_parts[: index + 1])}"
                    ) from None
                os.mkdir(component, 0o700, dir_fd=descriptor)
                changed = True
                child = _open_directory(descriptor, component)
                if os.geteuid() == 0:
                    os.fchown(child, uid, gid)
            except OSError as exc:
                raise IdentityError(
                    f"identity hierarchy component is not a no-follow directory: "
                    f"/{'/'.join(parent_parts[: index + 1])}"
                ) from exc
            os.close(descriptor)
            descriptor = child
            inspected.append("/" + "/".join(parent_parts[: index + 1]))
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise IdentityError("identity parent is not a directory")
        if create:
            if os.geteuid() == 0 and (info.st_uid != uid or info.st_gid != gid):
                os.fchown(descriptor, uid, gid)
                changed = True
            elif os.geteuid() != 0 and (info.st_uid != uid or info.st_gid != gid):
                raise IdentityError(
                    "identity parent is not owned by the configured user/group"
                )
            if stat.S_IMODE(info.st_mode) != 0o700:
                os.fchmod(descriptor, 0o700)
                changed = True
        return descriptor, inspected, changed
    except Exception:
        os.close(descriptor)
        raise


def _write_all(descriptor: int, payload: bytes, label: str) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = os.write(descriptor, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise IdentityError(f"{label} write made no progress")
        view = view[written:]


def _read_fd(descriptor: int, limit: int = 256 * 1024) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) <= limit:
        try:
            chunk = os.read(descriptor, min(65536, limit + 1 - len(result)))
        except InterruptedError:
            continue
        if not chunk:
            break
        result.extend(chunk)
    if len(result) > limit:
        raise IdentityError("identity file exceeds the size limit")
    return bytes(result)


def _inspection_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@dataclasses.dataclass(frozen=True)
class RegularBinding:
    payload: bytes
    identity: dict[str, int]


@dataclasses.dataclass(frozen=True)
class CreationIntentBinding:
    intent: dict[str, Any]
    regular: RegularBinding


@dataclasses.dataclass(frozen=True)
class CreationReconciliationPlan:
    authority: CreationIntentBinding
    prospective_private: bytes | None


def _read_regular(
    parent_fd: int, name: str, uid: int, expected_mode: int
) -> RegularBinding | None:
    try:
        descriptor = os.open(name, _inspection_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise IdentityError(f"identity entry cannot be opened safely: {name}") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != expected_mode
        ):
            raise IdentityError(
                f"identity file is not an owner-controlled regular file: {name}"
            )
        try:
            pathname = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise IdentityError(
                f"identity file changed before reading: {name}"
            ) from exc
        identity = _inspection_identity(info)
        if _inspection_identity(pathname) != identity:
            raise IdentityError(f"identity file changed before reading: {name}")
        payload = _read_fd(descriptor)
        after = os.fstat(descriptor)
        try:
            pathname = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise IdentityError(f"identity file changed while reading: {name}") from exc
        if (
            _inspection_identity(after) != identity
            or _inspection_identity(pathname) != identity
        ):
            raise IdentityError(f"identity file changed while reading: {name}")
        return RegularBinding(payload, _inode_identity(after))
    finally:
        os.close(descriptor)


def _inode_identity(info: os.stat_result) -> dict[str, int]:
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "mode": info.st_mode,
        "links": info.st_nlink,
        "owner": info.st_uid,
        "group": info.st_gid,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def _identity_matches(
    expected: dict[str, int],
    info: os.stat_result,
    *,
    links: frozenset[int] | set[int] = frozenset({1}),
) -> bool:
    return (
        expected["device"] == info.st_dev
        and expected["inode"] == info.st_ino
        and expected["mode"] == info.st_mode
        and info.st_nlink in links
        and expected["owner"] == info.st_uid
        and expected["group"] == info.st_gid
        and expected["size"] == info.st_size
        and expected["mtime_ns"] == info.st_mtime_ns
        and expected["ctime_ns"] == info.st_ctime_ns
        and stat.S_ISREG(info.st_mode)
    )


def _same_identity_across_rename(
    expected: dict[str, int], info: os.stat_result
) -> bool:
    actual = _inode_identity(info)
    return all(
        expected[key] == actual[key] for key in expected if key != "ctime_ns"
    ) and stat.S_ISREG(info.st_mode)


def _safe_unlink_identity(
    parent_fd: int,
    name: str,
    expected: dict[str, int],
    *,
    links: frozenset[int] | set[int] = frozenset({1}),
    expected_payload: bytes | None = None,
    pinned_descriptor: int | None = None,
    on_retirement_boundary: Callable[[str], None] | None = None,
) -> None:
    descriptor = os.open(name, _inspection_flags(), dir_fd=parent_fd)
    quarantine = f".{name.lstrip('.')}.remove-{uuid.uuid4().hex}.tmp"
    try:
        opened = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _identity_matches(expected, opened, links=links)
            or not _identity_matches(expected, current, links=links)
            or (
                expected_payload is not None
                and _read_fd(descriptor) != expected_payload
            )
            or (
                pinned_descriptor is not None
                and (
                    not _identity_matches(
                        expected, os.fstat(pinned_descriptor), links=links
                    )
                    or _read_fd(pinned_descriptor) != expected_payload
                )
            )
        ):
            raise IdentityError(f"controlled temporary identity changed: {name}")
        try:
            _rename_exclusive_at(parent_fd, name, quarantine)
        except FileExistsError as exc:
            raise IdentityError(
                f"controlled temporary quarantine exists; source preserved: {name}"
            ) from exc

        def require_source_absent(boundary: str) -> None:
            try:
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise IdentityError(
                f"controlled temporary canonical name was recreated {boundary}; "
                f"preserved as {quarantine}: {name}"
            )

        # The open descriptor remains the authority. A rename may change only its
        # ctime; never adopt authority from the quarantine pathname.
        require_source_absent("after quarantine rename")
        if on_retirement_boundary is not None:
            on_retirement_boundary("after quarantine rename")
        pinned = os.fstat(descriptor)
        pinned_identity = _inode_identity(pinned)
        stable_keys = set(expected) - {"ctime_ns"}
        moved = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if (
            any(expected[key] != pinned_identity[key] for key in stable_keys)
            or _inode_identity(moved) != pinned_identity
            or pinned.st_nlink not in links
        ):
            raise IdentityError(
                f"controlled temporary raced during cleanup; preserved as {quarantine}"
            )
        os.fsync(parent_fd)
        require_source_absent("after cleanup fsync")
        if on_retirement_boundary is not None:
            on_retirement_boundary("after cleanup fsync")
        if (
            _inode_identity(os.fstat(descriptor)) != pinned_identity
            or _inode_identity(
                os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
            )
            != pinned_identity
        ):
            raise IdentityError(
                f"controlled temporary changed after cleanup fsync: {quarantine}"
            )
        # Neither supported platform exposes a portable pathname-free unlink for
        # this exact open inode. Preserve the authenticated quarantine.
        os.fsync(parent_fd)
        require_source_absent("after final cleanup fsync")
        if on_retirement_boundary is not None:
            on_retirement_boundary("after final cleanup fsync")
        final_path = os.stat(quarantine, dir_fd=parent_fd, follow_symlinks=False)
        if (
            _inode_identity(os.fstat(descriptor)) != pinned_identity
            or _inode_identity(final_path) != pinned_identity
            or (
                expected_payload is not None
                and _read_fd(descriptor) != expected_payload
            )
            or (
                pinned_descriptor is not None
                and (
                    _inode_identity(os.fstat(pinned_descriptor)) != pinned_identity
                    or _read_fd(pinned_descriptor) != expected_payload
                )
            )
        ):
            raise IdentityError(
                f"controlled temporary changed after cleanup fsync: {quarantine}"
            )
    finally:
        os.close(descriptor)


def _create_verified_temporary(
    parent_fd: int,
    name: str,
    payload: bytes,
    mode: int,
    uid: int,
    gid: int,
    label: str,
) -> tuple[int, dict[str, int]]:
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
    created = os.fstat(descriptor)
    try:
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        _write_all(descriptor, payload, label)
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        pathname = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_nlink != 1
            or info.st_uid != uid
            or info.st_gid != gid
            or info.st_size != len(payload)
            or (info.st_dev, info.st_ino) != (pathname.st_dev, pathname.st_ino)
            or _read_fd(descriptor) != payload
        ):
            raise IdentityError(f"{label} temporary verification failed")
        return descriptor, _inode_identity(info)
    except BaseException:
        failed = os.fstat(descriptor)
        os.close(descriptor)
        if (failed.st_dev, failed.st_ino) != (created.st_dev, created.st_ino):
            raise IdentityError(f"{label} opened inode changed during failure")
        try:
            _safe_unlink_identity(parent_fd, name, _inode_identity(failed))
        except FileNotFoundError:
            pass
        raise


def _exchange_at(parent_fd: int, first: str, second: str) -> None:
    """Atomically exchange two descriptor-relative names on Linux or macOS."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        operation = libc.renameatx_np
        flag = 0x00000002  # RENAME_SWAP
    elif sys.platform.startswith("linux"):
        operation = getattr(libc, "renameat2", None)
        flag = 2  # RENAME_EXCHANGE
    else:
        raise IdentityError("identity-checked exchange is unsupported")
    if operation is None:
        raise IdentityError("identity-checked exchange is unavailable")
    operation.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    operation.restype = ctypes.c_int
    result = operation(
        parent_fd,
        os.fsencode(first),
        parent_fd,
        os.fsencode(second),
        flag,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    raise OSError(error_number, os.strerror(error_number), second)


def _publish_verified_temporary(
    parent_fd: int,
    name: str,
    temporary: str,
    descriptor: int,
    temporary_identity: dict[str, int],
    payload: bytes,
    expected: RegularBinding | None,
    label: str,
) -> RegularBinding:
    """Publish only from exact temporary/canonical inode bindings."""
    pathname = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
    if (
        not _identity_matches(temporary_identity, os.fstat(descriptor))
        or not _identity_matches(temporary_identity, pathname)
        or _read_fd(descriptor) != payload
    ):
        raise IdentityError(f"{label} temporary changed before publication")
    old_fd = -1
    old_temporary_identity: dict[str, int] | None = None
    try:
        if expected is None:
            try:
                _rename_exclusive_at(parent_fd, temporary, name)
            except FileExistsError as exc:
                raise IdentityError(f"{label} canonical path appeared") from exc
        else:
            old_fd = os.open(name, _inspection_flags(), dir_fd=parent_fd)
            opened = os.fstat(old_fd)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                not _identity_matches(expected.identity, opened)
                or not _identity_matches(expected.identity, current)
                or _read_fd(old_fd) != expected.payload
                or not _identity_matches(expected.identity, os.fstat(old_fd))
            ):
                raise IdentityError(f"{label} canonical binding changed before update")
            _exchange_at(parent_fd, temporary, name)
            moved = os.stat(temporary, dir_fd=parent_fd, follow_symlinks=False)
            pinned = os.fstat(old_fd)
            if (
                not _same_identity_across_rename(expected.identity, moved)
                or not _same_identity_across_rename(expected.identity, pinned)
                or (moved.st_dev, moved.st_ino) != (pinned.st_dev, pinned.st_ino)
                or _read_fd(old_fd) != expected.payload
            ):
                _exchange_at(parent_fd, temporary, name)
                os.fsync(parent_fd)
                raise IdentityError(
                    f"{label} canonical substitution raced; both entries preserved"
                )
            old_temporary_identity = _inode_identity(pinned)
        os.fsync(parent_fd)
        published = os.fstat(descriptor)
        canonical = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        published_identity = _inode_identity(published)
        if (
            not _identity_matches(published_identity, canonical)
            or _read_fd(descriptor) != payload
            or not _identity_matches(published_identity, os.fstat(descriptor))
            or not _identity_matches(
                published_identity,
                os.stat(name, dir_fd=parent_fd, follow_symlinks=False),
            )
        ):
            raise IdentityError(f"{label} changed after directory fsync")
        if old_temporary_identity is not None:
            assert expected is not None
            _safe_unlink_identity(
                parent_fd,
                temporary,
                old_temporary_identity,
                links=frozenset({1}),
                expected_payload=expected.payload,
                pinned_descriptor=old_fd,
            )
        # Old-name retirement performs its own final directory fsync. Keep the
        # publication descriptor and exact bytes authoritative through that fsync,
        # then reattest the canonical name before reporting success.
        final_descriptor = os.fstat(descriptor)
        final_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _identity_matches(published_identity, final_descriptor)
            or not _identity_matches(published_identity, final_path)
            or _read_fd(descriptor) != payload
            or not _identity_matches(published_identity, os.fstat(descriptor))
        ):
            raise IdentityError(f"{label} changed during retired-name cleanup")
        return RegularBinding(payload, published_identity)
    finally:
        if old_fd >= 0:
            os.close(old_fd)


def _replace(
    parent_fd: int,
    name: str,
    payload: bytes,
    mode: int,
    uid: int,
    gid: int,
    expected: RegularBinding | None,
) -> RegularBinding:
    temporary = f".{name}.{uuid.uuid4().hex}.tmp"
    descriptor = -1
    identity: dict[str, int] | None = None
    published = False
    result: RegularBinding | None = None
    try:
        descriptor, identity = _create_verified_temporary(
            parent_fd, temporary, payload, mode, uid, gid, "public identity"
        )
        result = _publish_verified_temporary(
            parent_fd,
            name,
            temporary,
            descriptor,
            identity,
            payload,
            expected,
            "public identity",
        )
        published = True
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if identity is not None and not published:
            try:
                _safe_unlink_identity(parent_fd, temporary, identity)
            except FileNotFoundError:
                pass


def _derive(keygen: str, private_bytes: bytes, comment: str) -> tuple[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="forwarding-identity-") as temporary:
        private = Path(temporary) / "identity"
        private.write_bytes(private_bytes)
        private.chmod(0o600)
        completed = subprocess.run(
            [keygen, "-y", "-P", "", "-f", str(private)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            env={"HOME": temporary, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        if completed.returncode != 0:
            raise IdentityError("forwarding identity is not passphrase-free")
        fields = completed.stdout.strip().split()
        if len(fields) < 2 or fields[0] != "ssh-ed25519":
            raise IdentityError("forwarding identity is not Ed25519")
        public_key = " ".join(fields[:2])
        return public_key, f"{public_key} {comment}\n".encode()


def _generate(keygen: str, comment: str) -> bytes:
    with tempfile.TemporaryDirectory(
        prefix="forwarding-identity-generate-"
    ) as temporary:
        private = Path(temporary) / "identity"
        completed = subprocess.run(
            [
                keygen,
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                comment,
                "-f",
                str(private),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            env={"HOME": temporary, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        if completed.returncode != 0:
            raise IdentityError("could not generate forwarding identity")
        return private.read_bytes()


def _intent_name(name: str) -> str:
    return f".{name}.creation.json"


def _read_creation_intent(
    parent_fd: int, name: str, uid: int
) -> CreationIntentBinding | None:
    binding = _read_regular(parent_fd, _intent_name(name), uid, 0o600)
    if binding is None:
        return None
    try:
        intent = json.loads(binding.payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdentityError("forwarding identity creation intent is malformed") from exc
    identity = intent.get("identity") if isinstance(intent, dict) else None
    if (
        not isinstance(intent, dict)
        or set(intent) != {"version", "staging_name", "size", "sha256", "identity"}
        or intent.get("version") != 1
        or not isinstance(intent.get("staging_name"), str)
        or not isinstance(intent.get("size"), int)
        or intent["size"] <= 0
        or not isinstance(intent.get("sha256"), str)
        or len(intent["sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in intent["sha256"])
        or (
            identity is not None
            and (
                not isinstance(identity, dict)
                or set(identity)
                != {
                    "device",
                    "inode",
                    "mode",
                    "links",
                    "owner",
                    "group",
                    "size",
                    "mtime_ns",
                    "ctime_ns",
                }
                or not all(isinstance(value, int) for value in identity.values())
                or identity["links"] != 1
                or identity["owner"] != uid
                or stat.S_IMODE(identity["mode"]) != 0o600
                or not stat.S_ISREG(identity["mode"])
                or identity["size"] != intent["size"]
            )
        )
    ):
        raise IdentityError("forwarding identity creation intent is malformed")
    prefix = f".{name}.creation-"
    staging = intent["staging_name"]
    if (
        not staging.startswith(prefix)
        or not staging.endswith(".tmp")
        or len(staging) != len(prefix) + 32 + 4
        or any(
            character not in "0123456789abcdef"
            for character in staging[len(prefix) : -4]
        )
    ):
        raise IdentityError("forwarding identity staging name is malformed")
    return CreationIntentBinding(intent, binding)


def _write_creation_intent(
    parent_fd: int,
    name: str,
    intent: dict[str, Any],
    uid: int,
    gid: int,
    *,
    create: bool,
    expected: RegularBinding | None = None,
) -> RegularBinding:
    payload = (json.dumps(intent, sort_keys=True) + "\n").encode()
    temporary = f".{name}.intent-{uuid.uuid4().hex}.tmp"
    descriptor = -1
    identity: dict[str, int] | None = None
    published = False
    intent_name = _intent_name(name)
    if create and expected is not None:
        raise IdentityError("initial creation intent unexpectedly has prior authority")
    if not create and expected is None:
        raise IdentityError("creation intent update lacks exact prior authority")
    result: RegularBinding | None = None
    try:
        descriptor, identity = _create_verified_temporary(
            parent_fd, temporary, payload, 0o600, uid, gid, "creation intent"
        )
        result = _publish_verified_temporary(
            parent_fd,
            intent_name,
            temporary,
            descriptor,
            identity,
            payload,
            expected,
            "creation intent",
        )
        published = True
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if identity is not None and not published:
            try:
                _safe_unlink_identity(parent_fd, temporary, identity)
            except FileNotFoundError:
                pass


def _clear_creation_intent(
    parent_fd: int,
    name: str,
    uid: int,
    expected: RegularBinding,
    *,
    staging_name: str | None = None,
    canonical: RegularBinding | None = None,
) -> None:
    intent_name = _intent_name(name)
    descriptor = os.open(intent_name, _inspection_flags(), dir_fd=parent_fd)
    try:
        opened = os.fstat(descriptor)
        pathname = os.stat(intent_name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not _identity_matches(expected.identity, opened)
            or not _identity_matches(expected.identity, pathname)
            or _read_fd(descriptor) != expected.payload
            or not _identity_matches(expected.identity, os.fstat(descriptor))
        ):
            raise IdentityError("forwarding identity creation intent changed")

        def attest_companions(boundary: str) -> None:
            if staging_name is None:
                return
            _attest_creation_companions(
                parent_fd,
                name,
                staging_name,
                uid,
                staging=None,
                canonical=canonical,
                boundary=boundary,
            )

        if staging_name is not None:
            attest_companions("before intent retirement")
        _safe_unlink_identity(
            parent_fd,
            intent_name,
            expected.identity,
            expected_payload=expected.payload,
            pinned_descriptor=descriptor,
            on_retirement_boundary=(
                attest_companions if staging_name is not None else None
            ),
        )
    finally:
        os.close(descriptor)


def _attest_creation_companions(
    parent_fd: int,
    name: str,
    staging_name: str,
    uid: int,
    *,
    staging: RegularBinding | None,
    canonical: RegularBinding | None,
    boundary: str,
) -> None:
    observed_staging = _read_regular(parent_fd, staging_name, uid, 0o600)
    observed_canonical = _read_regular(parent_fd, name, uid, 0o600)
    if observed_staging != staging or observed_canonical != canonical:
        raise IdentityError(
            f"forwarding identity companion state changed {boundary}; preserved"
        )


def _attest_creation_state(
    parent_fd: int,
    name: str,
    uid: int,
    authority: CreationIntentBinding,
    *,
    staging: RegularBinding | None,
    canonical: RegularBinding | None,
    boundary: str,
) -> None:
    current = _read_creation_intent(parent_fd, name, uid)
    if current != authority:
        raise IdentityError(
            f"forwarding identity creation intent changed {boundary}; preserved"
        )
    _attest_creation_companions(
        parent_fd,
        name,
        authority.intent["staging_name"],
        uid,
        staging=staging,
        canonical=canonical,
        boundary=boundary,
    )
    if _read_creation_intent(parent_fd, name, uid) != authority:
        raise IdentityError(
            f"forwarding identity creation intent changed {boundary}; preserved"
        )


def _plan_creation_reconciliation(
    parent_fd: int,
    name: str,
    keygen: str,
    comment: str,
    uid: int,
    authority: CreationIntentBinding | None = None,
) -> CreationReconciliationPlan | None:
    """Inspect recoverable creation state without changing any directory entry."""
    authority = authority or _read_creation_intent(parent_fd, name, uid)
    if authority is None:
        return None
    intent = authority.intent
    staging = intent["staging_name"]
    staging_binding = _read_regular(parent_fd, staging, uid, 0o600)
    canonical_binding = _read_regular(parent_fd, name, uid, 0o600)
    expected = intent["identity"]

    if expected is None:
        if staging_binding is not None or canonical_binding is not None:
            raise IdentityError(
                "ambiguous unbound forwarding identity state; "
                "entry beside intent is preserved"
            )
        _attest_creation_state(
            parent_fd,
            name,
            uid,
            authority,
            staging=None,
            canonical=None,
            boundary="immediately before returning the unbound plan",
        )
        return CreationReconciliationPlan(authority, None)

    staged_payload: bytes | None = None
    if staging_binding is not None:
        if staging_binding.identity != expected:
            raise IdentityError("forwarding identity temporary was replaced")
        staged_payload = staging_binding.payload
        if (
            len(staged_payload) != intent["size"]
            or hashlib.sha256(staged_payload).hexdigest() != intent["sha256"]
        ):
            raise IdentityError("forwarding identity temporary content changed")
        _derive(keygen, staged_payload, comment)

    if canonical_binding is not None:
        canonical_identity = canonical_binding.identity
        if not (
            canonical_identity == expected
            or (
                staging_binding is None
                and all(
                    expected[key] == canonical_identity[key]
                    for key in expected
                    if key != "ctime_ns"
                )
            )
        ):
            raise IdentityError("canonical forwarding identity was replaced")
        if (
            len(canonical_binding.payload) != intent["size"]
            or hashlib.sha256(canonical_binding.payload).hexdigest() != intent["sha256"]
        ):
            raise IdentityError("canonical forwarding identity changed")
        _derive(keygen, canonical_binding.payload, comment)
        if staging_binding is not None:
            raise IdentityError(
                "forwarding identity staging entry unexpectedly remains"
            )
        _attest_creation_state(
            parent_fd,
            name,
            uid,
            authority,
            staging=None,
            canonical=canonical_binding,
            boundary="immediately before returning the canonical plan",
        )
        return CreationReconciliationPlan(authority, canonical_binding.payload)

    if staged_payload is None or staging_binding is None:
        raise IdentityError("bound forwarding identity temporary disappeared")
    _attest_creation_state(
        parent_fd,
        name,
        uid,
        authority,
        staging=staging_binding,
        canonical=None,
        boundary="immediately before returning the staging plan",
    )
    return CreationReconciliationPlan(authority, staged_payload)


def _apply_creation_reconciliation(
    parent_fd: int,
    name: str,
    keygen: str,
    comment: str,
    uid: int,
    authority: CreationIntentBinding,
) -> bytes | None:
    """Mutate only after a complete inspection has produced an exact plan."""
    intent = authority.intent
    intent_binding = authority.regular
    staging = intent["staging_name"]
    try:
        staging_info = os.stat(staging, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        staging_info = None
    try:
        canonical_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        canonical_info = None
    expected = intent["identity"]

    if expected is None:
        if staging_info is not None or canonical_info is not None:
            raise IdentityError(
                "ambiguous unbound forwarding identity state; "
                "entry beside intent is preserved"
            )
        _attest_creation_state(
            parent_fd,
            name,
            uid,
            authority,
            staging=None,
            canonical=None,
            boundary="before applying the unbound creation plan",
        )
        # Present-state creation must carry this exact authority into allocation;
        # it is not retired merely because both companion names are absent.
        return None

    staged_payload: bytes | None = None
    if staging_info is not None:
        if not _identity_matches(expected, staging_info):
            raise IdentityError("forwarding identity temporary was replaced")
        staged_binding = _read_regular(parent_fd, staging, uid, 0o600)
        if staged_binding is None:
            raise IdentityError("forwarding identity temporary disappeared")
        staged_payload = staged_binding.payload
        if (
            len(staged_payload) != intent["size"]
            or hashlib.sha256(staged_payload).hexdigest() != intent["sha256"]
        ):
            raise IdentityError("forwarding identity temporary content changed")
        _derive(keygen, staged_payload, comment)

    if canonical_info is not None and not (
        _identity_matches(expected, canonical_info)
        or (
            staging_info is None
            and _same_identity_across_rename(expected, canonical_info)
        )
    ):
        raise IdentityError("canonical forwarding identity was replaced")
    if canonical_info is None:
        if staged_payload is None or expected is None:
            raise IdentityError("bound forwarding identity temporary disappeared")
        staging_fd = os.open(staging, _inspection_flags(), dir_fd=parent_fd)
        try:
            if (
                not _identity_matches(expected, os.fstat(staging_fd))
                or _read_fd(staging_fd) != staged_payload
                or not _identity_matches(
                    expected,
                    os.stat(staging, dir_fd=parent_fd, follow_symlinks=False),
                )
            ):
                raise IdentityError(
                    "forwarding identity temporary changed before publication"
                )
            _publish_verified_temporary(
                parent_fd,
                name,
                staging,
                staging_fd,
                expected,
                staged_payload,
                None,
                "private identity",
            )
        finally:
            os.close(staging_fd)
        staging_info = None

    canonical = _read_regular(parent_fd, name, uid, 0o600)
    if canonical is None:
        raise IdentityError("canonical forwarding identity is unavailable")
    canonical_identity = canonical.identity
    if (
        not (
            canonical_identity == expected
            or (
                staging_info is None
                and all(
                    expected[key] == canonical_identity[key]
                    for key in expected
                    if key != "ctime_ns"
                )
            )
        )
        or len(canonical.payload) != intent["size"]
        or hashlib.sha256(canonical.payload).hexdigest() != intent["sha256"]
    ):
        raise IdentityError("canonical forwarding identity changed")
    if canonical_identity != expected:
        intent["identity"] = canonical_identity
        intent_binding = _write_creation_intent(
            parent_fd,
            name,
            intent,
            uid,
            canonical_identity["group"],
            create=False,
            expected=intent_binding,
        )
        expected = intent["identity"]
    _derive(keygen, canonical.payload, comment)
    try:
        os.stat(staging, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise IdentityError("forwarding identity staging entry unexpectedly remains")
    final_authority = CreationIntentBinding(intent, intent_binding)
    _attest_creation_state(
        parent_fd,
        name,
        uid,
        final_authority,
        staging=None,
        canonical=canonical,
        boundary="before creation-intent retirement",
    )
    _clear_creation_intent(
        parent_fd,
        name,
        uid,
        intent_binding,
        staging_name=staging,
        canonical=canonical,
    )
    return canonical.payload


def _reconcile_creation(
    parent_fd: int,
    name: str,
    keygen: str,
    comment: str,
    uid: int,
    authority: CreationIntentBinding | None = None,
) -> bytes | None:
    """Compatibility mutation entry point with inspection kept as a separate phase."""
    plan = _plan_creation_reconciliation(
        parent_fd, name, keygen, comment, uid, authority
    )
    if plan is None:
        return None
    return _apply_creation_reconciliation(
        parent_fd, name, keygen, comment, uid, plan.authority
    )


def _create_private_crash_safe(
    parent_fd: int,
    name: str,
    payload: bytes,
    keygen: str,
    comment: str,
    uid: int,
    gid: int,
    *,
    authority: CreationIntentBinding | None = None,
) -> bytes:
    created_intent = authority is None
    if authority is None:
        intent: dict[str, Any] = {
            "version": 1,
            "staging_name": f".{name}.creation-{uuid.uuid4().hex}.tmp",
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "identity": None,
        }
        intent_binding = _write_creation_intent(
            parent_fd, name, intent, uid, gid, create=True
        )
        authority = CreationIntentBinding(intent, intent_binding)
    else:
        if authority.intent["identity"] is not None:
            raise IdentityError("creation restart requires an unbound exact intent")
        intent = {
            **authority.intent,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        intent_binding = authority.regular
    staging = intent["staging_name"]
    descriptor = -1
    identity: dict[str, int] | None = None
    allocation_complete = False
    try:
        _attest_creation_state(
            parent_fd,
            name,
            uid,
            authority,
            staging=None,
            canonical=None,
            boundary="before staging allocation",
        )
        descriptor, identity = _create_verified_temporary(
            parent_fd, staging, payload, 0o600, uid, gid, "private identity"
        )
        allocation_complete = True
        staging_binding = RegularBinding(payload, identity)
        _derive(keygen, _read_fd(descriptor), comment)
        os.fsync(parent_fd)
        _attest_creation_state(
            parent_fd,
            name,
            uid,
            authority,
            staging=staging_binding,
            canonical=None,
            boundary="after staging allocation fsync",
        )
        intent["identity"] = identity
        intent_binding = _write_creation_intent(
            parent_fd,
            name,
            intent,
            uid,
            gid,
            create=False,
            expected=intent_binding,
        )
        bound_authority = CreationIntentBinding(intent, intent_binding)
        _attest_creation_state(
            parent_fd,
            name,
            uid,
            bound_authority,
            staging=staging_binding,
            canonical=None,
            boundary="after staging binding",
        )
        canonical = _publish_verified_temporary(
            parent_fd,
            name,
            staging,
            descriptor,
            identity,
            payload,
            None,
            "private identity",
        )
        _attest_creation_state(
            parent_fd,
            name,
            uid,
            bound_authority,
            staging=None,
            canonical=canonical,
            boundary="after canonical publication",
        )
        _derive(keygen, canonical.payload, comment)
        _clear_creation_intent(
            parent_fd,
            name,
            uid,
            intent_binding,
            staging_name=staging,
            canonical=canonical,
        )
        return canonical.payload
    except BaseException:
        # Once an allocation completed, preserve the exact intent/staging or
        # intent/canonical evidence for fail-closed restart reconciliation.
        if not allocation_complete and created_intent:
            _clear_creation_intent(
                parent_fd,
                name,
                uid,
                intent_binding,
                staging_name=staging,
                canonical=None,
            )
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def manage(args: argparse.Namespace) -> dict[str, object]:
    user = pwd.getpwnam(args.user)
    group = grp.getgrnam(args.group)
    if os.geteuid() not in {0, user.pw_uid}:
        raise IdentityError("identity helper must run as root or the configured user")
    parent_fd, inspected, changed = open_parent(
        args.home,
        args.path,
        uid=user.pw_uid,
        gid=group.gr_gid,
        create=args.state == "present" and not args.check,
        allow_missing=args.check,
    )
    name = Path(args.path).name
    private_bytes: bytes | None
    if parent_fd < 0:
        if args.state == "absent":
            return {
                "status": "checked",
                "changed": False,
                "existing_directories": inspected,
            }
        private_bytes = _generate(args.keygen, args.comment)
        public_key, _public_bytes = _derive(args.keygen, private_bytes, args.comment)
        return {
            "status": "checked",
            "changed": False,
            "public_key": public_key,
            "existing_directories": inspected,
        }
    try:
        if args.state == "absent":
            if args.check:
                return {
                    "status": "checked",
                    "changed": False,
                    "existing_directories": inspected,
                }
            plan = _plan_creation_reconciliation(
                parent_fd, name, args.keygen, args.comment, user.pw_uid
            )
            if plan is not None:
                _apply_creation_reconciliation(
                    parent_fd,
                    name,
                    args.keygen,
                    args.comment,
                    user.pw_uid,
                    plan.authority,
                )
                if plan.authority.intent["identity"] is None:
                    _attest_creation_state(
                        parent_fd,
                        name,
                        user.pw_uid,
                        plan.authority,
                        staging=None,
                        canonical=None,
                        boundary="before explicit absent-state intent retirement",
                    )
                    _clear_creation_intent(
                        parent_fd,
                        name,
                        user.pw_uid,
                        plan.authority.regular,
                        staging_name=plan.authority.intent["staging_name"],
                        canonical=None,
                    )
            for candidate, expected_mode in ((f"{name}.pub", 0o644), (name, 0o600)):
                existing = _read_regular(
                    parent_fd, candidate, user.pw_uid, expected_mode
                )
                if existing is not None:
                    _safe_unlink_identity(parent_fd, candidate, existing.identity)
                    changed = True
            return {
                "status": "removed",
                "changed": changed,
                "existing_directories": inspected,
            }

        creation_plan = _plan_creation_reconciliation(
            parent_fd, name, args.keygen, args.comment, user.pw_uid
        )
        unbound_authority: CreationIntentBinding | None = None
        if creation_plan is None:
            private_bytes = None
        elif creation_plan.authority.intent["identity"] is None:
            # Keep the exact original null-identity intent as the authority for a
            # restarted creation; never clear it and open an unowned gap.
            private_bytes = None
            unbound_authority = creation_plan.authority
        elif args.check:
            private_bytes = creation_plan.prospective_private
        else:
            private_bytes = _apply_creation_reconciliation(
                parent_fd,
                name,
                args.keygen,
                args.comment,
                user.pw_uid,
                creation_plan.authority,
            )
        if private_bytes is None:
            private_binding = _read_regular(parent_fd, name, user.pw_uid, 0o600)
            private_bytes = None if private_binding is None else private_binding.payload
        existing_public_binding = _read_regular(
            parent_fd, f"{name}.pub", user.pw_uid, 0o644
        )
        existing_public = (
            None if existing_public_binding is None else existing_public_binding.payload
        )
        if private_bytes is None and existing_public is not None:
            raise IdentityError(
                "public forwarding identity exists without its private key"
            )
        if private_bytes is None:
            private_bytes = _generate(args.keygen, args.comment)
            if not args.check:
                private_bytes = _create_private_crash_safe(
                    parent_fd,
                    name,
                    private_bytes,
                    args.keygen,
                    args.comment,
                    user.pw_uid,
                    group.gr_gid,
                    authority=unbound_authority,
                )
                changed = True
        public_key, public_bytes = _derive(args.keygen, private_bytes, args.comment)
        if args.check and unbound_authority is not None:
            # This is deliberately adjacent to returning the plan: check mode must
            # describe one unchanged absent-companion snapshot.
            _attest_creation_state(
                parent_fd,
                name,
                user.pw_uid,
                unbound_authority,
                staging=None,
                canonical=None,
                boundary="immediately before returning the check plan",
            )
        if not args.check and existing_public != public_bytes:
            _replace(
                parent_fd,
                f"{name}.pub",
                public_bytes,
                0o644,
                user.pw_uid,
                group.gr_gid,
                existing_public_binding,
            )
            changed = True
        return {
            "status": "checked" if args.check else "present",
            "changed": False if args.check else changed,
            "public_key": public_key,
            "existing_directories": inspected,
        }
    finally:
        os.close(parent_fd)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", choices=("present", "absent"), required=True)
    parser.add_argument("--home", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--group", required=True)
    parser.add_argument("--comment", required=True)
    parser.add_argument("--keygen", required=True)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        print(json.dumps(manage(parse_args(argv)), sort_keys=True))
    except (IdentityError, KeyError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
