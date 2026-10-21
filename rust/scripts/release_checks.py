#!/usr/bin/env python3
"""Release checks of the Rust workspace (PLAN-foundation.md section 4).

Used by `.github/workflows/rust-release.yml`; stdlib only and Python 3.10
compatible (the release jobs run the runner's or the variant image's
python3). Tested in `test_release_checks.py`. Adapted from
`mailgun-relay:rust/scripts/release_checks.py` for several crates with
per-binary tags (`<crate>-v<semver>`) and per-crate release settings
(`rust/<crate>/release.json`).

Subcommands:

- ``tag``: resolve the crate to release, from a tag (``--tag
  <crate>-v<version>``, the crate is the longest workspace member whose
  ``<member>-v`` prefixes the tag) or from a crate name (``--crate``, the
  ``workflow_dispatch`` input). The crate must be a workspace member with a
  binary of the same name; a tag's version must equal the crate's version.
  Prints ``crate=<crate>`` and ``version=<version>`` (``$GITHUB_OUTPUT``
  lines).
- ``matrix``: read the crate's optional ``release.json`` (defaults below),
  validate it against ``cargo metadata`` and print ``matrix=<json>`` with one
  entry per variant: image, build packages, workspace members to build,
  binaries with their ``NEEDED`` allowlist, glibc ceiling and extra smoke
  commands, archive files, archive and artifact names.
- ``glibc-floor``: require every glibc symbol version a binary needs to be at
  most ``--max`` and every shared library it links to be glibc, libgcc_s or
  one given with ``--allow`` (``objdump -T`` and ``objdump -p``).
- ``smoke``: run ``<binary> --version`` and require exactly ``<name>
  <version> (<commit>)``; then run each ``--extra`` command (a JSON argv
  list) with an empty environment in an empty directory and require exit 0.
- ``verify``: ``glibc-floor`` and ``smoke`` for every binary of a matrix
  entry, with that binary's settings.
- ``pack``: write the deterministic archive of a matrix entry (its binaries,
  mode 0755, and files, mode 0644, at the archive root; root-owned entries,
  the commit time as mtime, gzip header without a name) and its ``.sha256``
  file; print the archive name.

``release.json`` (all keys optional; unknown keys are errors)::

    {"variants": [{
        "name": "ubuntu24.04",            # archive suffix; optional for a single variant
        "image": "ubuntu:24.04",          # container image (Debian/Ubuntu); default: the runner
        "packages": ["libapt-pkg-dev"],   # apt packages for the image (needs "image")
        "build": ["software-live", "software-live-apt"],   # members to build; default [<crate>]
        "binaries": [                     # default [{"name": <crate>}]
            {"name": "software-live"},
            {"name": "software-live-apt", "glibc_max": "2.39",
             "extra_needed": ["libapt-pkg.so.6.0", "libstdc++.so.6"],
             "extra_smoke": [["--help"]]}],
        "files": [                        # default [{"source": "rust/LICENSE", "name": "LICENSE"}]
            {"source": "rust/LICENSE", "name": "LICENSE"},
            {"source": "rust/software-live-apt/LICENSE", "name": "LICENSE.GPL-3.0"}]}]}

Without the file a crate has one unnamed variant built on the runner with
the defaults above, the base ``NEEDED`` allowlist (glibc and libgcc_s) and
the glibc ceiling 2.35.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

TARGET = "x86_64-unknown-linux-gnu"
GLIBC_FLOOR = "2.35"
RELEASE_JSON = "release.json"
DEFAULT_FILES = ({"source": "rust/LICENSE", "name": "LICENSE"},)

# Semantic Versioning 2.0.0 (the regex of semver.org without build metadata:
# a `+` in the tag would end up in the release download URL).
SEMVER = re.compile(
    r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
)
COMMIT = re.compile(r"[0-9a-f]{40}")
# Package names as cargo allows them (ASCII letters, digits, `-`, `_`): safe
# to word-split in a shell.
PACKAGE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]*")
VARIANT_NAME = re.compile(r"[a-z0-9][a-z0-9._-]*")
IMAGE = re.compile(r"[a-z0-9][a-z0-9._/:@-]*")
APT_PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+")
SONAME = re.compile(r"lib[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*\.so(?:\.\d+)*")
MEMBER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

# Shared libraries every glibc build may link to (PLAN-foundation.md section
# 2: only glibc and libgcc_s; TLS, where a crate needs it, is rustls).
BASE_NEEDED = frozenset(
    {
        "ld-linux-x86-64.so.2",
        "libc.so.6",
        "libdl.so.2",
        "libgcc_s.so.1",
        "libm.so.6",
        "libpthread.so.0",
        "librt.so.1",
        "libutil.so.1",
    }
)

GLIBC_VERSION = re.compile(r"\bGLIBC_([0-9A-Za-z_.]+)")
NEEDED = re.compile(r"^\s*NEEDED\s+(\S+)\s*$", re.MULTILINE)


class CheckError(Exception):
    """A release check failed; the message is the reason."""


# --- crate and tag ---------------------------------------------------------


def workspace_packages(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Workspace members of `cargo metadata` output by package name."""
    if not isinstance(metadata, dict):
        raise CheckError("cargo metadata is not a JSON object")
    member_ids = set(metadata.get("workspace_members") or [])
    members: dict[str, dict[str, Any]] = {}
    for package in metadata.get("packages") or []:
        if package.get("id") in member_ids:
            name = package.get("name")
            if name in members:
                raise CheckError(
                    f"workspace member {name!r} appears twice in cargo metadata"
                )
            members[name] = package
    return members


def binary_targets(package: dict[str, Any]) -> list[str]:
    return [
        target["name"]
        for target in package.get("targets") or []
        if "bin" in (target.get("kind") or [])
    ]


def release_crate(members: dict[str, dict[str, Any]], crate: str) -> tuple[str, str]:
    """(crate, version) of a releasable member: it has a binary of its name."""
    package = members.get(crate)
    if package is None:
        raise CheckError(f"{crate!r} is not a workspace member")
    if crate not in binary_targets(package):
        raise CheckError(f"workspace member {crate!r} has no binary named {crate!r}")
    version = package.get("version")
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        raise CheckError(
            f"{crate} version {version!r} is not semver (without build metadata)"
        )
    return crate, version


def resolve_tag(members: dict[str, dict[str, Any]], tag: str) -> tuple[str, str]:
    """The crate of `<crate>-v<version>`: the longest member that prefixes it."""
    candidates = [name for name in members if tag.startswith(f"{name}-v")]
    if not candidates:
        known = ", ".join(sorted(f"{name}-v<version>" for name in members))
        raise CheckError(
            f"tag {tag!r} matches no workspace member (expected one of: {known})"
        )
    crate = max(candidates, key=len)
    tag_version = tag[len(crate) + 2 :]
    if not SEMVER.fullmatch(tag_version):
        raise CheckError(
            f"tag {tag!r}: {tag_version!r} is not semver (without build metadata)"
        )
    crate, version = release_crate(members, crate)
    if tag_version != version:
        raise CheckError(
            f"tag {tag!r} does not match the {crate} version: expected {crate}-v{version!r}"
        )
    return crate, version


# --- release.json and the build matrix ---------------------------------------


def _object(value: Any, where: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CheckError(f"{where} must be a JSON object")
    unknown = sorted(set(value) - keys)
    if unknown:
        raise CheckError(f"{where}: unknown key(s) {', '.join(unknown)}")
    return value


def _strings(value: Any, where: str, pattern: re.Pattern[str], what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CheckError(f"{where} must be a list of strings")
    for item in value:
        if not pattern.fullmatch(item):
            raise CheckError(f"{where}: {item!r} is not a valid {what}")
    if len(set(value)) != len(value):
        raise CheckError(f"{where} lists an entry twice")
    return value


def _argv_lists(value: Any, where: str) -> list[list[str]]:
    if not isinstance(value, list) or not all(
        isinstance(argv, list) and all(isinstance(arg, str) for arg in argv)
        for argv in value
    ):
        raise CheckError(f"{where} must be a list of argument lists (strings)")
    return value


def _repo_file(repo_root: Path, source: Any, where: str) -> str:
    """A regular file inside the repository, as a relative POSIX path."""
    if not isinstance(source, str) or not source:
        raise CheckError(f"{where}: source must be a non-empty string")
    relative = PurePosixPath(source)
    if relative.is_absolute() or ".." in relative.parts or "\\" in source:
        raise CheckError(
            f"{where}: source {source!r} must be relative to the repository root"
        )
    path = repo_root / relative
    if path.is_symlink() or not path.is_file():
        raise CheckError(f"{where}: source {source!r} is not a regular file")
    if not path.resolve().is_relative_to(repo_root.resolve()):
        raise CheckError(f"{where}: source {source!r} leaves the repository")
    return relative.as_posix()


def variant_entries(
    metadata: dict[str, Any],
    crate: str,
    version: str,
    settings: dict[str, Any] | None,
    repo_root: Path,
    ci_excluded: list[str],
) -> list[dict[str, Any]]:
    """The build matrix entries of a crate (one per variant)."""
    members = workspace_packages(metadata)
    release_crate(members, crate)
    if settings is None:
        settings = {"variants": [{}]}
    settings = _object(settings, RELEASE_JSON, {"variants"})
    variants = settings.get("variants")
    if not isinstance(variants, list) or not variants:
        raise CheckError(f"{RELEASE_JSON}: variants must be a non-empty list")
    entries = []
    for index, raw in enumerate(variants):
        where = f"{RELEASE_JSON} variants[{index}]"
        variant = _object(
            raw, where, {"name", "image", "packages", "build", "binaries", "files"}
        )
        name = variant.get("name", "")
        if not isinstance(name, str) or (name and not VARIANT_NAME.fullmatch(name)):
            raise CheckError(f"{where}: name {name!r} is not a valid variant name")
        if not name and len(variants) > 1:
            raise CheckError(
                f"{where}: every variant needs a name when there are several"
            )
        image = variant.get("image", "")
        if not isinstance(image, str) or (image and not IMAGE.fullmatch(image)):
            raise CheckError(f"{where}: image {image!r} is not a valid image reference")
        packages = _strings(
            variant.get("packages", []),
            f"{where} packages",
            APT_PACKAGE,
            "apt package name",
        )
        if packages and not image:
            raise CheckError(f"{where}: packages need an image (the runner gets none)")
        build = _strings(
            variant.get("build", [crate]),
            f"{where} build",
            PACKAGE_NAME,
            "package name",
        )
        if crate not in build:
            raise CheckError(
                f"{where}: build must include the released crate {crate!r}"
            )
        for member in build:
            if member not in members:
                raise CheckError(
                    f"{where}: build member {member!r} is not a workspace member"
                )
        excluded = [member for member in build if member in ci_excluded]
        if excluded and not image:
            raise CheckError(
                f"{where}: CI-excluded member(s) {', '.join(excluded)} can only be built "
                "inside a variant image"
            )
        built_binaries = {
            name for member in build for name in binary_targets(members[member])
        }
        binaries_raw = variant.get("binaries", [{"name": crate}])
        if not isinstance(binaries_raw, list) or not binaries_raw:
            raise CheckError(f"{where}: binaries must be a non-empty list")
        binaries = []
        for position, item in enumerate(binaries_raw):
            spot = f"{where} binaries[{position}]"
            binary = _object(
                item, spot, {"name", "glibc_max", "extra_needed", "extra_smoke"}
            )
            binary_name = binary.get("name")
            if not isinstance(binary_name, str) or binary_name not in built_binaries:
                raise CheckError(
                    f"{spot}: {binary_name!r} is not a binary of the build members"
                )
            glibc_max = binary.get("glibc_max", GLIBC_FLOOR)
            if not isinstance(glibc_max, str):
                raise CheckError(
                    f"{spot}: glibc_max must be a string such as {GLIBC_FLOOR!r}"
                )
            parse_version(glibc_max)
            extra = _strings(
                binary.get("extra_needed", []), f"{spot} extra_needed", SONAME, "soname"
            )
            binaries.append(
                {
                    "name": binary_name,
                    "glibc_max": glibc_max,
                    "needed": sorted(BASE_NEEDED | set(extra)),
                    "extra_smoke": _argv_lists(
                        binary.get("extra_smoke", []), f"{spot} extra_smoke"
                    ),
                }
            )
        if crate not in [binary["name"] for binary in binaries]:
            raise CheckError(f"{where}: binaries must include {crate!r}")
        files_raw = variant.get("files", list(DEFAULT_FILES))
        if not isinstance(files_raw, list):
            raise CheckError(f"{where}: files must be a list")
        files = []
        for position, item in enumerate(files_raw):
            spot = f"{where} files[{position}]"
            entry = _object(item, spot, {"source", "name"})
            member_name = entry.get("name")
            if not isinstance(member_name, str) or not MEMBER_NAME.fullmatch(
                member_name
            ):
                raise CheckError(
                    f"{spot}: name {member_name!r} is not a plain file name"
                )
            files.append(
                {
                    "source": _repo_file(repo_root, entry.get("source"), spot),
                    "name": member_name,
                }
            )
        names = [binary["name"] for binary in binaries] + [
            entry["name"] for entry in files
        ]
        if len(set(names)) != len(names):
            raise CheckError(
                f"{where}: archive member names must be unique, got {names}"
            )
        archive = archive_name(crate, version, name)
        entries.append(
            {
                "crate": crate,
                "version": version,
                "variant": name,
                "image": image,
                "packages": " ".join(packages),
                "build_args": " ".join(f"-p {member}" for member in build),
                "container_checks": " ".join(f"-p {member}" for member in excluded),
                "commit_env": " ".join(commit_env(member) for member in build),
                "binaries": binaries,
                "files": files,
                "archive": archive,
                "artifact": archive[: -len(".tar.gz")],
            }
        )
    names = [entry["variant"] for entry in entries]
    if len(set(names)) != len(names):
        raise CheckError(f"{RELEASE_JSON}: variant names must be unique, got {names}")
    return entries


def commit_env(member: str) -> str:
    """The variable a crate's build.rs reads the commit from."""
    return member.upper().replace("-", "_") + "_GIT_COMMIT"


def archive_name(crate: str, version: str, variant: str = "") -> str:
    suffix = f"-{variant}" if variant else ""
    return f"{crate}-{version}-{TARGET}{suffix}.tar.gz"


def crate_directory(metadata: dict[str, Any], crate: str) -> Path:
    package = workspace_packages(metadata).get(crate)
    if package is None:
        raise CheckError(f"{crate!r} is not a workspace member")
    return Path(package["manifest_path"]).parent


def load_settings(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise CheckError(f"{path}: not valid JSON: {error}") from None


def ci_excluded_members(metadata: dict[str, Any]) -> list[str]:
    """`[workspace.metadata.ci] exclude`, validated by ci_excludes.py."""
    path = Path(__file__).resolve().with_name("ci_excludes.py")
    spec = importlib.util.spec_from_file_location("ci_excludes", path)
    if spec is None or spec.loader is None:
        raise CheckError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return list(module.excludes(metadata))
    except module.ExcludeError as error:
        raise CheckError(str(error)) from None


# --- binary checks -----------------------------------------------------------


def parse_version(text: str) -> tuple[int, ...]:
    """`2.35` → (2, 35); anything but dot-separated decimals is an error."""
    if not re.fullmatch(r"\d+(?:\.\d+)*", text):
        raise CheckError(f"not a glibc version: {text!r}")
    return tuple(int(part) for part in text.split("."))


def glibc_versions(objdump_text: str) -> set[str]:
    """Every `GLIBC_<x>` symbol or version reference in objdump output."""
    return set(GLIBC_VERSION.findall(objdump_text))


def needed_libraries(objdump_text: str) -> list[str]:
    """The `NEEDED` entries of the dynamic section (`objdump -p`)."""
    return NEEDED.findall(objdump_text)


def check_glibc(
    objdump_text: str, maximum: str, allowed: frozenset[str] = BASE_NEEDED
) -> str:
    """Validate objdump output; return the highest glibc version required."""
    limit = parse_version(maximum)
    versions = glibc_versions(objdump_text)
    if not versions:
        raise CheckError(
            "no GLIBC symbol versions found: not a dynamically linked glibc binary?"
        )
    parsed = {}
    for version in versions:
        try:
            parsed[version] = parse_version(version)
        except CheckError:
            raise CheckError(
                f"unexpected glibc symbol version GLIBC_{version}"
            ) from None
    newest = max(parsed, key=lambda version: parsed[version])
    too_new = sorted(
        (version for version, value in parsed.items() if value > limit),
        key=lambda version: parsed[version],
    )
    if too_new:
        listed = ", ".join(f"GLIBC_{version}" for version in too_new)
        raise CheckError(f"binary requires glibc newer than {maximum}: {listed}")
    libraries = needed_libraries(objdump_text)
    if not libraries:
        raise CheckError("no NEEDED entries found in the dynamic section")
    unexpected = sorted(set(libraries) - allowed)
    if unexpected:
        raise CheckError(
            f"binary links to libraries outside its allowlist: {', '.join(unexpected)}"
        )
    return newest


def check_version_output(stdout: str, name: str, version: str, commit: str) -> None:
    expected = f"{name} {version} ({commit})\n"
    if stdout != expected:
        raise CheckError(f"{name} --version printed {stdout!r}, expected {expected!r}")


def _objdump(binary: Path) -> str:
    texts = []
    for flag in ("-T", "-p"):
        command = ["objdump", flag, str(binary)]  # binutils from PATH
        result = subprocess.run(
            command, check=True, capture_output=True, text=True
        )  # noqa: S603
        texts.append(result.stdout)
    return "\n".join(texts)


def run_glibc_floor(binary: Path, maximum: str, allowed: frozenset[str]) -> str:
    newest = check_glibc(_objdump(binary), maximum, allowed)
    return (
        f"{binary}: newest glibc symbol version GLIBC_{newest} (ceiling {maximum}); "
        f"NEEDED within the allowlist"
    )


def run_smoke(
    binary: Path, name: str, version: str, commit: str, extra: list[list[str]]
) -> str:
    """`--version`, then every extra command; return what they printed."""
    if not COMMIT.fullmatch(commit):
        raise CheckError(f"commit must be 40 lowercase hex digits, got {commit!r}")
    result = subprocess.run(  # noqa: S603 - the binary under test
        [str(binary), "--version"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise CheckError(
            f"{name} --version exited {result.returncode} with stderr {result.stderr!r}"
        )
    check_version_output(result.stdout, name, version, commit)
    output = [result.stdout]
    for argv in extra:
        with tempfile.TemporaryDirectory(prefix=f"{name}-smoke-") as directory:
            result = subprocess.run(  # noqa: S603 - the binary under test
                [str(binary.resolve()), *argv],
                cwd=directory,
                env={},
                capture_output=True,
                text=True,
                check=False,
            )
        if result.returncode != 0:
            raise CheckError(
                f"{name} {' '.join(argv)} exited {result.returncode} with stderr "
                f"{result.stderr!r}"
            )
        output.append(f"$ {name} {' '.join(argv)}\n{result.stdout}")
    return "".join(output)


# --- archive -----------------------------------------------------------------


def _tar_member(
    name: str, data: bytes, mode: int, mtime: int
) -> tuple[tarfile.TarInfo, io.BytesIO]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = mtime
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.type = tarfile.REGTYPE
    return info, io.BytesIO(data)


def build_archive(members: dict[str, tuple[bytes, int]], mtime: int) -> bytes:
    """Deterministic tar.gz: the members (name → (content, mode)) sorted by name."""
    tar_bytes = io.BytesIO()
    with tarfile.open(
        fileobj=tar_bytes, mode="w", format=tarfile.GNU_FORMAT
    ) as archive:
        for name in sorted(members):
            data, mode = members[name]
            archive.addfile(*_tar_member(name, data, mode, mtime))
    compressed = io.BytesIO()
    # filename="" and a fixed mtime keep the gzip header reproducible.
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=mtime
    ) as gz:
        gz.write(tar_bytes.getvalue())
    return compressed.getvalue()


def verify_archive(data: bytes, members: dict[str, tuple[bytes, int]]) -> None:
    """Read the archive back: exactly the members, as regular files, contents and modes."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        found = archive.getmembers()
        names = [member.name for member in found]
        if sorted(names) != sorted(members):
            raise CheckError(f"archive members {names}, expected {sorted(members)}")
        for member in found:
            content, mode = members[member.name]
            if not member.isreg() or member.mode != mode:
                raise CheckError(
                    f"archive member {member.name} has mode {oct(member.mode)}"
                )
            extracted = archive.extractfile(member)
            if extracted is None or extracted.read() != content:
                raise CheckError(
                    f"archive member {member.name} differs from its source"
                )


def archive_members(
    entry: dict[str, Any], bin_dir: Path, repo_root: Path
) -> dict[str, tuple[bytes, int]]:
    members = {}
    for binary in entry["binaries"]:
        members[binary["name"]] = ((bin_dir / binary["name"]).read_bytes(), 0o755)
    for item in entry["files"]:
        members[item["name"]] = ((repo_root / item["source"]).read_bytes(), 0o644)
    return members


def checksum_line(data: bytes, name: str) -> str:
    """`sha256sum` output format: `<hex>  <name>\\n`."""
    return f"{hashlib.sha256(data).hexdigest()}  {name}\n"


def load_entry(text: str) -> dict[str, Any]:
    """A matrix entry (`toJSON(matrix)` in the workflow)."""
    try:
        entry = json.loads(text)
    except ValueError as error:
        raise CheckError(f"matrix entry is not valid JSON: {error}") from None
    if not isinstance(entry, dict):
        raise CheckError("matrix entry is not a JSON object")
    for key in ("crate", "version", "archive", "binaries", "files"):
        if key not in entry:
            raise CheckError(f"matrix entry has no {key!r}")
    return entry


# --- command line ------------------------------------------------------------


def _read_metadata(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CheckError(f"cannot read cargo metadata {path}: {error}") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)

    tag = commands.add_parser("tag")
    tag.add_argument(
        "--metadata", type=Path, required=True, help="cargo metadata JSON file"
    )
    which = tag.add_mutually_exclusive_group(required=True)
    which.add_argument("--tag", help="release tag <crate>-v<version>")
    which.add_argument("--crate", help="crate name (workflow_dispatch)")

    matrix = commands.add_parser("matrix")
    matrix.add_argument("--metadata", type=Path, required=True)
    matrix.add_argument("--crate", required=True)

    floor = commands.add_parser("glibc-floor")
    floor.add_argument(
        "--max", default=GLIBC_FLOOR, help="highest allowed glibc version"
    )
    floor.add_argument(
        "--allow", action="append", default=[], help="extra allowed NEEDED soname"
    )
    floor.add_argument("binary", type=Path)

    smoke = commands.add_parser("smoke")
    smoke.add_argument("--binary", type=Path, required=True)
    smoke.add_argument(
        "--name", help="binary name in the --version line (default: file name)"
    )
    smoke.add_argument("--version", required=True)
    smoke.add_argument("--commit", required=True, help="full 40-digit commit")
    smoke.add_argument(
        "--extra",
        action="append",
        default=[],
        help="JSON argv list of an extra smoke command",
    )

    verify = commands.add_parser("verify")
    verify.add_argument("--entry", required=True, help="matrix entry JSON")
    verify.add_argument("--bin-dir", type=Path, required=True)
    verify.add_argument("--commit", required=True)

    pack = commands.add_parser("pack")
    pack.add_argument("--entry", required=True, help="matrix entry JSON")
    pack.add_argument("--bin-dir", type=Path, required=True)
    pack.add_argument("--repo-root", type=Path, required=True)
    pack.add_argument(
        "--mtime", type=int, required=True, help="Unix time for all entries"
    )
    pack.add_argument("--out-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "tag":
            members = workspace_packages(_read_metadata(args.metadata))
            if args.tag is not None:
                crate, version = resolve_tag(members, args.tag)
            else:
                crate, version = release_crate(members, args.crate)
            print(f"crate={crate}\nversion={version}")
        elif args.command == "matrix":
            metadata = _read_metadata(args.metadata)
            crate, version = release_crate(workspace_packages(metadata), args.crate)
            workspace_root = Path(metadata["workspace_root"])
            entries = variant_entries(
                metadata,
                crate,
                version,
                load_settings(crate_directory(metadata, crate) / RELEASE_JSON),
                workspace_root.parent,
                ci_excluded_members(metadata),
            )
            print("matrix=" + json.dumps({"include": entries}, separators=(",", ":")))
        elif args.command == "glibc-floor":
            parse_version(args.max)
            for soname in args.allow:
                if not SONAME.fullmatch(soname):
                    raise CheckError(f"--allow {soname!r} is not a soname")
            print(run_glibc_floor(args.binary, args.max, BASE_NEEDED | set(args.allow)))
        elif args.command == "smoke":
            extra = []
            for text in args.extra:
                try:
                    extra.extend(_argv_lists([json.loads(text)], "--extra"))
                except ValueError:
                    raise CheckError(f"--extra {text!r} is not a JSON list") from None
            name = args.name or args.binary.name
            print(
                run_smoke(args.binary, name, args.version, args.commit, extra), end=""
            )
        elif args.command == "verify":
            entry = load_entry(args.entry)
            for binary in entry["binaries"]:
                path = args.bin_dir / binary["name"]
                print(
                    run_glibc_floor(
                        path, binary["glibc_max"], frozenset(binary["needed"])
                    )
                )
                print(
                    run_smoke(
                        path,
                        binary["name"],
                        entry["version"],
                        args.commit,
                        binary["extra_smoke"],
                    ),
                    end="",
                )
        else:
            entry = load_entry(args.entry)
            members = archive_members(entry, args.bin_dir, args.repo_root)
            data = build_archive(members, args.mtime)
            verify_archive(data, members)
            name = entry["archive"]
            args.out_dir.mkdir(parents=True, exist_ok=True)
            (args.out_dir / name).write_bytes(data)
            (args.out_dir / f"{name}.sha256").write_text(
                checksum_line(data, name), encoding="utf-8"
            )
            print(name)
    except CheckError as error:
        print(f"release check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
