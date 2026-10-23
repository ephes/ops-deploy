"""Patch-line release resolver for unattended Traefik binary updates.

A pure function over data the caller already fetched: the release list of
the GitHub API (``GET /repos/traefik/traefik/releases``, decoded JSON) and,
through an injected callable, the text of one release's
``traefik_v<version>_checksums.txt``. Nothing here opens a socket, reads a
file or looks at the clock; ``now`` is an argument.

Eligibility of a release for a host on patch line ``M.m``:

- its tag is exactly ``vM.m.<n>`` (no suffix, no leading zeros), it is
  neither a draft nor a prerelease, and ``n`` is greater than the host's
  installed patch: never a downgrade, never a reinstall;
- its ``published_at`` is at least ``cooldown_hours`` before ``now``;
- it has the ``linux_<arch>.tar.gz`` archive and the ``checksums.txt``
  asset, each at its canonical ``https://github.com/traefik/traefik/
  releases/download/`` URL, and the checksums text has exactly one
  well-formed sha256 line for that archive.

The newest eligible release is chosen, so a host may skip patches. A newer
stable minor or major (``3.8.0``, ``4.0.0``) is only reported as
``minor_available``; it is never a candidate. Releases of an older line (the
interleaved ``2.11.x``) are ignored.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

DOWNLOAD_BASE = "https://github.com/traefik/traefik/releases/download"
ARCHES = ("amd64", "arm64")
MAX_COOLDOWN_HOURS = 24 * 365

_NUMBER = r"(0|[1-9][0-9]{0,5})"
_TAG = re.compile(rf"v{_NUMBER}\.{_NUMBER}\.{_NUMBER}")
_VERSION = re.compile(rf"{_NUMBER}\.{_NUMBER}\.{_NUMBER}")
_LINE = re.compile(rf"{_NUMBER}\.{_NUMBER}")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")

SkipReason = Literal[
    "draft",
    "prerelease",
    "invalid_published_at",
    "cooldown",
    "missing_archive_asset",
    "missing_checksums_asset",
    "unexpected_asset_url",
    "checksum_entry_missing",
    "checksum_entry_ambiguous",
    "checksum_entry_malformed",
]
Status = Literal["update", "current", "cooldown"]


class ReleaseDataError(ValueError):
    """The release list is not the shape the GitHub API returns, or names a version or asset twice."""


class ChecksumError(ValueError):
    """The checksums text has no single well-formed digest for the archive."""

    def __init__(self, reason: SkipReason) -> None:
        super().__init__(reason)
        self.reason: SkipReason = reason


class PolicyError(ValueError):
    """The patch policy, installed version or arguments cannot be resolved against."""


@dataclass(frozen=True, order=True)
class Version:
    """A plain ``major.minor.patch`` release version."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, text: str) -> Version:
        """Parse ``M.m.p`` exactly; raises :class:`PolicyError` otherwise."""

        match = _VERSION.fullmatch(text)
        if match is None:
            raise PolicyError(f"not a plain major.minor.patch version: {text!r}")
        return cls(*(int(part) for part in match.groups()))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class PatchPolicy:
    """The part of the registry's ``patch_policy`` the resolver needs."""

    line: str
    cooldown_hours: int

    def __post_init__(self) -> None:
        if not isinstance(self.line, str) or _LINE.fullmatch(self.line) is None:
            raise PolicyError(f"patch line must be 'major.minor', got {self.line!r}")
        hours = self.cooldown_hours
        if isinstance(hours, bool) or not isinstance(hours, int) or not 0 <= hours <= MAX_COOLDOWN_HOURS:
            raise PolicyError(f"cooldown_hours must be an int in 0..{MAX_COOLDOWN_HOURS}, got {hours!r}")

    @property
    def major_minor(self) -> tuple[int, int]:
        """The line as ``(major, minor)``."""

        major, minor = self.line.split(".")
        return int(major), int(minor)


@dataclass(frozen=True)
class Asset:
    """One release asset: its file name and download URL."""

    name: str
    url: str


@dataclass(frozen=True)
class Release:
    """One release whose tag is a plain ``vM.m.p`` version."""

    version: Version
    draft: bool
    prerelease: bool
    published_at: datetime | None
    assets: tuple[Asset, ...]


@dataclass(frozen=True)
class Skipped:
    """A release of the line, newer than the installed one, that was not chosen."""

    version: Version
    reason: SkipReason


@dataclass(frozen=True)
class Candidate:
    """The release to install, with the digest pinned at resolution time."""

    version: Version
    arch: str
    published_at: datetime
    archive_url: str
    checksums_url: str
    sha256: str


@dataclass(frozen=True)
class Resolution:
    """The resolver's answer.

    ``status``: ``update`` (``target`` is set), ``cooldown`` (nothing is
    eligible yet, but a newer patch of the line waits out its cooldown) or
    ``current`` (nothing newer is eligible; ``skipped`` says why, if any newer
    patch exists at all).
    """

    status: Status
    installed: Version
    target: Candidate | None
    minor_available: bool
    skipped: tuple[Skipped, ...]


def archive_name(version: Version, arch: str) -> str:
    """``traefik_v<version>_linux_<arch>.tar.gz``."""

    return f"traefik_v{version}_linux_{arch}.tar.gz"


def checksums_name(version: Version) -> str:
    """``traefik_v<version>_checksums.txt``."""

    return f"traefik_v{version}_checksums.txt"


def asset_url(version: Version, name: str) -> str:
    """The canonical download URL of a release asset."""

    return f"{DOWNLOAD_BASE}/v{version}/{name}"


def _string(item: Mapping[str, object], key: str) -> str:
    value = item.get(key)
    if not isinstance(value, str):
        raise ReleaseDataError(f"release field {key!r} must be a string, got {value!r}")
    return value


def _flag(item: Mapping[str, object], key: str) -> bool:
    value = item.get(key)
    if not isinstance(value, bool):
        raise ReleaseDataError(f"release field {key!r} must be a boolean, got {value!r}")
    return value


def _published_at(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.utcoffset() is not None else None


def parse_releases(payload: object) -> tuple[Release, ...]:
    """Releases with a plain ``vM.m.p`` tag from decoded GitHub API JSON.

    Other tags (``v3.8.0-rc.1``, ``v3.07.1``) are left out. A malformed entry
    or a version listed twice raises :class:`ReleaseDataError`. An unparsable
    or offset-less ``published_at`` becomes ``None`` (that release is then
    skipped as ``invalid_published_at`` if it would matter).
    """

    if not isinstance(payload, list):
        raise ReleaseDataError("the release list must be a JSON array")
    releases: dict[Version, Release] = {}
    for item in payload:
        if not isinstance(item, dict):
            raise ReleaseDataError("each release must be a JSON object")
        match = _TAG.fullmatch(_string(item, "tag_name"))
        if match is None:
            continue
        version = Version(*(int(part) for part in match.groups()))
        if version in releases:
            raise ReleaseDataError(f"release {version} is listed twice")
        raw_assets = item.get("assets")
        if not isinstance(raw_assets, list) or not all(isinstance(raw, dict) for raw in raw_assets):
            raise ReleaseDataError(f"release {version}: assets must be a JSON array of objects")
        assets = tuple(Asset(name=_string(raw, "name"), url=_string(raw, "browser_download_url")) for raw in raw_assets)
        if len({asset.name for asset in assets}) != len(assets):
            raise ReleaseDataError(f"release {version} lists an asset name twice")
        releases[version] = Release(
            version=version,
            draft=_flag(item, "draft"),
            prerelease=_flag(item, "prerelease"),
            published_at=_published_at(item.get("published_at")),
            assets=assets,
        )
    return tuple(releases.values())


def parse_checksum(text: str, filename: str) -> str:
    """The lowercase sha256 of ``filename`` in a ``sha256sum``-style text.

    Exactly one line may name the file, and it must be ``<hex>  <name>``
    (an optional ``*`` before the name); a second line for it, or any line
    that names it in another shape, is not accepted. Lines for other files
    are not checked. Raises
    :class:`ChecksumError` with the skip reason when there is no single digest.
    """

    digests: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if filename not in (part.removeprefix("*") for part in parts):
            continue
        if len(parts) != 2 or parts[1].removeprefix("*") != filename or _SHA256.fullmatch(parts[0]) is None:
            raise ChecksumError("checksum_entry_malformed")
        digests.append(parts[0].lower())
    if not digests:
        raise ChecksumError("checksum_entry_missing")
    if len(digests) > 1:
        raise ChecksumError("checksum_entry_ambiguous")
    return digests[0]


def _asset(release: Release, name: str) -> Asset | None:
    return next((asset for asset in release.assets if asset.name == name), None)


def resolve_patch_release(
    releases: Sequence[Release],
    policy: PatchPolicy,
    installed: str,
    now: datetime,
    fetch_checksums: Callable[[str], str],
    *,
    arch: str = "amd64",
) -> Resolution:
    """Choose the newest eligible patch of ``policy.line`` above ``installed``.

    ``fetch_checksums(url)`` returns the checksums text of one release; it is
    called only for releases that passed every other check, newest first, and
    no more once one yields a digest. Whatever it raises propagates unchanged:
    the caller maps a failed fetch to its ``unavailable`` outcome. An
    ``installed`` version outside the line, a naive ``now`` or an unknown
    ``arch`` raises :class:`PolicyError`.
    """

    if arch not in ARCHES:
        raise PolicyError(f"arch must be one of {ARCHES}, got {arch!r}")
    if now.utcoffset() is None:
        raise PolicyError("now must be timezone-aware")
    current = Version.parse(installed)
    line = policy.major_minor
    if (current.major, current.minor) != line:
        raise PolicyError(
            f"installed {current} is not on patch line {policy.line}; changing the line is an owner decision"
        )

    stable = [r for r in releases if not r.draft and not r.prerelease]
    minor_available = any((r.version.major, r.version.minor) > line for r in stable)
    newer = sorted(
        (r for r in releases if (r.version.major, r.version.minor) == line and r.version > current),
        key=lambda r: r.version,
        reverse=True,
    )
    cooldown = timedelta(hours=policy.cooldown_hours)
    skipped: list[Skipped] = []
    target: Candidate | None = None
    for release in newer:
        outcome = _check(release, now, cooldown, arch, fetch_checksums)
        if isinstance(outcome, Candidate):
            target = outcome
            break
        skipped.append(Skipped(version=release.version, reason=outcome))

    status: Status
    if target is not None:
        status = "update"
    elif any(s.reason == "cooldown" for s in skipped):
        status = "cooldown"
    else:
        status = "current"
    return Resolution(
        status=status, installed=current, target=target, minor_available=minor_available, skipped=tuple(skipped)
    )


def _check(
    release: Release,
    now: datetime,
    cooldown: timedelta,
    arch: str,
    fetch_checksums: Callable[[str], str],
) -> Candidate | SkipReason:
    version = release.version
    if release.draft:
        return "draft"
    if release.prerelease:
        return "prerelease"
    if release.published_at is None:
        return "invalid_published_at"
    if now - release.published_at < cooldown:
        return "cooldown"
    archive = _asset(release, archive_name(version, arch))
    if archive is None:
        return "missing_archive_asset"
    sums = _asset(release, checksums_name(version))
    if sums is None:
        return "missing_checksums_asset"
    if archive.url != asset_url(version, archive.name) or sums.url != asset_url(version, sums.name):
        return "unexpected_asset_url"
    text = fetch_checksums(sums.url)  # outside the ``try``: whatever it raises propagates
    try:
        digest = parse_checksum(text, archive.name)
    except ChecksumError as error:
        return error.reason
    return Candidate(
        version=version,
        arch=arch,
        published_at=release.published_at,
        archive_url=archive.url,
        checksums_url=sums.url,
        sha256=digest,
    )
