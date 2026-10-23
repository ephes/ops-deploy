"""The patch-line release resolver against fixture release lists; nothing touches the network."""

from __future__ import annotations

import ast
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from ops_deploy.infra import traefik_release
from ops_deploy.infra.traefik_release import (
    ChecksumError,
    PatchPolicy,
    PolicyError,
    Release,
    ReleaseDataError,
    Skipped,
    Version,
    archive_name,
    asset_url,
    checksums_name,
    parse_checksum,
    parse_releases,
    resolve_patch_release,
)

NOW = datetime(2026, 10, 23, 10, 5, tzinfo=UTC)
POLICY = PatchPolicy(line="3.7", cooldown_hours=72)
BASE = "https://github.com/traefik/traefik/releases/download"


def digest(version: str, arch: str = "amd64") -> str:
    """A fake, distinct sha256 per version and arch (fixture data, not a real release digest)."""

    seed = f"{version}-{arch}".encode().hex()
    return (seed * 64)[:64]


def checksums_text(version: str, *, arches: tuple[str, ...] = ("amd64", "arm64")) -> str:
    lines = [f"{digest(version, arch)}  traefik_v{version}_linux_{arch}.tar.gz" for arch in arches]
    lines.append(f"{'0' * 64}  traefik_v{version}_windows_amd64.zip")
    return "\n".join(lines) + "\n"


def gh_release(
    version: str,
    *,
    age: timedelta = timedelta(days=10),
    tag: str | None = None,
    draft: bool = False,
    prerelease: bool = False,
    assets: list[dict[str, Any]] | None = None,
    published_at: Any = "auto",
) -> dict[str, Any]:
    """One entry as the GitHub releases API returns it (only the fields the resolver reads, plus noise)."""

    tag = tag if tag is not None else f"v{version}"
    if assets is None:
        names = [
            f"traefik_v{version}_checksums.txt",
            f"traefik_v{version}_linux_amd64.tar.gz",
            f"traefik_v{version}_linux_arm64.tar.gz",
            f"traefik_v{version}_windows_amd64.zip",
        ]
        assets = [{"name": n, "browser_download_url": f"{BASE}/{tag}/{n}", "size": 1} for n in names]
    if published_at == "auto":
        published_at = (NOW - age).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "tag_name": tag,
        "name": tag,
        "draft": draft,
        "prerelease": prerelease,
        "published_at": published_at,
        "assets": assets,
        "html_url": f"https://github.com/traefik/traefik/releases/tag/{tag}",
    }


class Fetcher:
    """Serves checksums texts by URL and records every call."""

    def __init__(self, texts: dict[str, str] | None = None) -> None:
        self.texts = texts
        self.calls: list[str] = []

    def __call__(self, url: str) -> str:
        self.calls.append(url)
        if self.texts is not None:
            return self.texts[url]
        version = url.split("/")[-2].removeprefix("v")
        return checksums_text(version)


def sums_url(version: str) -> str:
    return f"{BASE}/v{version}/traefik_v{version}_checksums.txt"


def resolve(
    payload: list[dict[str, Any]],
    installed: str = "3.7.14",
    *,
    fetch: Callable[[str], str] | None = None,
    policy: PatchPolicy = POLICY,
    arch: str = "amd64",
    now: datetime = NOW,
) -> Any:
    return resolve_patch_release(
        parse_releases(payload), policy, installed, now, fetch if fetch is not None else Fetcher(), arch=arch
    )


# --- the live-like case: interleaved 2.11 and 3.7 tags, newest first ------------------------------

INTERLEAVED = [
    gh_release("3.7.16", age=timedelta(days=3, hours=1)),
    gh_release("2.11.31", age=timedelta(days=3, hours=2)),
    gh_release("3.7.15", age=timedelta(days=8)),
    gh_release("2.11.30", age=timedelta(days=8, hours=1)),
    gh_release("3.7.14", age=timedelta(days=17)),
    gh_release("2.11.29", age=timedelta(days=17)),
]


def test_newest_eligible_patch_is_chosen_skipping_intermediate_ones() -> None:
    fetch = Fetcher()

    result = resolve(INTERLEAVED, fetch=fetch)

    assert result.status == "update"
    assert result.installed == Version(3, 7, 14)
    assert result.target is not None
    assert result.target.version == Version(3, 7, 16)
    assert result.target.arch == "amd64"
    assert result.target.sha256 == digest("3.7.16")
    assert result.target.archive_url == f"{BASE}/v3.7.16/traefik_v3.7.16_linux_amd64.tar.gz"
    assert result.target.checksums_url == sums_url("3.7.16")
    assert result.target.published_at == NOW - timedelta(days=3, hours=1)
    assert result.minor_available is False
    assert result.skipped == ()
    # One checksums fetch, for the chosen release only; 2.11 tags are never looked at.
    assert fetch.calls == [sums_url("3.7.16")]


def test_interleaved_older_line_is_neither_candidate_nor_minor() -> None:
    payload = [gh_release("2.11.40", age=timedelta(days=30))]

    result = resolve(payload)

    assert (result.status, result.target, result.minor_available, result.skipped) == ("current", None, False, ())


def test_order_of_the_release_list_does_not_matter() -> None:
    assert resolve(list(reversed(INTERLEAVED))).target.version == Version(3, 7, 16)


def test_arm64_takes_the_arm64_archive_and_digest() -> None:
    result = resolve(INTERLEAVED, arch="arm64")

    assert result.target.archive_url.endswith("traefik_v3.7.16_linux_arm64.tar.gz")
    assert result.target.sha256 == digest("3.7.16", "arm64")


# --- current, downgrade, reinstall ----------------------------------------------------------------


def test_installed_newest_is_current_without_fetching() -> None:
    fetch = Fetcher()

    result = resolve(INTERLEAVED, installed="3.7.16", fetch=fetch)

    assert (result.status, result.target, result.skipped) == ("current", None, ())
    assert fetch.calls == []


def test_never_downgrades_when_the_host_is_ahead_of_the_list() -> None:
    result = resolve(INTERLEAVED, installed="3.7.20")

    assert (result.status, result.target) == ("current", None)


def test_older_patches_are_never_candidates_even_when_newer_are_ineligible() -> None:
    payload = [gh_release("3.7.16", age=timedelta(hours=1)), gh_release("3.7.13", age=timedelta(days=40))]

    result = resolve(payload, installed="3.7.14")

    assert result.status == "cooldown"
    assert result.target is None
    assert result.skipped == (Skipped(Version(3, 7, 16), "cooldown"),)


def test_empty_release_list_is_current() -> None:
    assert resolve([]).status == "current"


# --- cooldown -------------------------------------------------------------------------------------


def test_cooldown_falls_back_to_the_newest_release_that_is_old_enough() -> None:
    payload = [gh_release("3.7.16", age=timedelta(hours=71, minutes=59)), gh_release("3.7.15", age=timedelta(days=8))]

    result = resolve(payload)

    assert result.status == "update"
    assert result.target.version == Version(3, 7, 15)
    assert result.skipped == (Skipped(Version(3, 7, 16), "cooldown"),)


def test_cooldown_boundary_is_inclusive() -> None:
    assert resolve([gh_release("3.7.16", age=timedelta(hours=72))]).status == "update"
    assert resolve([gh_release("3.7.16", age=timedelta(hours=72) - timedelta(seconds=1))]).status == "cooldown"


def test_release_published_in_the_future_waits() -> None:
    assert resolve([gh_release("3.7.16", age=-timedelta(hours=1))]).status == "cooldown"


def test_zero_cooldown_takes_a_fresh_release() -> None:
    result = resolve([gh_release("3.7.16", age=timedelta(0))], policy=PatchPolicy(line="3.7", cooldown_hours=0))

    assert result.target.version == Version(3, 7, 16)


def test_now_in_another_timezone_compares_by_instant() -> None:
    berlin = NOW.astimezone(ZoneInfo("Europe/Berlin"))

    assert resolve([gh_release("3.7.16", age=timedelta(hours=72))], now=berlin).status == "update"


# --- prerelease and draft -------------------------------------------------------------------------


def test_prerelease_flag_is_skipped_and_suffixed_tags_are_ignored() -> None:
    payload = [
        gh_release("3.7.17", prerelease=True),
        gh_release("3.7.18", tag="v3.7.18-rc.1", prerelease=True),
        gh_release("3.7.15"),
    ]

    result = resolve(payload)

    assert result.target.version == Version(3, 7, 15)
    assert result.skipped == (Skipped(Version(3, 7, 17), "prerelease"),)


def test_draft_is_skipped() -> None:
    payload = [gh_release("3.7.16", draft=True, published_at=None)]

    result = resolve(payload)

    assert (result.status, result.skipped) == ("current", (Skipped(Version(3, 7, 16), "draft"),))


@pytest.mark.parametrize("published_at", [None, "", "yesterday", "2026-10-01T00:00:00", 1760000000])
def test_unusable_published_at_is_skipped(published_at: Any) -> None:
    result = resolve([gh_release("3.7.16", published_at=published_at)])

    assert (result.status, result.skipped) == ("current", (Skipped(Version(3, 7, 16), "invalid_published_at"),))


def test_published_at_with_offset_is_accepted() -> None:
    stamp = (NOW - timedelta(days=4)).astimezone(ZoneInfo("Europe/Berlin")).isoformat()

    assert resolve([gh_release("3.7.16", published_at=stamp)]).status == "update"


# --- missing or bad checksums ---------------------------------------------------------------------


def _assets(version: str, *names: str, url_for: Callable[[str], str] | None = None) -> list[dict[str, Any]]:
    url_for = url_for or (lambda n: f"{BASE}/v{version}/{n}")
    return [{"name": n, "browser_download_url": url_for(n)} for n in names]


def test_missing_checksums_asset_is_skipped_for_the_next_older_release() -> None:
    fetch = Fetcher()
    payload = [
        gh_release("3.7.16", assets=_assets("3.7.16", "traefik_v3.7.16_linux_amd64.tar.gz")),
        gh_release("3.7.15"),
    ]

    result = resolve(payload, fetch=fetch)

    assert result.target.version == Version(3, 7, 15)
    assert result.skipped == (Skipped(Version(3, 7, 16), "missing_checksums_asset"),)
    assert fetch.calls == [sums_url("3.7.15")]


def test_missing_archive_asset_is_skipped() -> None:
    payload = [gh_release("3.7.16", assets=_assets("3.7.16", "traefik_v3.7.16_checksums.txt"))]

    result = resolve(payload)

    assert (result.status, result.skipped) == ("current", (Skipped(Version(3, 7, 16), "missing_archive_asset"),))


@pytest.mark.parametrize(
    "bad",
    [
        "http://github.com/traefik/traefik/releases/download/v3.7.16/{n}",
        "https://example.org/traefik/traefik/releases/download/v3.7.16/{n}",
        "https://github.com/traefik/traefik/releases/download/v3.7.15/{n}",
        "https://github.com/someone/traefik/releases/download/v3.7.16/{n}",
    ],
)
@pytest.mark.parametrize("which", ["archive", "checksums"])
def test_asset_off_its_canonical_url_is_skipped_without_fetching(bad: str, which: str) -> None:
    fetch = Fetcher()
    target = "traefik_v3.7.16_linux_amd64.tar.gz" if which == "archive" else "traefik_v3.7.16_checksums.txt"

    def url_for(name: str) -> str:
        return bad.format(n=name) if name == target else f"{BASE}/v3.7.16/{name}"

    payload = [
        gh_release(
            "3.7.16",
            assets=_assets(
                "3.7.16", "traefik_v3.7.16_linux_amd64.tar.gz", "traefik_v3.7.16_checksums.txt", url_for=url_for
            ),
        )
    ]

    result = resolve(payload, fetch=fetch)

    assert result.skipped == (Skipped(Version(3, 7, 16), "unexpected_asset_url"),)
    assert fetch.calls == []


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "checksum_entry_missing"),
        (checksums_text("3.7.16", arches=("arm64",)), "checksum_entry_missing"),
        (f"{'a' * 63}  traefik_v3.7.16_linux_amd64.tar.gz\n", "checksum_entry_malformed"),
        (f"{'g' * 64}  traefik_v3.7.16_linux_amd64.tar.gz\n", "checksum_entry_malformed"),
        (
            f"{'a' * 64}  traefik_v3.7.16_linux_amd64.tar.gz\n{'a' * 64}  traefik_v3.7.16_linux_amd64.tar.gz extra\n",
            "checksum_entry_malformed",
        ),
        (f"traefik_v3.7.16_linux_amd64.tar.gz  {'a' * 64}\n", "checksum_entry_malformed"),
        (f"{'a' * 64}\ttraefik_v3.7.16_linux_amd64.tar.gz\tsize=1\n", "checksum_entry_malformed"),
        ("traefik_v3.7.16_linux_amd64.tar.gz\n", "checksum_entry_malformed"),
        (
            f"{'a' * 64}  traefik_v3.7.16_linux_amd64.tar.gz\n{'b' * 64}  traefik_v3.7.16_linux_amd64.tar.gz\n",
            "checksum_entry_ambiguous",
        ),
        (
            f"{'a' * 64}  traefik_v3.7.16_linux_amd64.tar.gz\n{'a' * 64} *traefik_v3.7.16_linux_amd64.tar.gz\n",
            "checksum_entry_ambiguous",
        ),
    ],
)
def test_checksums_without_one_good_entry_skip_the_release(text: str, reason: str) -> None:
    fetch = Fetcher({sums_url("3.7.16"): text, sums_url("3.7.15"): checksums_text("3.7.15")})

    result = resolve([gh_release("3.7.16"), gh_release("3.7.15")], fetch=fetch)

    assert result.target.version == Version(3, 7, 15)
    assert result.skipped == (Skipped(Version(3, 7, 16), reason),)  # type: ignore[arg-type]
    assert fetch.calls == [sums_url("3.7.16"), sums_url("3.7.15")]


def test_checksum_error_raised_by_the_fetcher_propagates_too() -> None:
    def fetch(url: str) -> str:
        raise ChecksumError("checksum_entry_missing")

    with pytest.raises(ChecksumError):
        resolve(INTERLEAVED, fetch=fetch)


def test_fetch_failure_propagates_unchanged() -> None:
    class Down(OSError):
        pass

    def fetch(url: str) -> str:
        raise Down(url)

    with pytest.raises(Down):
        resolve(INTERLEAVED, fetch=fetch)


def test_skipped_everything_but_not_cooldown_is_current() -> None:
    payload = [gh_release("3.7.16", assets=[])]

    assert resolve(payload).status == "current"


def test_cooldown_status_wins_over_other_skips() -> None:
    payload = [gh_release("3.7.17", prerelease=True), gh_release("3.7.16", age=timedelta(hours=1))]

    result = resolve(payload)

    assert result.status == "cooldown"
    assert [s.reason for s in result.skipped] == ["prerelease", "cooldown"]


# --- minor available ------------------------------------------------------------------------------


@pytest.mark.parametrize("newer", ["3.8.0", "4.0.0"])
def test_newer_minor_or_major_is_only_reported(newer: str) -> None:
    fetch = Fetcher()

    result = resolve([gh_release(newer), gh_release("3.7.14")], fetch=fetch)

    assert (result.status, result.target, result.minor_available) == ("current", None, True)
    assert fetch.calls == []


def test_minor_available_alongside_a_patch_update() -> None:
    result = resolve([gh_release("3.8.1"), *INTERLEAVED])

    assert (result.status, result.minor_available) == ("update", True)
    assert result.target.version == Version(3, 7, 16)


@pytest.mark.parametrize(("draft", "prerelease"), [(False, True), (True, False)])
def test_unreleased_new_minor_is_not_reported(draft: bool, prerelease: bool) -> None:
    result = resolve([gh_release("3.8.0", draft=draft, prerelease=prerelease)])

    assert result.minor_available is False


def test_new_minor_tag_with_suffix_is_not_reported() -> None:
    result = resolve([gh_release("3.8.0", tag="v3.8.0-rc.2")])

    assert result.minor_available is False


# --- policy and argument validation ---------------------------------------------------------------


@pytest.mark.parametrize("installed", ["3.8.0", "3.6.9", "2.11.31", "4.7.14"])
def test_installed_outside_the_line_is_refused(installed: str) -> None:
    with pytest.raises(PolicyError, match=r"not on patch line 3\.7"):
        resolve(INTERLEAVED, installed=installed)


@pytest.mark.parametrize("installed", ["", "3.7", "v3.7.14", "3.7.14-rc.1", "3.07.14", " 3.7.14", "3.7.x"])
def test_malformed_installed_version_is_refused(installed: str) -> None:
    with pytest.raises(PolicyError, match=r"major\.minor\.patch"):
        resolve(INTERLEAVED, installed=installed)


def test_naive_now_is_refused() -> None:
    with pytest.raises(PolicyError, match="timezone-aware"):
        resolve(INTERLEAVED, now=NOW.replace(tzinfo=None))


@pytest.mark.parametrize("arch", ["x86_64", "arm", "AMD64", ""])
def test_unknown_arch_is_refused(arch: str) -> None:
    with pytest.raises(PolicyError, match="arch must be one of"):
        resolve(INTERLEAVED, arch=arch)


@pytest.mark.parametrize("line", ["3", "3.7.1", "v3.7", "03.7", "3.07", "", 3.7, None])
def test_policy_line_must_be_major_minor(line: Any) -> None:
    with pytest.raises(PolicyError, match="patch line"):
        PatchPolicy(line=line, cooldown_hours=72)


@pytest.mark.parametrize("hours", [-1, 24 * 365 + 1, True, 72.0, "72", None])
def test_policy_cooldown_must_be_a_bounded_int(hours: Any) -> None:
    with pytest.raises(PolicyError, match="cooldown_hours"):
        PatchPolicy(line="3.7", cooldown_hours=hours)


def test_policy_accepts_the_bounds_and_exposes_major_minor() -> None:
    assert PatchPolicy(line="3.7", cooldown_hours=0).major_minor == (3, 7)
    assert PatchPolicy(line="10.0", cooldown_hours=24 * 365).major_minor == (10, 0)


# --- release list parsing -------------------------------------------------------------------------


def test_parse_keeps_plain_tags_only() -> None:
    payload = [
        gh_release("3.7.16"),
        gh_release("3.7.16", tag="v3.7.16-rc.1"),
        gh_release("3.7.1", tag="v3.07.1"),
        gh_release("3.7.1", tag="3.7.1"),
        gh_release("3.7.1", tag="v3.7.1 "),
    ]

    releases = parse_releases(payload)

    assert [r.version for r in releases] == [Version(3, 7, 16)]
    assert isinstance(releases[0], Release)
    assert releases[0].assets[0].name == "traefik_v3.7.16_checksums.txt"


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({"tag_name": "v3.7.16"}, "JSON array"),
        (["v3.7.16"], "JSON object"),
        ([{"tag_name": 3}], "tag_name"),
        ([{**gh_release("3.7.16"), "assets": None}], "assets must be"),
        ([{**gh_release("3.7.16"), "assets": ["x"]}], "assets must be"),
        ([{**gh_release("3.7.16"), "assets": [{"name": "x"}]}], "browser_download_url"),
        ([{**gh_release("3.7.16"), "assets": [{"name": None, "browser_download_url": "x"}]}], "'name'"),
        ([{**gh_release("3.7.16"), "draft": "false"}], "'draft'"),
        ([{**gh_release("3.7.16"), "prerelease": 0}], "'prerelease'"),
        ([gh_release("3.7.16"), gh_release("3.7.16")], "listed twice"),
        (
            [
                {
                    **gh_release("3.7.16"),
                    "assets": _assets("3.7.16", "traefik_v3.7.16_checksums.txt", "traefik_v3.7.16_checksums.txt"),
                }
            ],
            "asset name twice",
        ),
    ],
)
def test_parse_refuses_malformed_data(payload: Any, match: str) -> None:
    with pytest.raises(ReleaseDataError, match=match):
        parse_releases(payload)


def test_unmatched_tags_are_dropped_before_their_other_fields_are_read() -> None:
    assert parse_releases([{"tag_name": "nightly", "assets": None, "draft": "?"}]) == ()


# --- checksums text and names ---------------------------------------------------------------------


def test_parse_checksum_lowercases_and_accepts_binary_marker() -> None:
    name = "traefik_v3.7.16_linux_amd64.tar.gz"
    upper = "AB" * 32

    assert parse_checksum(f"{upper} *{name}\r\n", name) == upper.lower()
    assert parse_checksum(f"junk line\n\n{'c' * 64}  other.tar.gz\n{'d' * 64}  {name}\n", name) == "d" * 64


def test_checksum_error_carries_its_reason() -> None:
    with pytest.raises(ChecksumError) as caught:
        parse_checksum("", "x")

    assert caught.value.reason == "checksum_entry_missing"


def test_names_and_urls() -> None:
    v = Version.parse("3.7.16")

    assert str(v) == "3.7.16"
    assert archive_name(v, "amd64") == "traefik_v3.7.16_linux_amd64.tar.gz"
    assert checksums_name(v) == "traefik_v3.7.16_checksums.txt"
    assert asset_url(v, checksums_name(v)) == sums_url("3.7.16")


def test_version_order_is_numeric() -> None:
    assert Version.parse("3.7.10") > Version.parse("3.7.9")
    assert Version.parse("10.0.0") > Version.parse("9.99.99")


def test_module_is_pure() -> None:
    """The resolver imports nothing that could reach the network, the file system or the clock."""

    tree = ast.parse(Path(traefik_release.__file__).read_text())
    imported = {
        alias.name if isinstance(node, ast.Import) else node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }

    assert imported == {"__future__", "re", "collections.abc", "dataclasses", "datetime", "typing"}
    assert "datetime.now" not in Path(traefik_release.__file__).read_text()
