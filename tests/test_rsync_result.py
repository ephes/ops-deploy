"""The exact rsync --out-format='%i %n%L' stdout contract."""

import pytest

from ops_deploy.core.rsync import RsyncResult


@pytest.mark.parametrize("path", ["old", "parent/old", "with spaces", " leading and trailing "])
def test_nonempty_refusal_is_not_a_directory_deletion(path: str) -> None:
    stdout = f"cannot delete non-empty directory: {path}\n*deleting   {path}/\n"
    result = RsyncResult(0, stdout, "unrelated stderr is retained\n")

    assert result.itemized_lines == []
    assert result.stdout == stdout
    assert result.stderr == "unrelated stderr is retained\n"


def test_ancestor_refusal_without_its_own_candidate_is_not_a_mutation() -> None:
    result = RsyncResult(
        0,
        "cannot delete non-empty directory: parent/child\n"
        "*deleting   parent/child/\n"
        "cannot delete non-empty directory: parent\n",
    )
    assert result.itemized_lines == []


@pytest.mark.parametrize(
    "line",
    [
        "*deleting   old",  # A file is not the refused directory.
        "*deleting   old/child/",  # A different directory can really be removed.
        "*deleting   older/",
        "*deleting  old/",  # Not our exact 11-character itemized field plus separator.
        "old/",  # Unknown stdout is not an itemized deletion.
        ">fc........ old",
        ".f...p..... old",
        "rsync warning: something else",
        "cannot delete non-empty directory without the exact delimiter",
    ],
)
def test_only_exact_corresponding_directory_candidates_are_suppressed(line: str) -> None:
    result = RsyncResult(0, f"cannot delete non-empty directory: old\n{line}\n")
    assert result.itemized_lines == [line]


def test_a_future_deletion_without_a_refusal_is_still_a_change() -> None:
    result = RsyncResult(0, "*deleting   old/\n")
    assert result.itemized_lines == ["*deleting   old/"]


def test_an_extra_slash_is_not_normalized_into_a_matching_candidate() -> None:
    result = RsyncResult(0, "cannot delete non-empty directory: old/\n*deleting   old/\n")
    assert result.itemized_lines == ["*deleting   old/"]
