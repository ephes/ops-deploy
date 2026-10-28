"""Bounded original-role failure recovery, with no real host apt calls."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.integration.paperless import bootstrap


def fixture(tmp_path: Path, log: str, *, first: int = 2, refresh: int = 0) -> Any:
    (tmp_path / "00-original-install.log").write_text(log)

    def write(name: str, value: Any) -> None:
        (tmp_path / name).write_text(json.dumps(value))

    return SimpleNamespace(
        EVIDENCE=tmp_path,
        ansible=Mock(side_effect=[first, 0]),
        command=Mock(return_value=subprocess.CompletedProcess([], refresh, "owned update output", "")),
        write=write,
        sanitize=lambda value: value,
    )


def exact_failure() -> str:
    return bootstrap.MISSING + "\nlocalhost : ok=53 changed=14 unreachable=0 failed=1 skipped=21 rescued=0 ignored=0\n"


def test_original_success_never_diagnoses_or_refreshes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = fixture(tmp_path, "original success", first=0)
    diagnostic = Mock(side_effect=AssertionError("no diagnostic needed"))
    monkeypatch.setattr(bootstrap, "cache_diagnostic", diagnostic)
    bootstrap.original_install(h, "3.0.4")
    diagnostic.assert_not_called()
    h.command.assert_not_called()
    h.ansible.assert_called_once_with("00-original-install", version="3.0.4", allow_failure=True)


@pytest.mark.parametrize("refresh", [0, 100])
def test_only_exact_missing_package_allows_one_labelled_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refresh: int
) -> None:
    h = fixture(tmp_path, exact_failure(), refresh=refresh)
    monkeypatch.setattr(
        bootstrap, "cache_diagnostic", Mock(side_effect=[{"policy": "missing"}, {"policy": "candidate"}])
    )
    if refresh:
        with pytest.raises(AssertionError, match="apt update failed"):
            bootstrap.original_install(h, "3.2.1")
    else:
        bootstrap.original_install(h, "3.2.1")
    h.command.assert_called_once_with(
        "apt-get", "-o", "APT::Update::Error-Mode=any", "update", timeout=300, check=False
    )
    assert h.ansible.call_count == (1 if refresh else 2)
    if not refresh:
        assert h.ansible.call_args.kwargs == {"version": "3.2.1"}
        assert h.ansible.call_args.args == ("00b-original-install-after-fixture-cache-recovery",)
    assert (tmp_path / "00-original-install.log").read_text() == exact_failure()
    receipt = json.loads((tmp_path / "original-bootstrap-cache-recovery.json").read_text())
    assert receipt["exit"] == refresh
    assert receipt["before"] == {"policy": "missing"}
    assert receipt["after"] == {"policy": "candidate"}
    assert "not original bootstrap success" in receipt["classification"]


@pytest.mark.parametrize(
    "log",
    [
        "[ERROR]: Authentication failed",
        "[ERROR]: repository unavailable",
        exact_failure() + "[ERROR]: network failure\n",
        exact_failure().replace("failed=1", "failed=2"),
        exact_failure().replace("unreachable=0", "unreachable=1"),
    ],
)
def test_unrelated_failures_never_refresh_or_retry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log: str) -> None:
    h = fixture(tmp_path, log)
    diagnostic = Mock(side_effect=AssertionError("no diagnostic admitted"))
    monkeypatch.setattr(bootstrap, "cache_diagnostic", diagnostic)
    with pytest.raises(AssertionError):
        bootstrap.original_install(h, "3.2.1")
    diagnostic.assert_not_called()
    h.command.assert_not_called()
    assert h.ansible.call_count == 1


def test_post_update_probe_failure_retains_actual_update_exit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = fixture(tmp_path, exact_failure(), refresh=100)
    monkeypatch.setattr(
        bootstrap, "cache_diagnostic", Mock(side_effect=[{"policy": "missing"}, RuntimeError("probe failed")])
    )
    with pytest.raises(RuntimeError, match="probe failed"):
        bootstrap.original_install(h, "3.2.1")
    assert json.loads((tmp_path / "original-bootstrap-cache-update-result.json").read_text())["exit"] == 100
    assert (tmp_path / "original-bootstrap-cache-update.log").read_text() == "owned update output"
    assert h.ansible.call_count == 1


def test_diagnostic_reads_only_fixed_public_source_and_bounded_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, lists = tmp_path / "postgresql.sources", tmp_path / "lists"
    source.write_text("Types: deb\nURIs: https://apt.postgresql.org/pub/repos/apt\n")
    lists.mkdir()
    (lists / "apt.postgresql.org_owned_Packages").write_text("public apt list")
    (lists / "unrelated").write_text("must not appear")
    monkeypatch.setattr(bootstrap, "SOURCES", source)
    monkeypatch.setattr(bootstrap, "LISTS", lists)
    h = SimpleNamespace(command=Mock(return_value=subprocess.CompletedProcess([], 0, "Candidate: 17\n", "")))
    value = bootstrap.cache_diagnostic(h)
    assert value["policy"] == "Candidate: 17\n"
    assert set(value["list_metadata"]) == {"apt.postgresql.org_owned_Packages"}
    h.command.assert_called_once_with("apt-cache", "policy", "postgresql-17", timeout=30, check=False)
    for number in range(32):
        (lists / f"postgresql-{number}").touch()
    with pytest.raises(AssertionError):
        bootstrap.cache_diagnostic(h)


def test_refresh_timeout_retains_attempt_and_partial_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    h = fixture(tmp_path, exact_failure())
    monkeypatch.setattr(bootstrap, "cache_diagnostic", Mock(return_value={"policy": "missing"}))
    h.command.side_effect = subprocess.TimeoutExpired(
        ["apt-get"], 300, output=b"partial public apt output", stderr=b"timeout detail"
    )
    with pytest.raises(subprocess.TimeoutExpired):
        bootstrap.original_install(h, "3.2.1")
    assert json.loads((tmp_path / "original-bootstrap-cache-update-started.json").read_text())["timeout_seconds"] == 300
    result = json.loads((tmp_path / "original-bootstrap-cache-update-result.json").read_text())
    assert result["timed_out"] is True
    assert result["exit"] is None
    assert (tmp_path / "original-bootstrap-cache-update.log").read_text() == "partial public apt outputtimeout detail"
    assert h.ansible.call_count == 1


def test_oversized_update_keeps_exit_and_bounded_prefix_before_refusal(tmp_path: Path) -> None:
    h = fixture(tmp_path, exact_failure())
    with pytest.raises(AssertionError, match="exceeded bound"):
        bootstrap.retain_update(h, "x" * (20 * 1024 * 1024 + 1), {"exit": 100, "timed_out": False})
    result = json.loads((tmp_path / "original-bootstrap-cache-update-result.json").read_text())
    assert result["exit"] == 100
    assert result["output_truncated"] is True
    assert (tmp_path / "original-bootstrap-cache-update.log").stat().st_size == 20 * 1024 * 1024
