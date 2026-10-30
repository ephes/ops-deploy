"""os_lifecycle host scripts: the status report, the SSH pull and the fallback HTTP server, on fixtures."""

from __future__ import annotations

import base64
import datetime as dt
import http.client
import importlib.util
import json
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

FILES = Path(__file__).parents[1] / "src/ops_deploy/services/os_lifecycle/files"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, FILES / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


status = load("os_lifecycle_status")
pull = load("os_lifecycle_pull")
httpd = load("os_lifecycle_httpd")

DEBIAN_CSV = """version,codename,series,created,release,eol,eol-lts,eol-elts
11,Bullseye,bullseye,2019-07-06,2021-08-14,2024-08-14,2026-08-31,2031-06-30
12,Bookworm,bookworm,2021-08-14,2023-06-10,2026-06-10,2028-06-30,2033-06-30
13,Trixie,trixie,2023-06-10,2025-08-09,2028-08-09,2030-06-30,2035-06-30
14,Forky,forky,2025-08-09,,,,
,Sid,sid,1993-08-16,,,,
"""
UBUNTU_CSV = """version,codename,series,created,release,eol,eol-server,eol-esm
22.04 LTS,Jammy Jellyfish,jammy,2021-10-21,2022-04-21,2027-06-01,2027-06-01,2032-04-21
24.04 LTS,Noble Numbat,noble,2023-10-26,2024-04-25,2029-05-31,2029-05-31,2034-04-25
25.10,Questing Quokka,questing,2025-04-17,2025-10-09,2026-07-01,,
26.04 LTS,Resolute Raccoon,resolute,2025-10-23,2026-04-23,2031-05-29,2031-05-29,2036-04-23
"""
SNAPSHOT: dict[str, Any] = {
    "fetched_at": "2026-10-22",
    "debian": [
        {
            "cycle": "13",
            "codename": "Trixie",
            "releaseDate": "2025-08-09",
            "support": "2028-08-09",
            "eol": "2030-06-30",
        },
        {
            "cycle": "12",
            "codename": "Bookworm",
            "releaseDate": "2023-06-10",
            "support": "2026-07-11",
            "eol": "2028-06-30",
        },
    ],
    "ubuntu": [
        {"cycle": "26.10", "releaseDate": "2026-10-15", "support": "2027-07-01", "eol": "2027-07-01", "lts": False},
        {"cycle": "26.04", "releaseDate": "2026-04-23", "support": "2031-05-29", "eol": "2031-05-29", "lts": True},
        {"cycle": "24.04", "releaseDate": "2024-04-25", "support": "2029-05-31", "eol": "2029-05-31", "lts": True},
    ],
}
TODAY = dt.date(2026, 10, 22)
NOW = time.mktime((2026, 10, 22, 12, 0, 0, 0, 0, -1))

DEBIAN_APT = """NOTE: This is only a simulation!
Inst openssl [3.0.15-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
Inst libssl3 [3.0.15-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64]) []
Inst tzdata [2025a-0+deb12u1] (2025b-0+deb12u1 Debian:12.12/stable [all])
Inst vector [0.53.0-1] (0.60.0-1 apt.vector.dev [amd64])
Conf openssl (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
"""
UBUNTU_APT = (
    "Inst libssl3t64 [3.0.13-0ubuntu3.4] "
    "(3.0.13-0ubuntu3.5 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\n"
    "Inst docker-ce [5:27.3.1-1~ubuntu.24.04~noble] (5:27.4.0-1~ubuntu.24.04~noble Docker CE:noble/noble [amd64])\n"
    "Inst linux-image-6.8.0-90-generic (6.8.0-90.91 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])\n"
)


def debian12(**changes: Any) -> dict[str, Any]:
    release = {"ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"}
    return status.lifecycle(  # type: ignore[no-any-return]
        {**release, **changes},
        status.parse_distro_info(DEBIAN_CSV, "debian"),
        status.parse_snapshot(SNAPSHOT["debian"]),
        today=TODAY,
        horizon_days=365,
        tolerance_days=31,
        snapshot_fetched=dt.date(2026, 10, 1),
    )


# -- lifecycle ------------------------------------------------------------------------------


def test_debian_12_is_in_lts_and_due_for_an_upgrade() -> None:
    os_ = debian12()

    assert os_["support_end"] == "2026-06-10"
    assert os_["eol"] == "2028-06-30"
    assert os_["support_days_remaining"] == -134
    assert os_["eol_days_remaining"] == 617
    assert os_["phase"] == "extended"
    assert os_["upgrade_due"] is True
    assert os_["latest_stable_cycle"] == "13"
    assert os_["releases_behind"] == 1
    assert os_["release_upgrade_available"] is True
    assert os_["lifecycle_source"] == "distro-info"
    # distro-info's security end and endoflife.date's last point release are 31 days apart.
    assert os_["lifecycle_sources_agree"] is True
    assert os_["lifecycle_data_age_days"] == 21


def test_debian_13_is_current() -> None:
    os_ = debian12(VERSION_ID="13", VERSION_CODENAME="trixie")

    assert os_["phase"] == "standard"
    assert os_["upgrade_due"] is False
    assert os_["releases_behind"] == 0
    assert os_["release_upgrade_available"] is False


FORKY = {"cycle": "14", "codename": "Forky", "releaseDate": "2027-06-12", "support": "2030-06-12", "eol": "2032-06-30"}


def trixie_on(today: dt.date, archive: tuple[str | None, int | None] = (None, None)) -> dict[str, Any]:
    return status.lifecycle(  # type: ignore[no-any-return]
        {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"},
        status.parse_distro_info(DEBIAN_CSV, "debian"),
        status.parse_snapshot([FORKY, *SNAPSHOT["debian"]]),
        today=today,
        horizon_days=365,
        tolerance_days=31,
        snapshot_fetched=dt.date(2027, 6, 1),
        archive=archive,
    )


def test_a_newer_stable_counts_from_its_release_day() -> None:
    before = trixie_on(dt.date(2027, 6, 11))
    release_day = trixie_on(dt.date(2027, 6, 12))

    assert (before["releases_behind"], before["latest_stable_cycle"]) == (0, "13")
    assert (release_day["releases_behind"], release_day["latest_stable_cycle"]) == (1, "14")
    assert release_day["release_upgrade_available"] is True
    # Regular support of 13 still runs for a year: the EOL view is not due yet.
    assert release_day["upgrade_due"] is False


def test_the_archive_suite_says_oldstable_before_the_data_knows_the_release() -> None:
    # Lifecycle data without Debian 14, but the mirror already moved trixie to oldstable.
    os_ = debian12(VERSION_ID="13", VERSION_CODENAME="trixie")
    assert (os_["releases_behind"], os_["archive_suite"]) == (0, None)

    moved = status.lifecycle(
        {"ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"},
        status.parse_distro_info(DEBIAN_CSV, "debian"),
        status.parse_snapshot(SNAPSHOT["debian"]),
        today=TODAY,
        horizon_days=365,
        tolerance_days=31,
        snapshot_fetched=dt.date(2026, 10, 1),
        archive=("oldstable", 1),
    )

    assert (moved["releases_behind"], moved["releases_behind_data"], moved["archive_suite"]) == (1, 0, "oldstable")
    assert moved["latest_stable_cycle"] == "13"


def test_the_archive_suite_never_lowers_what_the_data_says() -> None:
    os_ = trixie_on(dt.date(2027, 6, 12), archive=("stable", 0))

    assert (os_["releases_behind"], os_["releases_behind_data"]) == (1, 1)


def release_file(suite: str, codename: str = "trixie", origin: str = "Debian", label: str = "Debian") -> str:
    return (
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
        f"Origin: {origin}\nLabel: {label}\nSuite: {suite}\nVersion: 13.7\nCodename: {codename}\n"
        "Date: Sat, 12 Sep 2026 07:55:41 UTC\nSHA256:\n abc 1 main/Suite: oldstable\n"
    )


def test_the_debian_archive_suite_from_apt_lists(tmp_path: Path) -> None:
    lists = tmp_path / "var/lib/apt/lists"
    lists.mkdir(parents=True)
    assert status.debian_archive(tmp_path, "trixie") == (None, None)

    (lists / "deb.debian.org_debian_dists_trixie_InRelease").write_text(release_file("stable"))
    (lists / "deb.debian.org_debian_dists_trixie-updates_InRelease").write_text(
        release_file("oldstable-updates", "trixie-updates")
    )
    (lists / "vendor.example_dists_trixie_InRelease").write_text(release_file("oldstable", origin="Vendor"))
    (lists / "deb.debian.org_debian_dists_trixie-backports_InRelease").write_text(
        release_file("oldstable", "trixie-backports", "Debian Backports", "Debian Backports")
    )
    assert status.debian_archive(tmp_path, "trixie") == ("stable", 0)

    # A second, fresher mirror that already moved trixie on.
    (lists / "mirror.example_debian_dists_trixie_Release").write_text(release_file("oldstable"))
    assert status.debian_archive(tmp_path, "trixie") == ("oldstable", 1)
    assert status.debian_archive(tmp_path, "") == (None, None)
    assert status.debian_archive(tmp_path, "../x") == (None, None)


def test_sources_that_differ_by_more_than_the_tolerance_disagree() -> None:
    os_ = status.lifecycle(
        {"ID": "debian", "VERSION_ID": "12"},
        status.parse_distro_info(DEBIAN_CSV, "debian"),
        status.parse_snapshot(SNAPSHOT["debian"]),
        today=TODAY,
        horizon_days=365,
        tolerance_days=30,
        snapshot_fetched=None,
    )

    assert os_["lifecycle_sources_agree"] is False
    assert os_["lifecycle_data_age_days"] is None


def test_ubuntu_counts_only_released_lts_cycles() -> None:
    os_ = status.lifecycle(
        {"ID": "ubuntu", "VERSION_ID": "24.04", "VERSION_CODENAME": "noble"},
        status.parse_distro_info(UBUNTU_CSV, "ubuntu"),
        status.parse_snapshot(SNAPSHOT["ubuntu"]),
        today=TODAY,
        horizon_days=365,
        tolerance_days=31,
        snapshot_fetched=dt.date(2026, 10, 22),
    )

    assert os_["support_end"] == os_["eol"] == "2029-05-31"
    assert os_["upgrade_due"] is False
    assert os_["latest_stable_cycle"] == "26.04"
    assert os_["releases_behind"] == 1
    assert os_["lifecycle_sources_agree"] is True


def test_ubuntu_is_due_inside_the_horizon() -> None:
    os_ = status.lifecycle(
        {"ID": "ubuntu", "VERSION_ID": "24.04"},
        status.parse_distro_info(UBUNTU_CSV, "ubuntu"),
        [],
        today=dt.date(2028, 6, 1),
        horizon_days=365,
        tolerance_days=31,
        snapshot_fetched=None,
    )

    assert os_["upgrade_due"] is True
    assert os_["lifecycle_source"] == "distro-info"
    assert os_["lifecycle_sources_agree"] is False


def test_the_snapshot_stands_in_for_missing_distro_info() -> None:
    os_ = status.lifecycle(
        {"ID": "debian", "VERSION_ID": "12"},
        [],
        status.parse_snapshot(SNAPSHOT["debian"]),
        today=TODAY,
        horizon_days=365,
        tolerance_days=31,
        snapshot_fetched=None,
    )

    assert os_["lifecycle_source"] == "endoflife-snapshot"
    assert os_["support_end"] == "2026-07-11"


def test_an_unknown_release_reports_nulls() -> None:
    os_ = status.lifecycle(
        {"ID": "debian"}, [], [], today=TODAY, horizon_days=365, tolerance_days=31, snapshot_fetched=None
    )

    assert os_["phase"] == "unknown"
    assert os_["upgrade_due"] is None
    assert os_["support_days_remaining"] is None
    assert os_["lifecycle_source"] is None


# -- apt, unattended-upgrades, reboot ----------------------------------------------------------


def test_security_updates_are_found_by_origin() -> None:
    debian = status.parse_simulation(DEBIAN_APT)
    ubuntu = status.parse_simulation(UBUNTU_APT)

    assert [(p["package"], p["security"], p["third_party"]) for p in debian] == [
        ("openssl", True, False),
        ("libssl3", True, False),
        ("tzdata", False, False),
        ("vector", False, True),
    ]
    assert debian[3]["origins"] == ["apt.vector.dev"]
    assert [(p["package"], p["version"], p["security"], p["third_party"]) for p in ubuntu] == [
        ("libssl3t64", "3.0.13-0ubuntu3.5", True, False),
        ("docker-ce", "5:27.4.0-1~ubuntu.24.04~noble", False, True),
        ("linux-image-6.8.0-90-generic", "6.8.0-90.91", True, False),
    ]
    assert ubuntu[1]["origins"] == ["Docker CE:noble/noble"]


@pytest.mark.parametrize(
    ("origin", "third_party"),
    [
        ("Debian:13.7/stable", False),
        ("Debian:13-updates/stable-updates", False),
        ("Debian-Security:13/stable-security", False),
        ("Debian Backports:stable-backports/stable-backports", True),
        ("apt.vector.dev", True),
        ("vector:stable", True),
        ("Ubuntu:24.04/noble-updates", False),
        ("Docker CE:noble/noble", True),
    ],
)
def test_third_party_is_any_origin_outside_the_distribution(origin: str, third_party: bool) -> None:
    (item,) = status.parse_simulation(f"Inst pkg [1] (2 {origin} [amd64])\n")

    assert item["third_party"] is third_party


def test_the_last_uu_run_and_its_result() -> None:
    log = (
        "2026-10-20 06:10:01,100 INFO Starting unattended upgrades script\n"
        "2026-10-20 06:10:09,100 ERROR Installing the upgrades failed!\n"
        "2026-10-21 06:12:01,200 INFO Starting unattended upgrades script\n"
        "2026-10-21 06:12:03,200 INFO No packages found that can be upgraded unattended\n"
    )

    started, result = status.last_uu_run(log)

    assert result == "ok"
    assert started == time.mktime((2026, 10, 21, 6, 12, 1, 0, 0, -1))
    assert status.last_uu_run(log.rsplit("2026-10-21", 2)[0])[1] == "error"
    assert status.last_uu_run("") == (None, None)


def test_apt_config_values() -> None:
    dump = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'

    assert status.apt_config_value(dump, "APT::Periodic::Unattended-Upgrade") == "1"
    assert status.apt_config_value(dump, "APT::Periodic::AutocleanInterval") is None


def test_kernel_versions_ignore_removed_packages_and_meta_packages() -> None:
    output = (
        "linux-image-6.1.0-37-amd64 install ok installed\n"
        "linux-image-6.1.0-40-amd64 install ok installed\n"
        "linux-image-5.10.0-30-amd64 deinstall ok config-files\n"
        "linux-image-amd64 install ok installed\n"
    )

    assert status.kernel_versions(output) == ["6.1.0-37", "6.1.0-40"]


# -- the whole report on a fixture root --------------------------------------------------------


def touch(path: Path, mtime: float, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.utime(path, (mtime, mtime))


@pytest.fixture
def root(tmp_path: Path) -> Path:
    touch(tmp_path / "etc/os-release", NOW, 'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
    touch(tmp_path / "usr/share/distro-info/debian.csv", NOW, DEBIAN_CSV)
    touch(tmp_path / "var/lib/apt/lists/deb.debian.org_debian-security_dists_bookworm-security_InRelease", NOW - 7200)
    lists = tmp_path / "var/lib/apt/lists"
    touch(lists / "deb.debian.org_debian_dists_bookworm_InRelease", NOW - 7200, release_file("oldstable", "bookworm"))
    touch(tmp_path / "usr/bin/unattended-upgrade", NOW)
    touch(tmp_path / "var/lib/apt/periodic/unattended-upgrades-stamp", NOW - 36000)
    touch(tmp_path / "var/run/reboot-required", NOW - 40 * 3600)
    touch(tmp_path / "var/run/reboot-required.pkgs", NOW, "libc6\nlibc6\nlinux-base\n")
    touch(tmp_path / "var/lib/dpkg/info/linux-image-6.1.0-40-amd64.list", NOW - 50 * 3600)
    touch(tmp_path / "proc/uptime", NOW, f"{540 * 86400.0} 1.0\n")
    return tmp_path


def fake_run(argv: list[str]) -> tuple[int, str]:
    joined = " ".join(argv)
    if joined.startswith("apt-get -s"):
        return 0, DEBIAN_APT
    if joined == "apt-mark showhold":
        return 0, "postgresql-17\n"
    if joined == "apt-config dump":
        return 0, 'APT::Periodic::Unattended-Upgrade "1";\n'
    if joined.startswith("dpkg-query"):
        return 0, "linux-image-6.1.0-40-amd64 install ok installed\nlinux-image-6.1.0-37-amd64 install ok installed\n"
    if joined.startswith("systemctl show"):
        return 0, "success\n"
    return 127, ""


POLICY: dict[str, Any] = {
    "host": "marina",
    "reboot_class": "C",
    "upgrade_horizon_days": 365,
    "lifecycle_tolerance_days": 31,
    "state_group": "metrics",
    "endoflife": SNAPSHOT,
}


def test_a_full_report(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(status.os, "uname", lambda: os.uname_result(("Linux", "x", "6.1.0-37-amd64", "#1", "x86_64")))
    seen = {
        "openssl 3.0.17-1~deb12u2": NOW - 80 * 3600,
        "gone 1.0": NOW - 999 * 3600,
        "vector 0.60.0-1": NOW - 900 * 3600,
    }

    report, new_seen = status.build_report(POLICY, seen, root=root, run=fake_run, now=NOW)

    assert report["schema_version"] == 1
    assert report["host"] == "marina"
    assert report["errors"] == []
    assert report["os"]["upgrade_due"] is True
    assert report["os"]["archive_suite"] == "oldstable"
    assert report["os"]["releases_behind"] == 1
    assert report["apt"] == {
        "security_index_age_hours": 2.0,
        "pending_total": 4,
        "pending_security_count": 2,
        "pending_security_max_age_hours": 80.0,
        "pending_security": ["libssl3 3.0.17-1~deb12u2", "openssl 3.0.17-1~deb12u2"],
        "pending_third_party_count": 1,
        "pending_third_party_max_age_hours": 900.0,
        "pending_third_party": ["vector 0.60.0-1 (apt.vector.dev)"],
        "held": ["postgresql-17"],
    }
    assert new_seen == {
        "openssl 3.0.17-1~deb12u2": NOW - 80 * 3600,
        "libssl3 3.0.17-1~deb12u2": NOW,
        "vector 0.60.0-1": NOW - 900 * 3600,
    }
    assert report["uu"]["installed"] is True
    assert report["uu"]["enabled"] is True
    assert report["uu"]["last_success_age_hours"] == 10.0
    assert report["uu"]["service_result"] == "success"
    assert report["reboot"]["required"] is True
    assert report["reboot"]["reasons"] == ["reboot_required_flag", "stale_kernel"]
    assert report["reboot"]["required_age_hours"] == 50.0
    assert report["reboot"]["packages"] == ["libc6", "linux-base"]
    assert report["reboot"]["newest_installed_kernel"] == "6.1.0-40"
    assert report["reboot"]["kernel_check"] == "compared"
    assert report["reboot"]["uptime_days"] == 540.0
    assert report["reboot"]["reboot_class"] == "C"
    json.dumps(report)


def test_no_reboot_needed_reports_age_zero(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(status.os, "uname", lambda: os.uname_result(("Linux", "x", "6.1.0-40-amd64", "#1", "x86_64")))
    (root / "var/run/reboot-required").unlink()

    report, _ = status.build_report(POLICY, {}, root=root, run=fake_run, now=NOW)

    assert report["reboot"]["required"] is False
    assert report["reboot"]["required_age_hours"] == 0


def test_a_failing_section_is_null_and_named(root: Path) -> None:
    def broken(argv: list[str]) -> tuple[int, str]:
        return (100, "") if argv[0] == "apt-get" else fake_run(argv)

    seen = {"openssl 1": NOW}
    report, new_seen = status.build_report(POLICY, seen, root=root, run=broken, now=NOW)

    assert report["apt"] is None
    assert report["errors"] == ["apt: RuntimeError: apt-get -s dist-upgrade exited 100"]
    assert new_seen == seen
    assert report["os"] is not None


@pytest.mark.parametrize("code", [2, 124, 127])
def test_a_failing_kernel_query_makes_the_reboot_section_unknown(root: Path, code: int) -> None:
    (root / "var/run/reboot-required").unlink()

    def broken(argv: list[str]) -> tuple[int, str]:
        return (code, "") if argv[0] == "dpkg-query" else fake_run(argv)

    report, _ = status.build_report(POLICY, {}, root=root, run=broken, now=NOW)

    assert report["reboot"] is None
    assert report["errors"] == [f"reboot: RuntimeError: dpkg-query exited {code}"]


def test_no_dpkg_kernels_is_no_signal_and_says_so(root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(status.os, "uname", lambda: os.uname_result(("Linux", "x", "6.1.0-37-amd64", "#1", "x86_64")))
    (root / "var/run/reboot-required").unlink()

    def none(argv: list[str]) -> tuple[int, str]:
        return (1, "") if argv[0] == "dpkg-query" else fake_run(argv)

    report, _ = status.build_report(POLICY, {}, root=root, run=none, now=NOW)

    assert report["reboot"]["required"] is False
    assert report["reboot"]["kernel_check"] == "no-dpkg-kernels"


def test_uu_without_the_package_is_disabled(root: Path) -> None:
    (root / "usr/bin/unattended-upgrade").unlink()

    report, _ = status.build_report(POLICY, {}, root=root, run=fake_run, now=NOW)

    assert report["uu"]["enabled"] is False


def test_show_prints_the_report_and_nothing_else(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "state.json").write_text('{"host": "marina", "schema_version": 1}\n')

    assert status.show(tmp_path) == 0
    assert json.loads(capsys.readouterr().out) == {"host": "marina", "schema_version": 1}

    (tmp_path / "state.json").write_text("[1]")
    assert status.show(tmp_path) == 1
    assert "error" in json.loads(capsys.readouterr().out)


def test_the_simulation_never_locks_or_writes_caches() -> None:
    argv = status.APT_SIMULATE

    assert argv[:2] == ["apt-get", "-s"]
    assert "Debug::NoLocking=1" in argv
    assert "Dir::Cache::pkgcache=" in argv
    assert "Dir::Cache::srcpkgcache=" in argv


def test_atomic_writes_set_the_mode(tmp_path: Path) -> None:
    status.write_atomic(tmp_path / "x.json", "{}\n", mode=0o640)

    assert (tmp_path / "x.json").read_text() == "{}\n"
    assert (tmp_path / "x.json").stat().st_mode & 0o777 == 0o640
    assert not list(tmp_path.glob(".*.tmp"))


# -- pull ------------------------------------------------------------------------------------

CONFIG: dict[str, Any] = {
    "identity_file": "/etc/os-lifecycle/collector_ed25519",
    "known_hosts": "/etc/os-lifecycle/known_hosts",
    "state_group": "metrics",
    "timeout": 60,
    "hosts": [
        {"name": "marina", "address": "host.example.invalid", "port": 22, "user": "os-lifecycle"},
        {"name": "heis", "address": "192.0.2.10", "port": 2222, "user": "os-lifecycle"},
    ],
}


def report_for(name: str, generated: float) -> bytes:
    return json.dumps({"schema_version": 1, "host": name, "generated_at_epoch": int(generated)}).encode()


def test_ssh_argv_trusts_only_the_pinned_key_and_sends_no_command() -> None:
    argv = pull.ssh_argv(CONFIG, CONFIG["hosts"][1])

    assert argv[:3] == ["ssh", "-F", "/dev/null"]
    assert argv[-5:] == ["-p", "2222", "-l", "os-lifecycle", "192.0.2.10"]
    options = {argv[i + 1] for i, value in enumerate(argv) if value == "-o"}
    assert {
        "IdentitiesOnly=yes",
        "IdentityAgent=none",
        "BatchMode=yes",
        "StrictHostKeyChecking=yes",
        "UserKnownHostsFile=/etc/os-lifecycle/known_hosts",
        "GlobalKnownHostsFile=/dev/null",
        "HostKeyAlias=os-lifecycle-heis",
        "ClearAllForwardings=yes",
        "ForwardAgent=no",
    } <= options
    assert "-T" in argv


def test_pull_combines_and_keeps_the_last_good_report() -> None:
    previous = {"heis": {"last_pull_success_epoch": NOW - 7200, "report": json.loads(report_for("heis", NOW - 9000))}}

    def fetch(config: dict[str, Any], target: dict[str, Any]) -> tuple[int, bytes, bytes]:
        if target["name"] == "marina":
            return 0, report_for("marina", NOW - 1800), b""
        return 255, b"", b"Warning: x\nHost key verification failed.\n"

    combined = pull.pull(CONFIG, previous, now=NOW, fetch=fetch)

    marina, heis = combined["hosts"]["marina"], combined["hosts"]["heis"]
    assert marina["pull_ok"] is True
    assert marina["last_pull_success_age_hours"] == 0.0
    assert marina["report_age_hours"] == 0.5
    assert heis["pull_ok"] is False
    assert heis["pull_error"] == "ssh exited 255: Host key verification failed."
    assert heis["last_pull_success_age_hours"] == 2.0
    assert heis["report_age_hours"] == 2.5
    assert heis["report"]["host"] == "heis"


@pytest.mark.parametrize(
    ("stdout", "error"),
    [
        (report_for("other", NOW), "names host 'other'"),
        (b'{"schema_version": 2, "host": "marina"}', "schema_version"),
        (b'{"error": "no readable report: OSError"}', "host reported"),
        (b"[1]", "not a JSON object"),
        (b"not json", "Expecting value"),
        (b"\xff", "codec"),
        (b" " * (pull.MAX_REPORT_BYTES + 1), "larger"),
    ],
)
def test_pull_refuses_bad_reports(stdout: bytes, error: str) -> None:
    config = {**CONFIG, "hosts": CONFIG["hosts"][:1]}

    combined = pull.pull(config, {}, now=NOW, fetch=lambda c, t: (0, stdout, b""))

    entry = combined["hosts"]["marina"]
    assert entry["pull_ok"] is False
    assert error in entry["pull_error"]
    assert entry["report"] is None
    assert entry["last_pull_success_age_hours"] is None
    assert entry["report_age_hours"] is None


# -- the fallback HTTP server -----------------------------------------------------------------


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[int, Path]]:
    passwords = {"nyxmon": "right"}

    def fake_htpasswd(argv: list[str], **kwargs: Any) -> Any:
        assert argv[:3] == ["htpasswd", "-vi", str(tmp_path / "htpasswd")]
        return type("Done", (), {"returncode": 0 if passwords.get(argv[3]) == kwargs["input"] else 3})()

    monkeypatch.setattr(httpd.subprocess, "run", fake_htpasswd)
    report = tmp_path / "state.json"
    report.write_text('{"host": "x", "meta": {"stale": true}}')
    os.utime(report, (NOW, NOW))

    class Server(httpd.socketserver.TCPServer):  # type: ignore[name-defined,misc]
        allow_reuse_address = True

    instance = Server(("127.0.0.1", 0), httpd.Handler)
    instance.cfg = {
        "path": "/.well-known/os-lifecycle",
        "json_path": str(report),
        "htpasswd_file": str(tmp_path / "htpasswd"),
        "realm": "os-lifecycle",
    }
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        yield instance.server_address[1], report
    finally:
        instance.shutdown()
        instance.server_close()


def get(port: int, path: str, login: str | None = None) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Authorization": "Basic " + base64.b64encode(login.encode()).decode()} if login else {}
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    return response.status, dict(response.getheaders()), response.read()


def test_the_endpoint_needs_the_login(server: tuple[int, Path]) -> None:
    port, _ = server

    for login in (None, "nyxmon:wrong", "other:right"):
        code, headers, _ = get(port, "/.well-known/os-lifecycle", login)
        assert code == 401
        assert headers["WWW-Authenticate"] == 'Basic realm="os-lifecycle"'
    assert get(port, "/other")[0] == 404


def test_the_endpoint_serves_the_report_with_its_age(server: tuple[int, Path]) -> None:
    port, _ = server

    code, _, body = get(port, "/.well-known/os-lifecycle", "nyxmon:right")

    data = json.loads(body)
    assert code == 200
    assert data["host"] == "x"
    assert set(data["meta"]) == {"generated_at", "generated_at_epoch", "served_at_epoch", "age_seconds"}
    assert data["meta"]["generated_at_epoch"] == int(NOW)
    assert data["meta"]["age_seconds"] == data["meta"]["served_at_epoch"] - int(NOW)


def test_a_missing_report_is_503(server: tuple[int, Path]) -> None:
    port, report = server
    report.unlink()

    code, _, body = get(port, "/.well-known/os-lifecycle", "nyxmon:right")

    assert code == 503
    assert json.loads(body)["error_type"] == "metrics_file_missing"
