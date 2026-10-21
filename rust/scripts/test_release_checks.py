"""Tests of release_checks.py (PLAN-foundation.md section 4).

The script gates `.github/workflows/rust-release.yml`: the tag resolves to
exactly one crate and its version, `release.json` (or its defaults) becomes
the build matrix, every binary stays within its glibc ceiling and `NEEDED`
allowlist and prints `<name> <version> (<commit>)`, and the archive is
deterministic with exactly the declared members.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

import release_checks as checks

SCRIPTS = Path(__file__).resolve().parent
RUST = SCRIPTS.parent
REPO = RUST.parent
SCRIPT = SCRIPTS / "release_checks.py"
WORKFLOW = REPO / ".github" / "workflows" / "rust-release.yml"
TWO_VARIANTS = SCRIPTS / "testdata" / "release-two-variants.json"
COMMIT = "27cf52e7bd2525d6f8ba4b2f9be42a880c2f6e1a"  # pragma: allowlist secret
TARGET = "x86_64-unknown-linux-gnu"
RELEASE_CRATES = ("metrics-httpd", "echoport-command-guard", "software-live")

# Shapes of binutils 2.38 (ubuntu-22.04) output: `objdump -T` then `objdump -p`.
OBJDUMP_OK = """
metrics-httpd:     file format elf64-x86-64

DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.2.5) free
0000000000000000      DF *UND*\t0000000000000000 (GLIBC_2.34) __libc_start_main
0000000000000000      DF *UND*\t0000000000000000  GLIBC_2.18  __cxa_thread_atexit_impl
0000000000000000      DF *UND*\t0000000000000000 (GCC_4.2.0) _Unwind_Backtrace
0000000000000000  w   D  *UND*\t0000000000000000  Base        __gmon_start__

metrics-httpd:     file format elf64-x86-64

Dynamic Section:
  NEEDED               libgcc_s.so.1
  NEEDED               libm.so.6
  NEEDED               libc.so.6
  NEEDED               ld-linux-x86-64.so.2
  FLAGS                0x0000000000000008

Version References:
  required from libgcc_s.so.1:
    0x0b792650 0x00 13 GCC_3.0
    0x0d696914 0x00 12 GCC_4.2.0
  required from libc.so.6:
    0x06969194 0x00 05 GLIBC_2.14
    0x069691b5 0x00 04 GLIBC_2.35
    0x09691a75 0x00 02 GLIBC_2.2.5
"""

APT_NEEDED = (
    "  NEEDED               libapt-pkg.so.6.0\n  NEEDED               libstdc++.so.6\n"
)


def package(
    name: str, version: str = "0.1.0", bins: tuple[str, ...] | None = None
) -> dict:
    bins = (name,) if bins is None else bins
    targets = [{"kind": ["bin"], "name": item} for item in bins]
    targets.append({"kind": ["test"], "name": "binary"})
    return {
        "name": name,
        "version": version,
        "id": f"path+file:///w/rust/{name}#{version}",
        "manifest_path": f"/w/rust/{name}/Cargo.toml",
        "targets": targets,
    }


def metadata(
    *packages: dict, others: tuple[str, ...] = ("serde",), ci: object = None
) -> dict:
    deps = [
        {
            "name": name,
            "version": "1.0.0",
            "id": f"registry+https://x#{name}@1.0.0",
            "targets": [],
        }
        for name in others
    ]
    return {
        "packages": list(packages) + deps,
        "workspace_members": [item["id"] for item in packages],
        "workspace_root": "/w/rust",
        "metadata": ci,
    }


SOFTWARE_LIVE = metadata(
    package("software-live", "0.1.0"),
    package("software-live-apt", "0.1.0"),
    package("metrics-httpd", "0.2.0"),
    ci={"ci": {"exclude": ["software-live-apt"]}},
)


def run_script(
    *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - the script under test
        [sys.executable, "-I", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


class RepoTree:
    """A temporary repository root with the files the fixtures reference."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for relative, text in (
            ("rust/LICENSE", "MIT License\n"),
            ("rust/software-live-apt/LICENSE", "GNU GENERAL PUBLIC LICENSE\n"),
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def cleanup(self) -> None:
        self._tmp.cleanup()


class TagTest(unittest.TestCase):
    def setUp(self) -> None:
        self.members = checks.workspace_packages(
            metadata(
                package("metrics-httpd", "0.1.0"),
                package("echoport-command-guard", "1.2.3-rc.1"),
                package("software-live", "0.3.0"),
                package("software-live-apt", "0.3.0"),
            )
        )

    def test_all_three_prefixes(self) -> None:
        self.assertEqual(
            checks.resolve_tag(self.members, "metrics-httpd-v0.1.0"),
            ("metrics-httpd", "0.1.0"),
        )
        self.assertEqual(
            checks.resolve_tag(self.members, "echoport-command-guard-v1.2.3-rc.1"),
            ("echoport-command-guard", "1.2.3-rc.1"),
        )
        self.assertEqual(
            checks.resolve_tag(self.members, "software-live-v0.3.0"),
            ("software-live", "0.3.0"),
        )

    def test_prefix_pair_software_live_and_software_live_apt(self) -> None:
        # `software-live-v` never prefixes `software-live-apt-v...`; each tag
        # resolves to its own member regardless of the member order.
        for order in (1, -1):
            members = dict(list(self.members.items())[::order])
            self.assertEqual(
                checks.resolve_tag(members, "software-live-apt-v0.3.0"),
                ("software-live-apt", "0.3.0"),
            )
            self.assertEqual(
                checks.resolve_tag(members, "software-live-v0.3.0"),
                ("software-live", "0.3.0"),
            )
        with self.assertRaisesRegex(
            checks.CheckError, "does not match the software-live version"
        ):
            checks.resolve_tag(self.members, "software-live-v0.3.1")

    def test_longest_member_wins(self) -> None:
        members = checks.workspace_packages(
            metadata(package("tool", "1.0.0"), package("tool-v2", "2.0.0"))
        )
        self.assertEqual(
            checks.resolve_tag(members, "tool-v2-v2.0.0"), ("tool-v2", "2.0.0")
        )
        self.assertEqual(checks.resolve_tag(members, "tool-v1.0.0"), ("tool", "1.0.0"))

    def test_rejects(self) -> None:
        cases = {
            "metrics-httpd-v0.1.1": "does not match the metrics-httpd version",
            "metrics-httpd-v0.1": "is not semver",
            "metrics-httpd-v0.1.0+build.5": "is not semver",
            "metrics-httpd-v00.1.0": "is not semver",
            "metrics-httpd-0.1.0": "matches no workspace member",
            "v0.1.0": "matches no workspace member",
            "0.1.0": "matches no workspace member",
            "serde-v1.0.0": "matches no workspace member",
            "rs-v0.1.0": "matches no workspace member",
            "metrics-httpd-v": "is not semver",
        }
        for tag, message in cases.items():
            with self.subTest(tag), self.assertRaisesRegex(
                checks.CheckError, re.escape(message)
            ):
                checks.resolve_tag(self.members, tag)

    def test_member_needs_a_binary_of_its_name(self) -> None:
        members = checks.workspace_packages(
            metadata(
                package("lib-only", bins=()), package("other", bins=("other-cli",))
            )
        )
        for tag in ("lib-only-v0.1.0", "other-v0.1.0"):
            with self.subTest(tag), self.assertRaisesRegex(
                checks.CheckError, "has no binary"
            ):
                checks.resolve_tag(members, tag)

    def test_crate_version_must_be_semver(self) -> None:
        members = checks.workspace_packages(metadata(package("metrics-httpd", "0.1")))
        with self.assertRaisesRegex(checks.CheckError, "not semver"):
            checks.release_crate(members, "metrics-httpd")

    def test_crate_by_name(self) -> None:
        self.assertEqual(
            checks.release_crate(self.members, "software-live"),
            ("software-live", "0.3.0"),
        )
        with self.assertRaisesRegex(checks.CheckError, "not a workspace member"):
            checks.release_crate(self.members, "serde")

    def test_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metadata.json"
            path.write_text(json.dumps(SOFTWARE_LIVE), encoding="utf-8")
            result = run_script(
                "tag", "--metadata", str(path), "--tag", "software-live-v0.1.0"
            )
            self.assertEqual(
                (result.returncode, result.stdout),
                (0, "crate=software-live\nversion=0.1.0\n"),
            )
            result = run_script(
                "tag", "--metadata", str(path), "--crate", "metrics-httpd"
            )
            self.assertEqual(
                (result.returncode, result.stdout),
                (0, "crate=metrics-httpd\nversion=0.2.0\n"),
            )
            result = run_script(
                "tag", "--metadata", str(path), "--tag", "metrics-httpd-v0.3.0"
            )
            self.assertEqual((result.returncode, result.stdout), (1, ""))
            self.assertIn(
                "release check failed: tag 'metrics-httpd-v0.3.0'", result.stderr
            )
            result = run_script(
                "tag", "--metadata", str(path), "--tag", "echoport-command-guard-v0.1.0"
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("matches no workspace member", result.stderr)
            self.assertEqual(run_script("tag", "--metadata", str(path)).returncode, 2)


class MatrixTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = RepoTree()
        self.addCleanup(self.repo.cleanup)

    def entries(
        self,
        settings: dict | None,
        data: dict = SOFTWARE_LIVE,
        crate: str = "software-live",
    ):
        version = checks.workspace_packages(data)[crate]["version"]
        return checks.variant_entries(
            data,
            crate,
            version,
            settings,
            self.repo.root,
            checks.ci_excluded_members(data),
        )

    def test_defaults_without_release_json(self) -> None:
        (entry,) = self.entries(None, crate="metrics-httpd")
        self.assertEqual(
            entry,
            {
                "crate": "metrics-httpd",
                "version": "0.2.0",
                "variant": "",
                "image": "",
                "packages": "",
                "build_args": "-p metrics-httpd",
                "container_checks": "",
                "commit_env": "METRICS_HTTPD_GIT_COMMIT",
                "binaries": [
                    {
                        "name": "metrics-httpd",
                        "glibc_max": "2.35",
                        "needed": sorted(checks.BASE_NEEDED),
                        "extra_smoke": [],
                    }
                ],
                "files": [{"source": "rust/LICENSE", "name": "LICENSE"}],
                "archive": f"metrics-httpd-0.2.0-{TARGET}.tar.gz",
                "artifact": f"metrics-httpd-0.2.0-{TARGET}",
            },
        )
        self.assertEqual(
            self.entries({"variants": [{}]}, crate="metrics-httpd"), [entry]
        )

    def test_two_variant_fixture_yields_one_archive_per_variant(self) -> None:
        settings = json.loads(TWO_VARIANTS.read_text(encoding="utf-8"))
        entries = self.entries(settings)
        self.assertEqual(
            [entry["archive"] for entry in entries],
            [
                f"software-live-0.1.0-{TARGET}-ubuntu24.04.tar.gz",
                f"software-live-0.1.0-{TARGET}-debian13.tar.gz",
            ],
        )
        ubuntu, debian = entries
        self.assertEqual(
            (ubuntu["image"], debian["image"]), ("ubuntu:24.04", "debian:13")
        )
        self.assertEqual(ubuntu["packages"], "libapt-pkg-dev g++")
        self.assertEqual(ubuntu["build_args"], "-p software-live -p software-live-apt")
        # The CI-excluded helper is linted and tested inside the image.
        self.assertEqual(ubuntu["container_checks"], "-p software-live-apt")
        self.assertEqual(
            ubuntu["commit_env"],
            "SOFTWARE_LIVE_GIT_COMMIT SOFTWARE_LIVE_APT_GIT_COMMIT",
        )
        main, helper = ubuntu["binaries"]
        self.assertEqual(
            (main["glibc_max"], main["needed"]), ("2.35", sorted(checks.BASE_NEEDED))
        )
        self.assertEqual(helper["glibc_max"], "2.39")
        self.assertEqual(
            set(helper["needed"]) - checks.BASE_NEEDED,
            {"libapt-pkg.so.6.0", "libstdc++.so.6"},
        )
        self.assertEqual(helper["extra_smoke"], [["--help"]])
        self.assertIn("libapt-pkg.so.7.0", debian["binaries"][1]["needed"])
        self.assertNotIn("libapt-pkg.so.6.0", debian["binaries"][1]["needed"])
        self.assertEqual(
            [item["name"] for item in debian["files"]], ["LICENSE", "LICENSE.GPL-3.0"]
        )
        # The matrix is plain JSON (it travels through a job output).
        self.assertEqual(json.loads(json.dumps(entries)), entries)

    def test_rejects(self) -> None:
        base = {
            "name": "a",
            "image": "ubuntu:24.04",
            "build": ["software-live", "software-live-apt"],
        }

        def variant(**changes: object) -> dict:
            result = dict(base, **changes)
            return {"variants": [{k: v for k, v in result.items() if v is not None}]}

        cases = {
            "not an object": ([], "must be a JSON object"),
            "unknown top-level key": ({"variants": [{}], "x": 1}, "unknown key"),
            "no variants": ({"variants": []}, "non-empty list"),
            "unknown variant key": (variant(arch="arm64"), "unknown key"),
            "unnamed among several": (
                {"variants": [{"name": "a"}, {"image": "debian:13"}]},
                "needs a name",
            ),
            "duplicate names": ({"variants": [{"name": "a"}, {"name": "a"}]}, "unique"),
            "bad name": (variant(name="Ubuntu 24"), "not a valid variant name"),
            "bad image": (variant(image="ubuntu:24.04; rm -rf /"), "not a valid image"),
            "packages without image": (
                {"variants": [{"packages": ["g++"]}]},
                "packages need an image",
            ),
            "bad package": (variant(packages=["g++ ; x"]), "not a valid apt package"),
            "duplicate package": (variant(packages=["g++", "g++"]), "twice"),
            "build without the crate": (
                variant(build=["software-live-apt"]),
                "must include",
            ),
            "build of a non-member": (
                variant(build=["software-live", "serde"]),
                "not a workspace",
            ),
            "excluded member on the runner": (
                variant(image=None),
                "only be built inside",
            ),
            "binary not built": (
                variant(
                    build=["software-live"],
                    binaries=[{"name": "software-live"}, {"name": "software-live-apt"}],
                ),
                "not a binary of the build members",
            ),
            "crate binary missing": (
                variant(binaries=[{"name": "software-live-apt"}]),
                "binaries must include",
            ),
            "no binaries": (variant(binaries=[]), "non-empty list"),
            "unknown binary key": (
                variant(binaries=[{"name": "software-live", "needed": []}]),
                "unknown key",
            ),
            "bad glibc ceiling": (
                variant(binaries=[{"name": "software-live", "glibc_max": "2.x"}]),
                "not a glibc version",
            ),
            "glibc ceiling not a string": (
                variant(binaries=[{"name": "software-live", "glibc_max": 2.35}]),
                "must be a string",
            ),
            "bad soname": (
                variant(binaries=[{"name": "software-live", "extra_needed": ["apt"]}]),
                "not a valid soname",
            ),
            "bad extra smoke": (
                variant(
                    binaries=[{"name": "software-live", "extra_smoke": ["--help"]}]
                ),
                "argument lists",
            ),
            "absolute source": (
                variant(files=[{"source": "/etc/passwd", "name": "LICENSE"}]),
                "relative to the repository root",
            ),
            "source outside": (
                variant(files=[{"source": "rust/../../x", "name": "LICENSE"}]),
                "relative to the repository root",
            ),
            "missing source": (
                variant(files=[{"source": "rust/NOTICE", "name": "NOTICE"}]),
                "not a regular file",
            ),
            "directory source": (
                variant(files=[{"source": "rust", "name": "rust"}]),
                "not a regular file",
            ),
            "member name with a slash": (
                variant(files=[{"source": "rust/LICENSE", "name": "doc/LICENSE"}]),
                "plain file name",
            ),
            "duplicate member": (
                variant(files=[{"source": "rust/LICENSE", "name": "software-live"}]),
                "unique",
            ),
            "unknown file key": (
                variant(
                    files=[{"source": "rust/LICENSE", "name": "LICENSE", "mode": 420}]
                ),
                "unknown key",
            ),
        }
        for name, (settings, message) in cases.items():
            with self.subTest(name), self.assertRaisesRegex(
                checks.CheckError, re.escape(message)
            ):
                self.entries(settings)

    def test_symlinked_source_is_rejected(self) -> None:
        (self.repo.root / "rust" / "LINK").symlink_to(
            self.repo.root / "rust" / "LICENSE"
        )
        with self.assertRaisesRegex(checks.CheckError, "not a regular file"):
            self.entries(
                {"variants": [{"files": [{"source": "rust/LINK", "name": "LICENSE"}]}]},
                crate="metrics-httpd",
            )

    def test_ci_exclude_list_is_validated(self) -> None:
        data = metadata(package("metrics-httpd"), ci={"ci": {"exclude": ["nope"]}})
        with self.assertRaisesRegex(checks.CheckError, "non-members"):
            checks.ci_excluded_members(data)

    def test_cli_reads_release_json_next_to_the_manifest(self) -> None:
        crate_dir = self.repo.root / "rust" / "software-live"
        crate_dir.mkdir()
        shutil.copy(TWO_VARIANTS, crate_dir / "release.json")
        data = json.loads(
            json.dumps(SOFTWARE_LIVE).replace("/w/rust", str(self.repo.root / "rust"))
        )
        path = self.repo.root / "metadata.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        result = run_script(
            "matrix", "--metadata", str(path), "--crate", "software-live"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            result.stdout.startswith("matrix=") and result.stdout.count("\n") == 1
        )
        matrix = json.loads(result.stdout[len("matrix=") :])
        self.assertEqual(
            [entry["variant"] for entry in matrix["include"]],
            ["ubuntu24.04", "debian13"],
        )
        result = run_script(
            "matrix", "--metadata", str(path), "--crate", "metrics-httpd"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        (entry,) = json.loads(result.stdout[len("matrix=") :])["include"]
        self.assertEqual(entry["archive"], f"metrics-httpd-0.2.0-{TARGET}.tar.gz")
        (crate_dir / "release.json").write_text("{not json", encoding="utf-8")
        result = run_script(
            "matrix", "--metadata", str(path), "--crate", "software-live"
        )
        self.assertEqual((result.returncode, result.stdout), (1, ""))
        self.assertIn("not valid JSON", result.stderr)

    @unittest.skipUnless(shutil.which("cargo"), "cargo not on PATH")
    def test_real_workspace(self) -> None:
        """The committed workspace: every releasable crate yields a valid matrix."""
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--locked",
                "--offline",
            ],
            cwd=RUST,
            env=dict(os.environ, CARGO_TERM_COLOR="never"),
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        members = checks.workspace_packages(data)
        self.assertIn("metrics-httpd", members)
        for crate in RELEASE_CRATES:
            if crate not in members:
                continue
            with self.subTest(crate):
                _, version = checks.release_crate(members, crate)
                entries = checks.variant_entries(
                    data,
                    crate,
                    version,
                    checks.load_settings(
                        checks.crate_directory(data, crate) / "release.json"
                    ),
                    REPO,
                    checks.ci_excluded_members(data),
                )
                self.assertTrue(entries)


class GlibcTest(unittest.TestCase):
    def test_accepts_the_ubuntu_22_04_build(self) -> None:
        self.assertEqual(
            checks.glibc_versions(OBJDUMP_OK), {"2.2.5", "2.14", "2.18", "2.34", "2.35"}
        )
        self.assertEqual(
            checks.needed_libraries(OBJDUMP_OK),
            ["libgcc_s.so.1", "libm.so.6", "libc.so.6", "ld-linux-x86-64.so.2"],
        )
        self.assertEqual(checks.check_glibc(OBJDUMP_OK, "2.35"), "2.35")

    def test_compares_numerically(self) -> None:
        text = OBJDUMP_OK.replace("GLIBC_2.35", "GLIBC_2.4")
        with self.assertRaisesRegex(
            checks.CheckError, re.escape("newer than 2.14: GLIBC_2.18, GLIBC_2.34")
        ):
            checks.check_glibc(text, "2.14")
        self.assertEqual(checks.check_glibc(text, "2.34"), "2.34")

    def test_rejects_newer_or_private_versions(self) -> None:
        for symbol, message in (
            ("GLIBC_2.36", "newer than 2.35: GLIBC_2.36"),
            ("GLIBC_2.39", "newer than 2.35: GLIBC_2.39"),
            ("GLIBC_PRIVATE", "unexpected glibc symbol version GLIBC_PRIVATE"),
        ):
            text = (
                OBJDUMP_OK
                + f"0000000000000000      DF *UND*\t0000000000000000 ({symbol}) foo\n"
            )
            with self.subTest(symbol), self.assertRaisesRegex(
                checks.CheckError, re.escape(message)
            ):
                checks.check_glibc(text, "2.35")

    def test_rejects_foreign_libraries_and_static_binaries(self) -> None:
        with self.assertRaisesRegex(
            checks.CheckError, re.escape("allowlist: libssl.so.3")
        ):
            checks.check_glibc(
                OBJDUMP_OK + "  NEEDED               libssl.so.3\n", "2.35"
            )
        without_needed = "\n".join(
            line for line in OBJDUMP_OK.splitlines() if "NEEDED" not in line
        )
        with self.assertRaisesRegex(checks.CheckError, "no NEEDED entries"):
            checks.check_glibc(without_needed, "2.35")
        with self.assertRaisesRegex(checks.CheckError, "no GLIBC symbol versions"):
            checks.check_glibc("statically linked\n", "2.35")
        with self.assertRaisesRegex(checks.CheckError, "not a glibc version"):
            checks.check_glibc(OBJDUMP_OK, "2.35a")

    def test_per_binary_needed_allowlists(self) -> None:
        """The two-variant fixture: libapt only for the helper, only its soname."""
        repo = RepoTree()
        self.addCleanup(repo.cleanup)
        settings = json.loads(TWO_VARIANTS.read_text(encoding="utf-8"))
        ubuntu, debian = checks.variant_entries(
            SOFTWARE_LIVE,
            "software-live",
            "0.1.0",
            settings,
            repo.root,
            ["software-live-apt"],
        )
        apt = OBJDUMP_OK.replace("GLIBC_2.35", "GLIBC_2.38") + APT_NEEDED
        main, helper = (frozenset(binary["needed"]) for binary in ubuntu["binaries"])
        self.assertEqual(checks.check_glibc(apt, "2.39", helper), "2.38")
        with self.assertRaisesRegex(checks.CheckError, "libapt-pkg.so.6.0, libstdc"):
            checks.check_glibc(apt, "2.39", main)
        with self.assertRaisesRegex(checks.CheckError, "allowlist: libapt-pkg.so.6.0"):
            checks.check_glibc(apt, "2.41", frozenset(debian["binaries"][1]["needed"]))
        # The main binary keeps the 2.35 ceiling even inside the image.
        with self.assertRaisesRegex(checks.CheckError, "newer than 2.35: GLIBC_2.38"):
            checks.check_glibc(apt, ubuntu["binaries"][0]["glibc_max"], helper)


# A stand-in for a release binary: `--version` as build.rs embeds it, extra
# smoke commands that check the empty environment and working directory.
FAKE_BINARY = """#!/bin/sh
case "$1" in
--version) echo '{name} {version} ({commit})' ;;
--env-empty) [ -z "${{HOME+x}}" ] && [ -z "$(ls -A .)" ] && echo "clean" ;;
--fail) echo "boom" >&2; exit 3 ;;
*) exit 2 ;;
esac
"""

FAKE_OBJDUMP = """#!/bin/sh
case "$1" in
-T|-p) cat "$OBJDUMP_FIXTURE" ;;
*) exit 2 ;;
esac
"""


def fake_binary(directory: Path, name: str, version: str = "0.1.0") -> Path:
    path = directory / name
    path.write_text(
        FAKE_BINARY.format(name=name, version=version, commit=COMMIT), encoding="utf-8"
    )
    path.chmod(0o755)
    return path


@unittest.skipUnless(os.name == "posix", "POSIX shell script fakes")
class SmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.binary = fake_binary(self.dir, "metrics-httpd")

    def test_version_line_must_name_binary_version_and_commit(self) -> None:
        checks.check_version_output(
            f"metrics-httpd 0.1.0 ({COMMIT})\n", "metrics-httpd", "0.1.0", COMMIT
        )
        for stdout in (
            "metrics-httpd 0.1.0\n",
            f"metrics-httpd 0.1.0 ({COMMIT})",
            "metrics-httpd 0.1.0 (unknown)\n",
            f"metrics-httpd 0.1.0 ({COMMIT[:12]})\n",
            f"metrics-httpd 0.1.1 ({COMMIT})\n",
            f"software-live 0.1.0 ({COMMIT})\n",
        ):
            with self.subTest(stdout), self.assertRaisesRegex(
                checks.CheckError, "--version printed"
            ):
                checks.check_version_output(stdout, "metrics-httpd", "0.1.0", COMMIT)

    def test_cli_smoke(self) -> None:
        base = ["smoke", "--binary", str(self.binary), "--version"]
        result = run_script(*base, "0.1.0", "--commit", COMMIT)
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr),
            (0, f"metrics-httpd 0.1.0 ({COMMIT})\n", ""),
        )
        result = run_script(
            *base, "0.1.0", "--commit", COMMIT, "--extra", '["--env-empty"]'
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(
            result.stdout.endswith("$ metrics-httpd --env-empty\nclean\n"),
            result.stdout,
        )
        result = run_script(*base, "0.1.0", "--commit", COMMIT, "--extra", '["--fail"]')
        self.assertEqual(result.returncode, 1)
        self.assertIn("metrics-httpd --fail exited 3", result.stderr)
        for extra in ('"--fail"', "[1]", "not json"):
            with self.subTest(extra):
                result = run_script(
                    *base, "0.1.0", "--commit", COMMIT, "--extra", extra
                )
                self.assertEqual(result.returncode, 1)
        self.assertEqual(run_script(*base, "0.1.1", "--commit", COMMIT).returncode, 1)
        result = run_script(*base, "0.1.0", "--commit", COMMIT[:12])
        self.assertEqual(result.returncode, 1)
        self.assertIn("40 lowercase hex digits", result.stderr)
        result = run_script(*base, "0.1.0", "--commit", COMMIT, "--name", "other")
        self.assertEqual(result.returncode, 1)

    def test_cli_glibc_floor_and_verify_with_a_fake_objdump(self) -> None:
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        objdump = bin_dir / "objdump"
        objdump.write_text(FAKE_OBJDUMP, encoding="utf-8")
        objdump.chmod(0o755)
        fixture = self.dir / "objdump.txt"
        fixture.write_text(OBJDUMP_OK + APT_NEEDED, encoding="utf-8")
        env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "OBJDUMP_FIXTURE": str(fixture)}
        result = run_script("glibc-floor", str(self.binary), env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("libapt-pkg.so.6.0, libstdc++.so.6", result.stderr)
        result = run_script(
            "glibc-floor",
            "--allow",
            "libapt-pkg.so.6.0",
            "--allow",
            "libstdc++.so.6",
            str(self.binary),
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "newest glibc symbol version GLIBC_2.35 (ceiling 2.35)", result.stdout
        )
        self.assertEqual(
            run_script(
                "glibc-floor", "--max", "2.34", str(self.binary), env=env
            ).returncode,
            1,
        )
        self.assertEqual(
            run_script(
                "glibc-floor", "--allow", "x", str(self.binary), env=env
            ).returncode,
            1,
        )

        repo = RepoTree()
        self.addCleanup(repo.cleanup)
        settings = json.loads(TWO_VARIANTS.read_text(encoding="utf-8"))
        ubuntu, _ = checks.variant_entries(
            SOFTWARE_LIVE,
            "software-live",
            "0.1.0",
            settings,
            repo.root,
            ["software-live-apt"],
        )
        release = self.dir / "release"
        release.mkdir()
        fake_binary(release, "software-live")
        fake_binary(release, "software-live-apt")
        ubuntu["binaries"][1]["extra_smoke"] = [["--env-empty"]]
        args = [
            "verify",
            "--entry",
            json.dumps(ubuntu),
            "--bin-dir",
            str(release),
            "--commit",
            COMMIT,
        ]
        # The main binary has no libapt allowance.
        result = run_script(*args, env=env)
        self.assertEqual(result.returncode, 1)
        self.assertIn("allowlist: libapt-pkg.so.6.0", result.stderr)
        fixture.write_text(OBJDUMP_OK, encoding="utf-8")
        result = run_script(*args, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count("NEEDED within the allowlist"), 2)
        self.assertIn(
            f"software-live-apt 0.1.0 ({COMMIT})\n$ software-live-apt --env-empty\nclean\n",
            result.stdout,
        )
        fake_binary(release, "software-live-apt", version="0.0.9")
        self.assertEqual(run_script(*args, env=env).returncode, 1)


class PackTest(unittest.TestCase):
    def test_archive_is_deterministic(self) -> None:
        members = {
            "metrics-httpd": (b"\x7fELF binary", 0o755),
            "LICENSE": (b"MIT License\n", 0o644),
        }
        first = checks.build_archive(members, 1_700_000_000)
        self.assertEqual(
            first,
            checks.build_archive(dict(reversed(list(members.items()))), 1_700_000_000),
        )
        self.assertNotEqual(first, checks.build_archive(members, 1_700_000_001))
        checks.verify_archive(first, members)
        # gzip header: no FNAME flag, the given mtime.
        self.assertEqual(first[3] & 0x08, 0)
        self.assertEqual(int.from_bytes(first[4:8], "little"), 1_700_000_000)
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            found = archive.getmembers()
        self.assertEqual(
            [member.name for member in found], ["LICENSE", "metrics-httpd"]
        )
        self.assertTrue(all(member.isreg() for member in found))
        self.assertEqual(
            {m.name: m.mode for m in found}, {"LICENSE": 0o644, "metrics-httpd": 0o755}
        )
        self.assertEqual(
            {(m.uid, m.gid, m.uname, m.gname, m.mtime) for m in found},
            {(0, 0, "root", "root", 1_700_000_000)},
        )
        with self.assertRaisesRegex(checks.CheckError, "differs from its source"):
            checks.verify_archive(first, dict(members, LICENSE=(b"other", 0o644)))
        with self.assertRaisesRegex(checks.CheckError, "has mode"):
            checks.verify_archive(
                first, dict(members, LICENSE=(b"MIT License\n", 0o600))
            )
        with self.assertRaisesRegex(checks.CheckError, "archive members"):
            checks.verify_archive(first, {"metrics-httpd": members["metrics-httpd"]})
        self.assertEqual(
            gzip.decompress(first),
            gzip.decompress(checks.build_archive(members, 1_700_000_000)),
        )

    def test_cli_pack_of_a_matrix_entry(self) -> None:
        repo = RepoTree()
        self.addCleanup(repo.cleanup)
        settings = json.loads(TWO_VARIANTS.read_text(encoding="utf-8"))
        _, debian = checks.variant_entries(
            SOFTWARE_LIVE,
            "software-live",
            "0.1.0",
            settings,
            repo.root,
            ["software-live-apt"],
        )
        bin_dir = repo.root / "rust" / "target" / TARGET / "release"
        bin_dir.mkdir(parents=True)
        (bin_dir / "software-live").write_bytes(b"main")
        (bin_dir / "software-live-apt").write_bytes(b"helper")
        outputs = []
        for run in ("a", "b"):
            out = repo.root / run
            result = run_script(
                "pack",
                "--entry",
                json.dumps(debian),
                "--bin-dir",
                str(bin_dir),
                "--repo-root",
                str(repo.root),
                "--mtime",
                "1700000000",
                "--out-dir",
                str(out),
            )
            name = f"software-live-0.1.0-{TARGET}-debian13.tar.gz"
            self.assertEqual(
                (result.returncode, result.stdout), (0, f"{name}\n"), result.stderr
            )
            data = (out / name).read_bytes()
            self.assertEqual(
                (out / f"{name}.sha256").read_text(encoding="utf-8"),
                f"{hashlib.sha256(data).hexdigest()}  {name}\n",
            )
            outputs.append(data)
        self.assertEqual(outputs[0], outputs[1])
        with tarfile.open(fileobj=io.BytesIO(outputs[0]), mode="r:gz") as archive:
            found = {
                m.name: (m.mode, archive.extractfile(m).read())
                for m in archive.getmembers()
            }
        self.assertEqual(
            found,
            {
                "LICENSE": (0o644, b"MIT License\n"),
                "LICENSE.GPL-3.0": (0o644, b"GNU GENERAL PUBLIC LICENSE\n"),
                "software-live": (0o755, b"main"),
                "software-live-apt": (0o755, b"helper"),
            },
        )
        (bin_dir / "software-live-apt").unlink()
        result = run_script(
            "pack",
            "--entry",
            json.dumps(debian),
            "--bin-dir",
            str(bin_dir),
            "--repo-root",
            str(repo.root),
            "--mtime",
            "1700000000",
            "--out-dir",
            str(repo.root / "c"),
        )
        self.assertNotEqual(result.returncode, 0)
        result = run_script(
            "pack",
            "--entry",
            "{}",
            "--bin-dir",
            str(bin_dir),
            "--repo-root",
            str(repo.root),
            "--mtime",
            "1",
            "--out-dir",
            str(repo.root / "d"),
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("matrix entry has no", result.stderr)


class WorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def section(self, start: str, end: str) -> str:
        return self.text.split(start, 1)[1].split(end, 1)[0]

    def test_triggers_are_the_three_tag_prefixes(self) -> None:
        tags = re.findall(
            r'^      - "([^"]+)"$',
            self.section("    tags:\n", "  workflow_dispatch:"),
            re.M,
        )
        self.assertEqual(tags, [f"{crate}-v*" for crate in RELEASE_CRATES])
        options = re.findall(
            r"^          - (\S+)$",
            self.section("        options:\n", "\npermissions:"),
            re.M,
        )
        self.assertEqual(options, list(RELEASE_CRATES))

    def test_runs_every_check(self) -> None:
        for needle in (
            "runs-on: ubuntu-22.04",
            f"TARGET: {TARGET}",
            "release_checks.py tag",
            "release_checks.py matrix",
            "release_checks.py verify",
            "release_checks.py pack",
            "scripts/ci_excludes.py",
            "cargo fmt --check",
            'cargo clippy --workspace "${exclude_args[@]}" --all-targets --locked -- -D warnings',
            'cargo test --workspace "${exclude_args[@]}" --locked',
            'cargo build --release --locked --target "$TARGET" "${members[@]}"',
            "container: ${{ matrix.image }}",
            "matrix: ${{ fromJSON(needs.prepare.outputs.matrix) }}",
            "git log -1 --format=%ct",
            "sha256sum --check",
            "--verify-tag",
            "--latest=false",
            "--prerelease",
            'echo "${name}=${GITHUB_SHA}"',
            "if: github.event_name == 'push' && github.ref_type == 'tag'",
            "persist-credentials: false",
        ):
            self.assertIn(needle, self.text, needle)
        self.assertNotIn("actions/cache", self.text)

    def test_only_the_publish_job_may_write(self) -> None:
        code = "\n".join(
            line for line in self.text.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertEqual(code.count("contents: write"), 1)
        self.assertIn("permissions:\n  contents: read\n", self.text)
        publish = self.text.split("\n  publish:\n", 1)[1]
        self.assertIn("    permissions:\n      contents: write\n", publish)

    def test_actions_are_pinned_by_sha(self) -> None:
        uses = re.findall(r"uses: (\S+)", self.text)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")

    def test_no_expression_is_interpolated_into_a_script(self) -> None:
        """Values reach `run:` scripts through env, never as `${{ }}` text."""
        for block in re.findall(r"run: \|\n((?:          .*\n|\n)+)", self.text):
            self.assertNotIn("${{", block)
        for line in re.findall(r"run: (?!\|)(.*)", self.text):
            self.assertNotIn("${{", line)


if __name__ == "__main__":
    unittest.main()
