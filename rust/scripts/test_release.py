"""Tests of release.py, the local release build (rust/README.md "Releases").

They replace the workflow tests of ops-library's rust-release.yml: the
container jobs run every check the workflow ran, the build phase has no
network and no mount, taken versions are refused, and `publish` and
`import-old` reach one end state without ever moving a tag or replacing an
asset. git runs for real against a local bare "origin"; docker and gh are
fakes.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

import release
import release_checks as checks

SCRIPTS = Path(__file__).resolve().parent
RUST = SCRIPTS.parent
SOFTWARE_LIVE_RELEASE = RUST / "software-live" / "release.json"


def package(name: str, version: str) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "id": f"path+file:///w/rust/{name}#{version}",
        "manifest_path": f"/w/rust/{name}/Cargo.toml",
        "targets": [{"kind": ["bin"], "name": name}],
    }


METADATA = {
    "packages": [
        package("software-live", "0.1.3"),
        package("software-live-apt", "0.1.3"),
        package("metrics-httpd", "0.1.1"),
    ],
    "workspace_members": [
        "path+file:///w/rust/software-live#0.1.3",
        "path+file:///w/rust/software-live-apt#0.1.3",
        "path+file:///w/rust/metrics-httpd#0.1.1",
    ],
    "workspace_root": "/w/rust",
    "metadata": {"ci": {"exclude": ["software-live-apt"]}},
}


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603, S607
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


class Repo:
    """A clone with a local bare origin, holding the files a build reads."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.origin = base / "origin.git"
        self.root = base / "clone"
        subprocess.run(  # noqa: S603, S607
            ["git", "init", "--quiet", "--bare", "-b", "main", str(self.origin)], check=True
        )
        subprocess.run(  # noqa: S603, S607
            ["git", "clone", "--quiet", str(self.origin), str(self.root)], check=True, capture_output=True
        )
        git(self.root, "config", "user.name", "Test")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "checkout", "--quiet", "-b", "main")
        for relative, text in (
            ("rust/LICENSE", "MIT License\n"),
            ("rust/software-live-apt/LICENSE.GPL-3.0", "GNU GENERAL PUBLIC LICENSE\n"),
            ("rust/software-live/release.json", SOFTWARE_LIVE_RELEASE.read_text(encoding="utf-8")),
            ("rust/Cargo.lock", "# lock\n"),
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        self.commit("first")
        git(self.root, "push", "--quiet", "origin", "main")
        self.git = release.Git(self.root)

    def commit(self, message: str) -> str:
        git(self.root, "add", "-A")
        git(self.root, "commit", "--quiet", "--allow-empty", "-m", message)
        return git(self.root, "rev-parse", "HEAD")

    def head(self) -> str:
        return git(self.root, "rev-parse", "HEAD")

    def cleanup(self) -> None:
        self._tmp.cleanup()


class FakeDocker:
    """Simulates the container jobs: writes what the scripts would write."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.jobs: list[dict[str, Any]] = []

    def preflight(self) -> str:
        self.calls.append(("preflight",))
        return "linux/arm64"

    def pinned(self, image: str) -> str:
        self.calls.append(("pinned", image))
        return image.split(":")[0] + "@sha256:" + hashlib.sha256(image.encode()).hexdigest()

    def build_image(self, tag: str, context: Path, platform: str) -> None:
        self.calls.append(("build_image", tag, platform, (context / "Dockerfile").read_text(encoding="utf-8")))
        with tarfile.open(context / "source.tar") as archive:
            assert "rust/LICENSE" in archive.getnames()

    def remove_image(self, tag: str) -> None:
        self.calls.append(("remove_image", tag))

    def job(
        self,
        image: str,
        name: str,
        script: str,
        env: dict[str, str],
        copy_in: dict[Path, str],
        out_dir: Path,
        platform: str = release.AMD64,
    ) -> None:
        self.jobs.append(
            {
                "image": image,
                "name": name,
                "script": script,
                "env": dict(env),
                "copy_in": dict(copy_in),
                "platform": platform,
            }
        )
        (out_dir / "versions.txt").write_text("gcc=1\nrustc 1.99.1\n", encoding="utf-8")
        if "-shared-" in name:
            entry = json.loads(env["ENTRY"])
            (out_dir / "shared").mkdir()
            sums = {}
            for binary in entry["binaries"]:
                data = f"{binary['name']} binary".encode()
                (out_dir / "shared" / binary["name"]).write_bytes(data)
                sums[binary["name"]] = hashlib.sha256(data).hexdigest()
            (out_dir / "checksums.txt").write_text("sha256=" + json.dumps(sums) + "\n", encoding="utf-8")
        elif "-prepare-" not in name:
            entry = json.loads(env["ENTRY"])
            members = {"software-live-apt": (b"apt helper", 0o755), "LICENSE": (b"MIT\n", 0o644)}
            data = checks.build_archive(members, int(env["MTIME"]))
            (out_dir / "dist").mkdir()
            (out_dir / "dist" / entry["archive"]).write_bytes(data)
            (out_dir / "dist" / f"{entry['archive']}.sha256").write_text(
                checks.checksum_line(data, entry["archive"]), encoding="utf-8"
            )


class FakeGitHub(release.GitHub):
    """Releases in memory: tag -> {asset name: bytes}."""

    def __init__(self, repository: str = "ephes/ops-deploy", releases: dict[str, dict[str, bytes]] | None = None):
        super().__init__(repository)
        self.releases: dict[str, dict[str, bytes]] = releases or {}
        self.created: list[dict[str, Any]] = []
        self.uploaded: list[list[str]] = []

    def assets(self, tag: str) -> dict[str, str] | None:
        if tag not in self.releases:
            return None
        return {name: hashlib.sha256(data).hexdigest() for name, data in self.releases[tag].items()}

    def create(self, tag: str, title: str, notes: Path, files: list[Path], prerelease: bool) -> None:
        self.created.append({"tag": tag, "title": title, "notes": notes.read_text(), "prerelease": prerelease})
        self.releases[tag] = {path.name: path.read_bytes() for path in files}

    def upload(self, tag: str, files: list[Path]) -> None:
        self.uploaded.append([path.name for path in files])
        for path in files:
            assert path.name not in self.releases[tag], "upload must never replace an asset"
            self.releases[tag][path.name] = path.read_bytes()

    def download(self, tag: str, directory: Path) -> None:
        if tag not in self.releases:
            raise release.ReleaseError(f"release not found: {tag}")
        for name, data in self.releases[tag].items():
            (directory / name).write_bytes(data)


def quiet(*_: object) -> None:
    pass


class ScriptsTest(unittest.TestCase):
    """What ops-library's workflow tests asserted, now of the container jobs."""

    def test_prepare_runs_every_workspace_check(self) -> None:
        script = release.prepare_script(list(release.BASE_PACKAGES))
        for needle in (
            "cargo fmt --check",
            "scripts/ci_excludes.py",
            "cargo clippy --workspace $excludes --all-targets --locked --offline -- -D warnings",
            "cargo test --workspace $excludes --locked --offline",
            "python3 -I -m unittest discover -s scripts -p 'test_*.py'",
            "cargo metadata --format-version 1 --locked --offline --all-features",
            "release_checks.py apt-isolation",
        ):
            self.assertIn(needle, script)

    def test_shared_builds_once_and_hands_on_checksums(self) -> None:
        script = release.shared_script([])
        self.assertIn(f"cargo build --release --locked --offline --target {checks.TARGET} $BUILD_ARGS", script)
        self.assertIn('release_checks.py verify --entry "$ENTRY"', script)
        self.assertIn("release_checks.py checksums", script)

    def test_variant_checks_shared_binaries_by_sha256_and_packs(self) -> None:
        script = release.variant_script([])
        for needle in (
            "cargo clippy $CONTAINER_CHECKS --all-targets --locked --offline -- -D warnings",
            "cargo test $CONTAINER_CHECKS --locked --offline",
            'if [ -n "$BUILD_ARGS" ]',
            '--shared-bin-dir /work/release-shared --shared-sha256 "$SHARED_SHA256"',
            "release_checks.py verify",
            '--repo-root /work --mtime "$MTIME"',
            "sha256sum --check",
        ):
            self.assertIn(needle, script)
        self.assertEqual(script.count('"${shared_args[@]}"'), 2)

    def test_dockerfile_pins_base_and_rustup_and_fetches_locked(self) -> None:
        text = release.dockerfile("debian@sha256:" + "a" * 64, ["gcc", "libapt-pkg-dev"], "linux/amd64")
        self.assertTrue(text.startswith("FROM --platform=linux/amd64 debian@sha256:"))
        triple, digest = release.RUSTUP["linux/amd64"]
        self.assertEqual(triple, checks.TARGET)
        self.assertIn(f"/{triple}/rustup-init", text)
        self.assertIn(f'echo "{digest}  /tmp/rustup-init" | sha256sum --check', text)
        arm = release.dockerfile("debian@sha256:" + "a" * 64, [], "linux/arm64")
        self.assertIn("/aarch64-unknown-linux-gnu/rustup-init", arm)
        self.assertIn("rustup toolchain install", text)
        self.assertIn("rustup default", text)
        self.assertIn("rustc --version && cargo fetch --locked", text)
        self.assertIn("apt-get install -y --no-install-recommends gcc libapt-pkg-dev", text)
        self.assertNotIn(
            "/var/lib/apt/lists",
            text.split("# The package lists stay")[1].split("RUN curl")[0].replace("# on the image", ""),
        )
        with self.assertRaises(release.ReleaseError):
            release.dockerfile("debian@sha256:x", ["gcc; rm -rf /"], "linux/amd64")
        with self.assertRaises(release.ReleaseError):
            release.dockerfile("debian@sha256:x", [], "linux/s390x")

    def test_jobs_have_no_network_no_mount_and_limits(self) -> None:
        calls: list[list[str]] = []

        def fake_run(argv: list[str], **_: Any) -> str:
            calls.append(list(argv))
            return ""

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(release, "run", fake_run),
            mock.patch.object(release.subprocess, "run"),
        ):
            release.Docker().job("img", "job", "true", {"A": "1"}, {Path("/x"): "/work/x"}, Path(directory))
        create = calls[0]
        self.assertEqual(create[:2], ["docker", "create"])
        for flag, value in (("--network", "none"), ("--memory", release.MEMORY), ("--pids-limit", release.PIDS)):
            self.assertEqual(create[create.index(flag) + 1], value)
        self.assertNotIn("-v", create)
        self.assertNotIn("--volume", create)
        self.assertNotIn("--mount", create)
        self.assertIn(["docker", "cp", "/x", "job:/work/x"], calls)
        self.assertEqual(calls[-1][:2], ["docker", "cp"])

    def test_image_packages_map_the_runner_and_variants(self) -> None:
        images = release.image_packages(
            [
                {"image": "", "packages": ""},
                {"image": "debian:13", "packages": "g++ libapt-pkg-dev"},
            ]
        )
        self.assertEqual(list(images), [release.RUNNER_IMAGE, "debian:13"])
        self.assertEqual(images["debian:13"][-2:], ["g++", "libapt-pkg-dev"])
        self.assertEqual(images[release.RUNNER_IMAGE], list(release.BASE_PACKAGES))

    def test_gh_release_create_never_latest_and_upload_never_clobbers(self) -> None:
        calls: list[list[str]] = []
        with mock.patch.object(release, "run", lambda argv, **_: calls.append(list(argv)) or ""):
            github = release.GitHub("ephes/ops-deploy")
            github.create("x-v1.0.0-rc.1", "x 1.0.0-rc.1", Path("n.md"), [Path("a.tar.gz")], True)
            github.upload("x-v1.0.0", [Path("a.tar.gz")])
        self.assertIn("--verify-tag", calls[0])
        self.assertIn("--latest=false", calls[0])
        self.assertIn("--prerelease", calls[0])
        self.assertNotIn("--clobber", calls[1])


class ReleasesJsonTest(unittest.TestCase):
    def test_the_eight_old_releases(self) -> None:
        data = release.load_old_releases()
        tags = [entry["tag"] for entry in data["releases"]]
        self.assertEqual(len(tags), 8)
        self.assertEqual(len(set(tags)), 8)
        for entry in data["releases"]:
            self.assertRegex(entry["commit"], r"^[0-9a-f]{40}$")
            self.assertRegex(entry["ops_library_commit"], r"^[0-9a-f]{40}$")
            names = {asset["name"] for asset in entry["assets"]}
            archives = {name for name in names if name.endswith(".tar.gz")}
            self.assertTrue(archives)
            self.assertEqual(names, archives | {f"{name}.sha256" for name in archives})
            for archive in archives:
                self.assertTrue(archive.startswith(f"{entry['crate']}-{entry['version']}-{checks.TARGET}"))


class BuildTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()
        self.addCleanup(self.repo.cleanup)
        self.out = self.repo.root.parent / "out"
        self.docker = FakeDocker()

    def build(self, crate: str = "software-live", compare: bool = False, taken: set | None = None) -> Path:
        return release.build(
            crate,
            compare,
            self.out,
            git=self.repo.git,
            docker=self.docker,  # type: ignore[arg-type]
            metadata=METADATA,
            taken=taken if taken is not None else set(),
            log=quiet,
        )

    def assertRefused(self, message: str, **kwargs: Any) -> None:  # noqa: N802
        with self.assertRaisesRegex(release.ReleaseError, message):
            self.build(**kwargs)
        self.assertEqual(self.docker.calls, [], "refused before any container")

    def test_refuses_a_dirty_worktree(self) -> None:
        (self.repo.root / "untracked").write_text("x")
        self.assertRefused("clean checkout")

    def test_refuses_a_commit_not_on_origin_main(self) -> None:
        self.repo.commit("local only")
        self.assertRefused("is not on origin/main")

    def test_refuses_a_version_in_releases_json(self) -> None:
        self.assertRefused("already released", taken={("software-live", "0.1.3")})

    def test_refuses_a_version_whose_tag_is_on_origin(self) -> None:
        git(self.repo.root, "tag", "software-live-v0.1.3")
        git(self.repo.root, "push", "--quiet", "origin", "software-live-v0.1.3")
        self.assertRefused("already released")

    def test_compare_released_needs_a_released_version(self) -> None:
        self.assertRefused("not released", compare=True)

    def test_refuses_a_non_empty_output_directory(self) -> None:
        self.out.mkdir()
        (self.out / "old").write_text("x")
        self.assertRefused("not empty")

    def test_builds_shared_once_and_every_variant(self) -> None:
        out = self.build()
        commit = self.repo.head()
        self.assertEqual(self.docker.calls[0], ("preflight",))
        images = [call[1] for call in self.docker.calls if call[0] == "pinned"]
        self.assertEqual(images, [release.RUNNER_IMAGE, "ubuntu:24.04", "debian:13"])
        platforms = [call[2] for call in self.docker.calls if call[0] == "build_image"]
        self.assertEqual(platforms, ["linux/arm64", "linux/amd64", "linux/amd64", "linux/amd64"])
        # The workspace checks run natively; every release binary is built and
        # smoke-tested as linux/amd64.
        self.assertEqual([job["platform"] for job in self.docker.jobs], ["linux/arm64"] + ["linux/amd64"] * 3)
        self.assertEqual(len({job["image"] for job in self.docker.jobs}), 4)
        names = [job["name"].removeprefix("release-software-live-").rsplit("-", 1)[0] for job in self.docker.jobs]
        self.assertEqual(names, ["prepare", "shared", "ubuntu24.04", "debian13"])
        shared = self.docker.jobs[1]
        self.assertEqual(shared["env"]["BUILD_ARGS"], "-p software-live")
        sums = {"software-live": hashlib.sha256(b"software-live binary").hexdigest()}
        for job in self.docker.jobs[2:]:
            self.assertEqual(json.loads(job["env"]["SHARED_SHA256"]), sums)
            self.assertEqual(list(job["copy_in"].values()), ["/work/release-shared"])
            self.assertEqual(job["env"]["CONTAINER_CHECKS"], "-p software-live-apt")
        for job in self.docker.jobs:
            self.assertEqual(job["env"]["COMMIT"], commit)
            self.assertEqual(job["env"]["SOFTWARE_LIVE_GIT_COMMIT"], commit)
        record = json.loads((out / "build.json").read_text())
        self.assertFalse(record["compare_released"])
        self.assertEqual(record["commit"], commit)
        self.assertEqual(
            sorted(record["archives"]),
            [
                f"software-live-0.1.3-{checks.TARGET}-debian13.tar.gz",
                f"software-live-0.1.3-{checks.TARGET}-ubuntu24.04.tar.gz",
            ],
        )
        notes = (out / "notes.md").read_text()
        self.assertIn(f"built from {commit}", notes)
        self.assertIn("rustc 1.99.1", notes)
        removed = [call[1] for call in self.docker.calls if call[0] == "remove_image"]
        self.assertEqual(len(removed), 4)

    def test_compare_released_build_is_marked(self) -> None:
        out = self.build(compare=True, taken={("software-live", "0.1.3")})
        self.assertTrue(json.loads((out / "build.json").read_text())["compare_released"])


class PublishTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()
        self.addCleanup(self.repo.cleanup)
        self.out = self.repo.root.parent / "out"
        release.build(
            "software-live",
            False,
            self.out,
            git=self.repo.git,
            docker=FakeDocker(),  # type: ignore[arg-type]
            metadata=METADATA,
            taken=set(),
            log=quiet,
        )
        self.github = FakeGitHub()

    def publish(self, taken: set | None = None) -> None:
        release.publish(
            "software-live", self.out, git=self.repo.git, github=self.github, taken=taken or set(), log=quiet
        )

    def remote_tag(self) -> str:
        return git(self.repo.origin, "rev-parse", "software-live-v0.1.3^{commit}")

    def test_tags_publishes_and_is_repeatable(self) -> None:
        self.publish()
        self.assertEqual(self.remote_tag(), self.repo.head())
        self.assertEqual(len(self.github.created), 1)
        created = self.github.created[0]
        self.assertEqual(created["title"], "software-live 0.1.3")
        self.assertFalse(created["prerelease"])
        self.assertEqual(len(self.github.releases["software-live-v0.1.3"]), 4)
        self.publish()
        self.assertEqual(len(self.github.created), 1)
        self.assertEqual(self.github.uploaded, [])

    def test_default_directory_is_the_current_version(self) -> None:
        """Without --out-dir: the build of the crate's current version, never
        an older build or a dry run lying next to it."""
        seen = []

        def default_out_dir(crate: str, version: str) -> Path:
            seen.append((crate, version))
            return self.out

        with mock.patch.object(release, "default_out_dir", default_out_dir):
            release.publish(
                "software-live", git=self.repo.git, github=self.github, taken=set(), log=quiet, metadata=METADATA
            )
        self.assertEqual(seen, [("software-live", "0.1.3")])
        self.assertIn("software-live-v0.1.3", self.github.releases)

    def test_uploads_only_missing_assets(self) -> None:
        self.publish()
        name = next(name for name in self.github.releases["software-live-v0.1.3"] if name.endswith(".sha256"))
        del self.github.releases["software-live-v0.1.3"][name]
        self.publish()
        self.assertEqual(self.github.uploaded, [[name]])

    def test_refuses_an_asset_with_other_bytes(self) -> None:
        self.publish()
        name = next(iter(self.github.releases["software-live-v0.1.3"]))
        self.github.releases["software-live-v0.1.3"][name] = b"other"
        with self.assertRaisesRegex(release.ReleaseError, "has sha256"):
            self.publish()

    def test_refuses_an_unexpected_asset(self) -> None:
        self.publish()
        self.github.releases["software-live-v0.1.3"]["extra.tar.gz"] = b"x"
        with self.assertRaisesRegex(release.ReleaseError, "should not have"):
            self.publish()

    def test_refuses_a_tag_on_another_commit(self) -> None:
        git(self.repo.root, "tag", "software-live-v0.1.3", "HEAD")
        self.repo.commit("next")
        git(self.repo.root, "push", "--quiet", "origin", "main")
        git(self.repo.root, "push", "--quiet", "origin", "software-live-v0.1.3")
        record = json.loads((self.out / "build.json").read_text())
        record["commit"] = self.repo.head()
        (self.out / "build.json").write_text(json.dumps(record))
        with self.assertRaisesRegex(release.ReleaseError, "points at"):
            self.publish()
        self.assertEqual(self.github.created, [])

    def test_refuses_a_compare_released_build(self) -> None:
        record = json.loads((self.out / "build.json").read_text())
        record["compare_released"] = True
        (self.out / "build.json").write_text(json.dumps(record))
        with self.assertRaisesRegex(release.ReleaseError, "dry run"):
            self.publish()

    def test_refuses_a_version_in_releases_json(self) -> None:
        with self.assertRaisesRegex(release.ReleaseError, "never rebuilt"):
            self.publish(taken={("software-live", "0.1.3")})

    def test_refuses_a_changed_archive_and_extra_files(self) -> None:
        (self.out / "stray.txt").write_text("x")
        with self.assertRaisesRegex(release.ReleaseError, "not part of the release"):
            self.publish()
        (self.out / "stray.txt").unlink()
        archive = next(self.out.glob("*.tar.gz"))
        archive.write_bytes(b"changed")
        with self.assertRaisesRegex(release.ReleaseError, "does not name sha256"):
            self.publish()
        self.assertFalse(git(self.repo.origin, "tag", "--list"))


class ImportOldTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()
        self.addCleanup(self.repo.cleanup)
        self.commit = self.repo.head()
        archive = b"archive bytes"
        digest = hashlib.sha256(archive).hexdigest()
        name = f"metrics-httpd-0.1.1-{checks.TARGET}.tar.gz"
        sha_file = f"{digest}  {name}\n".encode()
        self.assets = {name: archive, f"{name}.sha256": sha_file}
        self.releases = {
            "source_repository": "ephes/ops-library",
            "releases": [
                {
                    "crate": "metrics-httpd",
                    "version": "0.1.1",
                    "tag": "metrics-httpd-v0.1.1",
                    "title": "metrics-httpd 0.1.1",
                    "ops_library_commit": "e" * 40,
                    "commit": self.commit,
                    "assets": [
                        {"name": n, "size": len(d), "sha256": hashlib.sha256(d).hexdigest()}
                        for n, d in self.assets.items()
                    ],
                }
            ],
        }
        self.source = FakeGitHub("ephes/ops-library", {"metrics-httpd-v0.1.1": dict(self.assets)})
        self.target = FakeGitHub()

    def run_import(self, tags: tuple[str, ...] = ()) -> None:
        release.import_old(
            tags,
            git=self.repo.git,
            source=self.source,
            github=self.target,
            releases=self.releases,
            log=quiet,
        )

    def test_publishes_byte_for_byte_and_is_repeatable(self) -> None:
        self.run_import()
        self.assertEqual(self.target.releases["metrics-httpd-v0.1.1"], self.assets)
        self.assertEqual(git(self.repo.origin, "rev-parse", "metrics-httpd-v0.1.1^{commit}"), self.commit)
        notes = self.target.created[0]["notes"]
        self.assertIn("e" * 40, notes)
        self.assertIn(self.commit, notes)
        self.run_import()
        self.assertEqual(len(self.target.created), 1)

    def test_refuses_a_source_asset_with_other_bytes(self) -> None:
        name = next(iter(self.assets))
        self.source.releases["metrics-httpd-v0.1.1"][name] = b"tampered"
        with self.assertRaisesRegex(release.ReleaseError, "recorded sha256"):
            self.run_import()
        self.assertFalse(git(self.repo.origin, "tag", "--list"))
        self.assertEqual(self.target.releases, {})

    def test_refuses_a_checksum_file_naming_another_sum(self) -> None:
        name = next(n for n in self.assets if n.endswith(".sha256"))
        bad = ("0" * 64 + "  " + name.removesuffix(".sha256") + "\n").encode()
        self.source.releases["metrics-httpd-v0.1.1"][name] = bad
        for asset in self.releases["releases"][0]["assets"]:
            if asset["name"] == name:
                asset["sha256"] = hashlib.sha256(bad).hexdigest()
        with self.assertRaisesRegex(release.ReleaseError, "does not name the recorded sha256"):
            self.run_import()

    def test_refuses_a_tag_on_another_commit(self) -> None:
        self.repo.commit("other")
        git(self.repo.root, "push", "--quiet", "origin", "main")
        git(self.repo.root, "tag", "metrics-httpd-v0.1.1")
        git(self.repo.root, "push", "--quiet", "origin", "metrics-httpd-v0.1.1")
        with self.assertRaisesRegex(release.ReleaseError, "points at"):
            self.run_import()
        self.assertEqual(self.target.releases, {})

    def test_refuses_a_commit_not_on_main_and_unknown_tags(self) -> None:
        with self.assertRaisesRegex(release.ReleaseError, "not in rust/releases.json"):
            self.run_import(("metrics-httpd-v9.9.9",))
        self.releases["releases"][0]["commit"] = "f" * 40
        with self.assertRaisesRegex(release.ReleaseError, "not on origin/main"):
            self.run_import()


if __name__ == "__main__":
    unittest.main()
