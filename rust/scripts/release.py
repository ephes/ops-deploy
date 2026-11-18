#!/usr/bin/env python3
"""Local release build and publication of the Rust workspace (rust/README.md
"Releases").

It replaces ops-library's `.github/workflows/rust-release.yml` (no GitHub
Actions): the same jobs run in local `linux/amd64` containers, and
`release_checks.py` still makes every decision (crate and version, matrix,
glibc ceiling, `NEEDED` allowlist, smoke test, deterministic archive). This
file only orchestrates. Stdlib only, Python 3.10 compatible (its tests run
inside the release images, whose python3 is the distribution's).

Commands (run from a checkout of ops-deploy, see `just rust-release`):

- ``build <crate> [--compare-released]``: build the crate's current version
  from the checked-out commit and write the archives, their ``.sha256``
  files, ``notes.md`` and ``build.json`` into
  ``rust/target/release-dist/<crate>-<version>/``. Publishes nothing.
- ``publish <crate>``: tag the build commit, push the tag and create the
  GitHub release of ops-deploy with exactly the built assets, then download
  them again and compare. Repeatable until that end state is reached.
- ``import-old [--tag <tag> ...]``: publish the releases listed in
  ``rust/releases.json`` (built in ops-library before the move) again on
  ops-deploy, byte for byte. Builds nothing.

A version is *taken* when its tag exists on ``origin`` or it is listed in
``rust/releases.json``. ``build`` refuses a taken version unless
``--compare-released`` is given; such a build is marked in ``build.json`` and
``publish`` refuses it. Neither ``publish`` nor ``import-old`` moves or
deletes a tag, replaces an asset, or accepts an asset it does not expect.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

# `python3 -I` leaves the script's directory off sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_checks as checks  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent
RUST = SCRIPTS.parent
REPO = RUST.parent
RELEASES_JSON = RUST / "releases.json"

GITHUB_REPO = "ephes/ops-deploy"
REMOTE = "origin"
MAIN = "main"
TARGET = checks.TARGET
# Releases are built, checked and smoke-tested as linux/amd64 (the hosts'
# platform). The `prepare` job (fmt, clippy, tests) runs on the engine's own
# platform: under Rosetta, emulation artefacts (its own open file descriptors)
# would fail tests that are about the code, not the target.
AMD64 = "linux/amd64"
# The image of the workflow's runner jobs (prepare, shared, and a variant
# without an image): ubuntu-22.04, glibc 2.35 (checks.GLIBC_FLOOR).
RUNNER_IMAGE = "ubuntu:22.04"
BASE_PACKAGES = ("binutils", "ca-certificates", "curl", "gcc", "git", "libc6-dev", "python3")
RUSTUP_VERSION = "1.29.1"
# rustup-init per container platform: target triple and sha256.
RUSTUP = {
    AMD64: (
        "x86_64-unknown-linux-gnu",
        "dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71",
    ),  # pragma: allowlist secret
    "linux/arm64": (
        "aarch64-unknown-linux-gnu",
        "15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433",
    ),  # pragma: allowlist secret
}
IMAGE_REPOSITORY = "ops-deploy-rust-release"
# Every container gets these limits; amd64 under Rosetta is slower than the
# runners were, hence the generous time.
MEMORY = "8g"
PIDS = "4096"
IMAGE_TIMEOUT = 3600
JOB_TIMEOUT = 5400
DIST = "release-dist"
BUILD_JSON = "build.json"
NOTES = "notes.md"
SHA256_LINE = re.compile(r"([0-9a-f]{64})  (\S+)\n")


class ReleaseError(Exception):
    """A release step refused or failed; the message is the reason."""


# --- processes ---------------------------------------------------------------


def run(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    capture: bool = True,
) -> str:
    """Run a command; return its stdout, raise ReleaseError on failure."""
    try:
        result = subprocess.run(  # noqa: S603 - argv lists only
            list(argv),
            cwd=cwd,
            timeout=timeout,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except subprocess.TimeoutExpired:
        raise ReleaseError(f"{shlex.join(argv)} did not finish within {timeout} s") from None
    except OSError as error:
        raise ReleaseError(f"cannot run {argv[0]}: {error}") from None
    if result.returncode != 0:
        detail = (result.stderr or "").strip() if capture else ""
        raise ReleaseError(f"{shlex.join(argv)} exited {result.returncode}" + (f": {detail}" if detail else ""))
    return result.stdout if capture else ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# --- git ---------------------------------------------------------------------


class Git:
    def __init__(self, repo: Path, remote: str = REMOTE, main: str = MAIN) -> None:
        self.repo = repo
        self.remote = remote
        self.main = main

    def __call__(self, *args: str) -> str:
        return run(["git", "-C", str(self.repo), *args])

    def head(self) -> str:
        return self("rev-parse", "HEAD").strip()

    def is_clean(self) -> bool:
        return self("status", "--porcelain", "--untracked-files=normal") == ""

    def fetch_main(self) -> None:
        self("fetch", "--quiet", self.remote, f"+refs/heads/{self.main}:refs/remotes/{self.remote}/{self.main}")

    def on_main(self, commit: str) -> bool:
        """Whether the commit is reachable from the remote main (after fetch_main)."""
        try:
            self("merge-base", "--is-ancestor", commit, f"refs/remotes/{self.remote}/{self.main}")
        except ReleaseError:
            return False
        return True

    def commit_time(self, commit: str) -> int:
        return int(self("log", "-1", "--format=%ct", commit).strip())

    def remote_tag(self, tag: str) -> str | None:
        """The commit a tag on the remote points at (peeled), or None."""
        text = self("ls-remote", "--tags", self.remote, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
        refs = dict(reversed(line.split("\t", 1)) for line in text.splitlines() if line)
        return refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")

    def local_tag(self, tag: str) -> str | None:
        try:
            return self("rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}").strip()
        except ReleaseError:
            return None

    def push_tag(self, tag: str, commit: str, message: str) -> None:
        """Create the annotated tag at the commit (unless it is there) and push it."""
        local = self.local_tag(tag)
        if local is None:
            self("tag", "-a", tag, commit, "-m", message)
        elif local != commit:
            raise ReleaseError(f"local tag {tag} points at {local}, not {commit}; settle it by hand")
        self("push", "--quiet", self.remote, f"refs/tags/{tag}:refs/tags/{tag}")


def taken_versions() -> set[tuple[str, str]]:
    return {(entry["crate"], entry["version"]) for entry in load_old_releases()["releases"]}


def load_old_releases(path: Path = RELEASES_JSON) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReleaseError(f"cannot read {path}: {error}") from None
    if not isinstance(data, dict) or not isinstance(data.get("releases"), list):
        raise ReleaseError(f"{path}: no releases list")
    for entry in data["releases"]:
        for key in ("crate", "version", "tag", "title", "ops_library_commit", "commit", "assets"):
            if key not in entry:
                raise ReleaseError(f"{path}: an entry has no {key!r}")
        if entry["tag"] != f"{entry['crate']}-v{entry['version']}":
            raise ReleaseError(f"{path}: tag {entry['tag']} does not match its crate and version")
    return data


# --- GitHub ------------------------------------------------------------------


class GitHub:
    """The `gh release` calls; tests replace it with a fake."""

    def __init__(self, repository: str) -> None:
        self.repository = repository

    def assets(self, tag: str) -> dict[str, str] | None:
        """Asset name -> sha256 ('' when GitHub reports none), or None without a release."""
        try:
            text = run(["gh", "release", "view", tag, "-R", self.repository, "--json", "assets"])
        except ReleaseError as error:
            if "release not found" in str(error):
                return None
            raise
        return {
            asset["name"]: (asset.get("digest") or "").removeprefix("sha256:") for asset in json.loads(text)["assets"]
        }

    def create(self, tag: str, title: str, notes: Path, files: list[Path], prerelease: bool) -> None:
        argv = ["gh", "release", "create", tag, *map(str, files), "-R", self.repository]
        argv += ["--verify-tag", "--latest=false", "--title", title, "--notes-file", str(notes)]
        if prerelease:
            argv.append("--prerelease")
        run(argv)

    def upload(self, tag: str, files: list[Path]) -> None:
        # Never --clobber: an existing asset is never replaced.
        run(["gh", "release", "upload", tag, *map(str, files), "-R", self.repository])

    def download(self, tag: str, directory: Path) -> None:
        run(["gh", "release", "download", tag, "-R", self.repository, "-D", str(directory)])


def ensure_release(
    github: GitHub,
    tag: str,
    title: str,
    notes: Path,
    files: dict[str, Path],
    prerelease: bool = False,
) -> list[str]:
    """Bring the release to exactly `files` (name -> local path), then
    download every asset and compare it with the local file. Returns the
    steps taken."""
    steps = []
    expected = {name: sha256_file(path) for name, path in files.items()}
    assets = github.assets(tag)
    if assets is None:
        github.create(tag, title, notes, [files[name] for name in sorted(files)], prerelease)
        steps.append(f"created release {tag} with {len(files)} assets")
    else:
        unexpected = sorted(set(assets) - set(files))
        if unexpected:
            raise ReleaseError(f"release {tag} has assets it should not have: {', '.join(unexpected)}")
        for name, digest in sorted(assets.items()):
            if digest and digest != expected[name]:
                raise ReleaseError(f"release {tag}: asset {name} has sha256 {digest}, expected {expected[name]}")
        missing = sorted(set(files) - set(assets))
        if missing:
            github.upload(tag, [files[name] for name in missing])
            steps.append(f"uploaded {', '.join(missing)}")
        else:
            steps.append(f"release {tag} already holds every asset")
    with tempfile.TemporaryDirectory(prefix="release-verify-") as directory:
        github.download(tag, Path(directory))
        found = {path.name: path for path in Path(directory).iterdir()}
        if sorted(found) != sorted(files):
            raise ReleaseError(f"release {tag} holds {sorted(found)}, expected {sorted(files)}")
        for name, path in sorted(found.items()):
            if path.read_bytes() != files[name].read_bytes():
                raise ReleaseError(f"release {tag}: downloaded {name} differs from the local file")
    steps.append(f"verified {len(files)} assets of {tag} byte for byte")
    return steps


def ensure_tag(git: Git, tag: str, commit: str, message: str) -> str:
    """The tag on the remote points at the commit afterwards; never moves a tag."""
    remote = git.remote_tag(tag)
    if remote is not None:
        if remote != commit:
            raise ReleaseError(f"tag {tag} on {git.remote} points at {remote}, not {commit}")
        return f"tag {tag} already on {git.remote}"
    git.fetch_main()
    if not git.on_main(commit):
        raise ReleaseError(f"{commit} is not on {git.remote}/{git.main}")
    git.push_tag(tag, commit, message)
    if git.remote_tag(tag) != commit:
        raise ReleaseError(f"tag {tag} on {git.remote} does not point at {commit} after the push")
    return f"pushed tag {tag} -> {commit}"


# --- build: images and container jobs ------------------------------------------


def image_packages(entries: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Image -> apt packages: the runner image for prepare and shared (and a
    variant without image), plus each variant image with its packages."""
    images: dict[str, list[str]] = {RUNNER_IMAGE: list(BASE_PACKAGES)}
    for entry in entries:
        image = entry["image"] or RUNNER_IMAGE
        packages = images.setdefault(image, list(BASE_PACKAGES))
        for package in entry["packages"].split():
            if package not in packages:
                packages.append(package)
    return images


def dockerfile(base: str, packages: list[str], platform: str) -> str:
    """The builder image: base pinned by digest, apt packages, pinned and
    sha256-checked rustup, the source (`git archive` of the build commit), the
    pinned toolchain and the locked dependencies. The only phase with network;
    it runs no code of the crates or their dependencies."""
    for package in packages:
        if not checks.APT_PACKAGE.fullmatch(package):
            raise ReleaseError(f"{package!r} is not an apt package name")
    if platform not in RUSTUP:
        raise ReleaseError(f"no rustup-init for platform {platform}")
    triple, rustup_sha256 = RUSTUP[platform]
    url = f"https://static.rust-lang.org/rustup/archive/{RUSTUP_VERSION}/{triple}/rustup-init"
    return f"""FROM --platform={platform} {base}
ENV DEBIAN_FRONTEND=noninteractive \\
    CARGO_HOME=/opt/cargo \\
    RUSTUP_HOME=/opt/rustup \\
    CARGO_TERM_COLOR=never \\
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# The package lists stay: software-live-apt's tests compare against python-apt
# on the image's APT cache (as the workflow's job did).
RUN apt-get update \\
    && apt-get install -y --no-install-recommends {" ".join(packages)}
RUN curl --proto '=https' --tlsv1.2 -sSfL -o /tmp/rustup-init {url} \\
    && echo "{rustup_sha256}  /tmp/rustup-init" | sha256sum --check \\
    && chmod 0755 /tmp/rustup-init \\
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \\
    && rm /tmp/rustup-init
COPY source.tar /tmp/source.tar
RUN mkdir /work && tar -C /work -xf /tmp/source.tar && rm /tmp/source.tar
WORKDIR /work/rust
# The pinned toolchain is also the default (cargo outside the workspace, as
# in the script tests), then the locked dependencies.
RUN rustup toolchain install \\
    && rustup default "$(sed -n 's/^channel = "\\(.*\\)"$/\\1/p' rust-toolchain.toml)" \\
    && rustc --version && cargo fetch --locked
"""


VERSIONS_SCRIPT = """mkdir -p /out
{{ dpkg-query -W -f '${{Package}}=${{Version}}\\n' {packages}; rustc --version; }} > /out/versions.txt
"""


def prepare_script(packages: list[str]) -> str:
    """The workflow's `prepare` job: fmt, clippy, tests, script tests and the
    rust-apt isolation check, without the CI-excluded members."""
    return (
        VERSIONS_SCRIPT.format(packages=" ".join(packages))
        + """cargo fmt --check
excludes=$(cargo metadata --format-version 1 --no-deps --locked --offline | python3 -I scripts/ci_excludes.py)
# Package names only (validated by ci_excludes.py): word-split on purpose.
cargo clippy --workspace $excludes --all-targets --locked --offline -- -D warnings
cargo test --workspace $excludes --locked --offline
python3 -I -m unittest discover -s scripts -p 'test_*.py'
cargo metadata --format-version 1 --locked --offline --all-features > /tmp/metadata-full.json
python3 -I scripts/release_checks.py apt-isolation --metadata /tmp/metadata-full.json
"""
    )


def shared_script(packages: list[str]) -> str:
    """The workflow's `shared` job: build the shared binaries once, check them
    and hand them on with their sha256."""
    return (
        VERSIONS_SCRIPT.format(packages=" ".join(packages))
        + f"""cargo build --release --locked --offline --target {TARGET} $BUILD_ARGS
python3 -I scripts/release_checks.py verify --entry "$ENTRY" --bin-dir target/{TARGET}/release --commit "$COMMIT"
python3 -I scripts/release_checks.py checksums --entry "$ENTRY" --bin-dir target/{TARGET}/release > /out/checksums.txt
mkdir -p /out/shared
for name in $BINARIES; do cp "target/{TARGET}/release/$name" "/out/shared/$name"; done
"""
    )


def variant_script(packages: list[str]) -> str:
    """The workflow's `build` job of one variant: checks of the CI-excluded
    members, release build, checks of every binary (the shared ones again,
    after their sha256), deterministic archive and its .sha256 file."""
    return (
        VERSIONS_SCRIPT.format(packages=" ".join(packages))
        + f"""if [ -n "$CONTAINER_CHECKS" ]; then
    cargo clippy $CONTAINER_CHECKS --all-targets --locked --offline -- -D warnings
    cargo test $CONTAINER_CHECKS --locked --offline
fi
# An empty build list (every binary is shared) builds nothing.
if [ -n "$BUILD_ARGS" ]; then
    cargo build --release --locked --offline --target {TARGET} $BUILD_ARGS
fi
shared_args=()
if [ -n "$SHARED_SHA256" ]; then
    chmod 0755 /work/release-shared/*
    shared_args=(--shared-bin-dir /work/release-shared --shared-sha256 "$SHARED_SHA256")
fi
python3 -I scripts/release_checks.py verify --entry "$ENTRY" --bin-dir target/{TARGET}/release \\
    --commit "$COMMIT" "${{shared_args[@]}}"
python3 -I scripts/release_checks.py pack --entry "$ENTRY" --bin-dir target/{TARGET}/release \\
    --repo-root /work --mtime "$MTIME" --out-dir /out/dist "${{shared_args[@]}}"
(cd /out/dist && sha256sum --check ./*.sha256)
"""
    )


class Docker:
    """The docker calls of a build; tests replace it with a fake."""

    def preflight(self) -> str:
        """Require working linux/amd64 containers; return the engine's own platform."""
        arch = run(["docker", "run", "--rm", "--platform", AMD64, RUNNER_IMAGE, "uname", "-m"], timeout=600)
        if arch.strip() != "x86_64":
            raise ReleaseError(f"a {AMD64} container reports {arch.strip()!r}, not x86_64 (rust/README.md)")
        native = run(["docker", "version", "-f", "{{.Server.Os}}/{{.Server.Arch}}"]).strip()
        if native not in RUSTUP:
            raise ReleaseError(f"unsupported Docker engine platform {native!r}")
        return native

    def pinned(self, image: str) -> str:
        """Pull the image and return it as <name>@<digest> (the digest of its
        index, the same for every platform)."""
        run(["docker", "pull", "--quiet", "--platform", AMD64, image], timeout=IMAGE_TIMEOUT)
        digests = json.loads(run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image]))
        name = image.split(":", 1)[0]
        for digest in digests or []:
            if digest.split("@", 1)[0] in (name, f"docker.io/library/{name}", f"library/{name}"):
                return f"{name}@{digest.split('@', 1)[1]}"
        raise ReleaseError(f"no repository digest for {image}")

    def build_image(self, tag: str, context: Path, platform: str) -> None:
        run(
            [
                "docker",
                "build",
                "--platform",
                platform,
                "--network",
                "default",
                "-t",
                tag,
                str(context),
            ],
            timeout=IMAGE_TIMEOUT,
            capture=False,
        )

    def job(
        self,
        image: str,
        name: str,
        script: str,
        env: dict[str, str],
        copy_in: dict[Path, str],
        out_dir: Path,
        platform: str = AMD64,
    ) -> None:
        """One build-phase job: no network, no mounts, memory and time limits;
        files go in and /out comes back with `docker cp`."""
        argv = ["docker", "create", "--name", name, "--platform", platform, "--network", "none"]
        argv += ["--memory", MEMORY, "--memory-swap", MEMORY, "--pids-limit", PIDS]
        for key, value in sorted(env.items()):
            argv += ["-e", f"{key}={value}"]
        argv += [image, "bash", "-euo", "pipefail", "-c", script]
        run(argv)
        try:
            for source, destination in copy_in.items():
                run(["docker", "cp", str(source), f"{name}:{destination}"])
            try:
                run(["docker", "start", "-a", name], timeout=JOB_TIMEOUT, capture=False)
            except ReleaseError:
                subprocess.run(["docker", "kill", name], check=False, capture_output=True)  # noqa: S603, S607
                raise
            run(["docker", "cp", f"{name}:/out/.", str(out_dir)])
        finally:
            subprocess.run(["docker", "rm", "-f", name], check=False, capture_output=True)  # noqa: S603, S607

    def remove_image(self, tag: str) -> None:
        subprocess.run(["docker", "image", "rm", tag], check=False, capture_output=True)  # noqa: S603, S607


def cargo_metadata(rust: Path) -> dict[str, Any]:
    return json.loads(run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"], cwd=rust))


def default_out_dir(crate: str, version: str) -> Path:
    return RUST / "target" / DIST / f"{crate}-{version}"


def build(
    crate: str,
    compare_released: bool,
    out_dir: Path | None = None,
    *,
    git: Git | None = None,
    docker: Docker | None = None,
    metadata: dict[str, Any] | None = None,
    taken: set[tuple[str, str]] | None = None,
    log: Any = print,
) -> Path:
    git = git or Git(REPO)
    docker = docker or Docker()
    repo = git.repo
    rust = repo / "rust"
    if not git.is_clean():
        raise ReleaseError("the worktree has changes or untracked files; build from a clean checkout")
    commit = git.head()
    git.fetch_main()
    if not git.on_main(commit):
        raise ReleaseError(f"HEAD {commit} is not on {git.remote}/{git.main}; push it first")
    metadata = metadata if metadata is not None else cargo_metadata(rust)
    crate, version = checks.release_crate(checks.workspace_packages(metadata), crate)
    tag = f"{crate}-v{version}"
    is_taken = (crate, version) in (taken if taken is not None else taken_versions())
    is_taken = is_taken or git.remote_tag(tag) is not None
    if is_taken and not compare_released:
        raise ReleaseError(
            f"{crate} {version} is already released (tag {tag} or rust/releases.json); "
            "bump the version, or pass --compare-released for a dry run"
        )
    if compare_released and not is_taken:
        raise ReleaseError(f"{crate} {version} is not released; drop --compare-released")
    shared, entries = checks.release_plan(
        metadata,
        crate,
        version,
        checks.load_settings(rust / crate / checks.RELEASE_JSON),
        repo,
        checks.ci_excluded_members(metadata),
    )
    out = out_dir or default_out_dir(crate, version)
    if out.exists() and any(out.iterdir()):
        raise ReleaseError(f"{out} is not empty; remove it first")
    out.mkdir(parents=True, exist_ok=True)
    native = docker.preflight()
    mtime = git.commit_time(commit)
    images = image_packages(entries)
    # (image, platform) of every job: prepare on the engine's own platform,
    # everything that builds or checks a release binary on linux/amd64.
    needed = [(RUNNER_IMAGE, native)]
    for image in images:
        if image != RUNNER_IMAGE or shared is not None or any(not entry["image"] for entry in entries):
            needed.append((image, AMD64))
    needed = list(dict.fromkeys(needed))
    work = Path(tempfile.mkdtemp(prefix=f"release-{crate}-"))
    built: dict[tuple[str, str], str] = {}
    pinned: dict[str, str] = {}
    try:
        context = work / "context"
        context.mkdir()
        git("archive", "--format=tar", "-o", str(context / "source.tar"), commit, "rust")
        for image, platform in needed:
            if image not in pinned:
                pinned[image] = docker.pinned(image)
            (context / "Dockerfile").write_text(dockerfile(pinned[image], images[image], platform), encoding="utf-8")
            slug = re.sub(r"[^a-z0-9]+", "-", f"{image}-{platform}")
            built[image, platform] = f"{IMAGE_REPOSITORY}:{crate}-{version}-{slug}-{commit[:12]}"
            log(f"== image {built[image, platform]} from {pinned[image]} ({platform})")
            docker.build_image(built[image, platform], context, platform)
        commit_env = {
            checks.commit_env(member): commit for member in checks.workspace_packages(metadata)
        }  # every member: build.rs never falls back to git (no .git in the image)
        base = {"COMMIT": commit, "MTIME": str(mtime), **commit_env}
        jobs_dir = work / "jobs"
        log("== prepare (fmt, clippy, tests, script tests, apt-isolation)")
        prepare_out = jobs_dir / "prepare"
        prepare_out.mkdir(parents=True)
        docker.job(
            built[RUNNER_IMAGE, native],
            f"release-{crate}-prepare-{os.getpid()}",
            prepare_script(images[RUNNER_IMAGE]),
            base,
            {},
            prepare_out,
            native,
        )
        versions = {f"{RUNNER_IMAGE} ({native})": (prepare_out / "versions.txt").read_text(encoding="utf-8")}
        shared_sha = ""
        shared_dir = jobs_dir / "shared"
        if shared is not None:
            log("== shared " + " ".join(binary["name"] for binary in shared["binaries"]))
            shared_dir.mkdir(parents=True)
            env = {
                **base,
                "ENTRY": json.dumps(shared, separators=(",", ":")),
                "BUILD_ARGS": shared["build_args"],
                "BINARIES": " ".join(binary["name"] for binary in shared["binaries"]),
            }
            docker.job(
                built[RUNNER_IMAGE, AMD64],
                f"release-{crate}-shared-{os.getpid()}",
                shared_script(images[RUNNER_IMAGE]),
                env,
                {},
                shared_dir,
            )
            versions[f"{RUNNER_IMAGE} ({AMD64})"] = (shared_dir / "versions.txt").read_text(encoding="utf-8")
            line = (shared_dir / "checksums.txt").read_text(encoding="utf-8").strip()
            if not line.startswith("sha256="):
                raise ReleaseError(f"shared job printed {line!r}")
            shared_sha = line.removeprefix("sha256=")
        archives: dict[str, str] = {}
        for entry in entries:
            image = entry["image"] or RUNNER_IMAGE
            log(f"== variant {entry['variant'] or '(default)'} in {image}")
            variant_out = jobs_dir / (entry["variant"] or "default")
            variant_out.mkdir(parents=True)
            env = {
                **base,
                "ENTRY": json.dumps(entry, separators=(",", ":")),
                "BUILD_ARGS": entry["build_args"],
                "CONTAINER_CHECKS": entry["container_checks"],
                "SHARED_SHA256": shared_sha,
            }
            copy_in = {shared_dir / "shared": "/work/release-shared"} if shared is not None else {}
            docker.job(
                built[image, AMD64],
                f"release-{crate}-{entry['variant'] or 'default'}-{os.getpid()}",
                variant_script(images[image]),
                env,
                copy_in,
                variant_out,
            )
            versions.setdefault(f"{image} ({AMD64})", (variant_out / "versions.txt").read_text(encoding="utf-8"))
            for name in (entry["archive"], entry["archive"] + ".sha256"):
                shutil.copyfile(variant_out / "dist" / name, out / name)
            archives[entry["archive"]] = check_sha256_file(out, entry["archive"])
    finally:
        shutil.rmtree(work, ignore_errors=True)
        for tag_name in built.values():
            docker.remove_image(tag_name)
    lock_sha = hashlib.sha256(git("show", f"{commit}:rust/Cargo.lock").encode()).hexdigest()
    record = {
        "crate": crate,
        "version": version,
        "tag": tag,
        "commit": commit,
        "compare_released": compare_released,
        "archives": archives,
        "images": pinned,
        "prepare_platform": native,
        "cargo_lock_sha256": lock_sha,
    }
    (out / BUILD_JSON).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (out / NOTES).write_text(release_notes(record, versions), encoding="utf-8")
    for name, digest in archives.items():
        log(f"{digest}  {name}")
        with tarfile.open(out / name, "r:gz") as archive:
            for member in archive.getmembers():
                log(f"    {member.name} ({oct(member.mode)}, {member.size} bytes)")
    if compare_released:
        log(f"dry run of the released {crate} {version}: {out} cannot be published")
    return out


def check_sha256_file(directory: Path, archive: str) -> str:
    """The archive's .sha256 file must be the sha256sum line of the archive."""
    digest = sha256_file(directory / archive)
    text = (directory / f"{archive}.sha256").read_text(encoding="utf-8")
    if text != f"{digest}  {archive}\n":
        raise ReleaseError(f"{archive}.sha256 does not name sha256 {digest}")
    return digest


def release_notes(record: dict[str, Any], versions: dict[str, str]) -> str:
    lines = [
        f"{record['crate']} {record['version']}, built from {record['commit']} for {TARGET} "
        "by rust/scripts/release.py (local linux/amd64 containers, no network during the build; "
        f"workspace checks on {record['prepare_platform']}).",
        "",
        "sha256:",
        *(f"{digest}  {name}" for name, digest in sorted(record["archives"].items())),
        "",
        "Build environment:",
        f"- Cargo.lock sha256 {record['cargo_lock_sha256']}",
        *(f"- {image}: {pinned}" for image, pinned in sorted(record["images"].items())),
    ]
    for job_image, text in sorted(versions.items()):
        lines.append(f"- packages and toolchain in {job_image}:")
        lines.extend(f"  - {line}" for line in text.splitlines())
    return "\n".join(lines) + "\n"


# --- publish -----------------------------------------------------------------


def publish(
    crate: str,
    out_dir: Path | None = None,
    *,
    git: Git | None = None,
    github: GitHub | None = None,
    taken: set[tuple[str, str]] | None = None,
    log: Any = print,
    metadata: dict[str, Any] | None = None,
) -> None:
    git = git or Git(REPO)
    github = github or GitHub(GITHUB_REPO)
    out = out_dir
    if out is None:
        # The build of the crate's current version (what `build` wrote by default).
        metadata = metadata if metadata is not None else cargo_metadata(git.repo / "rust")
        crate, version = checks.release_crate(checks.workspace_packages(metadata), crate)
        out = default_out_dir(crate, version)
    try:
        record = json.loads((out / BUILD_JSON).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReleaseError(f"no build in {out}: {error}") from None
    if record.get("crate") != crate:
        raise ReleaseError(f"{out} holds a build of {record.get('crate')!r}, not {crate!r}")
    if record.get("compare_released"):
        raise ReleaseError(f"{out} is a --compare-released dry run; it is never published")
    version, tag, commit = record["version"], record["tag"], record["commit"]
    if (crate, version) in (taken if taken is not None else taken_versions()):
        raise ReleaseError(f"{crate} {version} is listed in rust/releases.json; it is never rebuilt")
    if tag != f"{crate}-v{version}" or not checks.COMMIT.fullmatch(commit):
        raise ReleaseError(f"{out}/{BUILD_JSON} is inconsistent")
    files: dict[str, Path] = {}
    for archive, digest in record["archives"].items():
        if check_sha256_file(out, archive) != digest:
            raise ReleaseError(f"{archive} changed since the build")
        files[archive] = out / archive
        files[f"{archive}.sha256"] = out / f"{archive}.sha256"
    extra = sorted({path.name for path in out.iterdir()} - set(files) - {BUILD_JSON, NOTES})
    if extra:
        raise ReleaseError(f"{out} holds files that are not part of the release: {', '.join(extra)}")
    log(ensure_tag(git, tag, commit, f"{crate} {version}"))
    for step in ensure_release(github, tag, f"{crate} {version}", out / NOTES, files, prerelease="-" in version):
        log(step)


# --- import-old --------------------------------------------------------------


def import_old(
    tags: Sequence[str] = (),
    *,
    git: Git | None = None,
    source: GitHub | None = None,
    github: GitHub | None = None,
    releases: dict[str, Any] | None = None,
    log: Any = print,
) -> None:
    git = git or Git(REPO)
    data = releases if releases is not None else load_old_releases()
    source = source or GitHub(data.get("source_repository", "ephes/ops-library"))
    github = github or GitHub(GITHUB_REPO)
    entries = data["releases"]
    unknown = sorted(set(tags) - {entry["tag"] for entry in entries})
    if unknown:
        raise ReleaseError(f"not in rust/releases.json: {', '.join(unknown)}")
    for entry in entries:
        if tags and entry["tag"] not in tags:
            continue
        tag = entry["tag"]
        log(f"== {tag}")
        with tempfile.TemporaryDirectory(prefix="release-import-") as directory:
            downloaded = Path(directory)
            source.download(tag, downloaded)
            files = {path.name: path for path in downloaded.iterdir()}
            expected = {asset["name"]: asset["sha256"] for asset in entry["assets"]}
            if sorted(files) != sorted(expected):
                raise ReleaseError(f"{source.repository} {tag} holds {sorted(files)}, expected {sorted(expected)}")
            for name, path in files.items():
                if sha256_file(path) != expected[name]:
                    raise ReleaseError(f"{source.repository} {tag}: {name} does not have the recorded sha256")
            for name in files:
                if name.endswith(".sha256"):
                    archive = name.removesuffix(".sha256")
                    if archive not in expected or files[name].read_text(encoding="utf-8") != (
                        f"{expected[archive]}  {archive}\n"
                    ):
                        raise ReleaseError(f"{tag}: {name} does not name the recorded sha256 of {archive}")
            notes = downloaded.parent / f"{Path(directory).name}-notes.md"
            notes.write_text(import_notes(entry, data.get("source_repository", "ephes/ops-library")), encoding="utf-8")
            try:
                message = f"{entry['title']} (built in ops-library from {entry['ops_library_commit']})"
                log(ensure_tag(git, tag, entry["commit"], message))
                for step in ensure_release(github, tag, entry["title"], notes, files):
                    log(step)
            finally:
                notes.unlink(missing_ok=True)


def import_notes(entry: dict[str, Any], source_repository: str) -> str:
    archives = [asset for asset in entry["assets"] if asset["name"].endswith(".tar.gz")]
    return "\n".join(
        [
            f"{entry['title']}, built by ops-library's rust-release.yml from ops-library commit "
            f"{entry['ops_library_commit']} for {TARGET}.",
            "",
            f"Published again byte for byte from github.com/{source_repository} release {entry['tag']} "
            f"after the Rust workspace moved to ops-deploy (rust/HISTORY.md). The same source is "
            f"ops-deploy commit {entry['commit']}; the binaries print the ops-library commit.",
            "",
            "sha256:",
            *(f"{asset['sha256']}  {asset['name']}" for asset in archives),
            "",
        ]
    )


# --- command line ------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    build_parser = commands.add_parser("build", help="build a release (publishes nothing)")
    build_parser.add_argument("crate")
    build_parser.add_argument("--compare-released", action="store_true", help="dry run of a released version")
    build_parser.add_argument("--out-dir", type=Path)
    publish_parser = commands.add_parser("publish", help="tag and publish what build produced")
    publish_parser.add_argument("crate")
    publish_parser.add_argument("--out-dir", type=Path)
    old_parser = commands.add_parser("import-old", help="publish the releases of rust/releases.json again")
    old_parser.add_argument("--tag", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build(args.crate, args.compare_released, args.out_dir)
        elif args.command == "publish":
            publish(args.crate, args.out_dir)
        else:
            import_old(args.tag)
    except (ReleaseError, checks.CheckError) as error:
        print(f"release failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
