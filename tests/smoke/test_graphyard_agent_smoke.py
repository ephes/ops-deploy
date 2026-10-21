"""The Rust agent host script (``services/graphyard/files/agent.sh``) on the smoke target, as root.

Each command goes through root's login shell (fish on the VM, as on macmini)
the way pyinfra's connector sends it. A fake ``graphyard-agent`` (a shell script)
stands in for the release binary; archives are built here with ``tarfile``.
Everything happens below a throwaway install root, never ``/opt/graphyard-agent``.
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from collections.abc import Iterator

import pytest
from pyinfra.api.command import StringCommand
from pyinfra.connectors.util import make_unix_command

from ops_deploy.services.graphyard.agent import _agent
from tests.smoke.conftest import SmokeHost

ROOT = "/opt/graphyard-agent-smoke"
UPLOAD = f"{ROOT}/.upload.tar.gz"
DB = "/tmp/graphyard-agent-smoke.sqlite3"
USER = "nobody"
FAKE_AGENT = (
    "#!/bin/sh\n"
    'case "$1" in\n'
    '  --version) echo "graphyard-agent {version} (abc123)" ;;\n'
    '  --check-schema) [ "$2 $3" = "--db {db}" ] || exit 9; [ "$(id -un)" = {user} ] || exit 8; exit {schema} ;;\n'
    "esac\n"
)


def archive(members: list[tuple[str, bytes | str | None]]) -> bytes:
    """A gzip tarball: ``(name, bytes)`` is a regular file, ``(name, str)`` a symlink, ``(name, None)`` a directory."""

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in members:
            info = tarfile.TarInfo(name)
            if content is None:
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            elif isinstance(content, str):
                info.type, info.linkname = tarfile.SYMTYPE, content
                tar.addfile(info)
            else:
                info.size, info.mode = len(content), 0o644
                tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def agent(version: str = "0.1.0", schema: int = 0) -> bytes:
    return FAKE_AGENT.format(version=version, db=DB, user=USER, schema=schema).encode()


def release(version: str = "0.1.0", schema: int = 0) -> bytes:
    return archive([("graphyard-agent", agent(version, schema)), ("LICENSE", b"MIT\n")])


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def via_login_shell(smoke_host: SmokeHost, command: str, *, check: bool = False) -> tuple[int, str]:
    line = make_unix_command(StringCommand(command)).get_raw_value()
    result = smoke_host.run(line, login_shell=True, check=check)
    return result.returncode, result.stdout + result.stderr


def upload(smoke_host: SmokeHost, data: bytes, path: str = UPLOAD) -> None:
    smoke_host.run(f"install -d -m 0755 {ROOT} && base64 -d > {path}", input=base64.b64encode(data).decode())


def install(smoke_host: SmokeHost, data: bytes, version: str = "0.1.0", digest: str | None = None) -> tuple[int, str]:
    upload(smoke_host, data)
    command = _agent("install", ROOT, version, digest or sha256(data), "https://unused.invalid/x", USER, DB, UPLOAD)
    return via_login_shell(smoke_host, command)


@pytest.fixture(autouse=True)
def clean_root(smoke_host: SmokeHost) -> Iterator[None]:
    smoke_host.run(f"rm -rf {ROOT}; systemctl stop graphyard-agent-smoke-live 2>/dev/null; true")
    yield
    smoke_host.run(f"rm -rf {ROOT}; systemctl stop graphyard-agent-smoke-live 2>/dev/null; true")


def test_install_moves_a_valid_release_into_place(smoke_host: SmokeHost) -> None:
    data = release()

    rc, output = install(smoke_host, data)

    assert rc == 0, output
    listing = smoke_host.out(f"cd {ROOT} && stat -c '%a %U %G %F %n' 0.1.0 0.1.0/graphyard-agent 0.1.0/.archive-sha256")
    assert listing.splitlines() == [
        "755 root root directory 0.1.0",
        "755 root root regular file 0.1.0/graphyard-agent",
        "644 root root regular file 0.1.0/.archive-sha256",
    ]
    assert smoke_host.out(f"cat {ROOT}/0.1.0/.archive-sha256") == sha256(data)
    assert smoke_host.out(f"LC_ALL=C ls -A {ROOT}") == "0.1.0"  # no staging, no upload left


def test_download_by_url(smoke_host: SmokeHost) -> None:
    data = release()
    upload(smoke_host, data, "/tmp/graphyard-agent-smoke.tar.gz")
    url = "file:///tmp/graphyard-agent-smoke.tar.gz"

    rc, output = via_login_shell(smoke_host, _agent("install", ROOT, "0.1.0", sha256(data), url, USER, DB))

    assert rc == 0, output
    assert smoke_host.out(f"cat {ROOT}/0.1.0/.archive-sha256") == sha256(data)
    rc, output = via_login_shell(
        smoke_host, _agent("install", ROOT, "0.2.0", sha256(data), "file:///nonexistent.tar.gz", USER, DB)
    )
    assert rc != 0
    assert "downloading file:///nonexistent.tar.gz failed" in output


def test_an_installed_version_is_never_replaced(smoke_host: SmokeHost) -> None:
    assert install(smoke_host, release())[0] == 0
    before = smoke_host.out(f"stat -c %i {ROOT}/0.1.0")

    rc, output = install(smoke_host, release())

    assert rc != 0
    assert "exists already" in output
    assert smoke_host.out(f"stat -c %i {ROOT}/0.1.0") == before


LICENSE = ("LICENSE", b"MIT\n")
REFUSED = "exactly the regular files graphyard-agent and LICENSE"


@pytest.mark.parametrize(
    ("members", "error"),
    [
        ([("graphyard-agent", "/bin/sh"), LICENSE], REFUSED),
        ([("graphyard-agent", agent()), ("LICENSE", "/etc/passwd")], REFUSED),
        ([("graphyard-agent", agent()), LICENSE, ("evil", b"x")], REFUSED),
        ([("graphyard-agent", agent()), ("graphyard-agent", agent()), LICENSE], REFUSED),
        ([("graphyard-agent", agent()), LICENSE, LICENSE], REFUSED),
        ([LICENSE], REFUSED),
        ([("graphyard-agent", agent())], REFUSED),
        ([("./", None), ("./graphyard-agent", agent()), ("./LICENSE", b"MIT\n")], REFUSED),
        ([("../graphyard-agent", agent()), LICENSE], REFUSED),
        ([("bin/graphyard-agent", agent()), LICENSE], REFUSED),
    ],
    ids=[
        "symlink",
        "license-symlink",
        "extra",
        "duplicate",
        "duplicate-license",
        "no-agent",
        "no-license",
        "directory",
        "parent",
        "subdir",
    ],
)
def test_bad_archives_are_refused_before_extraction(
    smoke_host: SmokeHost, members: list[tuple[str, bytes | str | None]], error: str
) -> None:
    rc, output = install(smoke_host, archive(members))

    assert rc != 0, output
    assert error in output, output
    assert smoke_host.out(f"test -e {ROOT}/0.1.0 && echo present || echo absent") == "absent"


def test_dot_slash_members_are_accepted(smoke_host: SmokeHost) -> None:
    rc, output = install(smoke_host, archive([("./graphyard-agent", agent()), ("./LICENSE", b"MIT\n")]))

    assert rc == 0, output


def test_a_wrong_checksum_is_refused(smoke_host: SmokeHost) -> None:
    rc, output = install(smoke_host, release(), digest="0" * 64)

    assert rc != 0
    assert "expected " + "0" * 64 in output
    assert smoke_host.out(f"test -e {ROOT}/0.1.0 && echo present || echo absent") == "absent"


@pytest.mark.parametrize(
    ("version", "schema", "error"), [("0.0.9", 0, "--version exited 0"), ("0.1.0", 3, "--check-schema exited 3")]
)
def test_a_rejected_candidate_is_removed_again(smoke_host: SmokeHost, version: str, schema: int, error: str) -> None:
    rc, output = install(smoke_host, release(version, schema))

    assert rc != 0, output
    assert error in output, output
    assert smoke_host.out(f"test -e {ROOT}/0.1.0 && echo present || echo absent") == "absent"


def test_validate_leaves_an_installed_version_alone(smoke_host: SmokeHost) -> None:
    assert install(smoke_host, release())[0] == 0
    assert via_login_shell(smoke_host, _agent("validate", ROOT, "0.1.0", USER, DB))[0] == 0
    smoke_host.run(f"sed -i 's/exit 0 ;;/exit 4 ;;/' {ROOT}/0.1.0/graphyard-agent")

    rc, output = via_login_shell(smoke_host, _agent("validate", ROOT, "0.1.0", USER, DB))

    assert rc != 0
    assert "--check-schema exited 4" in output
    assert smoke_host.out(f"test -x {ROOT}/0.1.0/graphyard-agent && echo kept") == "kept"


def test_prune_keeps_pinned_previous_live_and_newest(smoke_host: SmokeHost) -> None:
    versions = ["0.0.1", "0.0.2", "0.0.3", "0.0.4", "0.0.5", "0.0.6", "1.0.0-rc.1"]
    smoke_host.run(" && ".join(f"install -d {ROOT}/{version}" for version in versions))
    # The live process runs a binary from 0.0.2 (a copy of sleep, so /proc/<pid>/exe names it).
    smoke_host.run(
        f"cp /bin/sleep {ROOT}/0.0.2/graphyard-agent && "
        f"systemd-run --unit graphyard-agent-smoke-live {ROOT}/0.0.2/graphyard-agent 600 >/dev/null"
    )
    for age, version in enumerate(reversed(versions)):
        smoke_host.run(f"touch -d '-{age + 1} hours' {ROOT}/{version}")
    smoke_host.run(f"install -d {ROOT}/latest {ROOT}/.staging && ln -s {ROOT}/0.0.6 {ROOT}/9.9.9")
    smoke_host.run(f"printf '0.0.1\\n' > {ROOT}/.previous-version")
    args = (ROOT, "0.0.3", "graphyard-agent-smoke-live", 2)

    rc, dry = via_login_shell(smoke_host, _agent("prune", *args, "--dry-run"))
    assert rc == 0, dry
    assert sorted(dry.split()) == [f"{ROOT}/0.0.4", f"{ROOT}/0.0.5"]
    assert len(smoke_host.out(f"LC_ALL=C ls -A {ROOT}").split()) == 11

    rc, output = via_login_shell(smoke_host, _agent("prune", *args))
    assert rc == 0, output
    # Kept: the two newest (1.0.0-rc.1, 0.0.6), pinned 0.0.3, previous 0.0.1,
    # live 0.0.2, and everything that is not a version directory.
    assert smoke_host.out(f"LC_ALL=C ls -A {ROOT}").split() == sorted(
        [".previous-version", ".staging", "0.0.1", "0.0.2", "0.0.3", "0.0.6", "1.0.0-rc.1", "9.9.9", "latest"]
    )
    assert via_login_shell(smoke_host, _agent("prune", *args, "--dry-run")) == (0, "")


def test_prune_without_an_install_root(smoke_host: SmokeHost) -> None:
    result = via_login_shell(smoke_host, _agent("prune", ROOT, "0.1.0", "graphyard-agent-smoke-none", 3, "--dry-run"))

    assert result == (0, "")
