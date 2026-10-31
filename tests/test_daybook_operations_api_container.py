"""Exercise the fixture wrapper with a Docker double, never a real daemon."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent / "integration/daybook_operations_api/run-container.sh"


@pytest.mark.parametrize(
    "case", ["success", "fixture_failure", "container_collision", "image_collision", "cleanup_failure", "volume_leak"]
)
def test_owned_container_cleanup_and_collision_refusal(tmp_path: Path, case: str) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\nfrom pathlib import Path\n"
        "root=Path(os.environ['FAKE_DOCKER_ROOT']);args=sys.argv[1:];case=os.environ['FAKE_DOCKER_CASE']\n"
        "with (root/'calls').open('a') as f:f.write(json.dumps(args)+'\\n')\n"
        "if args[0] in ('container','image') and args[1]=='inspect':\n"
        " if '--format' in args: print('a'*64 if args[0]=='container' else 'sha256:ownedimage');sys.exit(0)\n"
        " collision=(case=='container_collision' and args[0]=='container') or "
        "(case=='image_collision' and args[0]=='image')\n"
        " sys.exit(0 if collision or (root/args[0]).exists() else 1)\n"
        "if args[:2]==['volume','inspect']:sys.exit(0 if case=='volume_leak' else 1)\n"
        "if args[0]=='build': (root/'image').touch()\n"
        "if args[0]=='create': (root/'container').touch();print('ownedcontainer')\n"
        "if args[0]=='start': sys.exit(9 if case=='fixture_failure' else 0)\n"
        "if args[0] in ('container','image') and args[1]=='rm':\n"
        " if case=='cleanup_failure' and args[0]=='container':sys.exit(2)\n"
        " (root/args[0]).unlink()\n"
    )
    docker.chmod(0o755)
    uv = binaries / "uv"
    uv.write_text("#!/bin/sh\nexit 90\n")
    uv.chmod(0o755)
    python = binaries / "python3"
    python.write_text(
        '#!/bin/sh\nif [ "$1" = tests/integration/daybook_operations_api/prepare_source.py ]; then exit 0; fi\nexec '
        + sys.executable
        + ' "$@"\n'
    )
    python.chmod(0o755)
    env = dict(os.environ)
    env.update(
        PATH=str(binaries) + os.pathsep + env["PATH"],
        FAKE_DOCKER_ROOT=str(tmp_path),
        FAKE_DOCKER_CASE=case,
        GITHUB_ACTIONS="true",
        RUNNER_ENVIRONMENT="github-hosted",
        GITHUB_RUN_ID="123",
        GITHUB_RUN_ATTEMPT="1",
        IMPLEMENTATION_SHA="a" * 40,
        RUNNER_TEMP=str(tmp_path),
        DAYBOOK_SOURCE=str(tmp_path / "private-source"),
    )
    result = subprocess.run(["bash", str(SCRIPT.resolve())], env=env, capture_output=True, timeout=15)
    calls = [json.loads(line) for line in (tmp_path / "calls").read_text().splitlines()]
    receipt = tmp_path / "daybook-operations-api-123-1/container-cleanup.json"
    if "collision" in case:
        assert result.returncode == 64
        assert all(call[1] == "inspect" for call in calls)
        assert not receipt.exists()
        return
    data = json.loads(receipt.read_text())
    assert result.returncode == {"success": 0, "fixture_failure": 9, "cleanup_failure": 1, "volume_leak": 1}[case]
    assert data["fixture_exit"] == (9 if case == "fixture_failure" else 0)
    assert data["owned_container_and_image_tag_removed"] is (case not in {"cleanup_failure", "volume_leak"})
    create = next(call for call in calls if call[0] == "create")
    mounts = [create[i + 1] for i, arg in enumerate(create) if arg == "--mount"]
    assert len(mounts) == 3
    assert sum(value.endswith(",readonly") for value in mounts) == 2
    assert any("target=/daybook-source,readonly" in value for value in mounts)
    assert all("/root/.ssh" not in value and "/etc/" not in value for value in mounts)
    assert ["container", "rm", "-fv", "ownedcontainer"] in calls
    assert ["image", "rm", "daybook-operations-api-123-1:fixture"] in calls


def test_actual_private_source_preflight_refusals(tmp_path: Path) -> None:
    path = SCRIPT.parent / "prepare_source.py"
    spec = importlib.util.spec_from_file_location("owned_source", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    source.mkdir()
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")

    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(source), *args], env=env, text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    code = source / "src/daybook/operations_protocol.py"
    code.parent.mkdir(parents=True)
    code.write_text("ADAPTERS = ()\n")
    git("add", ".")
    git("commit", "-qm", "owned source")
    revision = git("rev-parse", "HEAD")
    git("remote", "add", "origin", "https://github.com/ephes/daybook.git")
    module.validate_source(source, revision, revision)
    with pytest.raises(ValueError, match="not_exact_clean"):
        module.validate_source(source, "a" * 40, revision)
    code.write_text("dirty\n")
    with pytest.raises(ValueError, match="not_exact_clean"):
        module.validate_source(source, revision, revision)
    git("checkout", "--", str(code))
    git("config", "http.https://github.com/.extraheader", "AUTHORIZATION: synthetic-only")
    with pytest.raises(ValueError, match="authorization"):
        module.validate_source(source, revision, revision)
    git("config", "--unset-all", "http.https://github.com/.extraheader")
    alternate = source / ".git/objects/info/alternates"
    alternate.write_text("/outside/objects\n")
    with pytest.raises(ValueError, match="alternates"):
        module.validate_source(source, revision, revision)
    alternate.unlink()
    link = tmp_path / "link"
    link.symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError, match="source_path"):
        module.validate_source(link, revision, revision)
    with pytest.raises(ValueError, match="git_refused"):
        module.validate_source(source, revision, "b" * 40)
    git("remote", "set-url", "origin", "https://synthetic@example.invalid/private")
    with pytest.raises(ValueError, match="origin"):
        module.validate_source(source, revision, revision)


def test_missing_private_source_refuses_before_docker(tmp_path: Path) -> None:
    binaries = tmp_path / "bin"
    binaries.mkdir()
    docker = binaries / "docker"
    docker.write_text("#!/bin/sh\ntouch '" + str(tmp_path / "docker-called") + "'\nexit 90\n")
    docker.chmod(0o755)
    env = dict(
        os.environ,
        PATH=str(binaries) + os.pathsep + os.environ["PATH"],
        GITHUB_ACTIONS="true",
        RUNNER_ENVIRONMENT="github-hosted",
        GITHUB_RUN_ID="123",
        GITHUB_RUN_ATTEMPT="1",
        IMPLEMENTATION_SHA="a" * 40,
        RUNNER_TEMP=str(tmp_path),
        DAYBOOK_SOURCE=str(tmp_path / "absent"),
    )
    result = subprocess.run(["bash", str(SCRIPT)], env=env, capture_output=True, timeout=30)
    assert result.returncode != 0
    assert not (tmp_path / "docker-called").exists()


def test_real_local_clone_across_uid_boundary(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("fixture", SCRIPT.parent / "management_fixture.py")
    assert spec
    assert spec.loader
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    source = tmp_path / "source"
    source.mkdir()
    clean_env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")

    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(source), *args], env=clean_env, text=True).strip()

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    (source / "public.py").write_text("pass\n")
    git("add", ".")
    git("commit", "-qm", "owned")
    revision = git("rev-parse", "HEAD")
    # Git's own test hook exercises the same ownership refusal without sudo.
    different_owner = dict(clean_env, GIT_TEST_ASSUME_DIFFERENT_OWNER="1")
    bad = subprocess.run(
        ["git", "clone", "--no-hardlinks", "--", str(source), str(tmp_path / "old")],
        env=different_owner,
        capture_output=True,
    )
    assert bad.returncode != 0
    assert b"dubious ownership" in bad.stderr
    destination = tmp_path / "fixed"
    argv = fixture.source_clone_command(source, destination)
    assert argv[:3] == ["git", "-c", "safe.directory=" + str(source / ".git")]
    fixed = subprocess.run(argv, env=different_owner, capture_output=True)
    assert fixed.returncode == 0, fixed.stderr.decode()
    assert (
        subprocess.check_output(["git", "-C", str(destination), "rev-parse", "HEAD"], env=clean_env, text=True).strip()
        == revision
    )
    assert "safe.directory" not in (source / ".git/config").read_text()


def test_archive_preparation_before_source_ownership_handoff(tmp_path: Path) -> None:
    # The later paired rsync run consumes the already prepared bytes and never
    # invokes root Git against the now service-user-owned checkout.
    import ast

    tree = ast.parse((SCRIPT.parent / "management_fixture.py").read_text())
    paired = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "paired_rsync_repeat")
    assert [arg.arg for arg in paired.args.args] == ["archive"]
    assert not any(isinstance(n, ast.Constant) and n.value == "git" for n in ast.walk(paired))
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    archive = next(
        n
        for n in ast.walk(main)
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "archive" for t in n.targets)
    )
    handoff = next(
        n
        for n in ast.walk(main)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "command"
        and n.args
        and isinstance(n.args[0], ast.List)
        and len(n.args[0].elts) > 3
        and isinstance(n.args[0].elts[0], ast.Constant)
        and n.args[0].elts[0].value == "chown"
        and ast.unparse(n.args[0].elts[-1]) == "str(HOME)"
    )
    assert archive.lineno < handoff.lineno
    source = tmp_path / "source"
    source.mkdir()
    env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")

    def git(*args: str) -> bytes:
        return subprocess.check_output(["git", "-C", str(source), *args], env=env)

    git("init", "-q")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.invalid")
    (source / "public.py").write_text("pass\n")
    git("add", ".")
    git("commit", "-qm", "owned")
    prepared = git("archive", "HEAD")
    assert prepared
    bad = subprocess.run(
        ["git", "-C", str(source), "archive", "HEAD"],
        env=dict(env, GIT_TEST_ASSUME_DIFFERENT_OWNER="1"),
        capture_output=True,
    )
    assert bad.returncode != 0
    assert b"dubious ownership" in bad.stderr
